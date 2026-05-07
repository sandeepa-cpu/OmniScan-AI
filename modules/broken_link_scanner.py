# Developed by Channa Sandeepa | OmniScan-AI v2.0 | Copyright 2026
"""External link harvest from HTML source + DNS / HTTP checks for takeover signals."""

from __future__ import annotations

import asyncio
import re
import socket
from typing import Callable
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup

from .evasion import EvasionProfile, build_browser_headers, friendly_network_error
from .scanner_engine import http_client_timeout

PlanCallback = Callable[[int], None]
ProgressCallback = Callable[[], None]

SEVERITY_HIGH = "High"

_SKIP_SCHEMES = frozenset(
    x + ":"
    for x in (
        "mailto",
        "tel",
        "javascript",
        "data",
        "blob",
        "about",
        "file",
        "ftp",
    )
)

# Hostnames (without leading www.) we may HTTP-probe for 404 / soft “gone” pages.
_PROBE_HOSTS: frozenset[str] = frozenset(
    {
        "twitter.com",
        "x.com",
        "facebook.com",
        "instagram.com",
        "linkedin.com",
        "tiktok.com",
        "youtube.com",
        "github.com",
        "gitlab.com",
        "medium.com",
        "pinterest.com",
        "reddit.com",
        "twitch.tv",
        "snapchat.com",
        "threads.net",
    }
)

_URL_IN_TEXT = re.compile(r"""https?://[^\s"'<>)\]]{4,2048}""", re.I)

_SOFT_DEAD = re.compile(
    r"(account.{0,12}suspended|doesn'?t exist|page( was)? not found|"
    r"profile( was)? not found|user( was)? not found|sorry.{0,40}exist|"
    r"no longer available|this page isn'?t available)",
    re.I,
)


def _normalize_target_host(target_url: str) -> str:
    raw = target_url.strip()
    if "://" not in raw:
        raw = f"https://{raw}"
    return (urlparse(raw).hostname or "").lower().rstrip(".")


def _normalize_external_url(page_url: str, raw: str) -> str | None:
    v = (raw or "").strip()
    if not v or v.startswith("#"):
        return None
    lv = v.lower()
    if any(lv.startswith(s) for s in _SKIP_SCHEMES):
        return None
    if lv.startswith("javascript:"):
        return None
    if v.startswith("//"):
        v = "https:" + v
    abs_u = urljoin(page_url, v)
    p = urlparse(abs_u)
    if p.scheme not in ("http", "https"):
        return None
    host = (p.hostname or "").lower().rstrip(".")
    if not host:
        return None
    return abs_u


def _is_internal(host: str, target_host: str) -> bool:
    if not host or not target_host:
        return True
    host = host.lower().rstrip(".")
    if host == target_host:
        return True
    return host.endswith("." + target_host)


def _rootish_host(host: str) -> str:
    host = host.lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    return host


def _should_http_probe(url: str, host: str) -> bool:
    rh = _rootish_host(host)
    if rh not in _PROBE_HOSTS:
        return False
    path = urlparse(url).path or "/"
    if path in ("/", ""):
        return False
    return True


async def _dns_resolves(host: str) -> bool:
    def _sync() -> bool:
        for port in (443, 80, None):
            try:
                if port is None:
                    socket.getaddrinfo(host, None)
                else:
                    socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
                return True
            except OSError:
                continue
        return False

    return await asyncio.to_thread(_sync)


class BrokenLinkScanner:
    """Collect external links from the landing HTML and flag likely takeover cases."""

    def __init__(self, *, max_dns_hosts: int = 48, max_http_urls: int = 36) -> None:
        self._max_dns_hosts = max_dns_hosts
        self._max_http_urls = max_http_urls

    async def scan(
        self,
        target_url: str,
        *,
        extra_headers: dict[str, str] | None = None,
        evasion: EvasionProfile | None = None,
        on_plan: PlanCallback | None = None,
        on_advance: ProgressCallback | None = None,
    ) -> list[dict]:
        ev = evasion or EvasionProfile()
        extra = dict(extra_headers or {})

        def _advance() -> None:
            if on_advance is not None:
                try:
                    on_advance()
                except Exception:
                    pass

        raw_u = target_url.strip()
        if "://" not in raw_u:
            raw_u = f"https://{raw_u}"
        target_host = _normalize_target_host(raw_u)
        page_ref = raw_u if raw_u.endswith("/") else f"{raw_u}/"

        try:
            connector = ev.aiohttp_connector(ssl=True, limit=16)
        except RuntimeError:
            raise

        findings: list[dict] = []
        try:
            async with aiohttp.ClientSession(
                timeout=http_client_timeout(),
                connector=connector,
                trust_env=False,
            ) as session:
                await ev.apply_jitter()
                headers = build_browser_headers(referer=page_ref, extra=extra, evasion=ev)
                async with session.get(
                    raw_u, headers=headers, allow_redirects=True
                ) as resp:
                    final_url = str(resp.url)
                    raw = await resp.read()
                    html = raw[:2_000_000].decode("utf-8", errors="replace")

                try:
                    soup = BeautifulSoup(html, "html.parser")
                except Exception:
                    soup = None

                collected: list[str] = []
                if soup is not None:
                    for tag in soup.find_all(True):
                        for attr in (
                            "href",
                            "src",
                            "cite",
                            "poster",
                            "formaction",
                            "data-url",
                            "data-href",
                            "data-link",
                        ):
                            val = tag.get(attr)
                            if val and isinstance(val, str):
                                nu = _normalize_external_url(final_url, val)
                                if nu:
                                    collected.append(nu)
                        if tag.name == "link":
                            href = tag.get("href")
                            if href and isinstance(href, str):
                                nu = _normalize_external_url(final_url, href)
                                if nu:
                                    collected.append(nu)
                    for script in soup.find_all("script"):
                        src = script.get("src")
                        if src and isinstance(src, str):
                            nu = _normalize_external_url(final_url, src)
                            if nu:
                                collected.append(nu)
                        for chunk in script.stripped_strings:
                            for m in _URL_IN_TEXT.finditer(str(chunk)):
                                nu = _normalize_external_url(final_url, m.group(0))
                                if nu:
                                    collected.append(nu)

                for m in _URL_IN_TEXT.finditer(html):
                    nu = _normalize_external_url(final_url, m.group(0))
                    if nu:
                        collected.append(nu)

                external: list[str] = []
                seen: set[str] = set()
                for u in collected:
                    host = (urlparse(u).hostname or "").lower().rstrip(".")
                    if not host or _is_internal(host, target_host):
                        continue
                    if u in seen:
                        continue
                    seen.add(u)
                    external.append(u)

                if on_plan is not None:
                    try:
                        on_plan(
                            max(
                                1,
                                min(
                                    len(external),
                                    self._max_dns_hosts + self._max_http_urls,
                                ),
                            )
                        )
                    except Exception:
                        pass

                if not external:
                    _advance()
                    return findings

                ext_sorted = external[:200]
                hosts_todo: list[str] = []
                host_seen: set[str] = set()
                for u in ext_sorted:
                    h = (urlparse(u).hostname or "").lower().rstrip(".")
                    if h and h not in host_seen:
                        host_seen.add(h)
                        hosts_todo.append(h)
                    if len(hosts_todo) >= self._max_dns_hosts:
                        break

                dns_bad: set[str] = set()
                for host in hosts_todo:
                    await ev.apply_jitter()
                    ok = await _dns_resolves(host)
                    _advance()
                    if not ok:
                        dns_bad.add(host)

                for u in ext_sorted:
                    host = (urlparse(u).hostname or "").lower().rstrip(".")
                    if host in dns_bad:
                        findings.append(
                            {
                                "type": "takeover_dangling_domain",
                                "severity": SEVERITY_HIGH,
                                "url": u[:2048],
                                "host": host,
                                "source_url": final_url,
                                "note": (
                                    "Potential takeover: hostname does not resolve "
                                    "(NXDOMAIN / no DNS)."
                                ),
                                "evidence": "dns_failure",
                            }
                        )

                http_candidates = [
                    u
                    for u in ext_sorted
                    if _should_http_probe(u, urlparse(u).hostname or "")
                ]
                sem = asyncio.Semaphore(6)

                async def _probe_one(u: str) -> dict | None:
                    host = (urlparse(u).hostname or "").lower().rstrip(".")
                    if host in dns_bad:
                        return None
                    await ev.apply_jitter()
                    status = 0
                    snippet = ""
                    try:
                        async with sem:
                            h = build_browser_headers(
                                referer=page_ref, extra=extra, evasion=ev
                            )
                            async with session.get(
                                u,
                                headers=h,
                                allow_redirects=True,
                                timeout=http_client_timeout(),
                            ) as resp:
                                status = resp.status
                                if status == 200:
                                    chunk = await resp.content.read(14_000)
                                    snippet = chunk.decode("utf-8", errors="replace")
                    except (aiohttp.ClientError, TimeoutError, OSError):
                        return None
                    finally:
                        _advance()

                    if status in (404, 410):
                        return {
                            "type": "takeover_dead_social",
                            "severity": SEVERITY_HIGH,
                            "url": u[:2048],
                            "host": host,
                            "source_url": final_url,
                            "note": (
                                "Potential takeover: linked social / profile URL returned "
                                f"HTTP {status} (account or resource may be gone)."
                            ),
                            "evidence": f"http_{status}",
                        }
                    if status == 200 and _SOFT_DEAD.search(snippet):
                        return {
                            "type": "takeover_dead_social",
                            "severity": SEVERITY_HIGH,
                            "url": u[:2048],
                            "host": host,
                            "source_url": final_url,
                            "note": (
                                "Potential takeover: response body suggests missing or "
                                "removed account (verify manually; some sites mask real status)."
                            ),
                            "evidence": "soft_not_found",
                        }
                    return None

                probe_slice = http_candidates[: self._max_http_urls]
                if probe_slice:
                    results = await asyncio.gather(
                        *(_probe_one(u) for u in probe_slice)
                    )
                    for r in results:
                        if r is not None:
                            findings.append(r)
        except (aiohttp.ClientError, TimeoutError, OSError) as exc:
            raise RuntimeError(friendly_network_error(exc)) from exc

        dedup: dict[tuple[str, str, str], dict] = {}
        for row in findings:
            key = (
                row.get("type", ""),
                row.get("url", "")[:800],
                row.get("evidence", ""),
            )
            dedup[key] = row
        return list(dedup.values())
