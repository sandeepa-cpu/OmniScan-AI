# Developed by Channa Sandeepa | OmniScan-AI v2.0 | Copyright 2026
"""Internet Archive (Wayback Machine) CDX discovery and live-host replay checks."""

from __future__ import annotations

import asyncio
import json
from typing import Callable
from urllib.parse import urlparse, urlunparse

import aiohttp

from .evasion import EvasionProfile, build_browser_headers, friendly_network_error
from .scanner_engine import http_client_timeout

ProgressCallback = Callable[[], None]
PlanCallback = Callable[[int], None]

SEVERITY_MEDIUM = "Medium"
SEVERITY_LOW = "Low"

CDX_URL = "https://web.archive.org/cdx/search/cdx"


class WaybackScanner:
    """Query Archive.org CDX for historical URLs, then probe the live host for those paths."""

    def __init__(
        self,
        timeout: aiohttp.ClientTimeout | None = None,
        concurrency: int = 14,
        evasion: EvasionProfile | None = None,
    ) -> None:
        self._timeout = timeout or http_client_timeout()
        self._cdx_timeout = aiohttp.ClientTimeout(total=120)
        self._concurrency = max(1, concurrency)
        self._evasion = evasion or EvasionProfile()

    @staticmethod
    def _normalize_target(url: str) -> tuple[str, str]:
        raw = url.strip()
        if "://" not in raw:
            raw = f"https://{raw}"
        p = urlparse(raw)
        scheme = p.scheme or "https"
        host = (p.netloc or p.path or "").lower()
        if host.endswith(":443"):
            host = host[:-4]
        base = urlunparse((scheme, host, "/", "", "", ""))
        return base, host

    @staticmethod
    def _live_url_for_path(base: str, path: str, query: str) -> str:
        p = urlparse(base)
        path = path if path.startswith("/") else f"/{path}"
        return urlunparse((p.scheme, p.netloc, path, "", query, ""))

    @staticmethod
    def seed_paths_from_history(
        historical_urls: list[str],
        live_host: str,
        *,
        max_paths: int = 400,
    ) -> list[tuple[str, str]]:
        """Return ``(path_for_bruter, severity)`` pairs to merge into path bruting."""
        host_l = live_host.lower().removeprefix("www.")
        seen: set[str] = set()
        out: list[tuple[str, str]] = []
        for hurl in historical_urls:
            try:
                u = urlparse(hurl)
            except Exception:
                continue
            uh = (u.netloc or "").lower().removeprefix("www.")
            if uh != host_l and uh != live_host.lower():
                continue
            path = u.path or "/"
            if not path.startswith("/"):
                path = "/" + path
            if path in ("/", ""):
                continue
            key = path + ("\0" + u.query if u.query else "")
            if key in seen:
                continue
            seen.add(key)
            rel = path.lstrip("/")
            if not rel:
                continue
            out.append((rel, SEVERITY_LOW))
            if len(out) >= max_paths:
                break
        return out

    async def _fetch_cdx(
        self,
        session: aiohttp.ClientSession,
        host: str,
        *,
        max_rows: int,
    ) -> list[str]:
        params = {
            "url": f"{host}/*",
            "matchType": "prefix",
            "output": "json",
            "fl": "original",
            "filter": "statuscode:200",
            "collapse": "urlkey",
            "limit": str(max(1, min(max_rows, 15_000))),
        }
        headers = {
            "User-Agent": (
                "OmniScan-AI/2.0 (authorized security research; +https://archive.org/help)"
            ),
            "Accept": "application/json",
        }
        await self._evasion.apply_jitter()
        async with session.get(
            CDX_URL, params=params, headers=headers, timeout=self._cdx_timeout
        ) as resp:
            if resp.status != 200:
                raw = await resp.content.read(4_096)
                body = raw.decode("utf-8", errors="replace")
                raise RuntimeError(f"Wayback CDX HTTP {resp.status}: {body[:200]}")
            raw = await resp.read()
        try:
            data = json.loads(raw.decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            raise RuntimeError("Wayback CDX returned invalid JSON") from exc
        if not data or not isinstance(data, list):
            return []
        originals: list[str] = []
        for row in data[1:]:
            if isinstance(row, list) and row:
                originals.append(str(row[0]))
            elif isinstance(row, str):
                originals.append(row)
        return originals

    async def scan(
        self,
        target_url: str,
        on_plan: PlanCallback | None = None,
        on_advance: ProgressCallback | None = None,
        *,
        max_cdx_urls: int = 8_000,
        live_probe_limit: int = 450,
    ) -> tuple[list[dict], list[str]]:
        base, host = self._normalize_target(target_url)
        referer = base if base.endswith("/") else f"{base}/"

        def _advance() -> None:
            if on_advance is not None:
                try:
                    on_advance()
                except Exception:
                    pass

        try:
            connector = self._evasion.aiohttp_connector(ssl=True, limit=40)
        except RuntimeError:
            raise

        findings: list[dict] = []

        async with aiohttp.ClientSession(
            timeout=self._timeout, connector=connector, trust_env=False
        ) as session:
            try:
                historical = await self._fetch_cdx(session, host, max_rows=max_cdx_urls)
            except (aiohttp.ClientError, TimeoutError, OSError) as exc:
                raise RuntimeError(friendly_network_error(exc)) from exc

            uniq: dict[tuple[str, str], str] = {}
            host_l = host.lower().removeprefix("www.")
            for hurl in historical:
                try:
                    u = urlparse(hurl)
                except Exception:
                    continue
                uh = (u.netloc or "").lower().removeprefix("www.")
                if uh != host_l and uh != host.lower():
                    continue
                path = u.path or "/"
                if not path.startswith("/"):
                    path = "/" + path
                q = u.query or ""
                key = (path, q)
                if key not in uniq:
                    uniq[key] = hurl

            triples = [(p, q, hu) for (p, q), hu in uniq.items()][:live_probe_limit]
            total = max(1, 1 + len(triples))
            if on_plan is not None:
                try:
                    on_plan(total)
                except Exception:
                    pass
            _advance()

            sem = asyncio.Semaphore(self._concurrency)

            async def _probe_one(hist_url: str, path: str, query: str) -> dict | None:
                live = self._live_url_for_path(base, path, query)
                async with sem:
                    try:
                        await self._evasion.apply_jitter()
                        h = build_browser_headers(
                            referer=referer, accept="*/*", evasion=self._evasion
                        )
                        async with session.get(
                            live, headers=h, allow_redirects=False, timeout=self._timeout
                        ) as resp:
                            st = resp.status
                    except (aiohttp.ClientError, TimeoutError, OSError):
                        return None
                    except Exception:
                        return None
                if st >= 400 and st != 403 and st != 401:
                    return None
                sev = SEVERITY_LOW
                if st == 200:
                    sev = SEVERITY_MEDIUM
                elif st in (401, 403):
                    sev = SEVERITY_LOW
                disp = path + (f"?{query}" if query else "")
                return {
                    "severity": sev,
                    "historical_url": hist_url,
                    "path": disp,
                    "live_url": live,
                    "live_status": st,
                    "note": "Historical URL; probed on live host (no redirect follow)",
                }

            tasks = [
                asyncio.create_task(_probe_one(hu, p, q)) for p, q, hu in triples
            ]
            for coro in asyncio.as_completed(tasks):
                row = await coro
                _advance()
                if row is not None:
                    findings.append(row)

        findings.sort(
            key=lambda r: (
                0 if r.get("severity") == SEVERITY_MEDIUM else 1,
                r.get("live_status", 999),
                r.get("path", ""),
            )
        )
        return findings, historical
