# Developed by Channa Sandeepa | OmniScan-AI v2.0 | Copyright 2026
"""Advanced JS analyzer: deep-crawl every linked JavaScript asset for endpoints + secrets.

Differs from :class:`SecretFinder` by (a) aggressively discovering every ``<script
src>`` / module / preload / link, (b) fetching them in parallel via a semaphore,
and (c) additionally extracting API endpoints, URLs, and ``fetch``/``axios``/
``XMLHttpRequest`` call targets.
"""

from __future__ import annotations

import asyncio
import re
from typing import Callable
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup

from .secret_finder import SEVERITY_HIGH, SEVERITY_LOW, SEVERITY_MEDIUM, SecretFinder, severity_for

ProgressCallback = Callable[[], None]
PlanCallback = Callable[[int], None]


class JSAnalyzer:
    """Deep-scan all linked JS assets for endpoints and secrets in parallel."""

    _SENSITIVE_PATH_HINTS: tuple[str, ...] = (
        "admin",
        "internal",
        "debug",
        "private",
        "backup",
        "config",
        "actuator",
        "oauth",
        "token",
        "keys",
        "env",
    )

    _ENDPOINT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
        (
            "endpoint_url",
            re.compile(
                r"""["'`](https?://[A-Za-z0-9._~%\-:@/?#\[\]!$&'()*+,;=]{4,512})["'`]"""
            ),
        ),
        (
            "endpoint_api_path",
            re.compile(
                r"""["'`](/(?:api|v\d+|graphql|rest|oauth|admin|internal|webhook|auth|users|accounts|payments|orders|webhooks|internal[_\-]api)"""
                r"""(?:/[A-Za-z0-9_\-./:]{0,256})?"""
                r"""(?:\?[A-Za-z0-9_\-./:=&%+]*)?)["'`]""",
                re.IGNORECASE,
            ),
        ),
        (
            "fetch_call",
            re.compile(
                r"""\bfetch\s*\(\s*["'`]([^"'`\s]{4,512})["'`]""",
            ),
        ),
        (
            "axios_call",
            re.compile(
                r"""\baxios(?:\.(?:get|post|put|delete|patch|request))?\s*\(\s*["'`]([^"'`\s]{4,512})["'`]""",
                re.IGNORECASE,
            ),
        ),
        (
            "xhr_open",
            re.compile(
                r"""\.open\s*\(\s*["'`](?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)["'`]\s*,\s*["'`]([^"'`\s]{4,512})["'`]""",
                re.IGNORECASE,
            ),
        ),
    ]

    def __init__(
        self,
        timeout: aiohttp.ClientTimeout | None = None,
        concurrency: int = 12,
        max_scripts: int = 60,
    ) -> None:
        self._timeout = timeout or aiohttp.ClientTimeout(total=25)
        self._concurrency = max(1, concurrency)
        self._max_scripts = max(1, max_scripts)
        self._secret_finder = SecretFinder(timeout=self._timeout)

    @staticmethod
    def _looks_like_js(url: str, content_type: str) -> bool:
        url_lower = url.lower().split("?", 1)[0]
        if url_lower.endswith((".js", ".mjs", ".cjs", ".jsx")):
            return True
        ct = (content_type or "").lower()
        return any(
            tok in ct
            for tok in ("javascript", "ecmascript", "text/js", "application/js")
        )

    def _collect_js_urls(self, html: str, page_url: str) -> list[str]:
        try:
            soup = BeautifulSoup(html, "html.parser")
        except Exception:
            return []

        seen: set[str] = set()
        urls: list[str] = []

        def _add(href: str | None) -> None:
            if not href:
                return
            href = str(href).strip()
            if not href or href.startswith(("data:", "javascript:", "blob:")):
                return
            abs_url = urljoin(page_url, href)
            parsed = urlparse(abs_url)
            if parsed.scheme not in ("http", "https"):
                return
            if abs_url in seen:
                return
            seen.add(abs_url)
            urls.append(abs_url)

        for tag in soup.find_all("script"):
            _add(tag.get("src"))

        for tag in soup.find_all("link"):
            rel = " ".join(tag.get("rel") or []).lower()
            as_attr = (tag.get("as") or "").lower()
            tag_type = (tag.get("type") or "").lower()
            if "modulepreload" in rel or as_attr == "script" or "module" in tag_type:
                _add(tag.get("href"))

        return urls[: self._max_scripts]

    def _scan_endpoints(self, text: str, source_url: str) -> list[dict]:
        findings: list[dict] = []
        for kind, pattern in self._ENDPOINT_PATTERNS:
            try:
                for m in pattern.finditer(text):
                    match_value = m.group(1) if m.groups() else m.group(0)
                    severity = SEVERITY_LOW
                    low_val = match_value.lower()
                    if any(h in low_val for h in self._SENSITIVE_PATH_HINTS):
                        severity = SEVERITY_MEDIUM
                    findings.append(
                        {
                            "type": kind,
                            "severity": severity,
                            "source_url": source_url,
                            "match": match_value,
                        }
                    )
            except re.error:
                continue
        return findings

    def _scan_content(self, text: str, source_url: str) -> list[dict]:
        out: list[dict] = []
        try:
            out.extend(self._secret_finder._scan_text(text, source_url))
        except Exception:
            pass

        endpoint_rows = self._scan_endpoints(text, source_url)

        seen: set[tuple[str, str, str]] = {
            (r["type"], r["match"], r["source_url"]) for r in out
        }
        for r in endpoint_rows:
            key = (r["type"], r["match"], r["source_url"])
            if key not in seen:
                seen.add(key)
                out.append(r)

        return out

    async def _fetch_and_scan(
        self,
        session: aiohttp.ClientSession,
        sem: asyncio.Semaphore,
        js_url: str,
        headers: dict[str, str],
    ) -> list[dict]:
        async with sem:
            try:
                async with session.get(
                    js_url, headers=headers, allow_redirects=True
                ) as resp:
                    if resp.status != 200:
                        return []
                    ctype = resp.headers.get("Content-Type") or ""
                    if not self._looks_like_js(js_url, ctype):
                        return []
                    text = await resp.text(errors="replace")
                    final_url = str(resp.url)
            except (aiohttp.ClientError, TimeoutError, OSError):
                return []
            except Exception:
                return []

        try:
            return self._scan_content(text, final_url)
        except Exception:
            return []

    async def analyze(
        self,
        target_url: str,
        on_plan: PlanCallback | None = None,
        on_advance: ProgressCallback | None = None,
    ) -> list[dict]:
        """Fetch page, enumerate linked JS, concurrently extract endpoints + secrets."""
        headers = {
            "User-Agent": "OmniScan-AI/1.0 (js-deep-analyzer)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

        def _advance() -> None:
            if on_advance is not None:
                try:
                    on_advance()
                except Exception:
                    pass

        async with aiohttp.ClientSession(timeout=self._timeout) as session:
            try:
                async with session.get(
                    target_url, headers=headers, allow_redirects=True
                ) as resp:
                    resp.raise_for_status()
                    html = await resp.text(errors="replace")
                    page_url = str(resp.url)
            except aiohttp.ClientResponseError as exc:
                raise RuntimeError(
                    f"HTTP {exc.status} while fetching page: {target_url}"
                ) from exc
            except (aiohttp.ClientError, TimeoutError, OSError) as exc:
                raise RuntimeError(f"Network error while fetching page: {exc}") from exc

            js_urls = self._collect_js_urls(html, page_url)

            total = max(1 + len(js_urls), 1)
            if on_plan is not None:
                try:
                    on_plan(total)
                except Exception:
                    pass
            _advance()

            if not js_urls:
                return []

            sem = asyncio.Semaphore(self._concurrency)
            tasks = [
                asyncio.create_task(self._fetch_and_scan(session, sem, u, headers))
                for u in js_urls
            ]

            results: list[dict] = []
            for coro in asyncio.as_completed(tasks):
                try:
                    rows = await coro
                    results.extend(rows)
                except Exception:
                    pass
                _advance()

        sev_rank = {SEVERITY_HIGH: 0, SEVERITY_MEDIUM: 1, SEVERITY_LOW: 2}
        results.sort(
            key=lambda r: (sev_rank.get(r.get("severity", "Low"), 3), r.get("type", ""))
        )
        return results
