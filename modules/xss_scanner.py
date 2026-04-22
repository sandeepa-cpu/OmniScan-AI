# Developed by Channa Sandeepa | OmniScan-AI v2.0 | Copyright 2026
"""Reflected-XSS probe: inject common payloads into discoverable GET parameters.

Authorized testing only. This module does not attempt DOM-based execution; it
only detects verbatim reflection of payloads in HTTP response bodies as a
heuristic signal for reflected XSS.
"""

from __future__ import annotations

import asyncio
from typing import Callable, Sequence
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import aiohttp
from bs4 import BeautifulSoup

ProgressCallback = Callable[[], None]
PlanCallback = Callable[[int], None]


class XSSScanner:
    """Probe URL query parameters and GET forms for reflected-XSS payloads."""

    PAYLOADS: tuple[str, ...] = (
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "';alert(1);//",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "\"><svg/onload=alert(1)>",
        "javascript:alert(1)",
        "\"><img src=x onerror=alert(1)>",
        "\" onmouseover=\"alert(1)",
        "<iframe src=\"javascript:alert(1)\">",
    )

    _DEFAULT_PROBE_PARAMS: tuple[str, ...] = ("q", "search", "s")

    def __init__(
        self,
        timeout: aiohttp.ClientTimeout | None = None,
        extra_payloads: Sequence[str] = (),
        concurrency: int = 10,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self._timeout = timeout or aiohttp.ClientTimeout(total=20)
        self._extra_payloads: tuple[str, ...] = tuple(
            p for p in extra_payloads if isinstance(p, str) and p
        )
        self._concurrency = max(1, concurrency)
        self._extra_headers: dict[str, str] = dict(extra_headers or {})

    def _effective_payloads(self) -> tuple[str, ...]:
        seen: set[str] = set()
        merged: list[str] = []
        for p in (*self.PAYLOADS, *self._extra_payloads):
            if p in seen:
                continue
            seen.add(p)
            merged.append(p)
        return tuple(merged)

    @staticmethod
    def _strip_query(url: str) -> str:
        parsed = urlparse(url)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, "", ""))

    @staticmethod
    def _build_url(base_url_no_query: str, params: dict[str, str]) -> str:
        qs = urlencode(params, doseq=True)
        return f"{base_url_no_query}?{qs}" if qs else base_url_no_query

    async def _fetch(
        self, session: aiohttp.ClientSession, url: str, method: str = "GET"
    ) -> tuple[str | None, str | None, int | None]:
        try:
            async with session.request(method, url, allow_redirects=True) as resp:
                text = await resp.text(errors="replace")
                return text, str(resp.url), resp.status
        except (aiohttp.ClientError, TimeoutError, OSError):
            return None, None, None
        except Exception:
            return None, None, None

    def _discover_injection_points(self, html: str, page_url: str) -> list[dict]:
        """
        Return GET-based injection points.

        Each point: {kind, method, action, base_params, param_name, label}.
        """
        points: list[dict] = []
        parsed = urlparse(page_url)

        if parsed.query:
            existing = dict(parse_qsl(parsed.query, keep_blank_values=True))
            base = self._strip_query(page_url)
            for name in existing:
                points.append(
                    {
                        "kind": "url_param",
                        "method": "GET",
                        "action": base,
                        "base_params": dict(existing),
                        "param_name": name,
                        "label": f"URL ?{name}=",
                    }
                )

        try:
            soup = BeautifulSoup(html, "html.parser")
        except Exception:
            soup = None

        if soup is not None:
            for form in soup.find_all("form"):
                try:
                    method = (form.get("method") or "GET").upper()
                    if method != "GET":
                        continue
                    action = str(form.get("action") or page_url)
                    action_url = self._strip_query(urljoin(page_url, action))
                    base_params: dict[str, str] = {}
                    for inp in form.find_all(["input", "textarea", "select"]):
                        name = inp.get("name")
                        if not name:
                            continue
                        itype = (inp.get("type") or "").lower()
                        if itype in {"submit", "button", "image", "file", "password"}:
                            continue
                        base_params[str(name)] = str(inp.get("value") or "")
                    for name in base_params:
                        points.append(
                            {
                                "kind": "form_get",
                                "method": "GET",
                                "action": action_url,
                                "base_params": dict(base_params),
                                "param_name": name,
                                "label": f"form GET {action_url}?{name}=",
                            }
                        )
                except (TypeError, ValueError):
                    continue

        if not points:
            base = self._strip_query(page_url)
            for probe in self._DEFAULT_PROBE_PARAMS:
                points.append(
                    {
                        "kind": "probe_param",
                        "method": "GET",
                        "action": base,
                        "base_params": {},
                        "param_name": probe,
                        "label": f"probe ?{probe}=",
                    }
                )

        return points

    @staticmethod
    def _severity_for_reflection(payload: str) -> str:
        low_payload = payload.lower()
        if "<script" in low_payload or "onerror=" in low_payload or "onload=" in low_payload:
            return "High"
        if "javascript:" in low_payload or "onmouseover=" in low_payload:
            return "High"
        return "Medium"

    @staticmethod
    def _context_snippet(text: str, payload: str, span: int = 40) -> str:
        idx = text.find(payload)
        if idx < 0:
            return "reflected"
        start = max(0, idx - span)
        end = min(len(text), idx + len(payload) + span)
        snippet = text[start:end].replace("\n", " ").replace("\r", " ")
        return snippet

    async def scan(
        self,
        target_url: str,
        on_plan: PlanCallback | None = None,
        on_advance: ProgressCallback | None = None,
    ) -> list[dict]:
        """
        Probe reflected-XSS signals on ``target_url``.

        Returns rows with:
          severity, kind, method, url, param, payload, note, status.
        """
        results: list[dict] = []
        headers = {
            "User-Agent": "OmniScan-AI/1.0 (security research)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            **self._extra_headers,
        }

        def _advance() -> None:
            if on_advance is not None:
                try:
                    on_advance()
                except Exception:
                    pass

        payloads = self._effective_payloads()

        async with aiohttp.ClientSession(timeout=self._timeout, headers=headers) as session:
            html, page_url, status = await self._fetch(session, target_url)
            if html is None or page_url is None:
                if on_plan is not None:
                    try:
                        on_plan(1)
                    except Exception:
                        pass
                _advance()
                return results

            points = self._discover_injection_points(html, page_url)
            total = max(len(points) * len(payloads), 1)
            if on_plan is not None:
                try:
                    on_plan(total)
                except Exception:
                    pass

            if not points:
                _advance()
                return results

            sem = asyncio.Semaphore(self._concurrency)

            async def _probe_point(point: dict) -> dict | None:
                hit: dict | None = None
                for payload in payloads:
                    if hit is not None:
                        _advance()
                        continue
                    async with sem:
                        params = dict(point["base_params"])
                        params[point["param_name"]] = payload
                        test_url = self._build_url(point["action"], params)
                        body, final_url, st = await self._fetch(session, test_url)
                    if body and payload in body:
                        hit = {
                            "severity": self._severity_for_reflection(payload),
                            "kind": point["kind"],
                            "method": point["method"],
                            "url": final_url or test_url,
                            "param": point["param_name"],
                            "payload": payload,
                            "status": st if st is not None else "-",
                            "note": self._context_snippet(body, payload),
                        }
                    _advance()
                return hit

            probe_tasks = [asyncio.create_task(_probe_point(pt)) for pt in points]
            for task in asyncio.as_completed(probe_tasks):
                try:
                    row = await task
                except Exception:
                    row = None
                if row is not None:
                    results.append(row)

        return results
