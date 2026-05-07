# Developed by Channa Sandeepa | OmniScan-AI v2.0 | Copyright 2026
"""Hidden GET/POST parameter probing (debug flags, admin toggles, etc.)."""

from __future__ import annotations

import asyncio
from typing import Callable
from urllib.parse import urlencode, urlparse, urlunparse

import aiohttp

from .evasion import EvasionProfile, build_browser_headers, friendly_network_error
from .scanner_engine import short_module_http_timeout

ProgressCallback = Callable[[], None]
PlanCallback = Callable[[int], None]

SEVERITY_MEDIUM = "Medium"
SEVERITY_LOW = "Low"

_PARAM_NAMES: tuple[str, ...] = (
    "debug",
    "test",
    "admin",
    "trace",
    "verbose",
    "source",
    "raw",
    "dev",
    "development",
    "staging",
    "format",
    "output",
    "callback",
    "preview",
    "draft",
    "internal",
    "api_key",
    "key",
    "token",
    "secret",
    "password",
    "passwd",
    "auth",
    "bypass",
    "nocache",
    "no_cache",
    "refresh",
    "reload",
    "expand",
    "fields",
    "include",
    "show",
    "print",
    "dump",
    "sql",
    "explain",
)

_VALUES: tuple[str, ...] = ("1", "true", "yes", "on", "")

_VALUES_SHORT: tuple[str, ...] = ("1", "")

_EXTENDED_PARAM_NAMES: tuple[str, ...] = (
    "id",
    "user",
    "user_id",
    "uid",
    "account",
    "order",
    "order_id",
    "file",
    "path",
    "url",
    "redirect",
    "next",
    "return",
    "continue",
    "dest",
    "view",
    "mode",
    "action",
    "cmd",
    "exec",
    "run",
    "query",
    "search",
    "q",
    "filter",
    "sort",
    "order_by",
    "limit",
    "offset",
    "page",
    "page_size",
    "callback",
    "jsonp",
    "_",
    "__",
    "data",
    "payload",
    "body",
    "content",
    "html",
    "text",
    "xml",
    "json",
    "yaml",
    "error",
    "errors",
    "msg",
    "message",
    "detail",
    "details",
    "exception",
    "stack",
    "traceback",
    "profile",
    "perf",
    "timing",
    "metrics",
    "health",
    "status",
    "ping",
    "ready",
    "live",
    "check",
    "validate",
    "test_mode",
    "fixture",
    "mock",
    "simulate",
    "dry_run",
    "noop",
    "role",
    "group",
    "perm",
    "permission",
    "scope",
    "access",
    "grant",
    "sudo",
    "impersonate",
    "csrf",
    "token_id",
    "session",
    "sid",
    "jwt",
    "bearer",
    "apikey",
    "x_api_key",
    "x-api-key",
    "signature",
    "nonce",
    "state",
    "code",
    "client_id",
    "client_secret",
    "redirect_uri",
    "version",
    "v",
    "api_version",
    "format_type",
    "encoding",
    "charset",
    "lang",
    "locale",
    "timezone",
    "tz",
    "region",
    "env",
    "environment",
    "branch",
    "commit",
    "build",
    "release",
    "channel",
    "tier",
    "plan",
    "feature",
    "flags",
    "toggle",
    "experiment",
    "ab",
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "ref",
    "referrer",
    "src",
    "from",
    "to",
    "start",
    "end",
    "since",
    "until",
    "min",
    "max",
)


class ParamProbeScanner:
    """Brute common query/body parameter names and compare to baseline response."""

    def __init__(
        self,
        timeout: aiohttp.ClientTimeout | None = None,
        concurrency: int = 14,
        evasion: EvasionProfile | None = None,
    ) -> None:
        # 10s per stage so --params stacks safely with brute/infiltrate (avoid long aiohttp hangs).
        self._timeout = timeout or short_module_http_timeout()
        self._concurrency = max(1, concurrency)
        self._evasion = evasion or EvasionProfile()

    @staticmethod
    def _url_without_query(url: str) -> str:
        p = urlparse(url if "://" in url else f"https://{url}")
        return urlunparse((p.scheme, p.netloc, p.path or "/", p.params, "", ""))

    async def scan(
        self,
        target_url: str,
        on_plan: PlanCallback | None = None,
        on_advance: ProgressCallback | None = None,
    ) -> list[dict]:
        print("[DEBUG] ParamProbeScanner.scan — baseline + probe jobs starting", flush=True)
        ev = self._evasion
        base = self._url_without_query(target_url)
        referer = base if base.endswith("/") else f"{base}/"

        try:
            connector = ev.aiohttp_connector(ssl=True, limit=30)
        except RuntimeError:
            raise

        results: list[dict] = []

        async def _advance() -> None:
            """Progress tick; async so callers must ``await`` (avoid un-awaited coroutine warnings)."""
            if on_advance is not None:
                try:
                    on_advance()
                except Exception:
                    pass

        async with aiohttp.ClientSession(
            timeout=self._timeout, connector=connector, trust_env=False
        ) as session:
            await ev.apply_jitter()
            bh = build_browser_headers(referer=referer, evasion=ev)
            try:
                async with session.get(base, headers=bh, allow_redirects=True) as resp:
                    base_status = resp.status
                    raw = await resp.content.read(400_000)
                    base_body = raw.decode("utf-8", errors="replace")
            except (aiohttp.ClientError, TimeoutError, OSError) as exc:
                raise RuntimeError(friendly_network_error(exc)) from exc

            base_len = len(base_body)

            jobs: list[tuple[str, str, str]] = []
            for name in _PARAM_NAMES:
                for val in _VALUES:
                    jobs.append(("GET", name, val))
                    jobs.append(("POST", name, val))
                    jobs.append(("POST_JSON", name, val))
            for name in _EXTENDED_PARAM_NAMES:
                for val in _VALUES_SHORT:
                    jobs.append(("GET", name, val))
                    jobs.append(("POST", name, val))
                    jobs.append(("POST_JSON", name, val))

            if on_plan is not None:
                try:
                    on_plan(len(jobs) + 1)
                except Exception:
                    pass
            await _advance()

            sem = asyncio.Semaphore(self._concurrency)

            async def _try_get(param: str, val: str) -> dict | None:
                try:
                    async with sem:
                        q = [(param, val)] if val else [(param, "")]
                        qs = urlencode(q)
                        url = (
                            f"{base}?{qs}"
                            if "?" not in base
                            else f"{base}&{qs}"
                        )
                        await ev.apply_jitter()
                        h = build_browser_headers(
                            referer=referer, accept="*/*", evasion=ev
                        )
                        try:
                            async with session.get(
                                url, headers=h, allow_redirects=True
                            ) as resp:
                                raw = await resp.content.read(400_000)
                                body = raw.decode("utf-8", errors="replace")
                                st = resp.status
                        except (aiohttp.ClientError, TimeoutError, OSError):
                            return None
                        return self._diff(
                            "GET",
                            param,
                            val or "(empty)",
                            url,
                            st,
                            body,
                            base_status,
                            base_body,
                            base_len,
                        )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    return None

            async def _try_post(param: str, val: str) -> dict | None:
                try:
                    async with sem:
                        await ev.apply_jitter()
                        h = build_browser_headers(
                            referer=referer, accept="*/*", evasion=ev
                        )
                        data = {param: val} if val else {param: ""}
                        try:
                            async with session.post(
                                base,
                                headers=h,
                                data=data,
                                allow_redirects=True,
                            ) as resp:
                                raw = await resp.content.read(400_000)
                                body = raw.decode("utf-8", errors="replace")
                                st = resp.status
                        except (aiohttp.ClientError, TimeoutError, OSError):
                            return None
                        return self._diff(
                            "POST",
                            param,
                            val or "(empty)",
                            base,
                            st,
                            body,
                            base_status,
                            base_body,
                            base_len,
                        )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    return None

            async def _try_post_json(param: str, val: str) -> dict | None:
                try:
                    async with sem:
                        await ev.apply_jitter()
                        h = build_browser_headers(
                            referer=referer,
                            accept="application/json",
                            extra={"Content-Type": "application/json"},
                            evasion=ev,
                        )
                        payload = {param: val} if val else {param: None}
                        try:
                            async with session.post(
                                base,
                                headers=h,
                                json=payload,
                                allow_redirects=True,
                            ) as resp:
                                raw = await resp.content.read(400_000)
                                body = raw.decode("utf-8", errors="replace")
                                st = resp.status
                        except (aiohttp.ClientError, TimeoutError, OSError):
                            return None
                        return self._diff(
                            "POST_JSON",
                            param,
                            val or "(empty)",
                            base,
                            st,
                            body,
                            base_status,
                            base_body,
                            base_len,
                        )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    return None

            tasks: list[asyncio.Task] = []
            print(
                f"[DEBUG] ParamProbeScanner — dispatch {len(jobs)} probe tasks",
                flush=True,
            )
            for method, name, val in jobs:
                if method == "GET":
                    tasks.append(asyncio.create_task(_try_get(name, val)))
                elif method == "POST":
                    tasks.append(asyncio.create_task(_try_post(name, val)))
                else:
                    tasks.append(asyncio.create_task(_try_post_json(name, val)))

            for coro in asyncio.as_completed(tasks):
                try:
                    row = await coro
                except asyncio.CancelledError:
                    raise
                except Exception:
                    row = None
                await _advance()
                if row is not None:
                    results.append(row)

        results.sort(
            key=lambda r: (
                0 if r["severity"] == SEVERITY_MEDIUM else 1,
                str(r["method"]),
                str(r["param"]),
            )
        )
        return results

    def _diff(
        self,
        method: str,
        param: str,
        val: str,
        url: str,
        status: int,
        body: str,
        base_status: int,
        base_body: str,
        base_len: int,
    ) -> dict | None:
        if status == base_status and body == base_body:
            return None
        bl = len(body)
        reflected = param.lower() in body.lower() or (val and val.lower() in body.lower())
        note_parts: list[str] = []
        if status != base_status:
            note_parts.append(f"status {base_status}->{status}")
        if abs(bl - base_len) > max(80, int(base_len * 0.03)):
            note_parts.append(f"len {base_len}->{bl}")
        if reflected:
            note_parts.append("parameter reflected")
        if status >= 500:
            note_parts.append("server error")
        if not note_parts:
            return None
        sev = SEVERITY_MEDIUM if (reflected or status >= 500 or abs(bl - base_len) > base_len * 0.1) else SEVERITY_LOW
        return {
            "severity": sev,
            "method": method,
            "param": param,
            "value": val,
            "url": url,
            "status": status,
            "note": "; ".join(note_parts),
        }
