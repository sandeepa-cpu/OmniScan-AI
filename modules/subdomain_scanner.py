# Developed by Channa Sandeepa | OmniScan-AI v2.0 | Copyright 2026
"""Probe common subdomain hostnames derived from a target URL (authorized testing only)."""

from __future__ import annotations

import asyncio
from typing import Callable
from urllib.parse import urlparse

import aiohttp

from .evasion import EvasionProfile, build_browser_headers, friendly_network_error
from .scanner_engine import http_client_timeout

ProgressCallback = Callable[[], None]
PlanCallback = Callable[[int], None]


class SubdomainScanner:
    """
    Build candidate hostnames ``{prefix}.{apex}`` from the target URL's apex domain,
    then check reachability over HTTP(S) with aiohttp.
    """

    COMMON_PREFIXES: tuple[str, ...] = (
        "dev",
        "api",
        "test",
        "staging",
        "mail",
        "www",
        "admin",
        "blog",
        "cdn",
        "app",
        "vpn",
        "portal",
        "beta",
        "demo",
        "qa",
        "uat",
        "internal",
        "shop",
        "store",
        "status",
        "git",
        "ci",
        "docs",
        "support",
        "help",
        "sandbox",
        "preview",
    )

    def __init__(
        self,
        timeout: aiohttp.ClientTimeout | None = None,
        evasion: EvasionProfile | None = None,
    ) -> None:
        self._timeout = timeout or http_client_timeout()
        self._evasion = evasion or EvasionProfile()

    @staticmethod
    def apex_hostname(target_url: str) -> str:
        """Strip scheme/path and reduce ``a.b.c`` to ``b.c`` when depth ≥ 3 (heuristic)."""
        raw = target_url.strip()
        if "://" not in raw:
            raw = f"https://{raw}"
        parsed = urlparse(raw)
        host = (parsed.hostname or "").strip().lower()
        if not host:
            raise ValueError("Could not parse a hostname from the target URL.")
        host = host.split(":")[0]
        parts = host.split(".")
        if len(parts) >= 3:
            return ".".join(parts[1:])
        return host

    async def _probe_host(
        self,
        session: aiohttp.ClientSession,
        fqdn: str,
        *,
        referer_base: str,
    ) -> dict:
        last_error: str | None = None

        for scheme in ("https", "http"):
            url = f"{scheme}://{fqdn}/"
            for method in ("HEAD", "GET"):
                try:
                    await self._evasion.apply_jitter()
                    headers = build_browser_headers(
                        referer=referer_base, evasion=self._evasion
                    )
                    async with session.request(
                        method,
                        url,
                        headers=headers,
                        allow_redirects=True,
                        ssl=False,
                    ) as resp:
                        return {
                            "subdomain": fqdn,
                            "url": str(resp.url),
                            "status": resp.status,
                            "scheme": scheme,
                            "alive": True,
                            "note": "",
                        }
                except aiohttp.ClientResponseError as exc:
                    st = getattr(exc, "status", None) or 0
                    if st > 0:
                        return {
                            "subdomain": fqdn,
                            "url": url,
                            "status": st,
                            "scheme": scheme,
                            "alive": True,
                            "note": "http error",
                        }
                    last_error = friendly_network_error(exc)
                except (aiohttp.ClientError, TimeoutError, OSError) as exc:
                    last_error = friendly_network_error(exc)

        return {
            "subdomain": fqdn,
            "url": f"https://{fqdn}/",
            "status": "-",
            "scheme": "-",
            "alive": False,
            "note": (last_error or "no response")[:160],
        }

    async def scan(
        self,
        target_url: str,
        on_plan: PlanCallback | None = None,
        on_advance: ProgressCallback | None = None,
    ) -> list[dict]:
        """
        Probe each common prefix against the apex derived from ``target_url``.

        Returns rows with keys: subdomain, url, status, scheme, alive, note.

        Optional progress hooks:
            on_plan(total): called once with the number of hosts that will be probed.
            on_advance(): called as each probe completes (real-time progress).
        """
        apex = self.apex_hostname(target_url)
        candidates = [f"{p}.{apex}" for p in self.COMMON_PREFIXES]
        referer_base = f"https://{apex}/"

        if on_plan is not None:
            try:
                on_plan(len(candidates))
            except Exception:
                pass

        def _advance() -> None:
            if on_advance is not None:
                try:
                    on_advance()
                except Exception:
                    pass

        try:
            connector = self._evasion.aiohttp_connector(ssl=False, limit=20)
        except RuntimeError:
            raise

        results: list[dict] = []

        async with aiohttp.ClientSession(
            timeout=self._timeout,
            connector=connector,
            trust_env=False,
        ) as session:
            tasks: list[asyncio.Task[dict]] = [
                asyncio.create_task(
                    self._probe_host(session, fqdn, referer_base=referer_base)
                )
                for fqdn in candidates
            ]
            try:
                for coro in asyncio.as_completed(tasks):
                    try:
                        row = await coro
                    except Exception as exc:
                        row = {
                            "subdomain": "?",
                            "url": "",
                            "status": "error",
                            "scheme": "-",
                            "alive": False,
                            "note": friendly_network_error(exc)[:160],
                        }
                    results.append(row)
                    _advance()
            finally:
                for task in tasks:
                    if not task.done():
                        task.cancel()

        order = {fqdn: i for i, fqdn in enumerate(candidates)}
        results.sort(key=lambda r: order.get(r.get("subdomain", ""), 10**9))
        return results
