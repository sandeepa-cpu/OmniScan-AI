# Developed by Channa Sandeepa | OmniScan-AI v2.0 | Copyright 2026
"""Focused probes for high-value sensitive files (configs, VCS, containers, phpinfo)."""

from __future__ import annotations

import asyncio
from typing import Callable
from urllib.parse import urljoin, urlparse, urlunparse

import aiohttp

from .evasion import EvasionProfile, build_browser_headers
from .scanner_engine import http_client_timeout

ProgressCallback = Callable[[], None]
PlanCallback = Callable[[int], None]

SEVERITY_HIGH = "High"
SEVERITY_MEDIUM = "Medium"
SEVERITY_LOW = "Low"


class SensitiveFileHunter:
    """HTTP GET each curated path; no redirects (same stance as path bruter)."""

    PATHS: tuple[tuple[str, str], ...] = (
        (".env", SEVERITY_HIGH),
        (".env.local", SEVERITY_HIGH),
        (".env.production", SEVERITY_HIGH),
        (".env.development", SEVERITY_HIGH),
        ("config.php", SEVERITY_HIGH),
        ("configuration.php", SEVERITY_HIGH),
        ("settings.php", SEVERITY_MEDIUM),
        ("wp-config.php", SEVERITY_HIGH),
        ("wp-config.php.bak", SEVERITY_HIGH),
        ("docker-compose.yml", SEVERITY_HIGH),
        ("docker-compose.yaml", SEVERITY_HIGH),
        ("compose.yml", SEVERITY_MEDIUM),
        (".docker/config.json", SEVERITY_MEDIUM),
        (".git/config", SEVERITY_HIGH),
        (".git/HEAD", SEVERITY_HIGH),
        (".svn/wc.db", SEVERITY_MEDIUM),
        ("phpinfo.php", SEVERITY_MEDIUM),
        ("info.php", SEVERITY_MEDIUM),
        ("test.php", SEVERITY_LOW),
        ("i.php", SEVERITY_LOW),
        ("web.config", SEVERITY_MEDIUM),
        ("appsettings.json", SEVERITY_HIGH),
        ("appsettings.Development.json", SEVERITY_HIGH),
        ("secrets.json", SEVERITY_HIGH),
        (".aws/credentials", SEVERITY_HIGH),
        ("id_rsa", SEVERITY_HIGH),
        ("database.yml", SEVERITY_MEDIUM),
        ("settings.py", SEVERITY_MEDIUM),
        (".htpasswd", SEVERITY_HIGH),
        ("backup.sql", SEVERITY_HIGH),
        ("dump.sql", SEVERITY_HIGH),
    )

    def __init__(
        self,
        timeout: aiohttp.ClientTimeout | None = None,
        concurrency: int = 16,
        evasion: EvasionProfile | None = None,
    ) -> None:
        self._timeout = timeout or http_client_timeout()
        self._concurrency = max(1, concurrency)
        self._evasion = evasion or EvasionProfile()

    @staticmethod
    def _base_url(url: str) -> str:
        parsed = urlparse(url if "://" in url else f"https://{url}")
        scheme = parsed.scheme or "https"
        netloc = parsed.netloc or parsed.path
        return urlunparse((scheme, netloc, "/", "", "", ""))

    @staticmethod
    def _classify(status: int, default_sev: str) -> tuple[str, str] | None:
        if status == 200:
            return ("exposed", default_sev)
        if status in (401, 403):
            downgrade = {
                SEVERITY_HIGH: SEVERITY_MEDIUM,
                SEVERITY_MEDIUM: SEVERITY_LOW,
                SEVERITY_LOW: SEVERITY_LOW,
            }
            return ("restricted", downgrade.get(default_sev, SEVERITY_LOW))
        if status in (301, 302, 307, 308):
            return ("redirect", SEVERITY_LOW)
        return None

    async def scan(
        self,
        target_url: str,
        on_plan: PlanCallback | None = None,
        on_advance: ProgressCallback | None = None,
    ) -> list[dict]:
        base = self._base_url(target_url)
        referer = base if base.endswith("/") else f"{base}/"
        pairs = list(self.PATHS)

        if on_plan is not None:
            try:
                on_plan(max(len(pairs), 1))
            except Exception:
                pass

        def _advance() -> None:
            if on_advance is not None:
                try:
                    on_advance()
                except Exception:
                    pass

        try:
            connector = self._evasion.aiohttp_connector(ssl=True, limit=30)
        except RuntimeError:
            raise

        sem = asyncio.Semaphore(self._concurrency)
        results: list[dict] = []

        async with aiohttp.ClientSession(
            timeout=self._timeout, connector=connector, trust_env=False
        ) as session:

            async def _one(path: str, sev: str) -> dict | None:
                url = urljoin(base, path)
                async with sem:
                    try:
                        await self._evasion.apply_jitter()
                        h = build_browser_headers(
                            referer=referer, evasion=self._evasion
                        )
                        async with session.get(
                            url, headers=h, allow_redirects=False
                        ) as resp:
                            verdict = self._classify(resp.status, sev)
                            if verdict is None:
                                return None
                            state, out_sev = verdict
                            length = resp.headers.get("Content-Length")
                            try:
                                length_val: int | str = int(length) if length else "-"
                            except ValueError:
                                length_val = length or "-"
                            return {
                                "severity": out_sev,
                                "state": state,
                                "path": "/" + path.lstrip("/"),
                                "url": url,
                                "status": resp.status,
                                "length": length_val,
                                "probe_phase": "sensitive",
                            }
                    except (aiohttp.ClientError, TimeoutError, OSError):
                        return None
                    except Exception:
                        return None

            tasks = [asyncio.create_task(_one(p, s)) for p, s in pairs]
            for coro in asyncio.as_completed(tasks):
                row = await coro
                _advance()
                if row is not None:
                    results.append(row)

        rank = {SEVERITY_HIGH: 0, SEVERITY_MEDIUM: 1, SEVERITY_LOW: 2}
        results.sort(
            key=lambda r: (
                rank.get(r["severity"], 9),
                r["status"],
                r["path"],
            )
        )
        return results
