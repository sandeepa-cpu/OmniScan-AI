# Developed by Channa Sandeepa | OmniScan-AI v2.0 | Copyright 2026
"""Sensitive-path brute forcer.

Async-probes a curated wordlist of commonly-exposed paths (`.git`, `.env`,
`admin`, CI/CD, backup, debug endpoints) against the target base URL and
reports status codes with a severity tier. Authorized testing only.
"""

from __future__ import annotations

import asyncio
from typing import Callable
from urllib.parse import urljoin, urlparse, urlunparse

import aiohttp

ProgressCallback = Callable[[], None]
PlanCallback = Callable[[int], None]

SEVERITY_HIGH = "High"
SEVERITY_MEDIUM = "Medium"
SEVERITY_LOW = "Low"


class PathBruter:
    """Probe a base URL for commonly-exposed sensitive paths."""

    HIGH_PATHS: tuple[str, ...] = (
        ".git/config",
        ".git/HEAD",
        ".git/index",
        ".env",
        ".env.local",
        ".env.production",
        ".env.development",
        ".env.backup",
        ".svn/entries",
        ".hg/store/00manifest.i",
        ".DS_Store",
        ".htpasswd",
        ".aws/credentials",
        "id_rsa",
        "id_ed25519",
        "private.key",
        "server.key",
        "dump.sql",
        "database.sql",
        "db.sqlite",
        "backup.zip",
        "backup.tar.gz",
        "backup.sql",
        "wp-config.php.bak",
        "config.php.bak",
        "phpinfo.php",
        "info.php",
        "actuator/env",
        "actuator/heapdump",
        "actuator/mappings",
        "debug",
        "debug/vars",
    )

    MEDIUM_PATHS: tuple[str, ...] = (
        "admin",
        "admin/",
        "admin/login",
        "administrator",
        "administrator/",
        "wp-admin/",
        "wp-login.php",
        "phpmyadmin/",
        "pma/",
        "adminer.php",
        "server-status",
        "server-info",
        "console",
        "manager/html",
        "jenkins/",
        "gitlab/",
        "graphql",
        "graphiql",
        "swagger-ui/",
        "swagger.json",
        "openapi.json",
        "api-docs",
        "api/v1/",
        "api/v2/",
        ".htaccess",
        ".well-known/openid-configuration",
    )

    LOW_PATHS: tuple[str, ...] = (
        "robots.txt",
        "sitemap.xml",
        "humans.txt",
        "security.txt",
        ".well-known/security.txt",
        "crossdomain.xml",
        "favicon.ico",
        "README.md",
        "CHANGELOG.md",
    )

    def __init__(
        self,
        timeout: aiohttp.ClientTimeout | None = None,
        concurrency: int = 20,
    ) -> None:
        self._timeout = timeout or aiohttp.ClientTimeout(total=10)
        self._concurrency = max(1, concurrency)

    @staticmethod
    def _base_url(url: str) -> str:
        parsed = urlparse(url if "://" in url else f"https://{url}")
        scheme = parsed.scheme or "https"
        netloc = parsed.netloc or parsed.path
        return urlunparse((scheme, netloc, "/", "", "", ""))

    def _all_paths(self) -> list[tuple[str, str]]:
        pairs: list[tuple[str, str]] = []
        pairs.extend((p, SEVERITY_HIGH) for p in self.HIGH_PATHS)
        pairs.extend((p, SEVERITY_MEDIUM) for p in self.MEDIUM_PATHS)
        pairs.extend((p, SEVERITY_LOW) for p in self.LOW_PATHS)
        return pairs

    @staticmethod
    def _classify(status: int, default_sev: str) -> tuple[str, str] | None:
        """Return (state, severity) for reportable statuses, else None."""
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

    async def _probe(
        self,
        session: aiohttp.ClientSession,
        sem: asyncio.Semaphore,
        base: str,
        path: str,
        default_sev: str,
    ) -> dict | None:
        url = urljoin(base, path)
        async with sem:
            try:
                async with session.get(url, allow_redirects=False) as resp:
                    verdict = self._classify(resp.status, default_sev)
                    if verdict is None:
                        return None
                    state, sev = verdict
                    length = resp.headers.get("Content-Length")
                    try:
                        length_val: int | str = int(length) if length else "-"
                    except ValueError:
                        length_val = length or "-"
                    return {
                        "severity": sev,
                        "state": state,
                        "path": "/" + path.lstrip("/"),
                        "url": url,
                        "status": resp.status,
                        "length": length_val,
                    }
            except (aiohttp.ClientError, TimeoutError, OSError):
                return None
            except Exception:
                return None

    async def scan(
        self,
        target_url: str,
        on_plan: PlanCallback | None = None,
        on_advance: ProgressCallback | None = None,
    ) -> list[dict]:
        base = self._base_url(target_url)
        paths = self._all_paths()
        total = max(len(paths), 1)
        if on_plan is not None:
            try:
                on_plan(total)
            except Exception:
                pass

        sem = asyncio.Semaphore(self._concurrency)
        headers = {"User-Agent": "OmniScan-AI/1.0 (path-recon)"}
        results: list[dict] = []
        async with aiohttp.ClientSession(timeout=self._timeout, headers=headers) as session:
            tasks = [
                asyncio.create_task(self._probe(session, sem, base, path, sev))
                for path, sev in paths
            ]
            for coro in asyncio.as_completed(tasks):
                row = await coro
                if on_advance is not None:
                    try:
                        on_advance()
                    except Exception:
                        pass
                if row is not None:
                    results.append(row)

        sev_rank = {SEVERITY_HIGH: 0, SEVERITY_MEDIUM: 1, SEVERITY_LOW: 2}
        results.sort(
            key=lambda r: (sev_rank.get(r["severity"], 9), r["status"], r["path"])
        )
        return results
