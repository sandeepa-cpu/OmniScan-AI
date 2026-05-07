# Developed by Channa Sandeepa | OmniScan-AI v2.0 | Copyright 2026
"""Sensitive-path brute forcer with tech-aware wordlists and recursive directory probing.

Fetches the target root once to detect stack hints (PHP, ASP.NET, Node, etc.),
merges context-specific paths, then optionally drills into discovered directory
prefixes with a second wave of suffix probes. Authorized testing only.
"""

from __future__ import annotations

import asyncio
from typing import Callable
from urllib.parse import urljoin, urlparse, urlunparse

import aiohttp

from .evasion import EvasionProfile, build_browser_headers
from .scanner_engine import http_client_timeout
from .wordlists import RECURSIVE_DIR_SUFFIXES, detect_tech_stack, smart_paths_for_stack

ProgressCallback = Callable[[], None]
PlanCallback = Callable[[int], None]

SEVERITY_HIGH = "High"
SEVERITY_MEDIUM = "Medium"
SEVERITY_LOW = "Low"

EXT_FUZZ_SUFFIXES: tuple[str, ...] = (
    ".bak",
    ".old",
    ".zip",
    ".log",
    ".sql",
    ".php.bak",
)


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

    def _static_paths(self) -> list[tuple[str, str]]:
        pairs: list[tuple[str, str]] = []
        pairs.extend((p, SEVERITY_HIGH) for p in self.HIGH_PATHS)
        pairs.extend((p, SEVERITY_MEDIUM) for p in self.MEDIUM_PATHS)
        pairs.extend((p, SEVERITY_LOW) for p in self.LOW_PATHS)
        return pairs

    @staticmethod
    def _dedupe_paths(pairs: list[tuple[str, str]]) -> list[tuple[str, str]]:
        seen: set[str] = set()
        out: list[tuple[str, str]] = []
        for path, sev in pairs:
            key = path.lstrip("/")
            if key in seen:
                continue
            seen.add(key)
            out.append((path, sev))
        return out

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

    @staticmethod
    def _directory_prefixes(results: list[dict], max_prefixes: int) -> list[str]:
        """Derive URL path prefixes worth drilling into (e.g. ``/admin/``)."""
        interesting = {200, 301, 302, 307, 308, 401, 403}
        seen: set[str] = set()
        out: list[str] = []

        for r in results:
            st = r.get("status")
            if st not in interesting:
                continue
            path = str(r.get("path", "")).strip()
            if not path or path == "/":
                continue
            path = path.rstrip("/")
            segments = [s for s in path.split("/") if s]
            if not segments:
                continue
            leaf = segments[-1]
            if "." in leaf and leaf not in ("web.config",):
                continue
            prefix = "/" + "/".join(segments) + "/"
            if prefix in seen:
                continue
            seen.add(prefix)
            out.append(prefix)
            if len(out) >= max_prefixes:
                break
        return out

    @staticmethod
    def _paths_for_extension_fuzz(results: list[dict], max_paths: int) -> list[str]:
        interesting = {200, 301, 302, 307, 308, 401, 403}
        seen: set[str] = set()
        out: list[str] = []
        for r in results:
            st = r.get("status")
            if st not in interesting:
                continue
            path = str(r.get("path", "")).strip().rstrip("/")
            if not path or path == "/":
                continue
            if path in seen:
                continue
            seen.add(path)
            out.append(path)
            if len(out) >= max_paths:
                break
        return out

    @classmethod
    def _extension_path_pairs(
        cls, paths: list[str]
    ) -> list[tuple[str, str]]:
        pairs: list[tuple[str, str]] = []
        for p in paths:
            rel = p.lstrip("/")
            if not rel:
                continue
            low = rel.lower()
            for suf in EXT_FUZZ_SUFFIXES:
                if low.endswith(suf):
                    continue
                pairs.append((rel + suf, SEVERITY_MEDIUM))
        return pairs

    async def _probe(
        self,
        session: aiohttp.ClientSession,
        sem: asyncio.Semaphore,
        base: str,
        path: str,
        default_sev: str,
        *,
        referer: str,
        probe_phase: str,
    ) -> dict | None:
        url = urljoin(base, path)
        async with sem:
            try:
                await self._evasion.apply_jitter()
                headers = build_browser_headers(referer=referer, evasion=self._evasion)
                async with session.get(
                    url, headers=headers, allow_redirects=False
                ) as resp:
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
                        "probe_phase": probe_phase,
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
        *,
        recursive: bool = True,
        max_recursive_prefixes: int = 14,
        max_recursive_depth: int = 1,
        extension_fuzz: bool = True,
        max_extension_sources: int = 55,
        extra_path_pairs: list[tuple[str, str]] | None = None,
    ) -> list[dict]:
        base = self._base_url(target_url)
        referer = base if base.endswith("/") else f"{base}/"

        try:
            connector = self._evasion.aiohttp_connector(ssl=True, limit=40)
        except RuntimeError:
            raise

        html_sample = ""
        resp_headers: dict[str, str] = {}

        async with aiohttp.ClientSession(
            timeout=self._timeout, connector=connector, trust_env=False
        ) as session:
            try:
                await self._evasion.apply_jitter()
                h = build_browser_headers(referer=referer, evasion=self._evasion)
                async with session.get(
                    base, headers=h, allow_redirects=True, timeout=self._timeout
                ) as resp:
                    resp_headers = {k: str(v) for k, v in resp.headers.items()}
                    ctype = (resp.headers.get("Content-Type") or "").lower()
                    if "html" in ctype or "text" in ctype:
                        chunk = await resp.content.read(524_288)
                        html_sample = chunk.decode("utf-8", errors="replace")
            except (aiohttp.ClientError, TimeoutError, OSError):
                html_sample = ""
                resp_headers = {}

            tags = detect_tech_stack(html_sample, resp_headers)
            smart = smart_paths_for_stack(tags)
            merged_static = self._static_paths() + smart
            if extra_path_pairs:
                merged_static = merged_static + list(extra_path_pairs)
            phase1_paths = self._dedupe_paths(merged_static)

            extra_recursive: list[tuple[str, str]] = []
            depth = max(0, min(int(max_recursive_depth), 2))
            for _ in range(depth):
                for suf, sev in RECURSIVE_DIR_SUFFIXES:
                    extra_recursive.append((suf, sev))
            extra_recursive = self._dedupe_paths(extra_recursive)

            total_pass1 = len(phase1_paths)
            est_pass2 = (
                max_recursive_prefixes * len(extra_recursive)
                if recursive and depth > 0
                else 0
            )
            est_ext = (
                max_extension_sources * len(EXT_FUZZ_SUFFIXES)
                if extension_fuzz
                else 0
            )
            total = max(total_pass1 + est_pass2 + est_ext, 1)
            if on_plan is not None:
                try:
                    on_plan(total)
                except Exception:
                    pass

            def _advance() -> None:
                if on_advance is not None:
                    try:
                        on_advance()
                    except Exception:
                        pass

            sem = asyncio.Semaphore(self._concurrency)
            results: list[dict] = []

            tasks1 = [
                asyncio.create_task(
                    self._probe(
                        session,
                        sem,
                        base,
                        path,
                        sev,
                        referer=referer,
                        probe_phase="base",
                    )
                )
                for path, sev in phase1_paths
            ]
            for coro in asyncio.as_completed(tasks1):
                row = await coro
                _advance()
                if row is not None:
                    results.append(row)

            tasks2: list[asyncio.Task] = []
            if recursive and depth > 0 and extra_recursive:
                prefixes = self._directory_prefixes(
                    results, max_prefixes=max_recursive_prefixes
                )
                for prefix in prefixes:
                    pbase = urljoin(base, prefix)
                    pref_ref = pbase if pbase.endswith("/") else f"{pbase}/"
                    for suf, sev in extra_recursive:
                        rel = prefix.rstrip("/") + "/" + suf.lstrip("/")
                        if not rel.startswith("/"):
                            rel = "/" + rel
                        tasks2.append(
                            asyncio.create_task(
                                self._probe(
                                    session,
                                    sem,
                                    base,
                                    rel.lstrip("/"),
                                    sev,
                                    referer=pref_ref,
                                    probe_phase="recursive",
                                )
                            )
                        )
                for coro in asyncio.as_completed(tasks2):
                    row = await coro
                    _advance()
                    if row is not None:
                        results.append(row)

            if extension_fuzz and EXT_FUZZ_SUFFIXES:
                ext_sources = self._paths_for_extension_fuzz(
                    results, max_paths=max_extension_sources
                )
                ext_pairs = self._dedupe_paths(self._extension_path_pairs(ext_sources))
                tasks3 = [
                    asyncio.create_task(
                        self._probe(
                            session,
                            sem,
                            base,
                            path,
                            sev,
                            referer=referer,
                            probe_phase="ext_fuzz",
                        )
                    )
                    for path, sev in ext_pairs
                ]
                for coro in asyncio.as_completed(tasks3):
                    row = await coro
                    _advance()
                    if row is not None:
                        results.append(row)

        sev_rank = {SEVERITY_HIGH: 0, SEVERITY_MEDIUM: 1, SEVERITY_LOW: 2}
        results.sort(
            key=lambda r: (
                sev_rank.get(r["severity"], 9),
                r.get("probe_phase", ""),
                r["status"],
                r["path"],
            )
        )
        return results
