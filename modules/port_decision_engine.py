# Developed by Channa Sandeepa | OmniScan-AI v2.5 | Copyright 2026
"""Port decision engine: follow-up probes when common ports are open (authorized testing only).

- 80 / 443: lightweight HTTP path discovery (aiohttp; curated paths, ``--brute``-scale dirb not used here).
- 21: anonymous FTP login attempt (stdlib ``ftplib``).
- 3306: MySQL default-credential probe (optional ``pymysql``; skipped if not installed).
"""

from __future__ import annotations

import asyncio
import logging
from ftplib import FTP, error_perm
from typing import Any

import aiohttp

from .evasion import EvasionProfile, build_browser_headers
from .scanner_engine import short_module_http_timeout

log = logging.getLogger(__name__)

SEVERITY_HIGH = "High"
SEVERITY_MEDIUM = "Medium"
SEVERITY_LOW = "Low"

# Short list similar to a quick dirb-style pass (no huge wordlists).
_DIR_CANDIDATES: tuple[str, ...] = (
    "/",
    "/admin",
    "/admin/",
    "/login",
    "/login/",
    "/api/",
    "/api/v1/",
    "/robots.txt",
    "/sitemap.xml",
    "/.git/HEAD",
    "/phpmyadmin/",
    "/wordpress/",
    "/wp-admin/",
    "/backup",
    "/uploads/",
    "/.env",
    "/server-status",
    "/actuator/health",
    "/metrics",
)

_MYSQL_DEFAULT_USERS: tuple[tuple[str, str], ...] = (
    ("root", ""),
    ("root", "root"),
    ("root", "password"),
    ("mysql", "mysql"),
    ("admin", "admin"),
)


def _decision_row(
    *,
    host: str,
    related_port: int,
    service_label: str,
    severity: str,
    detail: str,
    action: str,
) -> dict[str, Any]:
    return {
        "severity": severity,
        "port": related_port,
        "service": service_label,
        "state": "decision",
        "host": host,
        "decision_action": action,
        "decision_detail": detail[:2000],
    }


async def _probe_http_paths(
    host: str,
    *,
    schemes: list[str],
    evasion: EvasionProfile,
) -> list[dict]:
    rows: list[dict] = []
    if evasion.use_tor:
        rows.append(
            _decision_row(
                host=host,
                related_port=80,
                service_label="Decision: HTTP dirs",
                severity=SEVERITY_LOW,
                detail="Skipped HTTP directory follow-up in Tor mode (use direct scan for dir probes).",
                action="http_directory",
            )
        )
        return rows

    timeout = short_module_http_timeout()
    try:
        connector = evasion.aiohttp_connector(ssl=True, limit=8)
    except RuntimeError as exc:
        rows.append(
            _decision_row(
                host=host,
                related_port=80,
                service_label="Decision: HTTP dirs",
                severity=SEVERITY_LOW,
                detail=f"Could not build connector: {exc}",
                action="http_directory",
            )
        )
        return rows

    sem = asyncio.Semaphore(6)
    saw_interesting_path = False

    async with aiohttp.ClientSession(
        timeout=timeout, connector=connector, trust_env=False
    ) as session:
        for scheme in schemes:
            base_root = f"{scheme}://{host}".rstrip("/")
            ref = f"{base_root}/"
            for path in _DIR_CANDIDATES:
                url = f"{base_root}/" if path in ("/", "") else f"{base_root}{path}"

                async with sem:
                    await evasion.apply_jitter()
                    try:
                        bh = build_browser_headers(referer=ref, evasion=evasion)
                        async with session.get(
                            url, headers=bh, allow_redirects=True
                        ) as resp:
                            st = resp.status
                            clen = resp.content_length
                            _ = await resp.content.read(96_000)
                    except (aiohttp.ClientError, TimeoutError, OSError):
                        continue
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        continue

                if st in (200, 301, 302, 401, 403) and path not in ("/",):
                    saw_interesting_path = True
                    rows.append(
                        _decision_row(
                            host=host,
                            related_port=443 if scheme == "https" else 80,
                            service_label="Decision: HTTP path",
                            severity=SEVERITY_MEDIUM
                            if st in (200, 401, 403)
                            else SEVERITY_LOW,
                            detail=(
                                f"{scheme.upper()} GET {url} → HTTP {st}"
                                + (f" (Content-Length={clen})" if clen else "")
                            ),
                            action="http_directory",
                        )
                    )

    if not saw_interesting_path:
        rows.append(
            _decision_row(
                host=host,
                related_port=443 if "https" in schemes else 80,
                service_label="Decision: HTTP dirs",
                severity=SEVERITY_LOW,
                detail="No noteworthy paths returned 200/301/302/401/403 in quick probe set.",
                action="http_directory",
            )
        )
    return rows


async def _ftp_anonymous(host: str) -> list[dict]:
    rows: list[dict] = []

    def _sync_ftp() -> tuple[bool, str]:
        try:
            ftp = FTP()
            ftp.connect(host, timeout=10)
            try:
                ftp.login()
            finally:
                try:
                    ftp.quit()
                except Exception:
                    try:
                        ftp.close()
                    except Exception:
                        pass
            return True, "FTP anonymous login succeeded (USER anonymous)."
        except error_perm as e:
            return False, f"FTP anonymous rejected: {e}"
        except Exception as e:
            return False, f"FTP error: {e}"

    ok, msg = await asyncio.to_thread(_sync_ftp)
    rows.append(
        _decision_row(
            host=host,
            related_port=21,
            service_label="Decision: FTP",
            severity=SEVERITY_HIGH if ok else SEVERITY_LOW,
            detail=msg,
            action="ftp_anonymous",
        )
    )
    return rows


async def _mysql_default_creds(host: str) -> list[dict]:
    rows: list[dict] = []

    try:
        import pymysql  # type: ignore[import-untyped]
    except ImportError:
        rows.append(
            _decision_row(
                host=host,
                related_port=3306,
                service_label="Decision: MySQL",
                severity=SEVERITY_LOW,
                detail="Install pymysql for default-credential checks: pip install pymysql",
                action="mysql_creds",
            )
        )
        return rows

    def _try(u: str, p: str) -> tuple[bool, str]:
        try:
            conn = pymysql.connect(
                host=host,
                port=3306,
                user=u,
                password=p,
                connect_timeout=6,
                read_timeout=6,
                write_timeout=6,
            )
            try:
                conn.close()
            except Exception:
                pass
            return True, f"Accepted credentials user={u!r} password={'***' if p else '(empty)'}"
        except Exception as e:
            return False, str(e)[:200]

    for u, p in _MYSQL_DEFAULT_USERS:
        ok, msg = await asyncio.to_thread(_try, u, p)
        if ok:
            rows.append(
                _decision_row(
                    host=host,
                    related_port=3306,
                    service_label="Decision: MySQL",
                    severity=SEVERITY_HIGH,
                    detail=msg,
                    action="mysql_creds",
                )
            )
            return rows

    rows.append(
        _decision_row(
            host=host,
            related_port=3306,
            service_label="Decision: MySQL",
            severity=SEVERITY_LOW,
            detail="No common default pairs accepted (root/empty, root/root, root/password, mysql/mysql, admin/admin).",
            action="mysql_creds",
        )
    )
    return rows


async def enrich_open_ports(
    *,
    host: str,
    target_url: str,
    open_port_rows: list[dict],
    evasion: EvasionProfile,
) -> list[dict]:
    """Run decision-engine follow-ups for ports present in ``open_port_rows``.

    ``target_url`` is reserved for future use (scope / base URL hints).
    """
    _ = target_url
    if not host or not open_port_rows:
        return []

    open_ports = {int(r["port"]) for r in open_port_rows if r.get("port") is not None}
    out: list[dict] = []

    schemes: list[str] = []
    if 443 in open_ports:
        schemes.append("https")
    if 80 in open_ports:
        schemes.append("http")
    if 80 in open_ports or 443 in open_ports:
        out.extend(await _probe_http_paths(host, schemes=schemes, evasion=evasion))

    if 21 in open_ports:
        out.extend(await _ftp_anonymous(host))

    if 3306 in open_ports:
        out.extend(await _mysql_default_creds(host))

    return out
