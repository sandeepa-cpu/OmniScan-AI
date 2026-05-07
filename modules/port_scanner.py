# Developed by Channa Sandeepa | OmniScan-AI v2.0 | Copyright 2026
"""Async TCP port scanner for a curated list of common service ports.

Uses `asyncio.open_connection` with a short timeout and a semaphore-bounded
concurrency pool to quickly detect which well-known ports respond on the
target host. Authorized testing only.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Callable
from urllib.parse import urlparse

from .evasion import EvasionProfile, parse_socks_proxy
from . import nmap_stealth
from .scanner_engine import (
    NMAP_EXECUTOR_WALL_CLOCK_SEC,
    NMAP_STEALTH_SUBPROCESS_SEC,
)

ProgressCallback = Callable[[], None]
PlanCallback = Callable[[int], None]

SEVERITY_HIGH = "High"
SEVERITY_MEDIUM = "Medium"
SEVERITY_LOW = "Low"


class PortScanner:
    """TCP-connect scanner across a curated set of common service ports."""

    COMMON_PORTS: dict[int, str] = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        111: "RPCbind",
        135: "MS-RPC",
        139: "NetBIOS",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        465: "SMTPS",
        587: "SMTP-Sub",
        631: "IPP",
        993: "IMAPS",
        995: "POP3S",
        1433: "MSSQL",
        1521: "Oracle",
        2049: "NFS",
        2375: "Docker",
        2376: "Docker-TLS",
        3000: "Node/Dev",
        3306: "MySQL",
        3389: "RDP",
        5000: "HTTP-alt",
        5432: "PostgreSQL",
        5601: "Kibana",
        5900: "VNC",
        6379: "Redis",
        7001: "WebLogic",
        8000: "HTTP-alt",
        8008: "HTTP-alt",
        8080: "HTTP-Proxy",
        8443: "HTTPS-alt",
        8888: "HTTP-alt",
        9000: "HTTP-alt",
        9090: "HTTP-alt",
        9200: "Elasticsearch",
        9300: "Elasticsearch-TCP",
        11211: "Memcached",
        15672: "RabbitMQ-Mgmt",
        27017: "MongoDB",
        27018: "MongoDB",
    }

    HIGH_RISK_PORTS: frozenset[int] = frozenset(
        {
            21,
            23,
            135,
            139,
            445,
            1433,
            1521,
            2049,
            2375,
            2376,
            3306,
            3389,
            5432,
            5900,
            6379,
            9200,
            9300,
            11211,
            15672,
            27017,
            27018,
        }
    )

    def __init__(
        self,
        timeout: float = 1.2,
        concurrency: int = 100,
        evasion: EvasionProfile | None = None,
        *,
        use_nmap_stealth: bool = False,
        nmap_spoof_mac: bool = False,
    ) -> None:
        self._timeout = max(0.2, float(timeout))
        self._concurrency = max(1, concurrency)
        self._evasion = evasion or EvasionProfile()
        self._use_nmap_stealth = bool(use_nmap_stealth)
        self._nmap_spoof_mac = bool(nmap_spoof_mac)

    @staticmethod
    def _hostname(url: str) -> str | None:
        parsed = urlparse(url if "://" in url else f"https://{url}")
        host = (parsed.hostname or "").strip()
        return host or None

    def _severity_for(self, port: int) -> str:
        if port in self.HIGH_RISK_PORTS:
            return SEVERITY_HIGH
        if port in (80, 443):
            return SEVERITY_LOW
        return SEVERITY_MEDIUM

    async def _run_decision_engine(
        self, host: str, target_url: str, results: list[dict]
    ) -> None:
        """Append follow-up rows (HTTP dirs, FTP anon, MySQL defaults) for open ports."""
        open_rows = [r for r in results if r.get("state") == "open"]
        if not open_rows:
            return
        try:
            from .port_decision_engine import enrich_open_ports

            extra = await enrich_open_ports(
                host=host,
                target_url=target_url,
                open_port_rows=open_rows,
                evasion=self._evasion,
            )
            if extra:
                results.extend(extra)
        except Exception as exc:
            logging.getLogger(__name__).warning("Port decision engine failed: %s", exc)

    async def _tor_tcp_connect(self, host: str, port: int):
        """SOCKS5 connect via Tor (``python-socks`` asyncio backend)."""
        try:
            from python_socks.async_.asyncio import Proxy  # type: ignore[import-untyped]
            from python_socks import ProxyType  # type: ignore[import-untyped]
        except ImportError as exc:
            raise RuntimeError(
                "Tor port scan requires python-socks. Install: pip install 'python-socks[asyncio]'"
            ) from exc

        h, p, rdns = parse_socks_proxy(self._evasion.tor_socks_url)
        proxy = Proxy.create(
            proxy_type=ProxyType.SOCKS5,
            host=h,
            port=p,
            rdns=rdns,
        )
        return await proxy.connect(dest_host=host, dest_port=port)

    async def _probe(
        self, host: str, port: int, sem: asyncio.Semaphore
    ) -> dict | None:
        async with sem:
            await self._evasion.apply_jitter()
            writer = None
            sock = None
            try:
                if self._evasion.use_tor:
                    sock = await asyncio.wait_for(
                        self._tor_tcp_connect(host, port),
                        timeout=self._timeout,
                    )
                else:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host=host, port=port),
                        timeout=self._timeout,
                    )
                return {
                    "severity": self._severity_for(port),
                    "port": port,
                    "service": self.COMMON_PORTS.get(port, "unknown"),
                    "state": "open",
                }
            except (asyncio.TimeoutError, TimeoutError):
                return None
            except (ConnectionRefusedError, OSError):
                return None
            except Exception:
                return None
            finally:
                if writer is not None:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass
                if sock is not None:
                    try:
                        sock.close()
                    except Exception:
                        pass

    def _scan_with_nmap_sync(self, host: str, ports: list[int]) -> tuple[list[dict], int]:
        ports_csv = ",".join(str(p) for p in ports)
        code, stdout, blob = nmap_stealth.run_stealth_tcp_scan(
            host,
            ports_csv,
            spoof_mac=self._nmap_spoof_mac,
            timeout_sec=NMAP_STEALTH_SUBPROCESS_SEC,
        )
        if code != 0:
            logging.getLogger(__name__).warning(
                "nmap stealth port scan non-zero exit (%s): %s",
                code,
                blob[:500],
            )
        open_rows: list[dict] = []
        for port, _nmap_svc in nmap_stealth.parse_grepable_open_ports(stdout):
            if port not in self.COMMON_PORTS:
                continue
            open_rows.append(
                {
                    "severity": self._severity_for(port),
                    "port": port,
                    "service": self.COMMON_PORTS.get(port, "unknown"),
                    "state": "open",
                    "host": host,
                    "probe": "nmap",
                }
            )
        return open_rows, code

    async def scan(
        self,
        target_url: str,
        on_plan: PlanCallback | None = None,
        on_advance: ProgressCallback | None = None,
        *,
        decision_engine: bool = True,
    ) -> list[dict]:
        host = self._hostname(target_url)
        ports = sorted(self.COMMON_PORTS.keys())
        total = max(len(ports), 1)
        if on_plan is not None:
            try:
                on_plan(total)
            except Exception:
                pass

        if not host:
            if on_advance is not None:
                for _ in ports:
                    try:
                        on_advance()
                    except Exception:
                        pass
            return []

        if self._use_nmap_stealth and not self._evasion.use_tor:
            exe = nmap_stealth.nmap_executable()
            if exe:
                await self._evasion.apply_jitter()
                loop = asyncio.get_running_loop()
                nmap_results: list[dict] = []
                nmap_code = -1
                try:
                    nmap_results, nmap_code = await asyncio.wait_for(
                        loop.run_in_executor(
                            None,
                            lambda: self._scan_with_nmap_sync(host, ports),
                        ),
                        timeout=max(30.0, float(NMAP_EXECUTOR_WALL_CLOCK_SEC)),
                    )
                except asyncio.TimeoutError:
                    logging.getLogger(__name__).warning(
                        "nmap stealth scan exceeded executor budget (%ss); "
                        "falling back to async TCP probes.",
                        NMAP_EXECUTOR_WALL_CLOCK_SEC,
                    )
                    nmap_results, nmap_code = [], 124
                except Exception:
                    nmap_results, nmap_code = [], -1
                if nmap_code == 0 or nmap_results:
                    if on_advance is not None:
                        for _ in ports:
                            try:
                                on_advance()
                            except Exception:
                                pass
                    sev_rank = {SEVERITY_HIGH: 0, SEVERITY_MEDIUM: 1, SEVERITY_LOW: 2}
                    nmap_results.sort(
                        key=lambda r: (sev_rank.get(r["severity"], 9), r["port"])
                    )
                    if decision_engine and host:
                        await self._run_decision_engine(
                            host, target_url, nmap_results
                        )
                    return nmap_results
                logging.getLogger(__name__).warning(
                    "nmap stealth scan produced no usable result; falling back to async TCP probes."
                )
            else:
                logging.getLogger(__name__).warning(
                    "--nmap-stealth set but nmap not on PATH; falling back to async TCP probes."
                )

        sem = asyncio.Semaphore(self._concurrency)
        results: list[dict] = []
        tasks = [asyncio.create_task(self._probe(host, p, sem)) for p in ports]
        for coro in asyncio.as_completed(tasks):
            row = await coro
            if on_advance is not None:
                try:
                    on_advance()
                except Exception:
                    pass
            if row is not None:
                row["host"] = host
                results.append(row)

        sev_rank = {SEVERITY_HIGH: 0, SEVERITY_MEDIUM: 1, SEVERITY_LOW: 2}
        results.sort(key=lambda r: (sev_rank.get(r["severity"], 9), r["port"]))
        if decision_engine and host:
            await self._run_decision_engine(host, target_url, results)
        return results
