# Developed by Channa Sandeepa | OmniScan-AI v2.0 | Copyright 2026
"""Async TCP port scanner for a curated list of common service ports.

Uses `asyncio.open_connection` with a short timeout and a semaphore-bounded
concurrency pool to quickly detect which well-known ports respond on the
target host. Authorized testing only.
"""

from __future__ import annotations

import asyncio
from typing import Callable
from urllib.parse import urlparse

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

    def __init__(self, timeout: float = 1.2, concurrency: int = 100) -> None:
        self._timeout = max(0.2, float(timeout))
        self._concurrency = max(1, concurrency)

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

    async def _probe(
        self, host: str, port: int, sem: asyncio.Semaphore
    ) -> dict | None:
        async with sem:
            writer = None
            try:
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

    async def scan(
        self,
        target_url: str,
        on_plan: PlanCallback | None = None,
        on_advance: ProgressCallback | None = None,
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
        return results
