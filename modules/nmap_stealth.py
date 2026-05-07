# Developed by Channa Sandeepa | OmniScan-AI v2.0 | Copyright 2026
"""Optional Nmap-based TCP port discovery with polite timing (-T2).

Authorized testing only. ``--spoof-mac`` is best-effort: it usually requires a
privileged raw-capable Nmap build (often Unix + root); it is commonly ignored
or fails on Windows.
"""

from __future__ import annotations

import platform
import re
import shutil
import subprocess

_GREP_PORT_RE = re.compile(
    r"^(\d+)/open/(?:tcp|udp)(?:/|$)",
    re.MULTILINE,
)


def nmap_executable() -> str | None:
    return shutil.which("nmap")


def build_stealth_tcp_command(
    host: str,
    ports_csv: str,
    *,
    spoof_mac: bool,
) -> list[str]:
    cmd: list[str] = [
        "nmap",
        "-T2",
        "-Pn",
        "-n",
        "--open",
        "-p",
        ports_csv,
        "-oG",
        "-",
        host,
    ]
    if spoof_mac:
        cmd[1:1] = ["--spoof-mac", "0"]
    return cmd


def run_stealth_tcp_scan(
    host: str,
    ports_csv: str,
    *,
    spoof_mac: bool,
    timeout_sec: float = 420.0,
) -> tuple[int, str, str]:
    exe = nmap_executable()
    if not exe:
        return 127, "", "nmap not found on PATH"
    cmd = build_stealth_tcp_command(host, ports_csv, spoof_mac=spoof_mac)
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=max(30.0, float(timeout_sec)),
            creationflags=creationflags,
        )
    except subprocess.TimeoutExpired:
        return 124, "", "nmap timed out"
    except OSError as exc:
        return 1, "", str(exc)
    out = (r.stdout or "") + ("\n" + r.stderr if r.stderr else "")
    return int(r.returncode), r.stdout or "", out.strip()


def parse_grepable_open_ports(stdout: str) -> list[tuple[int, str]]:
    """Return ``(port, service_guess)`` from grepable (-oG) output."""
    found: list[tuple[int, str]] = []
    for line in stdout.splitlines():
        if "Ports:" not in line:
            continue
        chunk = line.split("Ports:", 1)[1]
        for part in chunk.split(","):
            part = part.strip()
            m = _GREP_PORT_RE.match(part)
            if not m:
                continue
            port = int(m.group(1))
            rest = part[m.end() :].strip("/")
            svc = rest.split("/")[0] if rest else "unknown"
            found.append((port, svc or "unknown"))
    return found


def spoof_mac_supported_hint() -> str:
    if platform.system() == "Windows":
        return (
            "Nmap --spoof-mac is rarely effective on Windows; use Linux/WSL with "
            "an appropriate Npcap/raw setup if you need L2 spoofing."
        )
    return "Nmap --spoof-mac typically requires a privileged (e.g. root) process."
