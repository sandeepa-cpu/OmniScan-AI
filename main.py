#!/usr/bin/env python3
# Developed by Channa Sandeepa | OmniScan-AI v2.5 | Copyright 2026
"""OmniScan-AI — CLI entry: secrets, subdomains, XSS, cloud, paths, ports, JS, API fuzz, zero-day fuzz, infiltration, AI."""

from __future__ import annotations

import argparse
import asyncio
import os
import time
from typing import Any
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass

from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.markup import escape
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

from modules.ai_auditor import AIAuditor
from modules.ai_mutator import (
    discovered_param_slots,
    flatten_mutator_bundles,
    mutate_all_discovered_params,
)
from modules.nuclei_engine import run_nuclei_scan
from modules.api_doc_fuzzer import APISchemaFuzzer
from modules.broken_link_scanner import BrokenLinkScanner
from modules.cloud_scanner import CloudScanner
from modules.evasion import EvasionProfile
from modules.html_source_scanner import HtmlSourceScanner
from modules.idor_scanner import IDORScanner
from modules.js_analyzer import JSAnalyzer
from modules.param_probe import ParamProbeScanner
from modules.sensitive_file_hunter import SensitiveFileHunter
from modules.wayback_scanner import WaybackScanner
from modules.path_bruter import PathBruter
from modules.port_scanner import PortScanner
from modules.exploit_gen import auto_generate_exploits_after_scan
from modules.report_generator import (
    APP_EDITION,
    APP_VERSION,
    DEVELOPER,
    SIGNATURE,
    build_json_report,
    save_reports,
)
from modules.smart_infiltration import SmartInfiltrationEngine
from modules.scanner_engine import (
    WAF_PROBE_WALL_CLOCK_SEC,
    WAYBACK_PRE_GATHER_WALL_CLOCK_SEC,
    apply_direct_http_environment,
)
from modules.secret_finder import SEVERITY_COLORS, SecretFinder, severity_for
from modules.subdomain_scanner import SubdomainScanner
from modules.xss_scanner import XSSScanner
from modules.oauth_social_scanner import OAuthSocialScanner
from modules.zero_day_hunter import ZeroDayHunter

PROJECT_ROOT = Path(__file__).resolve().parent
REPORTS_DIR = PROJECT_ROOT / "reports"

# Per parallel scan module: ``asyncio.wait_for`` budget (seconds). Infiltration runs after gather.
MODULE_TIMEOUT_SECONDS: dict[str, float] = {
    "secrets": 1800.0,
    "js": 3600.0,
    "subdomain": 1200.0,
    "xss": 3600.0,
    "idor": 1800.0,
    "cloud": 1200.0,
    "paths": 7200.0,
    "ports": 1200.0,
    "html_source": 1800.0,
    "param_probe": 3600.0,
    "sensitive_files": 1800.0,
    "broken_links": 2400.0,
    "api_fuzz": 3600.0,
    "zero_day": 7200.0,
    "oauth_social": 2400.0,
}
INFILTRATION_MODULE_TIMEOUT_SEC = 1200.0

_MODULE_PROGRESS_LABEL: dict[str, str] = {
    "ports": "Port scan",
    "param_probe": "Params (hidden parameter probe)",
}


def _module_timeout_return(module_name: str) -> Any:
    if module_name == "api_fuzz":
        return (
            {
                "discovered": [],
                "idor": [],
                "injection": [],
                "graphql": [],
            },
            "module timed out",
        )
    return [], "module timed out"

try:
    from dotenv import load_dotenv

    load_dotenv(PROJECT_ROOT / ".env", override=False)
except ImportError:
    pass

# Machine-readable events for the Flask-SocketIO dashboard (subprocess stdout parser).
DASHBOARD_JSON_PREFIX = "__OMNISCAN_DASHBOARD__"
# One JSON object per line → dashboard parses and ``socketio.emit("new_loot", ...)``.
LOOT_JSON_PREFIX = "__OMNISCAN_LOOT__"

# Lazy Socket.IO client → dashboard.py ``main_log`` relay (live logs in the web UI).
_dashboard_sio_client: Any = None
_real_stdout: Any = None
_real_stderr: Any = None


def _push_dashboard_socket_log(text: str) -> None:
    """Push a plain-text line to the dashboard via Socket.IO (``main_log`` → ``log_update``)."""
    global _dashboard_sio_client
    if not os.environ.get("OMNISCAN_DASHBOARD"):
        return
    msg = (text or "").strip()
    if not msg:
        return
    try:
        import socketio  # provided by flask-socketio dependency
    except ImportError:
        return
    try:
        if _dashboard_sio_client is None:
            client = socketio.Client(logger=False, engineio_logger=False)
            connected = False
            for _ in range(12):
                try:
                    client.connect(
                        "http://127.0.0.1:8080",
                        wait_timeout=6,
                        transports=["polling", "websocket"],
                    )
                    connected = True
                    break
                except Exception:
                    time.sleep(0.25)
            if not connected:
                return
            _dashboard_sio_client = client
        _dashboard_sio_client.emit(
            "main_log",
            {"text": msg, "line": msg},
        )
    except Exception:
        pass


class _DashboardTee:
    """Wrap stdout/stderr so Rich sees a TTY when possible; subprocess pipe carries bytes to the dashboard."""

    __slots__ = ("_real",)

    def __init__(self, real: Any) -> None:
        self._real = real

    def write(self, s: str) -> int:
        if not s:
            return 0
        self._real.write(s)
        # Do not mirror lines to Socket.IO here: dashboard.py already streams child
        # stdout from the subprocess pipe (avoids duplicate terminal lines).
        return len(s)

    def flush(self) -> None:
        self._real.flush()

    def isatty(self) -> bool:
        fn = getattr(self._real, "isatty", None)
        return bool(fn()) if callable(fn) else False

    def fileno(self) -> int:
        return self._real.fileno()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)


def _install_dashboard_stream_tees() -> None:
    """Wrap stdout/stderr for dashboard mode (TTY behavior); live logs use the subprocess pipe in dashboard.py."""
    global _real_stdout, _real_stderr
    if not os.environ.get("OMNISCAN_DASHBOARD"):
        return
    if isinstance(sys.stdout, _DashboardTee):
        return
    _real_stdout = sys.stdout
    _real_stderr = sys.stderr
    sys.stdout = _DashboardTee(_real_stdout)
    sys.stderr = _DashboardTee(_real_stderr)


def _dashboard_emit(event: dict) -> None:
    """Emit one JSON line for ``dashboard.py`` when ``OMNISCAN_DASHBOARD=1``."""
    if not os.environ.get("OMNISCAN_DASHBOARD"):
        return
    try:
        line = DASHBOARD_JSON_PREFIX + json.dumps(event, ensure_ascii=False) + "\n"
        out = _real_stdout if _real_stdout is not None else sys.stdout
        out.write(line)
        out.flush()
    except Exception:
        pass
    tag = str(event.get("event") or "")
    if tag == "scan_start":
        _push_dashboard_socket_log(f"[omniscan] scan_start → {event.get('target_url', '')}")
    elif tag == "scan_stage":
        _push_dashboard_socket_log(
            f"[omniscan] stage → {event.get('stage', '')} ({event.get('target_url', '')})"
        )
    elif tag == "scan_complete":
        _push_dashboard_socket_log(
            f"[omniscan] scan_complete exit={event.get('exit_code')} "
            f"target={event.get('target_url', '')}"
        )


def _dashboard_push_new_loot(
    *,
    category: str,
    severity: str,
    detail: str,
    source: str = "",
) -> None:
    """Send one loot row to the dashboard (stdout line parsed by ``dashboard.py`` → ``new_loot``)."""
    if not os.environ.get("OMNISCAN_DASHBOARD"):
        return
    payload = {
        "category": str(category or "").strip() or "finding",
        "severity": str(severity or "Medium").strip(),
        "detail": (detail or "")[:4000],
        "source": (source or "")[:2000],
    }
    try:
        line = LOOT_JSON_PREFIX + json.dumps(payload, ensure_ascii=False) + "\n"
        out = _real_stdout if _real_stdout is not None else sys.stdout
        out.write(line)
        out.flush()
    except Exception:
        pass


def _dashboard_stream_loot_results(
    *,
    target_url: str,
    findings: list[dict],
    sensitive_rows: list[dict],
    path_rows: list[dict],
    param_rows: list[dict],
    api_fuzz_bundle: dict[str, Any],
    zero_day_rows: list[dict],
    oauth_rows: list[dict],
    js_rows: list[dict],
    infiltration_bundle: dict[str, Any],
    nuclei_rows: list[dict],
) -> None:
    """Push high-signal rows to the live LOOT table as each module finishes (batched post-gather)."""
    if not os.environ.get("OMNISCAN_DASHBOARD"):
        return

    def _push(cat: str, sev: Any, det: Any, src: str = "") -> None:
        _dashboard_push_new_loot(
            category=cat,
            severity=str(sev or "Medium"),
            detail=str(det or ""),
            source=str(src or ""),
        )

    for f in findings[:120]:
        _push(
            "Secret / credential pattern",
            f.get("severity"),
            f.get("match", ""),
            str(f.get("source_url", "")),
        )
    for s in sensitive_rows[:80]:
        _push(
            "Sensitive file",
            s.get("severity"),
            s.get("path", s.get("url", "")),
            str(s.get("url", "")),
        )
    for p in path_rows[:70]:
        if p.get("state") in ("exposed", "restricted", "redirect"):
            _push(
                "Path / exposed endpoint",
                p.get("severity"),
                str(p.get("path", "")),
                str(p.get("url", "")),
            )
    for pr in param_rows[:80]:
        sev = pr.get("severity", "Low")
        if sev in ("Critical", "High", "Medium"):
            det = f"{pr.get('method', '')} {pr.get('param', '')}".strip()
            note = str(pr.get("note", "")).strip()
            if note:
                det = f"{det} — {note[:800]}".strip(" —")
            _push("Parameter probe", sev, det[:4000], str(pr.get("url", "")))
    for row in js_rows[:100]:
        t = str(row.get("type", "")).lower()
        sev = row.get("severity", "Medium")
        if "secret" in t or sev in ("Critical", "High"):
            det = str(
                row.get("value")
                or row.get("path")
                or row.get("url")
                or row.get("endpoint_url")
                or row
            )
            src = str(row.get("source_url") or row.get("page_url") or target_url)
            _push("JavaScript signal", sev, det[:4000], src)
    api_inj = api_fuzz_bundle.get("injection") or []
    for inj in api_inj[:50]:
        det = f"{inj.get('type', '')} {inj.get('param', '')}".strip()
        if inj.get("note"):
            det = f"{det} — {str(inj.get('note', ''))[:600]}".strip(" —")
        _push(
            "API / DB injection signal",
            inj.get("severity", "High"),
            det[:4000],
            str(inj.get("url", "")),
        )
    for row in (api_fuzz_bundle.get("idor") or [])[:40]:
        _push(
            "API IDOR signal",
            row.get("severity", "Medium"),
            str(row.get("detail") or row.get("note") or row)[:4000],
            str(row.get("url", "")),
        )
    zd_fuzz = [r for r in zero_day_rows if r.get("type") == "fuzz_hit"]
    for z in zd_fuzz[:60]:
        _push(
            "Zero-Day fuzz hit",
            z.get("severity", "High"),
            str(z.get("detail") or z.get("payload") or z)[:4000],
            str(z.get("url", "")),
        )
    for oz in oauth_rows[:40]:
        if oz.get("severity") in ("Critical", "High", "Medium"):
            _push(
                "OAuth / social login",
                oz.get("severity", "Medium"),
                str(oz.get("detail") or oz.get("type", ""))[:4000],
                str(oz.get("url") or oz.get("source_url") or target_url),
            )
    ce = infiltration_bundle.get("chain_extractions") or []
    for c in ce[:60]:
        _push(
            "Infiltration / credential-like chain",
            c.get("severity"),
            str(c.get("match_preview", ""))[:4000],
            str(c.get("source_url", "")),
        )
    for r in nuclei_rows[:150]:
        tid = str(r.get("template_id") or "").strip()
        name = str(r.get("name") or "").strip()
        det = f"{tid}" + (f" — {name}" if name else "")
        if not det:
            det = str(r.get("type") or "nuclei-match")
        url_hit = str(r.get("matched_at") or r.get("host") or target_url)
        _push(
            "Nuclei template match",
            str(r.get("severity") or "info").strip() or "info",
            det[:4000],
            url_hit,
        )


def _emit_dashboard_scan_complete(
    *,
    target_url: str,
    exit_code: int,
    findings: list[dict],
    sub_rows: list[dict],
    xss_rows: list[dict],
    idor_rows: list[dict],
    cloud_rows: list[dict],
    path_rows: list[dict],
    port_rows: list[dict],
    js_rows: list[dict],
    param_rows: list[dict],
    sensitive_rows: list[dict],
    broken_rows: list[dict],
    api_fuzz_bundle: dict[str, Any],
    zero_day_rows: list[dict],
    oauth_rows: list[dict],
    infiltration_bundle: dict[str, Any],
    xss_mutations: list[dict],
    detected_waf: str,
    jitter_multiplier: float,
    nuclei_rows: list[dict],
) -> None:
    def _crit_high(rows: list[dict]) -> int:
        return sum(
            1 for r in rows if r.get("severity") in ("Critical", "High")
        )

    def _nuclei_crit_high(rows: list[dict]) -> int:
        return sum(
            1
            for r in rows
            if str(r.get("severity", "")).strip().lower() in ("critical", "high")
        )

    zd_fuzz = [r for r in zero_day_rows if r.get("type") == "fuzz_hit"]
    api_inj = api_fuzz_bundle.get("injection") or []
    api_idor = api_fuzz_bundle.get("idor") or []
    vulnerabilities = (
        _crit_high(findings)
        + _crit_high(xss_rows)
        + _crit_high(idor_rows)
        + _crit_high(zero_day_rows)
        + _crit_high(oauth_rows)
        + _crit_high(param_rows)
        + _crit_high(sensitive_rows)
        + _crit_high(broken_rows)
        + len(api_inj)
        + len(api_idor)
        + len(zd_fuzz)
        + _nuclei_crit_high(nuclei_rows)
    )
    waf_bypass_signals = len(xss_mutations) + sum(
        1 for r in zd_fuzz if r.get("encoding") not in (None, "raw")
    )

    loot: list[dict] = []
    for f in findings[:60]:
        loot.append(
            {
                "kind": "secret",
                "severity": f.get("severity"),
                "detail": str(f.get("match", ""))[:400],
                "source": str(f.get("source_url", ""))[:400],
            }
        )
    for s in sensitive_rows[:40]:
        loot.append(
            {
                "kind": "sensitive_file",
                "severity": s.get("severity"),
                "detail": str(s.get("path", s.get("url", ""))),
                "source": str(s.get("url", "")),
            }
        )
    for p in path_rows[:35]:
        if p.get("state") in ("exposed", "restricted", "redirect"):
            loot.append(
                {
                    "kind": "path_hit",
                    "severity": p.get("severity"),
                    "detail": str(p.get("path", "")),
                    "source": str(p.get("url", "")),
                }
            )
    ce = infiltration_bundle.get("chain_extractions") or []
    for c in ce[:35]:
        loot.append(
            {
                "kind": "infiltration_chain",
                "severity": c.get("severity"),
                "detail": str(c.get("match_preview", ""))[:400],
                "source": str(c.get("source_url", ""))[:400],
            }
        )
    for r in nuclei_rows[:60]:
        tid = str(r.get("template_id") or "")
        loot.append(
            {
                "kind": "nuclei",
                "severity": r.get("severity"),
                "detail": tid[:400],
                "source": str(r.get("matched_at") or r.get("host") or "")[:400],
            }
        )

    _dashboard_emit(
        {
            "event": "scan_complete",
            "target_url": target_url,
            "exit_code": exit_code,
            "stats": {
                "targets": 1,
                "vulnerabilities": vulnerabilities,
                "waf_bypass_signals": waf_bypass_signals,
                "detected_waf": detected_waf,
                "waf_pacing_multiplier": jitter_multiplier,
                "secrets_count": len(findings),
                "subdomains_alive": sum(1 for r in sub_rows if r.get("alive")),
                "xss_signals": len(xss_rows),
                "idor_findings": len(idor_rows),
                "zero_day_fuzz_hits": len(zd_fuzz),
                "oauth_social_high": sum(
                    1 for r in oauth_rows if r.get("severity") == "High"
                ),
                "nuclei_findings": len(nuclei_rows),
            },
            "loot": loot,
        }
    )


EXAMPLES = """\
Examples:
  python main.py --url example.com
  python main.py --url example.com --ai
  python main.py --url example.com --js
  python main.py --url "https://api.example.com/users?id=42" --idor
  python main.py --url example.com --subdomain --report
  python main.py --url example.com --xss --ai          # AI-mutated WAF-bypass payloads
  python main.py --url example.com --cloud
  python main.py --url example.com --brute
  python main.py --url example.com --source --params
  python main.py --url example.com --broken-links --report
  python main.py --url api.example.com --api-fuzz --report    # same as --ai-fuzz
  python main.py --url example.com --zero-day --report
  python main.py --url example.com --port
  python main.py --url example.com --brute --sensitive --params --port --infiltrate
  python main.py --url example.com --brute --infiltrate --bypass-403   # extended 401/403 bypass (modules.bypass_403)
  python main.py --url example.com --xss --obfuscate                  # encoded XSS probe variants (modules.payload_obfuscation)
  python main.py --url https://x.com --gen-shell                       # policy panel only (modules.shell_generator)
  python main.py --url example.com --js --xss --ai --idor --report --pdf
  python main.py --url example.com --subdomain --xss --cloud --brute --port --js --idor --ai --report --pdf
  python main.py --url example.com --idor --js --xss \
    --headers '{"Authorization": "Bearer eyJ...", "X-Api-Key": "abc"}'
  python main.py --url https://scope.example.com --playtika-bounty --report

Notes:
  - `--url` accepts bare hostnames; `https://` is added automatically.
  - Combining `--ai` with `--xss` auto-generates WAF-bypass XSS payload mutations.
  - `--idor` needs a URL that exposes a numeric id (e.g. ?id=42 or /users/42).
  - `--api-fuzz` and `--ai-fuzz` are equivalent (Swagger/OpenAPI/GraphQL schema discovery + fuzz).
  - `--headers` takes a JSON object; headers flow into the XSS, IDOR, JS-secret,
    broken-link, API-schema fuzz, Zero-Day Hunter, and OAuth/social scanners. Invalid JSON exits with code 2.
  - `--playtika-bounty` adds X-Bug-Bounty: True on all probes, runs OAuth/OIDC/social checks, and tightens pacing (avoid DoS).
  - `--zero-day` requires env `OMINSCAN_ZERODAY_HWID` matching this machine (see module `zero_day_hunter.compute_machine_hwid`).
  - `--pdf` requires `fpdf2` (see requirements.txt).
  - `--tor` routes traffic via SOCKS5h (Tor); install `aiohttp-socks` and `python-socks[asyncio]`.
  - `--bypass-403` implies `--infiltrate` and uses `modules.bypass_403` for extra header/path retries.
  - `--gen-shell` prints policy from `modules.shell_generator` and exits (no payloads).
  - Use only on targets you are explicitly authorized to test.
"""


_BANNER_TITLE_LINE_1 = (
    r" _____  _   _   ___   _   _  _   _   ___  _ _____ " "\n"
    r"/  __ \| | | | / _ \ | \ | || \ | | / _ \( )  ___|" "\n"
    r"| /  \/| |_| |/ /_\ \|  \| ||  \| |/ /_\ \/\ `--. " "\n"
    r"| |    |  _  ||  _  || . ` || . ` ||  _  |  `--. \ " "\n"
    r"| \__/\| | | || | | || |\  || |\  || | | | /\__/ /" "\n"
    r" \____/\_| |_/\_| |_/\_| \_/\_| \_/\_| |_/ \____/ "
)

_BANNER_TITLE_LINE_2 = (
    r" ________  ___ _   _ _____ _____ _____   ___   _   _         ___  _____ " "\n"
    r"|  _  |  \/  || \ | |_   _/  ___/  __ \ / _ \ | \ | |       / _ \|_   _|" "\n"
    r"| | | | .  . ||  \| | | | \ `--.| /  \// /_\ \|  \| |______/ /_\ \ | |  " "\n"
    r"| | | | |\/| || . ` | | |  `--. \ |    |  _  || . ` |______|  _  | | |  " "\n"
    r"\ \_/ / |  | || |\  |_| |_/\__/ / \__/\| | | || |\  |      | | | |_| |_ " "\n"
    r" \___/\_|  |_/\_| \_/\___/\____/ \____/\_| |_/\_| \_/      \_| |_/\___/ "
)

_BANNER_SUBTITLE = (
    "The Ultimate Bug Hunter's Suite   |   Developed by Channa Sandeepa"
)

_BANNER_FEATURES = (
    "Secrets • Subdomains • XSS • Cloud • Paths • Ports • AI audits"
)


def _banner(console: Console) -> None:
    """Massive branded banner - printed exactly once at the start of a run."""
    title_1 = Text(_BANNER_TITLE_LINE_1, style="bold green", no_wrap=True)
    title_2 = Text(_BANNER_TITLE_LINE_2, style="bold green", no_wrap=True)
    subtitle = Text(_BANNER_SUBTITLE, style="bold white")
    features = Text(_BANNER_FEATURES, style="bold cyan")

    content = Group(
        Align.center(title_1),
        Text(""),
        Align.center(title_2),
        Text(""),
        Align.center(subtitle),
        Align.center(features),
    )
    console.print(
        Panel(
            content,
            border_style="bright_green",
            box=box.DOUBLE,
            padding=(1, 2),
        )
    )


def _parse_headers_arg(raw: str | None, console: Console) -> dict[str, str]:
    """Parse the optional --headers JSON argument into a flat string->string dict.

    Invalid JSON, non-object payloads, or non-string values are reported through
    the Rich console and cause a clean exit (code 2 - argparse convention) so the
    user can fix the value instead of silently running without auth headers.
    An empty dict is returned when ``raw`` is None / empty / whitespace.
    """
    if raw is None or not raw.strip():
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        console.print(
            f"[red]Invalid --headers JSON:[/red] {escape(str(exc))}\n"
            f"[dim]Example: --headers '{{\"Authorization\": \"Bearer eyJ...\", "
            f"\"X-Api-Key\": \"abc\"}}'[/dim]"
        )
        raise SystemExit(2) from None

    if not isinstance(parsed, dict):
        console.print(
            "[red]--headers must be a JSON object (dict), "
            f"got {type(parsed).__name__}.[/red]\n"
            "[dim]Example: --headers '{\"Authorization\": \"Bearer eyJ...\"}'[/dim]"
        )
        raise SystemExit(2)

    headers: dict[str, str] = {}
    bad: list[str] = []
    for key, value in parsed.items():
        if not isinstance(key, str) or not key.strip():
            bad.append(repr(key))
            continue
        if value is None:
            continue
        if not isinstance(value, (str, int, float, bool)):
            bad.append(f"{key}={type(value).__name__}")
            continue
        headers[key.strip()] = str(value)

    if bad:
        console.print(
            "[red]--headers contains unsupported entries:[/red] "
            f"{escape(', '.join(bad))}\n"
            "[dim]Header keys must be non-empty strings; values must be scalar.[/dim]"
        )
        raise SystemExit(2)

    return headers


def _normalize_url(raw: str) -> str:
    """Add https:// when missing; raise for empty input."""
    value = (raw or "").strip()
    if not value:
        raise argparse.ArgumentTypeError("URL cannot be empty.")
    if "://" not in value:
        value = f"https://{value}"
    parsed = urlparse(value)
    if not parsed.hostname:
        raise argparse.ArgumentTypeError(f"Could not parse a hostname from: {raw!r}")
    return value


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="OmniScan-AI",
        description=(
            "OmniScan-AI v2.5 (Aggressive Infiltration Edition) — The Modern Bug Hunter's Suite "
            "(authorized testing only). "
            "High-performance framework for JS secret hunting, deep JS endpoint/asset "
            "analysis, subdomain recon, reflected-XSS probing (with AI-guided WAF-bypass "
            "payload mutation), IDOR testing on numeric IDs, cloud storage exposure "
            "checks, sensitive path brute-forcing, TCP port sweeps, and AI/LLM "
            "prompt-injection playbooks."
        ),
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--url",
        required=True,
        type=_normalize_url,
        metavar="TARGET",
        help="Target URL or hostname (https:// prepended automatically if missing).",
    )
    parser.add_argument(
        "--ai",
        action="store_true",
        help="Include the AI/LLM prompt-injection playbook in output and report.",
    )
    parser.add_argument(
        "--subdomain",
        action="store_true",
        help="Probe common subdomains derived from the apex host.",
    )
    parser.add_argument(
        "--xss",
        action="store_true",
        help="Probe URL query parameters and GET forms for reflected-XSS payloads.",
    )
    parser.add_argument(
        "--cloud",
        action="store_true",
        help="Enumerate candidate public cloud buckets (S3 / Azure / GCP / DO).",
    )
    parser.add_argument(
        "--brute",
        action="store_true",
        help="Brute common sensitive paths (.git, .env, /admin, CI/CD, backups, debug).",
    )
    parser.add_argument(
        "--port",
        action="store_true",
        help="TCP-connect scan a curated list of common service ports.",
    )
    parser.add_argument(
        "--js",
        action="store_true",
        help="Deep JS analyzer - concurrently crawl every linked script for endpoints and secrets.",
    )
    parser.add_argument(
        "--idor",
        action="store_true",
        help=(
            "IDOR scanner - find numeric IDs in query params (id, user_id, order_id, ...) "
            "or path segments (/users/42), then probe neighbouring IDs and flag Critical "
            "when HTTP 200 returns different PII than the baseline."
        ),
    )
    parser.add_argument(
        "--source",
        action="store_true",
        help=(
            "HTML source recon — scan the page for HTML comments, leaked URLs in comments, "
            "and suspicious href/src/meta attributes."
        ),
    )
    parser.add_argument(
        "--params",
        action="store_true",
        help=(
            "Parameter discovery (Arjun-style) — large wordlist of GET query, form POST, and "
            "JSON body parameters; flags status/length/body deltas vs baseline."
        ),
    )
    parser.add_argument(
        "--sqli",
        action="store_true",
        help=(
            "SQLi-focused mode: tighter time-based detection threshold during "
            "--infiltrate GET parameter probes (authorized testing only)."
        ),
    )
    parser.add_argument(
        "--deep-scan",
        action="store_true",
        dest="deep_scan",
        help=(
            "Deeper JS harvest when combined with --js: allow more linked script assets "
            "per page (higher cap)."
        ),
    )
    parser.add_argument(
        "--wayback",
        action="store_true",
        help=(
            "Query the Internet Archive CDX API for historical URLs on this host, probe the "
            "live site for those paths, and (with --brute) merge unique paths into the path "
            "wordlist."
        ),
    )
    parser.add_argument(
        "--sensitive",
        action="store_true",
        help=(
            "Sensitive file hunter — focused GET probes for .env, config.php, docker-compose, "
            ".git/config, phpinfo, appsettings.json, and similar high-value paths."
        ),
    )
    parser.add_argument(
        "--broken-links",
        action="store_true",
        dest="broken_links",
        help=(
            "Harvest external links from the landing HTML (href/src/script text), then flag "
            "Potential Takeover when the hostname does not resolve or when major social/profile "
            "URLs return 404/410 or soft 'not found' body text."
        ),
    )
    parser.add_argument(
        "--api-fuzz",
        "--ai-fuzz",
        action="store_true",
        dest="api_fuzz",
        help=(
            "Probe for Swagger/OpenAPI/GraphQL schema docs (modules.api_doc_fuzzer), parse "
            "operations, then fuzz GET endpoints for IDOR (numeric id mutations) and SQLi "
            "(time/error heuristics) plus limited JSON-body SQLi on POST/PUT/PATCH. "
            "Alias: --ai-fuzz."
        ),
    )
    parser.add_argument(
        "--no-recursive-paths",
        action="store_true",
        help=(
            "With --brute, only run the flat path wordlist (disable recursive directory suffix "
            "probes on discovered folders)."
        ),
    )
    parser.add_argument(
        "--no-ext-fuzz",
        action="store_true",
        help=(
            "With --brute, skip backup/archive extension fuzzing (.bak, .old, .zip, .log, .sql, "
            ".php.bak) on discovered paths."
        ),
    )
    parser.add_argument(
        "--headers",
        metavar="JSON",
        default=None,
        help=(
            "Optional JSON object of custom HTTP headers to attach to every request "
            "made by the XSS, IDOR, JS-secret, broken-link, API-schema fuzz, Zero-Day "
            "Hunter, and OAuth/social scanners. "
            "Example: "
            "--headers '{\"Authorization\": \"Bearer eyJ...\", \"Cookie\": \"session=abc\"}'. "
            "If omitted, an empty header set is used."
        ),
    )
    parser.add_argument(
        "--tor",
        action="store_true",
        help=(
            "Route all HTTP(S) traffic and TCP port probes through a local Tor SOCKS "
            "proxy (default socks5h://127.0.0.1:9050). Requires aiohttp-socks and "
            "python-socks. Start Tor Browser or `tor` service first."
        ),
    )
    parser.add_argument(
        "--socks5",
        metavar="URL",
        default=None,
        help=(
            "SOCKS5 proxy URL when using --tor (default: socks5h://127.0.0.1:9050). "
            "Prefer socks5h:// so hostnames resolve through the proxy."
        ),
    )
    parser.add_argument(
        "--jitter",
        action="store_true",
        help=(
            "Adaptive random delay before each HTTP/TCP probe to mimic human pacing and "
            "reduce rate-limit triggers. Auto-enabled with --tor unless --no-jitter."
        ),
    )
    parser.add_argument(
        "--no-jitter",
        action="store_true",
        help="Disable all inter-request jitter (including smart evasion pacing and Tor).",
    )
    parser.add_argument(
        "--no-smart-evasion",
        action="store_true",
        help=(
            "Disable smart evasion: profile-based User-Agent rotation on every request, "
            "default anti rate-limit pacing, and WAF detection (Cloudflare, Akamai, etc.) "
            "with automatic slowdown."
        ),
    )
    parser.add_argument(
        "--no-waf-probe",
        action="store_true",
        help=(
            "Skip the initial WAF fingerprint GET before scanning (fewer round-trips; "
            "does not enable Tor — use only with --tor for SOCKS)."
        ),
    )
    parser.add_argument(
        "--stealth",
        action="store_true",
        help=(
            "Authorized low-noise mode: stronger jitter, broader browser-like header "
            "variation, and WAF-oriented XSS payload mutations when --xss is used "
            "(without requiring --ai)."
        ),
    )
    parser.add_argument(
        "--nmap-stealth",
        action="store_true",
        help=(
            "With --port, prefer an Nmap -T2 scan over the built-in port list (requires "
            "the nmap binary on PATH). Falls back to async TCP probes if Nmap is missing "
            "or exits with an error. Ignored with --tor."
        ),
    )
    parser.add_argument(
        "--nmap-spoof-mac",
        action="store_true",
        help=(
            "With --nmap-stealth, pass --spoof-mac 0 to Nmap (often needs Unix + root; "
            "commonly unsupported or ineffective on Windows)."
        ),
    )
    parser.add_argument(
        "--nuclei",
        action="store_true",
        help=(
            "Run ProjectDiscovery Nuclei (subprocess) against the target URL; "
            "parse JSONL findings. Requires ``nuclei`` on PATH — see "
            "https://github.com/projectdiscovery/nuclei/releases"
        ),
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Save results under reports/<target>/ as both .txt and .json.",
    )
    parser.add_argument(
        "--pdf",
        action="store_true",
        help="Also save a branded PDF report (requires fpdf2). Auto-enables --report.",
    )
    parser.add_argument(
        "--infiltrate",
        action="store_true",
        help=(
            "After scans, run autonomous follow-up: fetch sensitive paths and extract "
            "credential-like patterns, try 403 bypass headers/paths, active SQLi/XSS/LFI "
            "probes on discovered GET params, audit Set-Cookie flags, and HTTP-probe "
            "common admin paths on open alternate ports. Uses rule-based AI playbook hints."
        ),
    )
    parser.add_argument(
        "--bypass-403",
        action="store_true",
        dest="bypass_403",
        help=(
            "Enable extended 401/403 bypass attempts in the infiltration phase "
            "(modules.bypass_403): full header rotation (20+ bundles) and extra path "
            "encoding tricks. Implies --infiltrate. Best with --brute so forbidden paths "
            "exist in path_rows."
        ),
    )
    parser.add_argument(
        "--obfuscate",
        action="store_true",
        help=(
            "Add encoded variants (double-URL, percent-hex, Base64) to reflected-XSS "
            "payloads and to infiltration SQLi/XSS/LFI probe strings "
            "(modules.payload_obfuscation)."
        ),
    )
    parser.add_argument(
        "--logic-scan",
        action="store_true",
        dest="logic_scan",
        help=(
            "Passive triage on harvested endpoints (--js / --brute / --params): "
            "IDOR-shaped URLs and price/cart/checkout surfaces for manual logic tests."
        ),
    )
    parser.add_argument(
        "--ai-mutate",
        action="store_true",
        help=(
            "After the scan, run AI-Mutator (modules.ai_mutator) on each discovered "
            "parameter slot (param probe + XSS results + ?query on --url). "
            "Uses OPENAI_API_KEY or OMINSCAN_OPENAI_API_KEY when set; otherwise heuristics. "
            "Combine with --params and/or --xss for richer slot discovery."
        ),
    )
    parser.add_argument(
        "--mutate-kind",
        choices=("auto", "xss", "sqli"),
        default="auto",
        help=(
            "Base probe class for --ai-mutate: auto picks SQLi-shaped bases for id-like "
            "parameter names, else XSS (default: auto)."
        ),
    )
    parser.add_argument(
        "--gen-shell",
        action="store_true",
        dest="gen_shell",
        help=(
            "Print policy only: OmniScan-AI does not generate reverse-shell payloads "
            "(modules.shell_generator). Exits after the message; --url is still required."
        ),
    )
    parser.add_argument(
        "--zero-day",
        action="store_true",
        dest="zero_day",
        help=(
            "Zero-Day Hunter — HWID-gated logic-flaw fuzzing: deep JS/HTML harvest, "
            "heuristic 'interesting' parameters, WAF-rotated encodings, latency/stack "
            "anomaly detection with focused follow-up probes. Set OMINSCAN_ZERODAY_HWID "
            "to the fingerprint from modules.zero_day_hunter.compute_machine_hwid()."
        ),
    )
    parser.add_argument(
        "--playtika-bounty",
        action="store_true",
        dest="playtika_bounty",
        help=(
            "Playtika Bug Bounty mode: send X-Bug-Bounty: True on every HTTP probe, run "
            "OAuth/OpenID Connect + social-login checks (redirect_uri validation, linking "
            "surfaces), and apply stronger default request pacing to avoid DoS."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=(
            f"OmniScan-AI v{APP_VERSION} ({APP_EDITION}) — by {DEVELOPER}"
        ),
    )
    return parser


def _progress() -> Progress:
    return Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[bold]{task.description}"),
        BarColumn(bar_width=None),
        MofNCompleteColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        transient=True,
        expand=True,
    )


def _findings_table(rows: list[dict]) -> Table:
    table = Table(
        title="[bold magenta]Secret scan results[/bold magenta]",
        caption="[dim]Severities are heuristic. Validate impact before reporting.[/dim]",
        caption_justify="left",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta",
        border_style="magenta",
        expand=True,
    )
    table.add_column("#", style="dim", justify="right", width=3)
    table.add_column("Severity", width=10)
    table.add_column("Type", style="cyan", no_wrap=True)
    table.add_column("Source", overflow="fold")
    table.add_column("Match preview", overflow="fold")

    sev_order = {"High": 0, "Medium": 1, "Low": 2}
    rows_sorted = sorted(
        rows,
        key=lambda r: (sev_order.get(r.get("severity", "Low"), 3), r.get("type", "")),
    )

    for i, row in enumerate(rows_sorted, start=1):
        sev = row.get("severity") or severity_for(row.get("type", ""))
        color = SEVERITY_COLORS.get(sev, "white")
        preview = row["match"]
        if len(preview) > 80:
            preview = preview[:77] + "..."
        table.add_row(
            str(i),
            f"[bold {color}]{escape(sev)}[/bold {color}]",
            escape(str(row["type"])),
            escape(str(row["source_url"])),
            escape(preview),
        )
    return table


def _severity_summary(rows: list[dict]) -> str:
    counts = {"High": 0, "Medium": 0, "Low": 0}
    for r in rows:
        counts[r.get("severity", "Low")] = counts.get(r.get("severity", "Low"), 0) + 1
    return (
        f"[bold red]High: {counts['High']}[/bold red]  "
        f"[bold yellow]Medium: {counts['Medium']}[/bold yellow]  "
        f"[bold cyan]Low: {counts['Low']}[/bold cyan]"
    )


def _subdomain_table(rows: list[dict]) -> Table:
    table = Table(
        title="[bold green]Subdomain discovery[/bold green]",
        caption=(
            "[dim]Heuristic apex + common prefixes. Alive = any HTTP response. "
            "TLS verification relaxed during probing.[/dim]"
        ),
        caption_justify="left",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold green",
        border_style="green",
        expand=True,
    )
    table.add_column("#", style="dim", justify="right", width=3)
    table.add_column("Host", style="cyan", overflow="fold")
    table.add_column("Scheme", width=7)
    table.add_column("Status", justify="right", width=6)
    table.add_column("Alive", width=8)
    table.add_column("Final URL / note", overflow="fold")

    for i, r in enumerate(rows, start=1):
        alive_cell = (
            "[bold green]* live[/bold green]" if r["alive"] else "[dim]- -[/dim]"
        )
        url_disp = escape(str(r.get("url") or ""))
        note = escape(str(r.get("note") or ""))
        cell = url_disp if not note else f"{url_disp} [dim]({note})[/dim]"
        table.add_row(
            str(i),
            escape(str(r["subdomain"])),
            escape(str(r["scheme"])),
            escape(str(r["status"])),
            alive_cell,
            cell,
        )
    return table


def _xss_table(rows: list[dict]) -> Table:
    table = Table(
        title="[bold red]Reflected XSS signals[/bold red]",
        caption=(
            "[dim]Payloads reflected verbatim in the response body. "
            "Manually validate context/escaping before reporting.[/dim]"
        ),
        caption_justify="left",
        box=box.HEAVY_EDGE,
        show_header=True,
        header_style="bold red",
        border_style="red",
        expand=True,
    )
    table.add_column("#", style="dim", justify="right", width=3)
    table.add_column("Severity", width=10)
    table.add_column("Method", width=6)
    table.add_column("Param", style="cyan", no_wrap=True)
    table.add_column("URL", overflow="fold")
    table.add_column("Payload", overflow="fold")
    table.add_column("Status", justify="right", width=6)
    table.add_column("Context", overflow="fold")

    sev_order = {"High": 0, "Medium": 1, "Low": 2}
    rows_sorted = sorted(rows, key=lambda r: sev_order.get(r.get("severity", "Low"), 3))
    for i, r in enumerate(rows_sorted, start=1):
        sev = r.get("severity", "Medium")
        color = SEVERITY_COLORS.get(sev, "white")
        table.add_row(
            str(i),
            f"[bold {color}]{escape(sev)}[/bold {color}]",
            escape(str(r.get("method", ""))),
            escape(str(r.get("param", ""))),
            escape(str(r.get("url", ""))),
            escape(str(r.get("payload", ""))),
            escape(str(r.get("status", ""))),
            escape(str(r.get("note", ""))),
        )
    return table


def _cloud_table(rows: list[dict]) -> Table:
    table = Table(
        title="[bold blue]Cloud storage exposure[/bold blue]",
        caption=(
            "[dim]Candidate bucket names derived from the target apex. "
            "Public listable = inventory leak; access-denied still confirms existence.[/dim]"
        ),
        caption_justify="left",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold blue",
        border_style="blue",
        expand=True,
    )
    table.add_column("#", style="dim", justify="right", width=3)
    table.add_column("Severity", width=10)
    table.add_column("Provider", style="cyan", no_wrap=True)
    table.add_column("Bucket / Container", overflow="fold")
    table.add_column("State", no_wrap=True)
    table.add_column("Status", justify="right", width=6)
    table.add_column("URL", overflow="fold")
    table.add_column("Note", overflow="fold")

    for i, r in enumerate(rows, start=1):
        sev = r.get("severity", "Low")
        color = SEVERITY_COLORS.get(sev, "white")
        table.add_row(
            str(i),
            f"[bold {color}]{escape(sev)}[/bold {color}]",
            escape(str(r.get("provider", ""))),
            escape(str(r.get("bucket", ""))),
            escape(str(r.get("state", ""))),
            escape(str(r.get("status", ""))),
            escape(str(r.get("url", ""))),
            escape(str(r.get("note", ""))),
        )
    return table


def _path_table(rows: list[dict]) -> Table:
    table = Table(
        title="[bold yellow]Sensitive path discovery[/bold yellow]",
        caption=(
            "[dim]Status 200 = content served; 401/403 = restricted but present; "
            "3xx = redirect. Review each hit manually.[/dim]"
        ),
        caption_justify="left",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold yellow",
        border_style="yellow",
        expand=True,
    )
    table.add_column("#", style="dim", justify="right", width=3)
    table.add_column("Severity", width=10)
    table.add_column("State", no_wrap=True)
    table.add_column("Status", justify="right", width=6)
    table.add_column("Phase", no_wrap=True, width=10)
    table.add_column("Path", style="cyan", overflow="fold")
    table.add_column("Length", justify="right", width=8)
    table.add_column("URL", overflow="fold")

    for i, r in enumerate(rows, start=1):
        sev = r.get("severity", "Low")
        color = SEVERITY_COLORS.get(sev, "white")
        phase = str(r.get("probe_phase", "")) or "—"
        table.add_row(
            str(i),
            f"[bold {color}]{escape(sev)}[/bold {color}]",
            escape(str(r.get("state", ""))),
            escape(str(r.get("status", ""))),
            escape(phase),
            escape(str(r.get("path", ""))),
            escape(str(r.get("length", ""))),
            escape(str(r.get("url", ""))),
        )
    return table


def _html_source_table(rows: list[dict]) -> Table:
    table = Table(
        title="[bold bright_green]HTML / comment source recon[/bold bright_green]",
        caption=(
            "[dim]Developer comments, URL-like strings, and notable link attributes on the "
            "landing HTML. Validate manually — many hits are benign.[/dim]"
        ),
        caption_justify="left",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold bright_green",
        border_style="bright_green",
        expand=True,
    )
    table.add_column("#", style="dim", justify="right", width=3)
    table.add_column("Severity", width=10)
    table.add_column("Type", style="cyan", no_wrap=True)
    table.add_column("Page", overflow="fold")
    table.add_column("Match / detail", overflow="fold")

    sev_order = {"High": 0, "Medium": 1, "Low": 2}
    rows_sorted = sorted(
        rows,
        key=lambda r: (sev_order.get(r.get("severity", "Low"), 3), r.get("type", "")),
    )
    for i, r in enumerate(rows_sorted, start=1):
        sev = r.get("severity", "Low")
        color = SEVERITY_COLORS.get(sev, "white")
        preview = str(r.get("match", ""))
        if len(preview) > 100:
            preview = preview[:97] + "..."
        note = str(r.get("note", ""))
        pe = escape(preview)
        detail = pe if not note else f"{pe}\n[dim]{escape(note[:120])}[/dim]"
        table.add_row(
            str(i),
            f"[bold {color}]{escape(sev)}[/bold {color}]",
            escape(str(r.get("type", ""))),
            escape(str(r.get("source_url", ""))),
            detail,
        )
    return table


def _broken_links_table(rows: list[dict]) -> Table:
    table = Table(
        title="[bold bright_yellow]Broken links — potential takeover[/bold bright_yellow]",
        caption=(
            "[dim]External links from page source validated with DNS and limited HTTP probes. "
            "Confirm before reporting — false positives occur for geo-blocks, bot walls, and "
            "temporary outages.[/dim]"
        ),
        caption_justify="left",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold bright_yellow",
        border_style="yellow",
        expand=True,
    )
    table.add_column("#", style="dim", justify="right", width=3)
    table.add_column("Severity", width=10)
    table.add_column("Kind", style="cyan", no_wrap=True, width=22)
    table.add_column("Evidence", width=16)
    table.add_column("Linked URL", overflow="fold")
    table.add_column("Note", overflow="fold")

    kind_labels = {
        "takeover_dangling_domain": "dangling domain",
        "takeover_dead_social": "dead social / 404",
    }
    for i, r in enumerate(rows, start=1):
        sev = r.get("severity", "High")
        color = SEVERITY_COLORS.get(sev, "white")
        k = kind_labels.get(str(r.get("type", "")), str(r.get("type", "")))
        url = str(r.get("url", ""))
        if len(url) > 90:
            url = url[:87] + "..."
        table.add_row(
            str(i),
            f"[bold {color}]{escape(sev)}[/bold {color}]",
            escape(k),
            escape(str(r.get("evidence", ""))),
            escape(url),
            escape(str(r.get("note", ""))[:220]),
        )
    return table


def _api_injection_table(rows: list[dict]) -> Table:
    table = Table(
        title="[bold bright_red]API schema fuzz — injection signals[/bold bright_red]",
        caption="[dim]Heuristic SQLi from OpenAPI-derived requests; confirm with manual tests.[/dim]",
        caption_justify="left",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold bright_red",
        border_style="red",
        expand=True,
    )
    table.add_column("#", style="dim", justify="right", width=3)
    table.add_column("Severity", width=10)
    table.add_column("Type", style="cyan", width=18)
    table.add_column("Method", width=6)
    table.add_column("Param", overflow="fold")
    table.add_column("URL / note", overflow="fold")
    for i, r in enumerate(rows, start=1):
        sev = r.get("severity", "High")
        color = SEVERITY_COLORS.get(sev, "white")
        table.add_row(
            str(i),
            f"[bold {color}]{escape(sev)}[/bold {color}]",
            escape(str(r.get("type", ""))),
            escape(str(r.get("method", ""))),
            escape(str(r.get("param", ""))),
            escape(str(r.get("url", ""))[:120])
            + ("\n[dim]" + escape(str(r.get("note", ""))[:160]) + "[/dim]" if r.get("note") else ""),
        )
    return table


def _api_spec_discovered_table(rows: list[dict]) -> Table:
    table = Table(
        title="[bold bright_cyan]API schema discovery[/bold bright_cyan]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold bright_cyan",
        border_style="cyan",
        expand=True,
    )
    table.add_column("#", style="dim", justify="right", width=3)
    table.add_column("Severity", width=10)
    table.add_column("Flavor", width=12)
    table.add_column("Document URL", overflow="fold")
    table.add_column("Note", overflow="fold")
    for i, r in enumerate(rows, start=1):
        sev = r.get("severity", "Medium")
        color = SEVERITY_COLORS.get(sev, "white")
        table.add_row(
            str(i),
            f"[bold {color}]{escape(sev)}[/bold {color}]",
            escape(str(r.get("flavor", ""))),
            escape(str(r.get("url", ""))),
            escape(str(r.get("note", ""))),
        )
    return table


def _param_probe_table(rows: list[dict]) -> Table:
    table = Table(
        title="[bold bright_blue]Hidden parameter probe (GET / POST / JSON)[/bold bright_blue]",
        caption=(
            "[dim]Arjun-style: compares each request to an unparameterized baseline. "
            "Medium = stronger signal (reflection, large body delta, or 5xx).[/dim]"
        ),
        caption_justify="left",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold bright_blue",
        border_style="bright_blue",
        expand=True,
    )
    table.add_column("#", style="dim", justify="right", width=3)
    table.add_column("Sev", width=8)
    table.add_column("Method", width=11)
    table.add_column("Param", style="cyan", overflow="fold")
    table.add_column("HTTP", justify="right", width=6)
    table.add_column("URL & notes", overflow="fold")

    sev_order = {"High": 0, "Medium": 1, "Low": 2}
    rows_sorted = sorted(
        rows,
        key=lambda r: (sev_order.get(r.get("severity", "Low"), 3), r.get("method", ""), r.get("param", "")),
    )
    for i, r in enumerate(rows_sorted, start=1):
        sev = r.get("severity", "Low")
        color = SEVERITY_COLORS.get(sev, "white")
        url = str(r.get("url", ""))
        note = str(r.get("note", ""))
        cell = escape(url[:120] + ("…" if len(url) > 120 else ""))
        if note:
            cell = f"{cell}\n[dim]{escape(note)}[/dim]"
        table.add_row(
            str(i),
            f"[bold {color}]{escape(sev)}[/bold {color}]",
            escape(str(r.get("method", ""))),
            escape(str(r.get("param", ""))),
            escape(str(r.get("status", ""))),
            cell,
        )
    return table


def _zero_day_table(rows: list[dict]) -> Table:
    table = Table(
        title="[bold bright_white]Zero-Day Hunter — harvest & fuzz signals[/bold bright_white]",
        caption=(
            "[dim]Logic-flaw probes with rotated encodings; Critical/High often imply 5xx, stack-like "
            "bodies, or strong latency deltas — validate manually. Authorized testing only.[/dim]"
        ),
        caption_justify="left",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold white",
        border_style="white",
        expand=True,
    )
    table.add_column("#", style="dim", justify="right", width=3)
    table.add_column("Sev", width=10)
    table.add_column("Kind", style="cyan", width=14)
    table.add_column("Detail", overflow="fold")
    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    rows_sorted = sorted(
        rows,
        key=lambda r: (
            sev_order.get(str(r.get("severity", "Low")), 9),
            str(r.get("type", "")),
        ),
    )
    for i, r in enumerate(rows_sorted, start=1):
        sev = str(r.get("severity", "Low"))
        color = SEVERITY_COLORS.get(sev, "white")
        kind = str(r.get("type", ""))
        if kind == "fuzz_hit":
            detail = (
                f"{escape(str(r.get('method', 'GET')))} "
                f"param={escape(str(r.get('param', '')))} "
                f"class={escape(str(r.get('payload_class', '')))} "
                f"enc={escape(str(r.get('encoding', '')))} "
                f"HTTP {r.get('status', '')} "
                f"{r.get('latency_ms', '')}ms"
                f"\n[dim]{escape(str(r.get('url', '')))}[/dim]"
                f"\n[dim]{escape(str(r.get('note', '')))}[/dim]"
            )
        elif kind == "harvest_param":
            detail = (
                f"score={r.get('interest_score', '')} "
                f"src={escape(str(r.get('source', '')))} "
                f"{escape(str(r.get('param', '')))}\n"
                f"[dim]{escape(str(r.get('reason', '')))} — {escape(str(r.get('note', '')))}[/dim]"
            )
        else:
            detail = escape(str(r.get("url", r.get("note", ""))))
            if r.get("note") and kind != "harvest_endpoint":
                detail += f"\n[dim]{escape(str(r.get('note', '')))}[/dim]"
        table.add_row(
            str(i),
            f"[bold {color}]{escape(sev)}[/bold {color}]",
            escape(kind),
            detail,
        )
    return table


def _oauth_social_table(rows: list[dict]) -> Table:
    table = Table(
        title="[bold bright_blue]OAuth / OIDC / social login[/bold bright_blue]",
        caption=(
            "[dim]Playtika bounty mode: redirect_uri probes use https://example.com only; "
            "link/unlink surfaces are read-only GETs. Strong pacing to avoid DoS.[/dim]"
        ),
        caption_justify="left",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold bright_blue",
        border_style="bright_blue",
        expand=True,
    )
    table.add_column("#", style="dim", justify="right", width=3)
    table.add_column("Sev", width=10)
    table.add_column("Type", style="cyan", width=22)
    table.add_column("Detail", overflow="fold")
    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    rows_sorted = sorted(
        rows,
        key=lambda r: (
            sev_order.get(str(r.get("severity", "Low")), 9),
            str(r.get("type", "")),
        ),
    )
    for i, r in enumerate(rows_sorted, start=1):
        sev = str(r.get("severity", "Low"))
        color = SEVERITY_COLORS.get(sev, "white")
        u = str(r.get("url", ""))[:180]
        d = str(r.get("detail", ""))[:320]
        detail = f"{escape(d)}\n[dim]{escape(u)}[/dim]"
        note = r.get("note")
        if note:
            detail += f"\n[dim]{escape(str(note)[:240])}[/dim]"
        table.add_row(
            str(i),
            f"[bold {color}]{escape(sev)}[/bold {color}]",
            escape(str(r.get("type", ""))),
            detail,
        )
    return table


def _wayback_table(rows: list[dict]) -> Table:
    table = Table(
        title="[bold cyan]Wayback Machine — live replay[/bold cyan]",
        caption=(
            "[dim]Paths from Archive.org CDX probed on the live host (redirects not followed). "
            "Medium = HTTP 200.[/dim]"
        ),
        caption_justify="left",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        border_style="cyan",
        expand=True,
    )
    table.add_column("#", style="dim", justify="right", width=3)
    table.add_column("Sev", width=8)
    table.add_column("HTTP", justify="right", width=5)
    table.add_column("Path", overflow="fold", ratio=2)
    table.add_column("Live URL", overflow="fold", ratio=3)
    for i, r in enumerate(rows, start=1):
        sev = r.get("severity", "Low")
        color = SEVERITY_COLORS.get(sev, "white")
        table.add_row(
            str(i),
            f"[bold {color}]{escape(sev)}[/bold {color}]",
            escape(str(r.get("live_status", ""))),
            escape(str(r.get("path", ""))[:100]),
            escape(str(r.get("live_url", ""))[:160]),
        )
    return table


def _sensitive_file_table(rows: list[dict]) -> Table:
    table = Table(
        title="[bold red]Sensitive file hunter[/bold red]",
        caption=(
            "[dim]Dedicated wordlist for configs, VCS metadata, containers, and phpinfo.[/dim]"
        ),
        caption_justify="left",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold red",
        border_style="red",
        expand=True,
    )
    table.add_column("#", style="dim", justify="right", width=3)
    table.add_column("Severity", width=10)
    table.add_column("State", no_wrap=True)
    table.add_column("HTTP", justify="right", width=6)
    table.add_column("Path", style="cyan", overflow="fold")
    table.add_column("URL", overflow="fold")
    for i, r in enumerate(rows, start=1):
        sev = r.get("severity", "Low")
        color = SEVERITY_COLORS.get(sev, "white")
        table.add_row(
            str(i),
            f"[bold {color}]{escape(sev)}[/bold {color}]",
            escape(str(r.get("state", ""))),
            escape(str(r.get("status", ""))),
            escape(str(r.get("path", ""))),
            escape(str(r.get("url", ""))),
        )
    return table


def _js_table(rows: list[dict]) -> Table:
    table = Table(
        title="[bold bright_cyan]Deep JS analysis — endpoints & secrets[/bold bright_cyan]",
        caption=(
            "[dim]Concurrent crawl of every linked .js asset; optional beautify improves regex "
            "recovery (install jsbeautifier). "
            "Secrets dedupe with the [magenta]Secrets[/magenta] table above; "
            "endpoints expand the target's attack surface.[/dim]"
        ),
        caption_justify="left",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold bright_cyan",
        border_style="bright_cyan",
        expand=True,
    )
    table.add_column("#", style="dim", justify="right", width=3)
    table.add_column("Severity", width=10)
    table.add_column("Type", style="cyan", no_wrap=True)
    table.add_column("Source JS", overflow="fold")
    table.add_column("Match / Endpoint", overflow="fold")

    sev_order = {"High": 0, "Medium": 1, "Low": 2}
    rows_sorted = sorted(
        rows,
        key=lambda r: (sev_order.get(r.get("severity", "Low"), 3), r.get("type", "")),
    )
    for i, r in enumerate(rows_sorted, start=1):
        sev = r.get("severity", "Low")
        color = SEVERITY_COLORS.get(sev, "white")
        preview = str(r.get("match", ""))
        if len(preview) > 120:
            preview = preview[:117] + "..."
        table.add_row(
            str(i),
            f"[bold {color}]{escape(sev)}[/bold {color}]",
            escape(str(r.get("type", ""))),
            escape(str(r.get("source_url", ""))),
            escape(preview),
        )
    return table


def _xss_mutations_table(mutations: list[dict]) -> Table:
    table = Table(
        title="[bold magenta]AI-guided XSS payload mutations (WAF bypass)[/bold magenta]",
        caption=(
            "[dim]Generated via AIAuditor.mutate_xss_payloads(). "
            "These are added to the XSS scanner alongside the base payloads.[/dim]"
        ),
        caption_justify="left",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta",
        border_style="magenta",
        expand=True,
    )
    table.add_column("#", style="dim", justify="right", width=3)
    table.add_column("Technique", style="bold cyan", width=24, overflow="fold")
    table.add_column("Base payload", overflow="fold")
    table.add_column("Mutated payload", overflow="fold")

    for i, m in enumerate(mutations, start=1):
        base = str(m.get("base_payload", ""))
        if len(base) > 60:
            base = base[:57] + "..."
        mut = str(m.get("payload", ""))
        if len(mut) > 110:
            mut = mut[:107] + "..."
        table.add_row(
            str(i),
            escape(str(m.get("technique", ""))),
            escape(base),
            escape(mut),
        )
    return table


def _logic_scan_table(rows: list[dict]) -> Table:
    table = Table(
        title="[bold bright_yellow]Logic scan — IDOR / price & cart surfaces[/bold bright_yellow]",
        caption=(
            "[dim]Passive heuristics on harvested URLs (--js / --brute / --params). "
            "Verify manually; does not send exploit payloads.[/dim]"
        ),
        caption_justify="left",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold yellow",
        border_style="yellow",
        expand=True,
    )
    table.add_column("#", style="dim", justify="right", width=4)
    table.add_column("Sev", width=7)
    table.add_column("Subtype", style="cyan", width=22, overflow="fold")
    table.add_column("Endpoint", overflow="fold")
    table.add_column("Note", overflow="fold")
    for i, r in enumerate(rows, start=1):
        sev = str(r.get("severity", "Medium"))
        color = "bright_red" if sev == "High" else "yellow"
        table.add_row(
            str(i),
            f"[{color}]{escape(sev)}[/{color}]",
            escape(str(r.get("subtype", ""))),
            escape(str(r.get("endpoint", ""))[:300]),
            escape(str(r.get("note", ""))[:280]),
        )
    return table


def _ai_mutator_table(rows: list[dict], *, llm_note: str | None) -> Table:
    cap = (
        "[dim]AI-Mutator: one base probe (XSS or SQLi) per discovered parameter slot, "
        "10 variants each. LLM when API key set.[/dim]"
    )
    if llm_note:
        cap += f" [yellow]Note:[/yellow] {escape(llm_note[:200])}"
    table = Table(
        title="[bold magenta]AI-Mutator — WAF-oriented payload variants[/bold magenta]",
        caption=cap,
        caption_justify="left",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta",
        border_style="magenta",
        expand=True,
    )
    table.add_column("#", style="dim", justify="right", width=4)
    table.add_column("Param", style="cyan", width=14, overflow="fold")
    table.add_column("Src", width=8)
    table.add_column("Payload", overflow="fold")
    for r in rows:
        pl = str(r.get("payload", ""))
        if len(pl) > 140:
            pl = pl[:137] + "..."
        table.add_row(
            str(r.get("index", "")),
            escape(str(r.get("param", "") or "—")),
            escape(str(r.get("source", ""))),
            escape(pl),
        )
    return table


def _idor_table(rows: list[dict]) -> Table:
    table = Table(
        title="[bold bright_red]IDOR candidates (horizontal access control)[/bold bright_red]",
        caption=(
            "[dim]Critical = HTTP 200 but different PII (emails / phone / named fields) "
            "returned for a neighbouring id; manually verify authorization before reporting.[/dim]"
        ),
        caption_justify="left",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold bright_red",
        border_style="bright_red",
        expand=True,
    )
    table.add_column("#", style="dim", justify="right", width=3)
    table.add_column("Severity", width=10)
    table.add_column("Param / path", style="cyan", overflow="fold", ratio=2)
    table.add_column("Base -> Test", justify="center", width=14)
    table.add_column("HTTP / Sim.", justify="center", width=12)
    table.add_column("Mutated URL & evidence", overflow="fold", ratio=5)

    for i, r in enumerate(rows, start=1):
        sev = r.get("severity", "High")
        color = SEVERITY_COLORS.get(sev, "white")
        kind = r.get("kind", "?")
        param = str(r.get("param", ""))
        param_cell = f"{escape(param)}\n[dim]{escape(kind)}[/dim]"
        base_id = r.get("base_id", "?")
        test_id = r.get("test_id", "?")
        http_cell = (
            f"{escape(str(r.get('status', '')))}\n"
            f"[dim]sim {r.get('similarity', '?')}[/dim]"
        )
        url = str(r.get("url", ""))
        note = str(r.get("note", ""))
        if len(url) > 80:
            url = url[:77] + "..."
        evidence = escape(url)
        if note:
            evidence = f"{evidence}\n[dim]{escape(note[:180])}[/dim]"
        table.add_row(
            str(i),
            f"[bold {color}]{escape(sev)}[/bold {color}]",
            param_cell,
            f"{base_id} [dim]->[/dim] {test_id}",
            http_cell,
            evidence,
        )
    return table


def _port_table(rows: list[dict]) -> Table:
    table = Table(
        title="[bold bright_magenta]Open TCP ports[/bold bright_magenta]",
        caption=(
            "[dim]TCP-connect probe on a curated set of common service ports. "
            "Banner grabbing is not performed.[/dim]"
        ),
        caption_justify="left",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold bright_magenta",
        border_style="bright_magenta",
        expand=True,
    )
    table.add_column("#", style="dim", justify="right", width=3)
    table.add_column("Severity", width=10)
    table.add_column("Host", style="cyan", overflow="fold")
    table.add_column("Port", justify="right", width=6)
    table.add_column("State", no_wrap=True, width=10)
    table.add_column("Service", no_wrap=True)

    for i, r in enumerate(rows, start=1):
        sev = r.get("severity", "Medium")
        color = SEVERITY_COLORS.get(sev, "white")
        detail = r.get("decision_detail")
        svc = str(r.get("service", ""))
        if detail:
            svc = f"{svc}\n[dim]{escape(str(detail)[:200])}{'…' if len(str(detail)) > 200 else ''}[/dim]"
        table.add_row(
            str(i),
            f"[bold {color}]{escape(sev)}[/bold {color}]",
            escape(str(r.get("host", ""))),
            escape(str(r.get("port", ""))),
            escape(str(r.get("state", "open"))),
            svc,
        )
    return table


def _nuclei_table(rows: list[dict]) -> Table:
    table = Table(
        title="[bold bright_green]Nuclei — template matches[/bold bright_green]",
        caption=(
            "[dim]ProjectDiscovery Nuclei (JSONL). Missing binary → see GitHub releases. "
            "Verify each finding in-scope; severity comes from template metadata.[/dim]"
        ),
        caption_justify="left",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold bright_green",
        border_style="green",
        expand=True,
    )
    table.add_column("#", style="dim", justify="right", width=4)
    table.add_column("Severity", width=10)
    table.add_column("Template", style="cyan", width=28, overflow="fold")
    table.add_column("Name", overflow="fold")
    table.add_column("Matched / host", overflow="fold")
    table.add_column("Type", no_wrap=True, width=8)

    _sev_map = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Info",
        "unknown": "Info",
    }
    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

    def _disp_sev(raw: object) -> str:
        s = str(raw or "info").strip().lower()
        return _sev_map.get(s, s[:1].upper() + s[1:] if s else "Info")

    sorted_rows = sorted(
        rows,
        key=lambda r: (sev_order.get(_disp_sev(r.get("severity")), 9), str(r.get("template_id", ""))),
    )
    for i, r in enumerate(sorted_rows, start=1):
        dsev = _disp_sev(r.get("severity"))
        color = SEVERITY_COLORS.get(dsev, "white")
        matched = str(r.get("matched_at") or r.get("host") or "")
        if len(matched) > 140:
            matched = matched[:137] + "..."
        table.add_row(
            str(i),
            f"[bold {color}]{escape(dsev)}[/bold {color}]",
            escape(str(r.get("template_id", ""))[:120]),
            escape(str(r.get("name", ""))[:200]),
            escape(matched),
            escape(str(r.get("type", ""))[:12]),
        )
    return table


def _ai_payloads_table() -> Table:
    table = Table(
        title="[bold bright_yellow]AI / LLM — prompt injection playbook[/bold bright_yellow]",
        caption=(
            "[dim]Copy payloads into in-scope chatbots, support bots, or embedded assistants. "
            "Full strings: modules/ai_auditor.py[/dim]"
        ),
        caption_justify="left",
        box=box.DOUBLE_EDGE,
        show_header=True,
        show_lines=True,
        header_style="bold bright_yellow",
        border_style="yellow",
        expand=True,
        pad_edge=False,
    )
    table.add_column("#", style="dim", justify="right", width=3, vertical="middle")
    table.add_column("Technique", style="bold cyan", width=26, overflow="fold", vertical="middle")
    table.add_column("Payload", style="white", overflow="fold", vertical="top")

    for i, (technique, payload) in enumerate(AIAuditor.list_payloads(), start=1):
        table.add_row(str(i), escape(technique), escape(payload.strip()))
    return table


def _print_infiltration_section(
    console: Console,
    bundle: dict[str, Any],
    err: str | None,
) -> None:
    console.rule("[bold red]Autonomous infiltration[/bold red]", style="red")
    if err:
        console.print(f"[red]Infiltration engine error:[/red] {escape(err)}")
        return
    chain = bundle.get("chain_extractions") or []
    bypass = bundle.get("forbidden_bypass") or []
    params = bundle.get("param_active") or []
    cookies = bundle.get("cookie_audit") or []
    ports = bundle.get("alternate_port_hits") or []
    recs = bundle.get("ai_recommendations") or []

    console.print(
        f"[dim]Chain extractions:[/dim] {len(chain)}  "
        f"[dim]403 bypass:[/dim] {len(bypass)}  "
        f"[dim]Active param probes:[/dim] {len(params)}  "
        f"[dim]Cookies audited:[/dim] {len(cookies)}  "
        f"[dim]Alternate-port hits:[/dim] {len(ports)}\n"
    )
    if chain:
        console.print("[bold]Credential-like extractions[/bold]")
        for i, r in enumerate(chain[:12], 1):
            console.print(
                f"  [cyan]#{i}[/cyan] [{escape(str(r.get('subtype', '?')))}] "
                f"{escape(str(r.get('match_preview', '')))}"
            )
            console.print(f"      {escape(str(r.get('source_url', '')))}")
        console.print()
    if bypass:
        console.print("[bold]403 bypass candidates[/bold]")
        for i, r in enumerate(bypass[:12], 1):
            console.print(
                f"  [yellow]#{i}[/yellow] HTTP {r.get('status')} "
                f"{escape(str(r.get('url', '')))}"
            )
        console.print()
    if params:
        console.print("[bold]Active parameter probes[/bold]")
        for i, r in enumerate(params[:12], 1):
            console.print(
                f"  [magenta]#{i}[/magenta] [{escape(str(r.get('type', '?')))}] "
                f"param={escape(str(r.get('param', '')))}"
            )
            console.print(f"      {escape(str(r.get('note', '')))}")
        console.print()
    if cookies:
        console.print("[bold]Cookie session flags[/bold]")
        for i, r in enumerate(cookies[:16], 1):
            ho = "yes" if r.get("httponly") else "no"
            sec = "yes" if r.get("secure") else "no"
            console.print(
                f"  [dim]#{i}[/dim] {escape(str(r.get('cookie_name', '')))}  "
                f"HttpOnly={ho}  Secure={sec}"
            )
            if r.get("severity") == "Medium":
                console.print(f"      [yellow]{escape(str(r.get('risk', '')))}[/yellow]")
        console.print()
    if ports:
        console.print("[bold]Alternate port HTTP[/bold]")
        for i, r in enumerate(ports[:12], 1):
            console.print(
                f"  [blue]#{i}[/blue] port {r.get('port')} HTTP {r.get('status')} "
                f"{escape(str(r.get('url', '')))}"
            )
        console.print()
    if recs:
        console.print("[bold]AI auditor — next moves (rule-based)[/bold]")
        for i, r in enumerate(recs, 1):
            console.print(
                f"  [green]{i}.[/green] [bold]{escape(str(r.get('action', '')))}[/bold] "
                f"[dim]({escape(str(r.get('priority', '')))})[/dim]"
            )
            console.print(f"      {escape(str(r.get('rationale', '')))}")
            console.print(
                f"      [italic]{escape(str(r.get('execute_hint', '')))}[/italic]"
            )
        console.print()
    if not (chain or bypass or params or cookies or ports):
        console.print(
            "[yellow]No follow-up signals in this pass.[/yellow] "
            "[dim]Combine --infiltrate with --brute, --sensitive, --params, and/or --port "
            "for richer input.[/dim]\n"
        )


def _print_ai_section(console: Console, url: str) -> None:
    console.rule("[bold bright_yellow]AI chat assessment[/bold bright_yellow]", style="yellow")
    console.print(
        f"[bold]Scope reference:[/bold] [link={url}]{escape(url)}[/link]\n"
        "[dim]Use only under program rules. Watch for policy bypass, hidden-instruction "
        "leaks, unsafe tool invocation, and cross-session data bleed.[/dim]\n"
    )
    console.print(_ai_payloads_table())


async def _run(
    url: str,
    show_ai: bool,
    subdomain: bool,
    xss: bool,
    cloud: bool,
    brute: bool,
    port: bool,
    js: bool,
    idor: bool,
    source_scan: bool,
    param_scan: bool,
    wayback_scan: bool,
    sensitive_scan: bool,
    broken_links: bool,
    api_fuzz: bool,
    zero_day: bool,
    playtika_bounty: bool,
    recursive_paths: bool,
    extension_fuzz: bool,
    save_report: bool,
    save_pdf: bool,
    infiltrate: bool,
    extra_headers: dict[str, str],
    evasion: EvasionProfile,
    nmap_stealth_ports: bool,
    nmap_spoof_mac: bool,
    bypass_403: bool,
    obfuscate: bool,
    logic_scan: bool,
    ai_mutate: bool,
    mutate_kind: str,
    sqli: bool,
    deep_scan: bool,
    nuclei: bool,
    console: Console,
) -> int:
    def _mode(flag: bool) -> str:
        col = "green" if flag else "dim"
        return f"[{col}]{'on' if flag else 'off'}[/{col}]"

    xss_mutations: list[dict] = []
    extra_xss_payloads: tuple[str, ...] = ()
    waf_mutate_xss = xss and (show_ai or evasion.stealth_mode)
    if waf_mutate_xss:
        xss_mutations = AIAuditor.mutate_xss_payloads(list(XSSScanner.PAYLOADS))
        seen_payloads = {m["payload"] for m in xss_mutations}
        for row in AIAuditor.chained_waf_mutations(list(XSSScanner.PAYLOADS)):
            p = row["payload"]
            if p in seen_payloads:
                continue
            seen_payloads.add(p)
            xss_mutations.append(row)
        extra_xss_payloads = tuple(m["payload"] for m in xss_mutations)

    console.print(f"[bold]Target:[/bold] [link={url}]{escape(url)}[/link]")
    if evasion.smart_evasion:
        try:
            await asyncio.wait_for(
                evasion.probe_target_waf(url),
                timeout=WAF_PROBE_WALL_CLOCK_SEC,
            )
        except asyncio.TimeoutError:
            evasion.detected_waf = "none"
            evasion.jitter_multiplier = 1.0
            console.print(
                "[yellow]WAF fingerprint probe timed out; continuing without CDN/WAF hints.[/yellow]"
            )
    console.print(
        f"[dim]Modes:[/dim] "
        f"secrets={_mode(True)}  "
        f"js={_mode(js)}  "
        f"subdomain={_mode(subdomain)}  "
        f"xss={_mode(xss)}  "
        f"cloud={_mode(cloud)}  "
        f"brute={_mode(brute)}  "
        f"port={_mode(port)}  "
        f"idor={_mode(idor)}  "
        f"source={_mode(source_scan)}  "
        f"params={_mode(param_scan)}  "
        f"wayback={_mode(wayback_scan)}  "
        f"sensitive={_mode(sensitive_scan)}  "
        f"broken_links={_mode(broken_links)}  "
        f"api_fuzz={_mode(api_fuzz)}  "
        f"zero_day={_mode(zero_day)}  "
        f"playtika_bounty={_mode(playtika_bounty)}  "
        f"ai={_mode(show_ai)}  "
        f"report={_mode(save_report)}  "
        f"pdf={_mode(save_pdf)}  "
        f"infiltrate={_mode(infiltrate)}  "
        f"bypass_403={_mode(bypass_403)}  "
        f"obfuscate={_mode(obfuscate)}  "
        f"headers={_mode(bool(extra_headers))}  "
        f"tor={_mode(evasion.use_tor)}  "
        f"jitter={_mode(evasion.jitter_enabled)}  "
        f"stealth={_mode(evasion.stealth_mode)}  "
        f"smart={_mode(evasion.smart_evasion)}  "
        f"waf_probe={_mode(evasion.waf_probe)}  "
        f"nmap_stealth={_mode(nmap_stealth_ports)}  "
        f"ext_fuzz={_mode(extension_fuzz and brute)}  "
        f"logic_scan={_mode(logic_scan)}  "
        f"ai_mutate={_mode(ai_mutate)}  "
        f"sqli={_mode(sqli)}  "
        f"deep_scan={_mode(deep_scan)}  "
        f"nuclei={_mode(nuclei)}\n"
    )
    if evasion.smart_evasion and evasion.detected_waf != "none":
        console.print(
            f"[dim]WAF hint:[/dim] [yellow]{escape(evasion.detected_waf)}[/yellow] — "
            f"pacing ×{evasion.jitter_multiplier:.1f} "
            f"[dim](inter-request delay scaled)[/dim]\n"
        )
    if os.environ.get("OMNISCAN_DASHBOARD"):
        _push_dashboard_socket_log(f"[omniscan] initializing scan for {url}")
        _dashboard_emit({"event": "scan_start", "target_url": url})
        _dashboard_push_new_loot(
            category="Test Loot",
            severity="Low",
            detail="Test Loot — verify LOOT table wiring (sent at scan start).",
            source=url,
        )
    if evasion.use_tor:
        console.print(
            f"[dim]Tor proxy:[/dim] [cyan]{escape(evasion.tor_socks_url)}[/cyan]\n"
        )
    if extra_headers:
        header_names = ", ".join(sorted(extra_headers.keys()))
        console.print(
            f"[dim]Custom headers attached to XSS / IDOR / JS-secret / broken-link / "
            f"API-fuzz / Zero-Day Hunter / OAuth-social scanners: "
            f"{escape(header_names)}[/dim]\n"
        )
    if playtika_bounty:
        console.print(
            "[dim]Playtika bounty mode:[/dim] [cyan]X-Bug-Bounty: True[/cyan] on all probes; "
            "[dim]OAuth/OIDC/social checks + stronger default jitter (avoid DoS).[/dim]\n"
        )
    if xss_mutations:
        mut_label = (
            "AI Auditor (WAF mutations + heuristic chains)"
            if evasion.stealth_mode and not show_ai
            else "AI Auditor"
        )
        console.print(
            f"[bold magenta]{mut_label}:[/bold magenta] generated "
            f"[bold]{len(xss_mutations)}[/bold] WAF-bypass XSS mutations "
            f"[dim](fed into --xss scanner)[/dim]\n"
        )

    findings: list[dict] = []
    secret_err: str | None = None
    sub_rows: list[dict] = []
    sub_err: str | None = None
    xss_rows: list[dict] = []
    xss_err: str | None = None
    cloud_rows: list[dict] = []
    cloud_err: str | None = None
    path_rows: list[dict] = []
    path_err: str | None = None
    port_rows: list[dict] = []
    port_err: str | None = None
    js_rows: list[dict] = []
    js_err: str | None = None
    idor_rows: list[dict] = []
    idor_err: str | None = None
    html_rows: list[dict] = []
    html_err: str | None = None
    param_rows: list[dict] = []
    param_err: str | None = None
    wayback_rows: list[dict] = []
    wayback_hist: list[str] = []
    wayback_err: str | None = None
    wayback_seed_pairs: list[tuple[str, str]] = []
    sensitive_rows: list[dict] = []
    sensitive_err: str | None = None
    broken_rows: list[dict] = []
    broken_err: str | None = None
    api_fuzz_bundle: dict[str, Any] = {
        "discovered": [],
        "idor": [],
        "injection": [],
        "graphql": [],
    }
    api_fuzz_err: str | None = None
    zero_day_rows: list[dict] = []
    zero_day_err: str | None = None
    oauth_rows: list[dict] = []
    oauth_err: str | None = None
    logic_rows: list[dict] = []

    with _progress() as progress:
        secret_task = progress.add_task(
            "[magenta]Secret scan — discovering scripts…", total=None
        )
        sub_task = (
            progress.add_task("[green]Subdomain probe — planning…", total=None)
            if subdomain else None
        )
        xss_task = (
            progress.add_task("[red]XSS probe — discovering params…", total=None)
            if xss else None
        )
        cloud_task = (
            progress.add_task("[blue]Cloud probe — building candidates…", total=None)
            if cloud else None
        )
        path_task = (
            progress.add_task("[yellow]Path bruter — planning…", total=None)
            if brute else None
        )
        port_task = (
            progress.add_task("[bright_magenta]Port scan — planning…", total=None)
            if port else None
        )
        js_task = (
            progress.add_task("[bright_cyan]JS deep analysis — planning…", total=None)
            if js else None
        )
        idor_task = (
            progress.add_task("[bright_red]IDOR probe — planning…", total=None)
            if idor else None
        )
        source_task = (
            progress.add_task("[bright_green]HTML source — fetching…", total=None)
            if source_scan else None
        )
        param_task = (
            progress.add_task("[bright_blue]Param probe — planning…", total=None)
            if param_scan else None
        )
        sensitive_task = (
            progress.add_task("[red]Sensitive files — planning…", total=None)
            if sensitive_scan else None
        )
        wayback_task = (
            progress.add_task("[cyan]Wayback CDX — planning…", total=None)
            if wayback_scan else None
        )
        broken_task = (
            progress.add_task("[bright_yellow]Broken links — planning…", total=None)
            if broken_links else None
        )
        api_fuzz_task = (
            progress.add_task("[bright_cyan]API schema fuzz — planning…", total=None)
            if api_fuzz else None
        )
        zero_day_task = (
            progress.add_task("[bold white]Zero-Day Hunter — planning…", total=None)
            if zero_day else None
        )
        oauth_task = (
            progress.add_task("[bold bright_blue]OAuth / social — planning…", total=None)
            if playtika_bounty else None
        )

        def _make_plan(task_id, label: str):
            def _fn(total: int) -> None:
                progress.update(task_id, total=max(total, 1), description=label.format(total=total))
            return _fn

        def _make_advance(task_id):
            def _fn() -> None:
                progress.advance(task_id)
            return _fn

        secret_on_plan = _make_plan(secret_task, "[magenta]Secret scan ({total} sources)")
        secret_on_advance = _make_advance(secret_task)

        sub_on_plan = _make_plan(sub_task, "[green]Subdomain probe ({total} hosts)") if sub_task is not None else None
        sub_on_advance = _make_advance(sub_task) if sub_task is not None else None

        xss_on_plan = _make_plan(xss_task, "[red]XSS probe ({total} probes)") if xss_task is not None else None
        xss_on_advance = _make_advance(xss_task) if xss_task is not None else None

        cloud_on_plan = _make_plan(cloud_task, "[blue]Cloud probe ({total} candidates)") if cloud_task is not None else None
        cloud_on_advance = _make_advance(cloud_task) if cloud_task is not None else None

        path_on_plan = _make_plan(path_task, "[yellow]Path bruter ({total} paths)") if path_task is not None else None
        path_on_advance = _make_advance(path_task) if path_task is not None else None

        port_on_plan = _make_plan(port_task, "[bright_magenta]Port scan ({total} ports)") if port_task is not None else None
        port_on_advance = _make_advance(port_task) if port_task is not None else None

        js_on_plan = _make_plan(js_task, "[bright_cyan]JS deep analysis ({total} assets)") if js_task is not None else None
        js_on_advance = _make_advance(js_task) if js_task is not None else None

        idor_on_plan = _make_plan(idor_task, "[bright_red]IDOR probe ({total} requests)") if idor_task is not None else None
        idor_on_advance = _make_advance(idor_task) if idor_task is not None else None

        source_on_plan = _make_plan(source_task, "[bright_green]HTML source ({total} steps)") if source_task is not None else None
        source_on_advance = _make_advance(source_task) if source_task is not None else None

        param_on_plan = _make_plan(param_task, "[bright_blue]Param probe ({total} requests)") if param_task is not None else None
        param_on_advance = _make_advance(param_task) if param_task is not None else None

        sens_on_plan = _make_plan(sensitive_task, "[red]Sensitive files ({total} paths)") if sensitive_task is not None else None
        sens_on_advance = _make_advance(sensitive_task) if sensitive_task is not None else None

        wb_on_plan = _make_plan(wayback_task, "[cyan]Wayback ({total} steps)") if wayback_task is not None else None
        wb_on_advance = _make_advance(wayback_task) if wayback_task is not None else None

        broken_on_plan = (
            _make_plan(broken_task, "[bright_yellow]Broken links ({total} checks)")
            if broken_task is not None
            else None
        )
        broken_on_advance = _make_advance(broken_task) if broken_task is not None else None

        api_fuzz_on_plan = (
            _make_plan(api_fuzz_task, "[bright_cyan]API schema fuzz ({total} steps)")
            if api_fuzz_task is not None
            else None
        )
        api_fuzz_on_advance = _make_advance(api_fuzz_task) if api_fuzz_task is not None else None

        zero_day_on_plan = (
            _make_plan(zero_day_task, "[bold white]Zero-Day Hunter ({total} steps)")
            if zero_day_task is not None
            else None
        )
        zero_day_on_advance = (
            _make_advance(zero_day_task) if zero_day_task is not None else None
        )
        oauth_on_plan = (
            _make_plan(oauth_task, "[bright_blue]OAuth / social bounty ({total} steps)")
            if oauth_task is not None
            else None
        )
        oauth_on_advance = _make_advance(oauth_task) if oauth_task is not None else None

        if wayback_scan:
            try:
                wbs = WaybackScanner(evasion=evasion)
                wayback_rows, wayback_hist = await asyncio.wait_for(
                    wbs.scan(
                        url, on_plan=wb_on_plan, on_advance=wb_on_advance
                    ),
                    timeout=WAYBACK_PRE_GATHER_WALL_CLOCK_SEC,
                )
                if wayback_task is not None:
                    progress.update(wayback_task, description="[cyan]Wayback complete")
            except asyncio.TimeoutError:
                wayback_err = (
                    f"Wayback CDX phase exceeded {WAYBACK_PRE_GATHER_WALL_CLOCK_SEC:.0f}s; "
                    "skipped (path merge from history disabled for this run)."
                )
                wayback_rows, wayback_hist = [], []
                if wayback_task is not None:
                    progress.update(wayback_task, description="[yellow]Wayback timed out")
            except Exception as exc:
                wayback_err = str(exc)
                wayback_rows, wayback_hist = [], []
                if wayback_task is not None:
                    progress.update(wayback_task, description="[red]Wayback failed")

        if wayback_scan and brute and wayback_hist:
            host = urlparse(url if "://" in url else f"https://{url}").hostname or ""
            if host:
                wayback_seed_pairs = WaybackScanner.seed_paths_from_history(
                    wayback_hist, host, max_paths=400
                )

        async def _wrap(
            coro,
            task_id,
            ok_label: str,
            fail_label: str,
        ) -> tuple[list[dict], str | None]:
            try:
                data = await coro
                if task_id is not None:
                    progress.update(task_id, description=ok_label)
                return data, None
            except Exception as exc:
                if task_id is not None:
                    progress.update(task_id, description=fail_label)
                return [], str(exc)

        async def do_secrets():
            return await _wrap(
                SecretFinder(extra_headers=extra_headers, evasion=evasion).find(
                    url, on_plan=secret_on_plan, on_advance=secret_on_advance
                ),
                secret_task,
                "[magenta]Secret scan complete",
                "[red]Secret scan failed",
            )

        async def do_subdomain():
            return await _wrap(
                SubdomainScanner(evasion=evasion).scan(
                    url, on_plan=sub_on_plan, on_advance=sub_on_advance
                ),
                sub_task,
                "[green]Subdomain probe complete",
                "[red]Subdomain probe failed",
            )

        async def do_xss():
            scanner = XSSScanner(
                extra_payloads=extra_xss_payloads,
                extra_headers=extra_headers,
                evasion=evasion,
                obfuscate_payloads=obfuscate,
            )
            return await _wrap(
                scanner.scan(url, on_plan=xss_on_plan, on_advance=xss_on_advance),
                xss_task,
                "[red]XSS probe complete",
                "[red]XSS probe failed",
            )

        async def do_cloud():
            return await _wrap(
                CloudScanner(evasion=evasion).scan(
                    url, on_plan=cloud_on_plan, on_advance=cloud_on_advance
                ),
                cloud_task,
                "[blue]Cloud probe complete",
                "[red]Cloud probe failed",
            )

        async def do_paths():
            return await _wrap(
                PathBruter(evasion=evasion).scan(
                    url,
                    on_plan=path_on_plan,
                    on_advance=path_on_advance,
                    recursive=recursive_paths,
                    extension_fuzz=extension_fuzz,
                    extra_path_pairs=wayback_seed_pairs or None,
                ),
                path_task,
                "[yellow]Path bruter complete",
                "[red]Path bruter failed",
            )

        async def do_ports():
            return await _wrap(
                PortScanner(
                    evasion=evasion,
                    use_nmap_stealth=nmap_stealth_ports,
                    nmap_spoof_mac=nmap_spoof_mac,
                ).scan(
                    url, on_plan=port_on_plan, on_advance=port_on_advance
                ),
                port_task,
                "[bright_magenta]Port scan complete",
                "[red]Port scan failed",
            )

        async def do_js():
            js_cap = 120 if deep_scan else 60
            return await _wrap(
                JSAnalyzer(
                    extra_headers=extra_headers,
                    evasion=evasion,
                    max_scripts=js_cap,
                ).analyze(
                    url, on_plan=js_on_plan, on_advance=js_on_advance
                ),
                js_task,
                "[bright_cyan]JS deep analysis complete",
                "[red]JS deep analysis failed",
            )

        async def do_idor():
            return await _wrap(
                IDORScanner(extra_headers=extra_headers, evasion=evasion).scan(
                    url, on_plan=idor_on_plan, on_advance=idor_on_advance
                ),
                idor_task,
                "[bright_red]IDOR probe complete",
                "[red]IDOR probe failed",
            )

        async def do_html_source():
            return await _wrap(
                HtmlSourceScanner().scan(
                    url,
                    on_plan=source_on_plan,
                    on_advance=source_on_advance,
                    evasion=evasion,
                ),
                source_task,
                "[bright_green]HTML source scan complete",
                "[red]HTML source scan failed",
            )

        async def do_param_probe():
            return await _wrap(
                ParamProbeScanner(evasion=evasion).scan(
                    url, on_plan=param_on_plan, on_advance=param_on_advance
                ),
                param_task,
                "[bright_blue]Param probe complete",
                "[red]Param probe failed",
            )

        async def do_sensitive():
            return await _wrap(
                SensitiveFileHunter(evasion=evasion).scan(
                    url, on_plan=sens_on_plan, on_advance=sens_on_advance
                ),
                sensitive_task,
                "[red]Sensitive file hunter complete",
                "[red]Sensitive file hunter failed",
            )

        async def do_broken_links():
            return await _wrap(
                BrokenLinkScanner().scan(
                    url,
                    extra_headers=extra_headers,
                    evasion=evasion,
                    on_plan=broken_on_plan,
                    on_advance=broken_on_advance,
                ),
                broken_task,
                "[bright_yellow]Broken link check complete",
                "[red]Broken link check failed",
            )

        async def do_api_fuzz():
            try:
                data = await APISchemaFuzzer(
                    extra_headers=extra_headers,
                    evasion=evasion,
                ).scan(
                    url,
                    on_plan=api_fuzz_on_plan,
                    on_advance=api_fuzz_on_advance,
                )
                if api_fuzz_task is not None:
                    progress.update(
                        api_fuzz_task,
                        description="[bright_cyan]API schema fuzz complete",
                    )
                return data, None
            except Exception as exc:
                if api_fuzz_task is not None:
                    progress.update(
                        api_fuzz_task,
                        description="[red]API schema fuzz failed",
                    )
                return (
                    {
                        "discovered": [],
                        "idor": [],
                        "injection": [],
                        "graphql": [],
                    },
                    str(exc),
                )

        async def do_zero_day():
            try:
                rows, zerr = await ZeroDayHunter(
                    extra_headers=extra_headers,
                    evasion=evasion,
                ).scan(
                    url,
                    on_plan=zero_day_on_plan,
                    on_advance=zero_day_on_advance,
                )
                if zero_day_task is not None:
                    progress.update(
                        zero_day_task,
                        description="[bold white]Zero-Day Hunter complete",
                    )
                return rows, zerr
            except Exception as exc:
                if zero_day_task is not None:
                    progress.update(
                        zero_day_task,
                        description="[red]Zero-Day Hunter failed",
                    )
                return [], str(exc)

        async def do_oauth_social():
            try:
                rows, oerr = await OAuthSocialScanner(
                    evasion=evasion,
                    extra_headers=extra_headers,
                ).scan(
                    url,
                    on_plan=oauth_on_plan,
                    on_advance=oauth_on_advance,
                )
                if oauth_task is not None:
                    progress.update(
                        oauth_task,
                        description="[bright_blue]OAuth / social (bounty) complete",
                    )
                return rows, oerr
            except Exception as exc:
                if oauth_task is not None:
                    progress.update(
                        oauth_task,
                        description="[red]OAuth / social (bounty) failed",
                    )
                return [], str(exc)

        job_specs: list[tuple[str, callable]] = [("secrets", do_secrets)]
        if js:
            job_specs.append(("js", do_js))
        if subdomain:
            job_specs.append(("subdomain", do_subdomain))
        if xss:
            job_specs.append(("xss", do_xss))
        if idor:
            job_specs.append(("idor", do_idor))
        if cloud:
            job_specs.append(("cloud", do_cloud))
        if brute:
            job_specs.append(("paths", do_paths))
        if port:
            job_specs.append(("ports", do_ports))
        if source_scan:
            job_specs.append(("html_source", do_html_source))
        if param_scan:
            job_specs.append(("param_probe", do_param_probe))
        if sensitive_scan:
            job_specs.append(("sensitive_files", do_sensitive))
        if broken_links:
            job_specs.append(("broken_links", do_broken_links))
        if api_fuzz:
            job_specs.append(("api_fuzz", do_api_fuzz))
        if zero_day:
            job_specs.append(("zero_day", do_zero_day))
        if playtika_bounty:
            job_specs.append(("oauth_social", do_oauth_social))

        async def _timed_scan_module(module_name: str, factory: Any) -> Any:
            label = _MODULE_PROGRESS_LABEL.get(module_name, module_name.replace("_", " "))
            budget = float(MODULE_TIMEOUT_SECONDS.get(module_name, 3600.0))
            print(f"[MODULE] START {label}", flush=True)
            try:
                out = await asyncio.wait_for(factory(), timeout=budget)
            except asyncio.TimeoutError:
                print(
                    f"[MODULE] END {label} (timeout after {budget:.0f}s)",
                    flush=True,
                )
                return _module_timeout_return(module_name)
            print(f"[MODULE] END {label}", flush=True)
            return out

        outputs = await asyncio.gather(
            *(_timed_scan_module(name, factory) for name, factory in job_specs)
        )
        results_by_name = {name: out for (name, _), out in zip(job_specs, outputs)}

        findings, secret_err = results_by_name.get("secrets", ([], None))
        js_rows, js_err = results_by_name.get("js", ([], None))
        sub_rows, sub_err = results_by_name.get("subdomain", ([], None))
        xss_rows, xss_err = results_by_name.get("xss", ([], None))
        idor_rows, idor_err = results_by_name.get("idor", ([], None))
        cloud_rows, cloud_err = results_by_name.get("cloud", ([], None))
        path_rows, path_err = results_by_name.get("paths", ([], None))
        port_rows, port_err = results_by_name.get("ports", ([], None))
        html_rows, html_err = results_by_name.get("html_source", ([], None))
        param_rows, param_err = results_by_name.get("param_probe", ([], None))
        sensitive_rows, sensitive_err = results_by_name.get("sensitive_files", ([], None))
        broken_rows, broken_err = results_by_name.get("broken_links", ([], None))
        api_fuzz_bundle, api_fuzz_err = results_by_name.get(
            "api_fuzz",
            (
                {
                    "discovered": [],
                    "idor": [],
                    "injection": [],
                    "graphql": [],
                },
                None,
            ),
        )
        zero_day_rows, zero_day_err = results_by_name.get("zero_day", ([], None))
        oauth_rows, oauth_err = results_by_name.get("oauth_social", ([], None))

        if logic_scan:
            logic_rows = harvest_logic_signals(url, js_rows, path_rows, param_rows)

    ai_mutator_rows: list[dict] = []
    ai_mutator_err: str | None = None
    ai_mutator_slots = 0
    ai_mutator_note: str | None = None
    if ai_mutate:

        def _do_ai_mutate() -> tuple[list[dict], str | None, int]:
            slots = discovered_param_slots(url, param_rows, xss_rows)
            if not slots:
                return (
                    [],
                    "no discovered parameter slots (use --params / --xss or ?query on --url)",
                    0,
                )
            bundles, err = mutate_all_discovered_params(slots, mutate_kind)
            return flatten_mutator_bundles(bundles), err, len(slots)

        ai_mutator_rows, ai_mutator_err, ai_mutator_slots = await asyncio.to_thread(
            _do_ai_mutate
        )
        if ai_mutator_slots:
            ai_mutator_note = (
                f"{ai_mutator_slots} slot(s) · {len(ai_mutator_rows)} variant row(s)"
            )

    nuclei_rows: list[dict] = []
    nuclei_err: str | None = None
    if nuclei:
        nuclei_rows, nuclei_err = await asyncio.to_thread(run_nuclei_scan, url)

    infiltration_bundle: dict[str, Any] = {}
    infiltration_err: str | None = None
    if infiltrate:
        base_url = url if "://" in url else f"https://{url}"
        print("[MODULE] START Infiltration", flush=True)
        try:
            sql_threshold = 1.65 if sqli else 2.2
            infiltration_bundle = await asyncio.wait_for(
                SmartInfiltrationEngine(
                    evasion,
                    sql_delay_threshold_sec=sql_threshold,
                    extended_403_bypass=bypass_403,
                    obfuscate_payloads=obfuscate,
                ).run(
                    target_url=base_url,
                    path_rows=path_rows,
                    sensitive_rows=sensitive_rows,
                    param_rows=param_rows,
                    port_rows=port_rows,
                    extra_headers=extra_headers,
                ),
                timeout=INFILTRATION_MODULE_TIMEOUT_SEC,
            )
        except asyncio.TimeoutError:
            infiltration_err = (
                f"Infiltration timed out after {INFILTRATION_MODULE_TIMEOUT_SEC:.0f}s"
            )
            infiltration_bundle = {}
        except Exception as exc:
            infiltration_err = str(exc)
            infiltration_bundle = {}
        print("[MODULE] END Infiltration", flush=True)

    if os.environ.get("OMNISCAN_DASHBOARD"):
        _dashboard_stream_loot_results(
            target_url=url,
            findings=findings,
            sensitive_rows=sensitive_rows,
            path_rows=path_rows,
            param_rows=param_rows,
            api_fuzz_bundle=api_fuzz_bundle,
            zero_day_rows=zero_day_rows,
            oauth_rows=oauth_rows,
            js_rows=js_rows,
            infiltration_bundle=infiltration_bundle,
            nuclei_rows=nuclei_rows,
        )
        _dashboard_emit({"event": "scan_stage", "stage": "post_scan", "target_url": url})

    exit_code = 0

    console.rule("[bold magenta]Secrets[/bold magenta]", style="magenta")
    if secret_err:
        console.print(f"[red]Secret scan error:[/red] {escape(secret_err)}")
        exit_code = 1
    elif not findings:
        console.print(
            "[yellow]No secret-pattern matches in inline or external scripts.[/yellow]"
        )
    else:
        console.print(f"[bold]Findings:[/bold] {len(findings)}   {_severity_summary(findings)}\n")
        console.print(_findings_table(findings))

    if js:
        console.print()
        console.rule("[bold bright_cyan]Deep JS analysis[/bold bright_cyan]", style="bright_cyan")
        if js_err:
            console.print(f"[red]JS deep analysis error:[/red] {escape(js_err)}")
            if exit_code == 0:
                exit_code = 1
        elif not js_rows:
            console.print("[yellow]No endpoints or secrets recovered from linked JS assets.[/yellow]")
        else:
            endpoint_kinds = {
                "endpoint_url",
                "endpoint_api_path",
                "fetch_call",
                "axios_call",
                "xhr_open",
                "websocket_url",
                "dynamic_import",
                "sourcemap_ref",
                "route_path_string",
                "base_url_concat",
                "relative_api_path",
                "firebase_realtime_url",
                "gcp_storage_url",
                "aws_s3_url",
                "amazonaws_generic",
                "staging_dev_host",
            }
            ep_n = sum(1 for r in js_rows if r.get("type") in endpoint_kinds)
            se_n = len(js_rows) - ep_n
            console.print(
                f"[bold]Endpoints:[/bold] [bright_cyan]{ep_n}[/bright_cyan]  "
                f"[bold]Secret hits:[/bold] [red]{se_n}[/red]\n"
            )
            console.print(_js_table(js_rows))

    if subdomain:
        console.print()
        console.rule("[bold green]Subdomains[/bold green]", style="green")
        if sub_err:
            console.print(f"[red]Subdomain scan error:[/red] {escape(sub_err)}")
            if exit_code == 0:
                exit_code = 1
        else:
            alive_n = sum(1 for r in sub_rows if r["alive"])
            console.print(
                f"[bold]Probed[/bold] {len(sub_rows)} · "
                f"[bold green]{alive_n} responded[/bold green]\n"
            )
            console.print(_subdomain_table(sub_rows))

    if xss:
        console.print()
        console.rule("[bold red]Reflected XSS[/bold red]", style="red")
        if xss_err:
            console.print(f"[red]XSS scan error:[/red] {escape(xss_err)}")
            if exit_code == 0:
                exit_code = 1
        elif not xss_rows:
            console.print(
                "[yellow]No reflected payloads observed on discovered injection points.[/yellow]"
            )
        else:
            console.print(
                f"[bold]Reflected signals:[/bold] [bold red]{len(xss_rows)}[/bold red]\n"
            )
            console.print(_xss_table(xss_rows))

    if xss_mutations:
        console.print()
        console.rule(
            "[bold magenta]AI-guided XSS mutations (WAF bypass)[/bold magenta]",
            style="magenta",
        )
        console.print(
            f"[bold]Total mutations:[/bold] [magenta]{len(xss_mutations)}[/magenta]\n"
        )
        console.print(_xss_mutations_table(xss_mutations))

    if idor:
        console.print()
        console.rule("[bold bright_red]IDOR (horizontal)[/bold bright_red]", style="bright_red")
        if idor_err:
            console.print(f"[red]IDOR scan error:[/red] {escape(idor_err)}")
            if exit_code == 0:
                exit_code = 1
        elif not idor_rows:
            console.print(
                "[yellow]No numeric IDs found in URL parameters or path segments, "
                "or all probed neighbouring IDs returned matching content.[/yellow]\n"
                "[dim]Tip: pass a URL like "
                "`https://api.example.com/users?id=42` or `.../orders/42` to exercise this scanner.[/dim]"
            )
        else:
            crit_n = sum(1 for r in idor_rows if r.get("severity") == "Critical")
            high_n = sum(1 for r in idor_rows if r.get("severity") == "High")
            info_n = sum(1 for r in idor_rows if r.get("severity") == "Info")
            console.print(
                f"[bold]IDOR findings:[/bold] "
                f"[bold bright_red]Critical={crit_n}[/bold bright_red]  "
                f"[red]High={high_n}[/red]  "
                f"[dim]Info={info_n}[/dim]  "
                f"Total=[bold]{len(idor_rows)}[/bold]\n"
            )
            console.print(_idor_table(idor_rows))

    if logic_scan:
        console.print()
        console.rule(
            "[bold bright_yellow]Logic scan (harvested endpoints)[/bold bright_yellow]",
            style="bright_yellow",
        )
        if not logic_rows:
            console.print(
                "[yellow]No IDOR- or price-shaped URLs in the current harvest.[/yellow] "
                "[dim]Combine --logic-scan with --js, --brute, and/or --params.[/dim]"
            )
        else:
            hi = sum(1 for r in logic_rows if r.get("severity") == "High")
            console.print(
                f"[bold]Signals:[/bold] {len(logic_rows)}  "
                f"[bold red]High={hi}[/bold red]\n"
            )
            console.print(_logic_scan_table(logic_rows))

    if ai_mutate:
        console.print()
        console.rule("[bold magenta]AI-Mutator (per parameter)[/bold magenta]", style="magenta")
        console.print(
            f"[dim]Kind hint:[/dim] {escape(mutate_kind)}  ·  "
            f"[dim]Slots:[/dim] {ai_mutator_slots}  ·  "
            f"[dim]Variant rows:[/dim] {len(ai_mutator_rows)}\n"
        )
        if ai_mutator_note:
            console.print(f"[dim]{escape(ai_mutator_note)}[/dim]\n")
        if ai_mutator_err:
            console.print(f"[yellow]LLM / transport:[/yellow] {escape(ai_mutator_err)}")
        if not ai_mutator_rows:
            console.print(
                "[yellow]No variants produced — discover parameters with "
                "[cyan]--params[/cyan] / [cyan]--xss[/cyan] or add a [cyan]?query[/cyan] to --url.[/yellow]"
            )
        else:
            console.print(_ai_mutator_table(ai_mutator_rows, llm_note=ai_mutator_err))

    if wayback_scan:
        console.print()
        console.rule("[bold cyan]Wayback Machine[/bold cyan]", style="cyan")
        if wayback_err:
            console.print(f"[red]Wayback error:[/red] {escape(wayback_err)}")
            if exit_code == 0:
                exit_code = 1
        elif not wayback_rows:
            console.print(
                "[yellow]No live 200/401/403 hits from historical URLs "
                "(or CDX returned nothing).[/yellow]"
            )
            if wayback_hist:
                console.print(
                    f"[dim]CDX returned {len(wayback_hist)} URL(s); "
                    "none matched the live filter.[/dim]"
                )
        else:
            n_med = sum(1 for r in wayback_rows if r.get("severity") == "Medium")
            console.print(
                f"[bold]Live signals:[/bold] [cyan]{len(wayback_rows)}[/cyan]  "
                f"[dim](HTTP 200 → Medium: {n_med})[/dim]\n"
            )
            console.print(_wayback_table(wayback_rows))

    if sensitive_scan:
        console.print()
        console.rule("[bold red]Sensitive file hunter[/bold red]", style="red")
        if sensitive_err:
            console.print(f"[red]Sensitive file hunter error:[/red] {escape(sensitive_err)}")
            if exit_code == 0:
                exit_code = 1
        elif not sensitive_rows:
            console.print(
                "[yellow]No interesting responses on the sensitive-file wordlist.[/yellow]"
            )
        else:
            console.print(
                f"[bold]Hits:[/bold] [red]{len(sensitive_rows)}[/red]\n"
            )
            console.print(_sensitive_file_table(sensitive_rows))

    if source_scan:
        console.print()
        console.rule(
            "[bold bright_green]HTML / comment source[/bold bright_green]",
            style="bright_green",
        )
        if html_err:
            console.print(f"[red]HTML source scan error:[/red] {escape(html_err)}")
            if exit_code == 0:
                exit_code = 1
        elif not html_rows:
            console.print(
                "[yellow]No HTML comments or notable attributes recovered from the page.[/yellow]"
            )
        else:
            console.print(
                f"[bold]Source hints:[/bold] [bright_green]{len(html_rows)}[/bright_green]\n"
            )
            console.print(_html_source_table(html_rows))

    if broken_links:
        console.print()
        console.rule(
            "[bold bright_yellow]Broken links / takeover candidates[/bold bright_yellow]",
            style="yellow",
        )
        if broken_err:
            console.print(f"[red]Broken link scan error:[/red] {escape(broken_err)}")
            if exit_code == 0:
                exit_code = 1
        elif not broken_rows:
            console.print(
                "[yellow]No external takeover signals (or no external links in source).[/yellow]"
            )
        else:
            console.print(
                f"[bold]Potential takeover flags:[/bold] [bright_yellow]{len(broken_rows)}[/bright_yellow]\n"
            )
            console.print(_broken_links_table(broken_rows))

    if api_fuzz:
        console.print()
        console.rule(
            "[bold bright_cyan]API schema fuzzer (Swagger / OpenAPI / GraphQL)[/bold bright_cyan]",
            style="bright_cyan",
        )
        if api_fuzz_err:
            console.print(f"[red]API schema fuzz error:[/red] {escape(api_fuzz_err)}")
            if exit_code == 0:
                exit_code = 1
        else:
            disc = api_fuzz_bundle.get("discovered") or []
            gql = api_fuzz_bundle.get("graphql") or []
            aid = api_fuzz_bundle.get("idor") or []
            inj = api_fuzz_bundle.get("injection") or []
            if not disc and not gql and not aid and not inj:
                console.print(
                    "[yellow]No API documentation or fuzz signals found "
                    "(try authenticated --headers if docs are protected).[/yellow]"
                )
            else:
                if disc:
                    console.print(
                        f"[bold]Specs discovered:[/bold] [bright_cyan]{len(disc)}[/bright_cyan]\n"
                    )
                    console.print(_api_spec_discovered_table(disc))
                    console.print()
                if gql:
                    console.print(f"[bold]GraphQL:[/bold] {len(gql)} signal(s)\n")
                    for i, r in enumerate(gql, 1):
                        console.print(
                            f"  [cyan]{i}.[/cyan] {escape(str(r.get('note', '')))}  "
                            f"[dim]{escape(str(r.get('url', '')))}[/dim]"
                        )
                    console.print()
                if aid:
                    console.print(
                        f"[bold]IDOR (from schema):[/bold] [red]{len(aid)}[/red] finding(s)\n"
                    )
                    console.print(_idor_table(aid))
                    console.print()
                if inj:
                    console.print(
                        f"[bold]Injection probes:[/bold] [red]{len(inj)}[/red] signal(s)\n"
                    )
                    console.print(_api_injection_table(inj))

    if param_scan:
        console.print()
        console.rule(
            "[bold bright_blue]Hidden parameters (GET / POST / JSON)[/bold bright_blue]",
            style="bright_blue",
        )
        if param_err:
            console.print(f"[red]Parameter probe error:[/red] {escape(param_err)}")
            if exit_code == 0:
                exit_code = 1
        elif not param_rows:
            console.print(
                "[yellow]No parameter-induced response changes vs baseline.[/yellow]"
            )
        else:
            med_n = sum(1 for r in param_rows if r.get("severity") == "Medium")
            console.print(
                f"[bold]Signals:[/bold] [bright_blue]{len(param_rows)}[/bright_blue]  "
                f"[dim](Medium={med_n})[/dim]\n"
            )
            console.print(_param_probe_table(param_rows))

    if zero_day:
        console.print()
        console.rule(
            "[bold white]Zero-Day Hunter (predictive logic-flaw fuzz)[/bold white]",
            style="white",
        )
        if zero_day_err:
            console.print(f"[red]Zero-Day Hunter:[/red] {escape(zero_day_err)}")
            if exit_code == 0:
                exit_code = 1
        elif not zero_day_rows:
            console.print("[yellow]No harvest rows (unexpected if HWID passed).[/yellow]")
        else:
            fuzz_n = sum(1 for r in zero_day_rows if r.get("type") == "fuzz_hit")
            console.print(
                f"[bold]Rows:[/bold] {len(zero_day_rows)}  "
                f"[dim](fuzz signals={fuzz_n})[/dim]\n"
            )
            console.print(_zero_day_table(zero_day_rows))

    if playtika_bounty:
        console.print()
        console.rule(
            "[bold bright_blue]OAuth / OIDC / social login (Playtika bounty)[/bold bright_blue]",
            style="bright_blue",
        )
        if oauth_err:
            console.print(f"[red]OAuth / social scanner:[/red] {escape(oauth_err)}")
            if exit_code == 0:
                exit_code = 1
        elif not oauth_rows:
            console.print(
                "[yellow]No OAuth/OIDC/social signals this pass "
                "(or target blocked probes).[/yellow]"
            )
        else:
            hi = sum(1 for r in oauth_rows if r.get("severity") == "High")
            console.print(
                f"[bold]Signals:[/bold] [bright_blue]{len(oauth_rows)}[/bright_blue]  "
                f"[dim](High={hi})[/dim]\n"
            )
            console.print(_oauth_social_table(oauth_rows))

    if cloud:
        console.print()
        console.rule("[bold blue]Cloud exposure[/bold blue]", style="blue")
        if cloud_err:
            console.print(f"[red]Cloud scan error:[/red] {escape(cloud_err)}")
            if exit_code == 0:
                exit_code = 1
        elif not cloud_rows:
            console.print(
                "[yellow]No candidate buckets/containers responded positively.[/yellow]"
            )
        else:
            console.print(
                f"[bold]Cloud findings:[/bold] [bold blue]{len(cloud_rows)}[/bold blue]\n"
            )
            console.print(_cloud_table(cloud_rows))

    if brute:
        console.print()
        console.rule("[bold yellow]Sensitive paths[/bold yellow]", style="yellow")
        if path_err:
            console.print(f"[red]Path scan error:[/red] {escape(path_err)}")
            if exit_code == 0:
                exit_code = 1
        elif not path_rows:
            console.print(
                "[yellow]No interesting status codes on the configured wordlist.[/yellow]"
            )
        else:
            console.print(
                f"[bold]Path findings:[/bold] [bold yellow]{len(path_rows)}[/bold yellow]\n"
            )
            console.print(_path_table(path_rows))

    if port:
        console.print()
        console.rule("[bold bright_magenta]Open ports[/bold bright_magenta]", style="bright_magenta")
        if port_err:
            console.print(f"[red]Port scan error:[/red] {escape(port_err)}")
            if exit_code == 0:
                exit_code = 1
        elif not port_rows:
            console.print("[yellow]No probed ports responded.[/yellow]")
        else:
            n_open = sum(
                1 for r in port_rows if str(r.get("state", "")) == "open"
            )
            n_dec = sum(
                1 for r in port_rows if str(r.get("state", "")) == "decision"
            )
            extras = (
                f"  ·  [dim]{n_dec} decision-engine follow-up(s)[/dim]"
                if n_dec
                else ""
            )
            console.print(
                f"[bold]Open TCP ports:[/bold] [bold bright_magenta]{n_open}[/bold bright_magenta]"
                f"{extras}\n"
            )
            console.print(_port_table(port_rows))

    if nuclei:
        console.print()
        console.rule(
            "[bold bright_green]Nuclei (ProjectDiscovery)[/bold bright_green]",
            style="bright_green",
        )
        if nuclei_err and not nuclei_rows:
            console.print(f"[yellow]Nuclei:[/yellow] {escape(nuclei_err)}")
            if exit_code == 0:
                exit_code = 1
        elif not nuclei_rows:
            console.print(
                "[green]Nuclei finished with no template matches on this target.[/green]"
            )
            if nuclei_err:
                console.print(f"[dim]{escape(nuclei_err)}[/dim]")
        else:
            if nuclei_err:
                console.print(f"[dim]{escape(nuclei_err)}[/dim]\n")
            crit_n = sum(
                1
                for r in nuclei_rows
                if str(r.get("severity", "")).strip().lower() == "critical"
            )
            hi_n = sum(
                1
                for r in nuclei_rows
                if str(r.get("severity", "")).strip().lower() == "high"
            )
            console.print(
                f"[bold]Findings:[/bold] [bright_green]{len(nuclei_rows)}[/bright_green]  "
                f"[dim](Critical={crit_n}  High={hi_n})[/dim]\n"
            )
            console.print(_nuclei_table(nuclei_rows))

    if infiltrate:
        console.print()
        _print_infiltration_section(console, infiltration_bundle, infiltration_err)
        if infiltration_err and exit_code == 0:
            exit_code = 1

    if show_ai:
        console.print()
        _print_ai_section(console, url)

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    _exploit_report = build_json_report(
        target_url=url,
        generated_at=generated_at,
        secret_findings=findings,
        secret_error=secret_err,
        subdomain_rows=sub_rows,
        subdomain_error=sub_err,
        subdomain_enabled=subdomain,
        xss_rows=xss_rows,
        xss_error=xss_err,
        xss_enabled=xss,
        cloud_rows=cloud_rows,
        cloud_error=cloud_err,
        cloud_enabled=cloud,
        path_rows=path_rows,
        path_error=path_err,
        path_enabled=brute,
        port_rows=port_rows,
        port_error=port_err,
        port_enabled=port,
        js_rows=js_rows,
        js_error=js_err,
        js_enabled=js,
        idor_rows=idor_rows,
        idor_error=idor_err,
        idor_enabled=idor,
        wayback_rows=wayback_rows,
        wayback_error=wayback_err,
        wayback_enabled=wayback_scan,
        sensitive_file_rows=sensitive_rows,
        sensitive_file_error=sensitive_err,
        sensitive_file_enabled=sensitive_scan,
        html_source_rows=html_rows,
        html_source_error=html_err,
        html_source_enabled=source_scan,
        broken_link_rows=broken_rows,
        broken_link_error=broken_err,
        broken_link_enabled=broken_links,
        api_fuzz_bundle=api_fuzz_bundle,
        api_fuzz_error=api_fuzz_err,
        api_fuzz_enabled=api_fuzz,
        param_probe_rows=param_rows,
        param_probe_error=param_err,
        param_probe_enabled=param_scan,
        zero_day_rows=zero_day_rows,
        zero_day_error=zero_day_err,
        zero_day_enabled=zero_day,
        oauth_social_rows=oauth_rows,
        oauth_social_error=oauth_err,
        oauth_social_enabled=playtika_bounty,
        infiltration_bundle=infiltration_bundle,
        infiltration_error=infiltration_err,
        infiltration_enabled=infiltrate,
        xss_mutations=xss_mutations,
        include_ai=show_ai,
        logic_scan_rows=logic_rows,
        logic_scan_enabled=logic_scan,
        ai_mutator_rows=ai_mutator_rows,
        ai_mutator_error=ai_mutator_err,
        ai_mutator_input=ai_mutator_note,
        ai_mutator_kind=mutate_kind,
        ai_mutator_enabled=ai_mutate,
        ai_mutator_slots=ai_mutator_slots,
        nuclei_rows=nuclei_rows,
        nuclei_error=nuclei_err,
        nuclei_enabled=nuclei,
    )

    def _emit_exploit_line(msg: str) -> None:
        line = (msg or "").strip()
        if not line:
            return
        console.print(f"[bold cyan]▸[/bold cyan] {escape(line)}")
        _push_dashboard_socket_log(line)

    auto_generate_exploits_after_scan(
        _exploit_report,
        project_root=PROJECT_ROOT,
        max_items=6,
        emit=_emit_exploit_line,
    )

    if save_report or save_pdf:
        console.print()
        save_reports(
            target_url=url,
            generated_at=generated_at,
            secret_findings=findings,
            secret_error=secret_err,
            subdomain_rows=sub_rows,
            subdomain_error=sub_err,
            subdomain_enabled=subdomain,
            xss_rows=xss_rows,
            xss_error=xss_err,
            xss_enabled=xss,
            cloud_rows=cloud_rows,
            cloud_error=cloud_err,
            cloud_enabled=cloud,
            path_rows=path_rows,
            path_error=path_err,
            path_enabled=brute,
            port_rows=port_rows,
            port_error=port_err,
            port_enabled=port,
            js_rows=js_rows,
            js_error=js_err,
            js_enabled=js,
            idor_rows=idor_rows,
            idor_error=idor_err,
            idor_enabled=idor,
            wayback_rows=wayback_rows,
            wayback_error=wayback_err,
            wayback_enabled=wayback_scan,
            sensitive_file_rows=sensitive_rows,
            sensitive_file_error=sensitive_err,
            sensitive_file_enabled=sensitive_scan,
            html_source_rows=html_rows,
            html_source_error=html_err,
            html_source_enabled=source_scan,
            broken_link_rows=broken_rows,
            broken_link_error=broken_err,
            broken_link_enabled=broken_links,
            api_fuzz_bundle=api_fuzz_bundle,
            api_fuzz_error=api_fuzz_err,
            api_fuzz_enabled=api_fuzz,
            param_probe_rows=param_rows,
            param_probe_error=param_err,
            param_probe_enabled=param_scan,
            zero_day_rows=zero_day_rows,
            zero_day_error=zero_day_err,
            zero_day_enabled=zero_day,
            oauth_social_rows=oauth_rows,
            oauth_social_error=oauth_err,
            oauth_social_enabled=playtika_bounty,
            infiltration_bundle=infiltration_bundle,
            infiltration_error=infiltration_err,
            infiltration_enabled=infiltrate,
            xss_mutations=xss_mutations,
            include_ai=show_ai,
            logic_scan_rows=logic_rows,
            logic_scan_enabled=logic_scan,
            ai_mutator_rows=ai_mutator_rows,
            ai_mutator_error=ai_mutator_err,
            ai_mutator_input=ai_mutator_note,
            ai_mutator_kind=mutate_kind,
            ai_mutator_enabled=ai_mutate,
            ai_mutator_slots=ai_mutator_slots,
            nuclei_rows=nuclei_rows,
            nuclei_error=nuclei_err,
            nuclei_enabled=nuclei,
            save_pdf=save_pdf,
            reports_dir=REPORTS_DIR,
            console=console,
        )

    console.print()
    console.print(
        Text(
            f"Developer: {DEVELOPER}  |  OmniScan-AI v{APP_VERSION} ({APP_EDITION})",
            style="dim italic",
        )
    )

    if os.environ.get("OMNISCAN_DASHBOARD"):
        _emit_dashboard_scan_complete(
            target_url=url,
            exit_code=exit_code,
            findings=findings,
            sub_rows=sub_rows,
            xss_rows=xss_rows,
            idor_rows=idor_rows,
            cloud_rows=cloud_rows,
            path_rows=path_rows,
            port_rows=port_rows,
            js_rows=js_rows,
            param_rows=param_rows,
            sensitive_rows=sensitive_rows,
            broken_rows=broken_rows,
            api_fuzz_bundle=api_fuzz_bundle,
            zero_day_rows=zero_day_rows,
            oauth_rows=oauth_rows,
            infiltration_bundle=infiltration_bundle,
            xss_mutations=xss_mutations,
            detected_waf=getattr(evasion, "detected_waf", "none") or "none",
            jitter_multiplier=float(getattr(evasion, "jitter_multiplier", 1.0) or 1.0),
            nuclei_rows=nuclei_rows,
        )

    return exit_code


def main() -> None:
    if os.environ.get("OMNISCAN_DASHBOARD"):
        _install_dashboard_stream_tees()
        console = Console(force_terminal=True, width=120, legacy_windows=False)
    else:
        console = Console()
    if not os.environ.get("OMNISCAN_DASHBOARD"):
        _banner(console)
        console.print()
    else:
        console.print(
            f"[bold green]OmniScan-AI[/bold green] [dim]dashboard worker[/dim] "
            f"[cyan]v{APP_VERSION} ({APP_EDITION})[/cyan]\n"
        )

    parser = _build_parser()
    args = parser.parse_args()

    if args.gen_shell:
        from modules.shell_generator import print_shell_policy

        print_shell_policy(console)
        raise SystemExit(0)

    if args.bypass_403:
        args.infiltrate = True

    if os.environ.get("OMINSCAN_FORCE_DIRECT", "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    ):
        args.tor = False
    if not args.tor:
        apply_direct_http_environment()

    extra_headers = _parse_headers_arg(args.headers, console)
    if args.playtika_bounty:
        os.environ["OMNISCAN_PLAYTIKA_BOUNTY"] = "1"
        extra_headers["X-Bug-Bounty"] = "True"

    if args.stealth and args.no_smart_evasion:
        console.print(
            "[yellow]Tip:[/yellow] [bold]--stealth[/bold] is most effective without "
            "[bold]--no-smart-evasion[/bold] (User-Agent / Sec-Fetch rotation).\n"
        )
    if args.nmap_spoof_mac:
        from modules.nmap_stealth import spoof_mac_supported_hint

        console.print(f"[dim]{spoof_mac_supported_hint()}[/dim]\n")

    if args.tor:
        try:
            import aiohttp_socks  # noqa: F401
        except ImportError:
            console.print(
                "[red]--tor requires `aiohttp-socks`.[/red] "
                "[dim]pip install aiohttp-socks[/dim]"
            )
            raise SystemExit(1) from None
        try:
            import python_socks  # noqa: F401
        except ImportError:
            console.print(
                "[red]--tor requires `python-socks` (for --port via SOCKS).[/red] "
                "[dim]pip install 'python-socks[asyncio]'[/dim]"
            )
            raise SystemExit(1) from None

    jitter_on = (
        args.jitter or args.tor or args.stealth or args.playtika_bounty
    ) and not args.no_jitter
    evasion = EvasionProfile(
        use_tor=args.tor,
        tor_socks_url=(args.socks5 or "socks5h://127.0.0.1:9050"),
        jitter_enabled=jitter_on,
        smart_evasion=not args.no_smart_evasion,
        waf_probe=not args.no_waf_probe,
        no_jitter=args.no_jitter,
        stealth_mode=args.stealth,
    )
    if args.playtika_bounty and not args.no_jitter:
        evasion.jitter_base_sec = max(float(evasion.jitter_base_sec), 0.52)
        evasion.jitter_max_extra_sec = max(float(evasion.jitter_max_extra_sec), 0.9)
        evasion.smart_jitter_base_sec = max(float(evasion.smart_jitter_base_sec), 0.42)
        evasion.smart_jitter_max_extra_sec = max(
            float(evasion.smart_jitter_max_extra_sec), 0.72
        )

    try:
        raise SystemExit(
            asyncio.run(
                _run(
                    args.url,
                    args.ai,
                    args.subdomain,
                    args.xss,
                    args.cloud,
                    args.brute,
                    args.port,
                    args.js,
                    args.idor,
                    args.source,
                    args.params,
                    args.wayback,
                    args.sensitive,
                    args.broken_links,
                    args.api_fuzz,
                    args.zero_day,
                    args.playtika_bounty,
                    not args.no_recursive_paths,
                    not args.no_ext_fuzz,
                    args.report or args.pdf,
                    args.pdf,
                    args.infiltrate,
                    extra_headers,
                    evasion,
                    args.nmap_stealth,
                    args.nmap_spoof_mac,
                    args.bypass_403,
                    args.obfuscate,
                    args.logic_scan,
                    args.ai_mutate,
                    args.mutate_kind,
                    args.sqli,
                    args.deep_scan,
                    args.nuclei,
                    console,
                )
            )
        )
    except KeyboardInterrupt:
        console.print("\n[red]Aborted.[/red]")
        raise SystemExit(130) from None


if __name__ == "__main__":
    main()
