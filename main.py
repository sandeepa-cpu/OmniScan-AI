#!/usr/bin/env python3
# Developed by Channa Sandeepa | OmniScan-AI v2.0 | Copyright 2026
"""OmniScan-AI — CLI entry: secrets, subdomains, XSS, cloud, paths, ports, JS, AI."""

from __future__ import annotations

import argparse
import asyncio
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
from modules.cloud_scanner import CloudScanner
from modules.idor_scanner import IDORScanner
from modules.js_analyzer import JSAnalyzer
from modules.path_bruter import PathBruter
from modules.port_scanner import PortScanner
from modules.report_generator import (
    APP_VERSION,
    DEVELOPER,
    SIGNATURE,
    save_reports,
)
from modules.secret_finder import SEVERITY_COLORS, SecretFinder, severity_for
from modules.subdomain_scanner import SubdomainScanner
from modules.xss_scanner import XSSScanner

PROJECT_ROOT = Path(__file__).resolve().parent
REPORTS_DIR = PROJECT_ROOT / "reports"

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
  python main.py --url example.com --port
  python main.py --url example.com --js --xss --ai --idor --report --pdf
  python main.py --url example.com --subdomain --xss --cloud --brute --port --js --idor --ai --report --pdf
  python main.py --url example.com --idor --js --xss \
    --headers '{"Authorization": "Bearer eyJ...", "X-Api-Key": "abc"}'

Notes:
  - `--url` accepts bare hostnames; `https://` is added automatically.
  - Combining `--ai` with `--xss` auto-generates WAF-bypass XSS payload mutations.
  - `--idor` needs a URL that exposes a numeric id (e.g. ?id=42 or /users/42).
  - `--headers` takes a JSON object; headers flow into the XSS, IDOR, and JS
    secret scanners (for authenticated endpoints). Invalid JSON exits with code 2.
  - `--pdf` requires `fpdf2` (see requirements.txt).
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
            "OmniScan-AI v2.0 - The Modern Bug Hunter's Suite (authorized testing only). "
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
        "--headers",
        metavar="JSON",
        default=None,
        help=(
            "Optional JSON object of custom HTTP headers to attach to every request "
            "made by the XSS, IDOR, and JS-secret scanners. Example: "
            "--headers '{\"Authorization\": \"Bearer eyJ...\", \"Cookie\": \"session=abc\"}'. "
            "If omitted, an empty header set is used."
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
        "--version",
        action="version",
        version=f"OmniScan-AI {APP_VERSION} — by {DEVELOPER}",
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
    table.add_column("Path", style="cyan", overflow="fold")
    table.add_column("Length", justify="right", width=8)
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
            escape(str(r.get("length", ""))),
            escape(str(r.get("url", ""))),
        )
    return table


def _js_table(rows: list[dict]) -> Table:
    table = Table(
        title="[bold bright_cyan]Deep JS analysis — endpoints & secrets[/bold bright_cyan]",
        caption=(
            "[dim]Concurrent crawl of every linked .js asset. "
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
    table.add_column("Service", no_wrap=True)
    table.add_column("State", no_wrap=True)

    for i, r in enumerate(rows, start=1):
        sev = r.get("severity", "Medium")
        color = SEVERITY_COLORS.get(sev, "white")
        table.add_row(
            str(i),
            f"[bold {color}]{escape(sev)}[/bold {color}]",
            escape(str(r.get("host", ""))),
            escape(str(r.get("port", ""))),
            escape(str(r.get("service", ""))),
            escape(str(r.get("state", "open"))),
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
    save_report: bool,
    save_pdf: bool,
    extra_headers: dict[str, str],
    console: Console,
) -> int:
    def _mode(flag: bool) -> str:
        col = "green" if flag else "dim"
        return f"[{col}]{'on' if flag else 'off'}[/{col}]"

    xss_mutations: list[dict] = []
    extra_xss_payloads: tuple[str, ...] = ()
    if xss and show_ai:
        xss_mutations = AIAuditor.mutate_xss_payloads(list(XSSScanner.PAYLOADS))
        extra_xss_payloads = tuple(m["payload"] for m in xss_mutations)

    console.print(f"[bold]Target:[/bold] [link={url}]{escape(url)}[/link]")
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
        f"ai={_mode(show_ai)}  "
        f"report={_mode(save_report)}  "
        f"pdf={_mode(save_pdf)}  "
        f"headers={_mode(bool(extra_headers))}\n"
    )
    if extra_headers:
        header_names = ", ".join(sorted(extra_headers.keys()))
        console.print(
            f"[dim]Custom headers attached to XSS / IDOR / JS-secret scanners: "
            f"{escape(header_names)}[/dim]\n"
        )
    if xss_mutations:
        console.print(
            f"[bold magenta]AI Auditor:[/bold magenta] generated "
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
                SecretFinder(extra_headers=extra_headers).find(
                    url, on_plan=secret_on_plan, on_advance=secret_on_advance
                ),
                secret_task,
                "[magenta]Secret scan complete",
                "[red]Secret scan failed",
            )

        async def do_subdomain():
            return await _wrap(
                SubdomainScanner().scan(url, on_plan=sub_on_plan, on_advance=sub_on_advance),
                sub_task,
                "[green]Subdomain probe complete",
                "[red]Subdomain probe failed",
            )

        async def do_xss():
            scanner = XSSScanner(
                extra_payloads=extra_xss_payloads,
                extra_headers=extra_headers,
            )
            return await _wrap(
                scanner.scan(url, on_plan=xss_on_plan, on_advance=xss_on_advance),
                xss_task,
                "[red]XSS probe complete",
                "[red]XSS probe failed",
            )

        async def do_cloud():
            return await _wrap(
                CloudScanner().scan(url, on_plan=cloud_on_plan, on_advance=cloud_on_advance),
                cloud_task,
                "[blue]Cloud probe complete",
                "[red]Cloud probe failed",
            )

        async def do_paths():
            return await _wrap(
                PathBruter().scan(url, on_plan=path_on_plan, on_advance=path_on_advance),
                path_task,
                "[yellow]Path bruter complete",
                "[red]Path bruter failed",
            )

        async def do_ports():
            return await _wrap(
                PortScanner().scan(url, on_plan=port_on_plan, on_advance=port_on_advance),
                port_task,
                "[bright_magenta]Port scan complete",
                "[red]Port scan failed",
            )

        async def do_js():
            return await _wrap(
                JSAnalyzer(extra_headers=extra_headers).analyze(
                    url, on_plan=js_on_plan, on_advance=js_on_advance
                ),
                js_task,
                "[bright_cyan]JS deep analysis complete",
                "[red]JS deep analysis failed",
            )

        async def do_idor():
            return await _wrap(
                IDORScanner(extra_headers=extra_headers).scan(
                    url, on_plan=idor_on_plan, on_advance=idor_on_advance
                ),
                idor_task,
                "[bright_red]IDOR probe complete",
                "[red]IDOR probe failed",
            )

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

        outputs = await asyncio.gather(*(factory() for _, factory in job_specs))
        results_by_name = {name: out for (name, _), out in zip(job_specs, outputs)}

        findings, secret_err = results_by_name.get("secrets", ([], None))
        js_rows, js_err = results_by_name.get("js", ([], None))
        sub_rows, sub_err = results_by_name.get("subdomain", ([], None))
        xss_rows, xss_err = results_by_name.get("xss", ([], None))
        idor_rows, idor_err = results_by_name.get("idor", ([], None))
        cloud_rows, cloud_err = results_by_name.get("cloud", ([], None))
        path_rows, path_err = results_by_name.get("paths", ([], None))
        port_rows, port_err = results_by_name.get("ports", ([], None))

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
            console.print(
                f"[bold]Open ports:[/bold] [bold bright_magenta]{len(port_rows)}[/bold bright_magenta]\n"
            )
            console.print(_port_table(port_rows))

    if show_ai:
        console.print()
        _print_ai_section(console, url)

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
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
            xss_mutations=xss_mutations,
            include_ai=show_ai,
            save_pdf=save_pdf,
            reports_dir=REPORTS_DIR,
            console=console,
        )

    console.print()
    console.print(
        Text(
            f"Developer: {DEVELOPER}  |  OmniScan-AI v{APP_VERSION}",
            style="dim italic",
        )
    )
    return exit_code


def main() -> None:
    console = Console()
    _banner(console)
    console.print()

    parser = _build_parser()
    args = parser.parse_args()

    extra_headers = _parse_headers_arg(args.headers, console)

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
                    args.report or args.pdf,
                    args.pdf,
                    extra_headers,
                    console,
                )
            )
        )
    except KeyboardInterrupt:
        console.print("\n[red]Aborted.[/red]")
        raise SystemExit(130) from None


if __name__ == "__main__":
    main()
