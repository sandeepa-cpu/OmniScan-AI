# Developed by Channa Sandeepa | OmniScan-AI v2.0 | Copyright 2026
"""OmniScan-AI report generator - renders .txt, .json, and branded .pdf reports.

The developer signature (``Developed by Channa Sandeepa``) is intentionally
hardcoded in this module so that the footer of every generated text report and
the running header + footer of every page of every PDF report carries the
author's name. Do not remove.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel

from .ai_auditor import AIAuditor

# ---------------------------------------------------------------------------
# Hardcoded branding - DO NOT REMOVE.
# Appears in the footer of every .txt and .pdf report.
# ---------------------------------------------------------------------------
DEVELOPER: str = "Channa Sandeepa"
APP_VERSION: str = "2.0"
PROJECT_NAME: str = "OmniScan-AI"
COPYRIGHT_YEAR: int = 2026
SIGNATURE: str = f"Developed by {DEVELOPER} | {PROJECT_NAME} v{APP_VERSION} | (c) {COPYRIGHT_YEAR}"


_JS_ENDPOINT_KINDS: frozenset[str] = frozenset(
    {"endpoint_url", "endpoint_api_path", "fetch_call", "axios_call", "xhr_open"}
)


def _target_slug(url: str) -> str:
    """Filesystem-safe slug from the target hostname (e.g. google.com -> google_com)."""
    import re

    host = urlparse(url).hostname or "target"
    return re.sub(r"[^a-z0-9]+", "_", host.lower()).strip("_") or "target"


def build_json_report(
    *,
    target_url: str,
    generated_at: str,
    secret_findings: list[dict],
    secret_error: str | None,
    subdomain_rows: list[dict],
    subdomain_error: str | None,
    subdomain_enabled: bool,
    xss_rows: list[dict],
    xss_error: str | None,
    xss_enabled: bool,
    cloud_rows: list[dict],
    cloud_error: str | None,
    cloud_enabled: bool,
    path_rows: list[dict],
    path_error: str | None,
    path_enabled: bool,
    port_rows: list[dict],
    port_error: str | None,
    port_enabled: bool,
    js_rows: list[dict],
    js_error: str | None,
    js_enabled: bool,
    idor_rows: list[dict],
    idor_error: str | None,
    idor_enabled: bool,
    xss_mutations: list[dict],
    include_ai: bool,
) -> dict:
    counts = {"High": 0, "Medium": 0, "Low": 0}
    for r in secret_findings:
        counts[r.get("severity", "Low")] = counts.get(r.get("severity", "Low"), 0) + 1

    js_endpoints = sum(1 for r in js_rows if r.get("type") in _JS_ENDPOINT_KINDS)
    js_secrets = sum(1 for r in js_rows if r.get("type") not in _JS_ENDPOINT_KINDS)

    idor_critical = sum(1 for r in idor_rows if r.get("severity") == "Critical")
    idor_high = sum(1 for r in idor_rows if r.get("severity") == "High")

    return {
        "tool": PROJECT_NAME,
        "version": APP_VERSION,
        "developer": DEVELOPER,
        "signature": SIGNATURE,
        "copyright": f"(c) {COPYRIGHT_YEAR} {DEVELOPER}",
        "generated_at_utc": generated_at,
        "target": {
            "url": target_url,
            "hostname": urlparse(target_url).hostname,
            "slug": _target_slug(target_url),
        },
        "summary": {
            "total_findings": len(secret_findings),
            "severity_counts": counts,
            "subdomain_scan": subdomain_enabled,
            "subdomain_alive": sum(1 for r in subdomain_rows if r.get("alive")),
            "xss_scan": xss_enabled,
            "xss_reflected": len(xss_rows),
            "xss_ai_mutations_used": len(xss_mutations),
            "cloud_scan": cloud_enabled,
            "cloud_findings": len(cloud_rows),
            "path_scan": path_enabled,
            "path_findings": len(path_rows),
            "port_scan": port_enabled,
            "ports_open": len(port_rows),
            "js_scan": js_enabled,
            "js_endpoints": js_endpoints,
            "js_secret_hits": js_secrets,
            "idor_scan": idor_enabled,
            "idor_findings": len(idor_rows),
            "idor_critical": idor_critical,
            "idor_high": idor_high,
            "ai_section_included": include_ai,
        },
        "secrets": {
            "error": secret_error,
            "findings": secret_findings,
        },
        "subdomains": {
            "enabled": subdomain_enabled,
            "error": subdomain_error,
            "results": subdomain_rows,
        },
        "xss": {
            "enabled": xss_enabled,
            "error": xss_error,
            "results": xss_rows,
            "ai_mutations": xss_mutations,
        },
        "idor": {
            "enabled": idor_enabled,
            "error": idor_error,
            "results": idor_rows,
        },
        "cloud": {
            "enabled": cloud_enabled,
            "error": cloud_error,
            "results": cloud_rows,
        },
        "paths": {
            "enabled": path_enabled,
            "error": path_error,
            "results": path_rows,
        },
        "ports": {
            "enabled": port_enabled,
            "error": port_error,
            "results": port_rows,
        },
        "js_analysis": {
            "enabled": js_enabled,
            "error": js_error,
            "results": js_rows,
        },
        "ai_prompt_injection": (
            [
                {"id": i, "technique": name, "payload": payload}
                for i, (name, payload) in enumerate(AIAuditor.list_payloads(), start=1)
            ]
            if include_ai
            else []
        ),
    }


def render_text_report(
    *,
    target_url: str,
    generated_at: str,
    secret_findings: list[dict],
    secret_error: str | None,
    subdomain_rows: list[dict],
    subdomain_error: str | None,
    subdomain_enabled: bool,
    xss_rows: list[dict],
    xss_error: str | None,
    xss_enabled: bool,
    cloud_rows: list[dict],
    cloud_error: str | None,
    cloud_enabled: bool,
    path_rows: list[dict],
    path_error: str | None,
    path_enabled: bool,
    port_rows: list[dict],
    port_error: str | None,
    port_enabled: bool,
    js_rows: list[dict],
    js_error: str | None,
    js_enabled: bool,
    idor_rows: list[dict],
    idor_error: str | None,
    idor_enabled: bool,
    xss_mutations: list[dict],
    include_ai: bool,
) -> str:
    def hr(char: str = "=") -> str:
        return char * 78

    def _truncate(value: str, n: int) -> str:
        return value if len(value) <= n else value[: n - 3] + "..."

    def _center(value: str, width: int = 76) -> str:
        return value.center(width)

    counts = {"High": 0, "Medium": 0, "Low": 0}
    for r in secret_findings:
        counts[r.get("severity", "Low")] = counts.get(r.get("severity", "Low"), 0) + 1

    lines: list[str] = []
    lines.append(hr("="))
    lines.append("=" + _center("O M N I S C A N - A I   S E C U R I T Y   R E P O R T") + "=")
    lines.append("=" + _center(f"Developed by {DEVELOPER}") + "=")
    lines.append("=" + _center("The Ultimate Bug Hunter's Suite") + "=")
    lines.append(hr("="))
    lines.append(f"  Generated (UTC) : {generated_at}")
    lines.append(f"  Target URL      : {target_url}")
    lines.append(f"  Hostname        : {urlparse(target_url).hostname or ''}")
    lines.append(f"  Developer       : {DEVELOPER}")
    lines.append(f"  Tool version    : {PROJECT_NAME} {APP_VERSION}")
    lines.append(f"  Copyright       : (c) {COPYRIGHT_YEAR} {DEVELOPER}")
    lines.append("")

    lines.append(hr("-"))
    lines.append("  [1] SECRET PATTERN MATCHES (JavaScript)")
    lines.append(hr("-"))
    lines.append(
        f"  Severity summary: High={counts['High']}  Medium={counts['Medium']}  Low={counts['Low']}"
    )
    lines.append(f"  Total findings  : {len(secret_findings)}")
    if secret_error:
        lines.append(f"  Scanner error   : {secret_error}")
    lines.append("")
    if secret_findings:
        for i, row in enumerate(secret_findings, start=1):
            lines.append(f"  #{i:>3} [{row.get('severity','Low'):<6}] {row.get('type','?')}")
            lines.append(f"       source : {_truncate(str(row.get('source_url','')), 200)}")
            lines.append(f"       match  : {_truncate(str(row.get('match','')), 200)}")
            lines.append("")
    else:
        lines.append("  No findings for configured patterns.")
        lines.append("")

    lines.append(hr("-"))
    lines.append("  [2] DEEP JS ANALYSIS (endpoints + secrets, concurrent crawl)")
    lines.append(hr("-"))
    if not js_enabled:
        lines.append("  JS deep scan was not requested (use --js to include).")
    elif js_error:
        lines.append(f"  JS analyzer error: {js_error}")
    elif not js_rows:
        lines.append("  No endpoints or secrets recovered from linked JS assets.")
    else:
        eps = [r for r in js_rows if r.get("type") in _JS_ENDPOINT_KINDS]
        secs = [r for r in js_rows if r.get("type") not in _JS_ENDPOINT_KINDS]
        lines.append(f"  Endpoints found : {len(eps)}")
        lines.append(f"  Secret hits     : {len(secs)}")
        lines.append("")
        for i, r in enumerate(js_rows, start=1):
            lines.append(
                f"  #{i:>3} [{r.get('severity','Low'):<6}] {r.get('type','?')}"
            )
            lines.append(f"       source : {_truncate(str(r.get('source_url','')), 200)}")
            lines.append(f"       value  : {_truncate(str(r.get('match','')), 200)}")
            lines.append("")
    lines.append("")

    lines.append(hr("-"))
    lines.append("  [3] SUBDOMAIN DISCOVERY")
    lines.append(hr("-"))
    if not subdomain_enabled:
        lines.append("  Subdomain scan was not requested (use --subdomain to include).")
    elif subdomain_error:
        lines.append(f"  Subdomain scan error: {subdomain_error}")
    elif not subdomain_rows:
        lines.append("  No rows returned.")
    else:
        alive_n = sum(1 for r in subdomain_rows if r.get("alive"))
        lines.append(f"  Probed {len(subdomain_rows)} host(s); {alive_n} responded.")
        lines.append("")
        lines.append(f"  {'#':>3}  {'HOST':<40} {'SCHEME':<6} {'STATUS':>6}  ALIVE")
        for i, r in enumerate(subdomain_rows, start=1):
            alive_txt = "yes" if r.get("alive") else "no"
            lines.append(
                f"  {i:>3}  {_truncate(str(r.get('subdomain','')), 40):<40} "
                f"{str(r.get('scheme','')):<6} {str(r.get('status','')):>6}  {alive_txt}"
            )
            note = r.get("note") or ""
            url = r.get("url") or ""
            if url:
                lines.append(f"        -> {_truncate(str(url), 200)}")
            if note:
                lines.append(f"        note: {_truncate(str(note), 200)}")
    lines.append("")

    lines.append(hr("-"))
    lines.append("  [4] REFLECTED XSS CANDIDATES")
    lines.append(hr("-"))
    if not xss_enabled:
        lines.append("  XSS scan was not requested (use --xss to include).")
    elif xss_error:
        lines.append(f"  XSS scanner error: {xss_error}")
    elif not xss_rows:
        lines.append("  No reflected payloads observed on discovered injection points.")
    else:
        lines.append(f"  Reflected signals: {len(xss_rows)}")
        if xss_mutations:
            lines.append(
                f"  AI mutation set : {len(xss_mutations)} WAF-bypass payloads added."
            )
        lines.append("")
        for i, r in enumerate(xss_rows, start=1):
            lines.append(
                f"  #{i:>3} [{r.get('severity','Medium'):<6}] "
                f"{r.get('method','GET')} param={r.get('param','')}"
            )
            lines.append(f"       url     : {_truncate(str(r.get('url','')), 200)}")
            lines.append(f"       payload : {_truncate(str(r.get('payload','')), 200)}")
            lines.append(f"       status  : {r.get('status','')}")
            lines.append(f"       context : {_truncate(str(r.get('note','')), 200)}")
            lines.append("")
    lines.append("")

    lines.append(hr("-"))
    lines.append("  [5] AI-GUIDED XSS PAYLOAD MUTATIONS (WAF bypass)")
    lines.append(hr("-"))
    if not xss_mutations:
        lines.append(
            "  No AI-guided mutations applied (combine --xss with --ai to enable)."
        )
    else:
        lines.append(f"  Techniques applied per base payload: {len(xss_mutations)} total.")
        lines.append("")
        for i, m in enumerate(xss_mutations, start=1):
            lines.append(f"  #{i:>3} technique: {m.get('technique','?')}")
            lines.append(f"       description: {_truncate(str(m.get('description','')), 200)}")
            lines.append(f"       base       : {_truncate(str(m.get('base_payload','')), 200)}")
            lines.append(f"       mutated    : {_truncate(str(m.get('payload','')), 200)}")
            lines.append("")
    lines.append("")

    lines.append(hr("-"))
    lines.append("  [6] IDOR CANDIDATES (horizontal access control)")
    lines.append(hr("-"))
    if not idor_enabled:
        lines.append("  IDOR scan was not requested (use --idor to include).")
    elif idor_error:
        lines.append(f"  IDOR scanner error: {idor_error}")
    elif not idor_rows:
        lines.append("  No numeric IDs found in URL parameters or path segments,")
        lines.append("  or all probed neighbouring IDs returned matching content.")
    else:
        crit = sum(1 for r in idor_rows if r.get("severity") == "Critical")
        high = sum(1 for r in idor_rows if r.get("severity") == "High")
        info = sum(1 for r in idor_rows if r.get("severity") == "Info")
        lines.append(
            f"  Findings: Critical={crit}  High={high}  Info={info}  Total={len(idor_rows)}"
        )
        lines.append("")
        for i, r in enumerate(idor_rows, start=1):
            lines.append(
                f"  #{i:>3} [{r.get('severity','High'):<8}] {r.get('kind','?')}  "
                f"{r.get('param','')}  base_id={r.get('base_id','?')} -> "
                f"test_id={r.get('test_id','?')}  status={r.get('status','?')}"
            )
            lines.append(f"       url      : {_truncate(str(r.get('url','')), 200)}")
            lines.append(f"       similar. : {r.get('similarity','?')}")
            lines.append(f"       evidence : {_truncate(str(r.get('note','')), 200)}")
            lines.append("")
    lines.append("")

    lines.append(hr("-"))
    lines.append("  [7] CLOUD STORAGE EXPOSURE")
    lines.append(hr("-"))
    if not cloud_enabled:
        lines.append("  Cloud scan was not requested (use --cloud to include).")
    elif cloud_error:
        lines.append(f"  Cloud scanner error: {cloud_error}")
    elif not cloud_rows:
        lines.append("  No candidate buckets/containers responded positively.")
    else:
        lines.append(f"  Cloud findings: {len(cloud_rows)}")
        lines.append("")
        for i, r in enumerate(cloud_rows, start=1):
            lines.append(
                f"  #{i:>3} [{r.get('severity','Low'):<6}] {r.get('provider','?')}  "
                f"bucket={r.get('bucket','')}  state={r.get('state','')}  "
                f"status={r.get('status','')}"
            )
            lines.append(f"       url  : {_truncate(str(r.get('url','')), 200)}")
            lines.append(f"       note : {_truncate(str(r.get('note','')), 200)}")
            lines.append("")
    lines.append("")

    lines.append(hr("-"))
    lines.append("  [8] SENSITIVE PATH DISCOVERY")
    lines.append(hr("-"))
    if not path_enabled:
        lines.append("  Path brute scan was not requested (use --brute to include).")
    elif path_error:
        lines.append(f"  Path scanner error: {path_error}")
    elif not path_rows:
        lines.append("  No interesting status codes on the configured wordlist.")
    else:
        lines.append(f"  Path findings: {len(path_rows)}")
        lines.append("")
        lines.append(f"  {'#':>3}  {'SEV':<6}  {'STATE':<11} {'STATUS':>6}  PATH")
        for i, r in enumerate(path_rows, start=1):
            lines.append(
                f"  {i:>3}  {r.get('severity','Low'):<6}  "
                f"{str(r.get('state','')):<11} {str(r.get('status','')):>6}  "
                f"{_truncate(str(r.get('path','')), 200)}"
            )
            lines.append(f"        -> {_truncate(str(r.get('url','')), 200)}")
    lines.append("")

    lines.append(hr("-"))
    lines.append("  [9] OPEN TCP PORTS")
    lines.append(hr("-"))
    if not port_enabled:
        lines.append("  Port scan was not requested (use --port to include).")
    elif port_error:
        lines.append(f"  Port scanner error: {port_error}")
    elif not port_rows:
        lines.append("  No probed ports responded.")
    else:
        lines.append(f"  Open ports: {len(port_rows)}")
        lines.append("")
        lines.append(f"  {'#':>3}  {'SEV':<6}  {'PORT':>6}  {'SERVICE':<18} HOST")
        for i, r in enumerate(port_rows, start=1):
            lines.append(
                f"  {i:>3}  {r.get('severity','Medium'):<6}  "
                f"{str(r.get('port','')):>6}  {str(r.get('service','')):<18} "
                f"{_truncate(str(r.get('host','')), 200)}"
            )
    lines.append("")

    lines.append(hr("-"))
    lines.append("  [10] AI / PROMPT-INJECTION REFERENCE")
    lines.append(hr("-"))
    if not include_ai:
        lines.append("  AI section not included (run with --ai to capture in future reports).")
    else:
        for i, (name, payload) in enumerate(AIAuditor.list_payloads(), start=1):
            lines.append(f"  #{i:>2} {name}")
            for pl_line in payload.splitlines() or [payload]:
                lines.append(f"       {pl_line}")
            lines.append("")
    lines.append("")

    lines.append(hr("="))
    lines.append("=" + _center(f"Report generated by {PROJECT_NAME} v{APP_VERSION}") + "=")
    lines.append("=" + _center(f"Developed by {DEVELOPER}") + "=")
    lines.append("=" + _center(f"(c) {COPYRIGHT_YEAR} {DEVELOPER} - Authorized testing only.") + "=")
    lines.append(hr("="))
    return "\n".join(lines) + "\n"


def save_pdf_report(
    pdf_path: Path,
    json_body: dict,
    console: Console,
) -> Path | None:
    """Render ``json_body`` to a branded PDF with Developer signature in every page header."""
    try:
        from fpdf import FPDF  # type: ignore[import-not-found]
        from fpdf.enums import XPos, YPos  # type: ignore[import-not-found]
    except Exception:
        console.print(
            "[yellow]PDF skipped:[/yellow] `fpdf2` is not installed. "
            "Install it with `pip install fpdf2` (already listed in requirements.txt)."
        )
        return None

    NEXT_LINE = {"new_x": XPos.LMARGIN, "new_y": YPos.NEXT}

    def _ascii(value: object) -> str:
        return str(value).encode("latin-1", errors="replace").decode("latin-1")

    class _OmniPDF(FPDF):
        def header(self) -> None:
            self.set_font("Helvetica", "B", 11)
            self.set_text_color(0, 102, 0)
            self.cell(
                0, 6,
                _ascii(f"{PROJECT_NAME} - Security Assessment Report"),
                align="C",
                **NEXT_LINE,
            )
            self.set_font("Helvetica", "I", 9)
            self.set_text_color(70, 70, 70)
            self.cell(
                0, 5,
                _ascii(f"Developed by {DEVELOPER}"),
                align="C",
                **NEXT_LINE,
            )
            self.set_draw_color(0, 102, 0)
            self.set_line_width(0.3)
            y = self.get_y() + 1
            self.line(10, y, 200, y)
            self.set_text_color(0, 0, 0)
            self.ln(4)

        def footer(self) -> None:
            self.set_y(-15)
            self.set_font("Helvetica", "I", 8)
            self.set_text_color(120, 120, 120)
            self.cell(
                0, 8,
                _ascii(
                    f"{PROJECT_NAME} v{APP_VERSION}  |  "
                    f"Developed by {DEVELOPER}  |  "
                    f"(c) {COPYRIGHT_YEAR}  |  Page {self.page_no()}"
                ),
                align="C",
            )
            self.set_text_color(0, 0, 0)

    def _mc(pdf_obj: FPDF, height: float, text: str) -> None:
        pdf_obj.set_x(10)
        pdf_obj.multi_cell(
            0, height, _ascii(text),
            new_x=XPos.LMARGIN, new_y=YPos.NEXT,
        )

    pdf = _OmniPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    target = json_body.get("target", {})
    summary = json_body.get("summary", {})

    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 8, _ascii("Executive summary"), **NEXT_LINE)
    pdf.set_font("Helvetica", "", 10)
    meta_rows = [
        ("Generated (UTC)", json_body.get("generated_at_utc", "")),
        ("Target URL", target.get("url", "")),
        ("Hostname", target.get("hostname", "") or ""),
        ("Tool version", f"{PROJECT_NAME} {json_body.get('version', APP_VERSION)}"),
        ("Developer", DEVELOPER),
        ("Copyright", f"(c) {COPYRIGHT_YEAR} {DEVELOPER}"),
    ]
    for label, value in meta_rows:
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 5, _ascii(f"{label}:"), **NEXT_LINE)
        pdf.set_font("Helvetica", "", 10)
        _mc(pdf, 5, f"    {value}")
    pdf.ln(2)

    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, _ascii("Scan summary"), **NEXT_LINE)
    pdf.set_font("Helvetica", "", 10)
    sev_counts = summary.get("severity_counts", {"High": 0, "Medium": 0, "Low": 0})
    summary_lines = [
        f"Secret findings        : {summary.get('total_findings', 0)}  "
        f"(High={sev_counts.get('High', 0)}, "
        f"Medium={sev_counts.get('Medium', 0)}, "
        f"Low={sev_counts.get('Low', 0)})",
        f"JS endpoints found     : {summary.get('js_endpoints', 0)}",
        f"JS secret hits (deep)  : {summary.get('js_secret_hits', 0)}",
        f"Subdomains responding  : {summary.get('subdomain_alive', 0)}",
        f"XSS reflected signals  : {summary.get('xss_reflected', 0)}",
        f"AI WAF-bypass mutations: {summary.get('xss_ai_mutations_used', 0)}",
        f"IDOR findings (total)  : {summary.get('idor_findings', 0)}  "
        f"(Critical={summary.get('idor_critical', 0)}, "
        f"High={summary.get('idor_high', 0)})",
        f"Cloud findings         : {summary.get('cloud_findings', 0)}",
        f"Sensitive path hits    : {summary.get('path_findings', 0)}",
        f"Open TCP ports         : {summary.get('ports_open', 0)}",
    ]
    for line in summary_lines:
        _mc(pdf, 5.5, line)
    pdf.ln(2)

    def _section(title: str) -> None:
        pdf.ln(2)
        pdf.set_draw_color(180, 180, 180)
        pdf.set_line_width(0.2)
        y = pdf.get_y()
        pdf.line(10, y, 200, y)
        pdf.ln(2)
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(0, 80, 0)
        pdf.cell(0, 7, _ascii(title), **NEXT_LINE)
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", "", 10)

    def _render_rows(rows: list[dict], formatter) -> None:
        if not rows:
            pdf.set_font("Helvetica", "I", 9)
            pdf.cell(0, 5, _ascii("No rows."), **NEXT_LINE)
            pdf.set_font("Helvetica", "", 10)
            return
        for idx, row in enumerate(rows, start=1):
            for line in formatter(idx, row):
                _mc(pdf, 5, line)
            pdf.ln(0.5)

    _section("1. Secret pattern matches (JavaScript)")
    secrets_block = json_body.get("secrets", {})
    if secrets_block.get("error"):
        _mc(pdf, 5, f"Scanner error: {secrets_block['error']}")
    _render_rows(
        secrets_block.get("findings", []),
        lambda i, r: [
            f"#{i} [{r.get('severity','Low')}] {r.get('type','?')}",
            f"    source: {r.get('source_url','')}",
            f"    match : {str(r.get('match',''))[:160]}",
        ],
    )

    _section("2. Deep JS analysis (endpoints + secrets)")
    js_block = json_body.get("js_analysis", {})
    if not js_block.get("enabled"):
        _mc(pdf, 5, "Not requested (use --js to include).")
    elif js_block.get("error"):
        _mc(pdf, 5, f"Scanner error: {js_block['error']}")
    else:
        _render_rows(
            js_block.get("results", []),
            lambda i, r: [
                f"#{i} [{r.get('severity','Low')}] {r.get('type','?')}",
                f"    source: {r.get('source_url','')}",
                f"    value : {str(r.get('match',''))[:160]}",
            ],
        )

    _section("3. Subdomain discovery")
    sub_block = json_body.get("subdomains", {})
    if not sub_block.get("enabled"):
        _mc(pdf, 5, "Not requested (use --subdomain).")
    elif sub_block.get("error"):
        _mc(pdf, 5, f"Scanner error: {sub_block['error']}")
    else:
        _render_rows(
            sub_block.get("results", []),
            lambda i, r: [
                f"#{i} {r.get('subdomain','')}  scheme={r.get('scheme','')}  "
                f"status={r.get('status','')}  alive={'yes' if r.get('alive') else 'no'}",
                f"    url : {r.get('url','')}",
            ],
        )

    _section("4. Reflected XSS candidates")
    xss_block = json_body.get("xss", {})
    if not xss_block.get("enabled"):
        _mc(pdf, 5, "Not requested (use --xss).")
    elif xss_block.get("error"):
        _mc(pdf, 5, f"Scanner error: {xss_block['error']}")
    else:
        _render_rows(
            xss_block.get("results", []),
            lambda i, r: [
                f"#{i} [{r.get('severity','Medium')}] {r.get('method','GET')} "
                f"param={r.get('param','')}",
                f"    url     : {r.get('url','')}",
                f"    payload : {str(r.get('payload',''))[:160]}",
                f"    context : {str(r.get('note',''))[:160]}",
            ],
        )

    _section("5. AI-guided XSS payload mutations (WAF bypass)")
    muts = xss_block.get("ai_mutations", [])
    if not muts:
        _mc(pdf, 5, "No AI mutations applied (combine --xss with --ai).")
    else:
        _render_rows(
            muts,
            lambda i, m: [
                f"#{i} technique: {m.get('technique','?')}",
                f"    base   : {str(m.get('base_payload',''))[:160]}",
                f"    mutated: {str(m.get('payload',''))[:160]}",
            ],
        )

    _section("6. IDOR candidates (horizontal access control)")
    idor_block = json_body.get("idor", {})
    if not idor_block.get("enabled"):
        _mc(pdf, 5, "Not requested (use --idor).")
    elif idor_block.get("error"):
        _mc(pdf, 5, f"Scanner error: {idor_block['error']}")
    else:
        _render_rows(
            idor_block.get("results", []),
            lambda i, r: [
                f"#{i} [{r.get('severity','High')}] {r.get('kind','?')}  "
                f"{r.get('param','')}  status={r.get('status','?')}  "
                f"similarity={r.get('similarity','?')}",
                f"    base_id={r.get('base_id','?')}  test_id={r.get('test_id','?')}",
                f"    url : {r.get('url','')}",
                f"    evidence: {str(r.get('note',''))[:180]}",
            ],
        )

    _section("7. Cloud storage exposure")
    cloud_block = json_body.get("cloud", {})
    if not cloud_block.get("enabled"):
        _mc(pdf, 5, "Not requested (use --cloud).")
    elif cloud_block.get("error"):
        _mc(pdf, 5, f"Scanner error: {cloud_block['error']}")
    else:
        _render_rows(
            cloud_block.get("results", []),
            lambda i, r: [
                f"#{i} [{r.get('severity','Low')}] {r.get('provider','?')}  "
                f"state={r.get('state','')}  status={r.get('status','')}",
                f"    bucket: {r.get('bucket','')}",
                f"    url   : {r.get('url','')}",
            ],
        )

    _section("8. Sensitive path discovery")
    path_block = json_body.get("paths", {})
    if not path_block.get("enabled"):
        _mc(pdf, 5, "Not requested (use --brute).")
    elif path_block.get("error"):
        _mc(pdf, 5, f"Scanner error: {path_block['error']}")
    else:
        _render_rows(
            path_block.get("results", []),
            lambda i, r: [
                f"#{i} [{r.get('severity','Low')}] state={r.get('state','')}  "
                f"status={r.get('status','')}",
                f"    path: {r.get('path','')}",
                f"    url : {r.get('url','')}",
            ],
        )

    _section("9. Open TCP ports")
    port_block = json_body.get("ports", {})
    if not port_block.get("enabled"):
        _mc(pdf, 5, "Not requested (use --port).")
    elif port_block.get("error"):
        _mc(pdf, 5, f"Scanner error: {port_block['error']}")
    else:
        _render_rows(
            port_block.get("results", []),
            lambda i, r: [
                f"#{i} [{r.get('severity','Medium')}] port {r.get('port','')} "
                f"({r.get('service','')}) on {r.get('host','')}  "
                f"state={r.get('state','open')}",
            ],
        )

    ai_block = json_body.get("ai_prompt_injection", []) or []
    if ai_block:
        _section("10. AI / prompt-injection reference")
        for entry in ai_block:
            pdf.set_font("Helvetica", "B", 10)
            _mc(pdf, 5, f"#{entry.get('id','?')} {entry.get('technique','')}")
            pdf.set_font("Helvetica", "", 10)
            _mc(pdf, 5, str(entry.get("payload", "")))
            pdf.ln(1)

    pdf.output(str(pdf_path))
    return pdf_path


def save_reports(
    *,
    target_url: str,
    generated_at: str,
    secret_findings: list[dict],
    secret_error: str | None,
    subdomain_rows: list[dict],
    subdomain_error: str | None,
    subdomain_enabled: bool,
    xss_rows: list[dict],
    xss_error: str | None,
    xss_enabled: bool,
    cloud_rows: list[dict],
    cloud_error: str | None,
    cloud_enabled: bool,
    path_rows: list[dict],
    path_error: str | None,
    path_enabled: bool,
    port_rows: list[dict],
    port_error: str | None,
    port_enabled: bool,
    js_rows: list[dict],
    js_error: str | None,
    js_enabled: bool,
    idor_rows: list[dict],
    idor_error: str | None,
    idor_enabled: bool,
    xss_mutations: list[dict],
    include_ai: bool,
    save_pdf: bool,
    reports_dir: Path,
    console: Console,
) -> tuple[Path, Path, Path | None]:
    slug = _target_slug(target_url)
    target_dir = (reports_dir / slug).resolve()
    target_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    base = f"omniscan_{stamp}"
    txt_path = target_dir / f"{base}.txt"
    json_path = target_dir / f"{base}.json"
    pdf_path = target_dir / f"{base}.pdf"

    common_kwargs = dict(
        target_url=target_url,
        generated_at=generated_at,
        secret_findings=secret_findings,
        secret_error=secret_error,
        subdomain_rows=subdomain_rows,
        subdomain_error=subdomain_error,
        subdomain_enabled=subdomain_enabled,
        xss_rows=xss_rows,
        xss_error=xss_error,
        xss_enabled=xss_enabled,
        cloud_rows=cloud_rows,
        cloud_error=cloud_error,
        cloud_enabled=cloud_enabled,
        path_rows=path_rows,
        path_error=path_error,
        path_enabled=path_enabled,
        port_rows=port_rows,
        port_error=port_error,
        port_enabled=port_enabled,
        js_rows=js_rows,
        js_error=js_error,
        js_enabled=js_enabled,
        idor_rows=idor_rows,
        idor_error=idor_error,
        idor_enabled=idor_enabled,
        xss_mutations=xss_mutations,
        include_ai=include_ai,
    )
    text_body = render_text_report(**common_kwargs)
    json_body = build_json_report(**common_kwargs)

    txt_path.write_text(text_body, encoding="utf-8")
    json_path.write_text(
        json.dumps(json_body, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    pdf_written: Path | None = None
    if save_pdf:
        try:
            pdf_written = save_pdf_report(pdf_path, json_body, console)
        except Exception as exc:
            console.print(
                f"[yellow]PDF generation failed:[/yellow] {escape(str(exc))}"
            )
            pdf_written = None

    file_lines = [
        f"  * [cyan]{escape(txt_path.name)}[/cyan]",
        f"  * [cyan]{escape(json_path.name)}[/cyan]",
    ]
    if pdf_written is not None:
        file_lines.append(f"  * [cyan]{escape(pdf_written.name)}[/cyan]")

    console.print(
        Panel.fit(
            f"[bold green]Reports saved to[/bold green] "
            f"[link={target_dir.as_uri()}]{escape(str(target_dir))}[/link]\n"
            + "\n".join(file_lines)
            + f"\n[dim]Signed: {escape(SIGNATURE)}[/dim]",
            border_style="green",
            title="[bold]Report[/bold]",
        )
    )
    return txt_path, json_path, pdf_written
