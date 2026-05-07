# Developed by Channa Sandeepa | OmniScan-AI v2.5 | Copyright 2026
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
APP_VERSION: str = "2.5"
APP_EDITION: str = "Aggressive Infiltration Edition"
PROJECT_NAME: str = "OmniScan-AI"
COPYRIGHT_YEAR: int = 2026
SIGNATURE: str = (
    f"Developed by {DEVELOPER} | {PROJECT_NAME} v{APP_VERSION} ({APP_EDITION}) | (c) {COPYRIGHT_YEAR}"
)


def _nuclei_report_rows(rows: list[dict] | None) -> list[dict]:
    """Strip bulky ``raw`` blobs from Nuclei rows for JSON/text/PDF consumers."""
    out: list[dict] = []
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        out.append({k: v for k, v in r.items() if k != "raw"})
    return out


_JS_ENDPOINT_KINDS: frozenset[str] = frozenset(
    {
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
)


def _target_slug(url: str) -> str:
    """Filesystem-safe slug from the target hostname (e.g. google.com -> google_com)."""
    import re

    host = urlparse(url).hostname or "target"
    return re.sub(r"[^a-z0-9]+", "_", host.lower()).strip("_") or "target"


def collect_critical_findings(
    *,
    secret_findings: list[dict],
    xss_rows: list[dict],
    idor_rows: list[dict],
    sensitive_file_rows: list[dict],
    path_rows: list[dict],
    param_probe_rows: list[dict],
    broken_link_rows: list[dict],
    zero_day_rows: list[dict],
    oauth_social_rows: list[dict],
    cloud_rows: list[dict],
    js_rows: list[dict],
    api_fuzz_bundle: dict,
    infiltration_bundle: dict,
    nuclei_rows: list[dict] | None = None,
) -> list[dict]:
    """Flatten every row tagged *Critical* across modules for the priority table."""
    crit = "Critical"
    rows: list[dict] = []

    def _add(area: str, r: dict) -> None:
        detail = (
            r.get("match")
            or r.get("detail")
            or r.get("note")
            or r.get("path")
            or r.get("param")
            or r.get("payload")
            or r.get("type")
            or ""
        )
        src = r.get("source_url") or r.get("url") or r.get("target") or ""
        rows.append(
            {
                "area": area,
                "kind": r.get("type"),
                "severity": crit,
                "detail": str(detail)[:1200],
                "source": str(src)[:1200],
            }
        )

    for r in secret_findings:
        if r.get("severity") == crit:
            _add("Secret pattern", r)
    for r in xss_rows:
        if r.get("severity") == crit:
            _add("Reflected XSS", r)
    for r in idor_rows:
        if r.get("severity") == crit:
            _add("IDOR", r)
    for r in sensitive_file_rows:
        if r.get("severity") == crit:
            _add("Sensitive file", r)
    for r in path_rows:
        if r.get("severity") == crit:
            _add("Path / brute", r)
    for r in param_probe_rows:
        if r.get("severity") == crit:
            _add("Parameter probe", r)
    for r in broken_link_rows:
        if r.get("severity") == crit:
            _add("Broken link", r)
    for r in zero_day_rows:
        if r.get("severity") == crit:
            _add("Zero-Day Hunter", r)
    for r in oauth_social_rows:
        if r.get("severity") == crit:
            _add("OAuth / social login", r)
    for r in cloud_rows:
        if r.get("severity") == crit:
            _add("Cloud exposure", r)
    for r in js_rows:
        if r.get("severity") == crit:
            _add("JS analysis", r)
    for r in api_fuzz_bundle.get("injection") or []:
        if isinstance(r, dict) and r.get("severity") == crit:
            _add("API injection", r)
    for r in api_fuzz_bundle.get("idor") or []:
        if isinstance(r, dict) and r.get("severity") == crit:
            _add("API IDOR", r)
    for key in ("chain_extractions", "param_active", "forbidden_bypass"):
        for r in infiltration_bundle.get(key) or []:
            if isinstance(r, dict) and r.get("severity") == crit:
                _add(f"Infiltration ({key})", r)
    for r in nuclei_rows or []:
        if not isinstance(r, dict):
            continue
        if str(r.get("severity") or "").strip().lower() != "critical":
            continue
        detail = r.get("name") or r.get("template_id") or r.get("matched_at") or ""
        src = r.get("matched_at") or r.get("host") or ""
        rows.append(
            {
                "area": "Nuclei",
                "kind": r.get("type"),
                "severity": crit,
                "detail": str(detail)[:1200],
                "source": str(src)[:1200],
            }
        )
    return rows


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
    wayback_rows: list[dict],
    wayback_error: str | None,
    wayback_enabled: bool,
    sensitive_file_rows: list[dict],
    sensitive_file_error: str | None,
    sensitive_file_enabled: bool,
    html_source_rows: list[dict],
    html_source_error: str | None,
    html_source_enabled: bool,
    broken_link_rows: list[dict],
    broken_link_error: str | None,
    broken_link_enabled: bool,
    api_fuzz_bundle: dict,
    api_fuzz_error: str | None,
    api_fuzz_enabled: bool,
    param_probe_rows: list[dict],
    param_probe_error: str | None,
    param_probe_enabled: bool,
    zero_day_rows: list[dict],
    zero_day_error: str | None,
    zero_day_enabled: bool,
    oauth_social_rows: list[dict],
    oauth_social_error: str | None,
    oauth_social_enabled: bool,
    infiltration_bundle: dict,
    infiltration_error: str | None,
    infiltration_enabled: bool,
    xss_mutations: list[dict],
    include_ai: bool,
    logic_scan_rows: list[dict] | None = None,
    logic_scan_enabled: bool = False,
    ai_mutator_rows: list[dict] | None = None,
    ai_mutator_error: str | None = None,
    ai_mutator_input: str | None = None,
    ai_mutator_kind: str | None = None,
    ai_mutator_enabled: bool = False,
    ai_mutator_slots: int = 0,
    nuclei_rows: list[dict] | None = None,
    nuclei_error: str | None = None,
    nuclei_enabled: bool = False,
) -> dict:
    counts = {"High": 0, "Medium": 0, "Low": 0}
    for r in secret_findings:
        counts[r.get("severity", "Low")] = counts.get(r.get("severity", "Low"), 0) + 1

    js_endpoints = sum(1 for r in js_rows if r.get("type") in _JS_ENDPOINT_KINDS)
    js_secrets = sum(1 for r in js_rows if r.get("type") not in _JS_ENDPOINT_KINDS)
    idor_critical = sum(1 for r in idor_rows if r.get("severity") == "Critical")
    idor_high = sum(1 for r in idor_rows if r.get("severity") == "High")

    _logic_rows = list(logic_scan_rows or [])
    _mut_rows = list(ai_mutator_rows or [])

    _nuclei = list(nuclei_rows or [])

    critical_findings = collect_critical_findings(
        secret_findings=secret_findings,
        xss_rows=xss_rows,
        idor_rows=idor_rows,
        sensitive_file_rows=sensitive_file_rows,
        path_rows=path_rows,
        param_probe_rows=param_probe_rows,
        broken_link_rows=broken_link_rows,
        zero_day_rows=zero_day_rows,
        oauth_social_rows=oauth_social_rows,
        cloud_rows=cloud_rows,
        js_rows=js_rows,
        api_fuzz_bundle=api_fuzz_bundle,
        infiltration_bundle=infiltration_bundle,
        nuclei_rows=_nuclei,
    )

    return {
        "tool": PROJECT_NAME,
        "version": APP_VERSION,
        "edition": APP_EDITION,
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
            "ports_open": sum(
                1 for r in port_rows if str(r.get("state", "")) == "open"
            ),
            "port_decision_followups": sum(
                1 for r in port_rows if str(r.get("state", "")) == "decision"
            ),
            "js_scan": js_enabled,
            "js_endpoints": js_endpoints,
            "js_secret_hits": js_secrets,
            "idor_scan": idor_enabled,
            "idor_findings": len(idor_rows),
            "idor_critical": idor_critical,
            "idor_high": idor_high,
            "wayback_scan": wayback_enabled,
            "wayback_live_hits": len(wayback_rows),
            "sensitive_file_scan": sensitive_file_enabled,
            "sensitive_file_findings": len(sensitive_file_rows),
            "html_source_scan": html_source_enabled,
            "html_source_findings": len(html_source_rows),
            "broken_link_scan": broken_link_enabled,
            "broken_link_takeover_flags": len(broken_link_rows),
            "api_fuzz_scan": api_fuzz_enabled,
            "api_fuzz_specs_found": len(api_fuzz_bundle.get("discovered", []) or []),
            "api_fuzz_idor": len(api_fuzz_bundle.get("idor", []) or []),
            "api_fuzz_injection": len(api_fuzz_bundle.get("injection", []) or []),
            "api_fuzz_graphql": len(api_fuzz_bundle.get("graphql", []) or []),
            "param_probe_scan": param_probe_enabled,
            "param_probe_findings": len(param_probe_rows),
            "zero_day_scan": zero_day_enabled,
            "zero_day_fuzz_hits": sum(
                1 for r in zero_day_rows if r.get("type") == "fuzz_hit"
            ),
            "zero_day_harvest_rows": sum(
                1
                for r in zero_day_rows
                if str(r.get("type", "")).startswith("harvest")
            ),
            "oauth_social_scan": oauth_social_enabled,
            "oauth_social_signals": len(oauth_social_rows),
            "oauth_social_high": sum(
                1 for r in oauth_social_rows if r.get("severity") == "High"
            ),
            "infiltration_enabled": infiltration_enabled,
            "infiltration_chain_extractions": len(infiltration_bundle.get("chain_extractions", [])),
            "infiltration_bypass_hits": len(infiltration_bundle.get("forbidden_bypass", [])),
            "infiltration_param_active": len(infiltration_bundle.get("param_active", [])),
            "infiltration_port_hits": len(infiltration_bundle.get("alternate_port_hits", [])),
            "ai_section_included": include_ai,
            "critical_findings_count": len(critical_findings),
            "logic_scan_enabled": logic_scan_enabled,
            "logic_scan_findings": len(_logic_rows),
            "logic_scan_high": sum(
                1 for r in _logic_rows if r.get("severity") == "High"
            ),
            "ai_mutator_variants": len(_mut_rows),
            "ai_mutator_enabled": ai_mutator_enabled,
            "ai_mutator_slots": ai_mutator_slots,
            "ai_mutator_ran": bool(ai_mutator_enabled),
            "nuclei_scan": nuclei_enabled,
            "nuclei_findings": len(_nuclei),
            "nuclei_critical": sum(
                1
                for r in _nuclei
                if str(r.get("severity", "")).strip().lower() == "critical"
            ),
            "nuclei_high": sum(
                1
                for r in _nuclei
                if str(r.get("severity", "")).strip().lower() == "high"
            ),
        },
        "critical_findings": critical_findings,
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
        "wayback": {
            "enabled": wayback_enabled,
            "error": wayback_error,
            "results": wayback_rows,
        },
        "sensitive_files": {
            "enabled": sensitive_file_enabled,
            "error": sensitive_file_error,
            "results": sensitive_file_rows,
        },
        "html_source": {
            "enabled": html_source_enabled,
            "error": html_source_error,
            "results": html_source_rows,
        },
        "broken_links": {
            "enabled": broken_link_enabled,
            "error": broken_link_error,
            "results": broken_link_rows,
        },
        "api_schema_fuzz": {
            "enabled": api_fuzz_enabled,
            "error": api_fuzz_error,
            "results": api_fuzz_bundle,
        },
        "param_probe": {
            "enabled": param_probe_enabled,
            "error": param_probe_error,
            "results": param_probe_rows,
        },
        "zero_day_hunter": {
            "enabled": zero_day_enabled,
            "error": zero_day_error,
            "results": zero_day_rows,
        },
        "oauth_social": {
            "enabled": oauth_social_enabled,
            "error": oauth_social_error,
            "results": oauth_social_rows,
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
        "infiltration": {
            "enabled": infiltration_enabled,
            "error": infiltration_error,
            "results": infiltration_bundle,
        },
        "ai_prompt_injection": (
            [
                {"id": i, "technique": name, "payload": payload}
                for i, (name, payload) in enumerate(AIAuditor.list_payloads(), start=1)
            ]
            if include_ai
            else []
        ),
        "logic_scan": {
            "enabled": logic_scan_enabled,
            "results": _logic_rows,
        },
        "ai_mutator": {
            "enabled": ai_mutator_enabled,
            "slots": ai_mutator_slots,
            "input_preview": (ai_mutator_input[:500] + "…")
            if ai_mutator_input and len(ai_mutator_input) > 500
            else ai_mutator_input,
            "kind_hint": ai_mutator_kind,
            "error": ai_mutator_error,
            "variants": _mut_rows,
        },
        "nuclei_results": {
            "enabled": nuclei_enabled,
            "error": nuclei_error,
            "findings": _nuclei_report_rows(_nuclei),
        },
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
    wayback_rows: list[dict],
    wayback_error: str | None,
    wayback_enabled: bool,
    sensitive_file_rows: list[dict],
    sensitive_file_error: str | None,
    sensitive_file_enabled: bool,
    html_source_rows: list[dict],
    html_source_error: str | None,
    html_source_enabled: bool,
    broken_link_rows: list[dict],
    broken_link_error: str | None,
    broken_link_enabled: bool,
    api_fuzz_bundle: dict,
    api_fuzz_error: str | None,
    api_fuzz_enabled: bool,
    param_probe_rows: list[dict],
    param_probe_error: str | None,
    param_probe_enabled: bool,
    zero_day_rows: list[dict],
    zero_day_error: str | None,
    zero_day_enabled: bool,
    oauth_social_rows: list[dict],
    oauth_social_error: str | None,
    oauth_social_enabled: bool,
    infiltration_bundle: dict,
    infiltration_error: str | None,
    infiltration_enabled: bool,
    xss_mutations: list[dict],
    include_ai: bool,
    logic_scan_rows: list[dict] | None = None,
    logic_scan_enabled: bool = False,
    ai_mutator_rows: list[dict] | None = None,
    ai_mutator_error: str | None = None,
    ai_mutator_input: str | None = None,
    ai_mutator_kind: str | None = None,
    ai_mutator_enabled: bool = False,
    ai_mutator_slots: int = 0,
    nuclei_rows: list[dict] | None = None,
    nuclei_error: str | None = None,
    nuclei_enabled: bool = False,
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
    lines.append(
        f"  Tool version    : {PROJECT_NAME} v{APP_VERSION} ({APP_EDITION})"
    )
    lines.append(f"  Copyright       : (c) {COPYRIGHT_YEAR} {DEVELOPER}")
    lines.append("")

    _nuclei_txt = list(nuclei_rows or [])

    critical_rows = collect_critical_findings(
        secret_findings=secret_findings,
        xss_rows=xss_rows,
        idor_rows=idor_rows,
        sensitive_file_rows=sensitive_file_rows,
        path_rows=path_rows,
        param_probe_rows=param_probe_rows,
        broken_link_rows=broken_link_rows,
        zero_day_rows=zero_day_rows,
        oauth_social_rows=oauth_social_rows,
        cloud_rows=cloud_rows,
        js_rows=js_rows,
        api_fuzz_bundle=api_fuzz_bundle,
        infiltration_bundle=infiltration_bundle,
        nuclei_rows=_nuclei_txt,
    )
    if critical_rows:
        lines.append(hr("*"))
        lines.append("  *** CRITICAL FINDINGS — PRIORITY TABLE (all scanners) ***")
        lines.append(hr("*"))
        lines.append(f"  Count: {len(critical_rows)}  (review before other sections)")
        lines.append("")
        lines.append(f"  {'#':<4}{'Area':<22} Detail")
        lines.append("  " + "-" * 74)
        for i, cr in enumerate(critical_rows, start=1):
            lines.append(
                f"  {i:<4}{_truncate(str(cr.get('area', '')), 20):<22} "
                f"{_truncate(str(cr.get('detail', '')), 48)}"
            )
            src = str(cr.get("source") or "").strip()
            if src:
                lines.append(f"      source: {_truncate(src, 72)}")
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
    lines.append("  [7] WAYBACK MACHINE (live replay of historical URLs)")
    lines.append(hr("-"))
    if not wayback_enabled:
        lines.append("  Wayback scan was not requested (use --wayback to include).")
    elif wayback_error:
        lines.append(f"  Wayback error: {wayback_error}")
    elif not wayback_rows:
        lines.append(
            "  No historical paths returned a 200/401/403 on the live host "
            "(or CDX returned no URLs)."
        )
    else:
        lines.append(f"  Live host signals: {len(wayback_rows)}")
        lines.append("")
        for i, r in enumerate(wayback_rows, start=1):
            lines.append(
                f"  #{i:>3} [{r.get('severity','Low'):<6}] HTTP {r.get('live_status','?')}  "
                f"path={_truncate(str(r.get('path','')), 120)}"
            )
            lines.append(f"       archive: {_truncate(str(r.get('historical_url','')), 200)}")
            lines.append(f"       live   : {_truncate(str(r.get('live_url','')), 200)}")
            note = r.get("note") or ""
            if note:
                lines.append(f"       note   : {_truncate(str(note), 200)}")
            lines.append("")
    lines.append("")

    lines.append(hr("-"))
    lines.append("  [8] SENSITIVE FILE HUNTER")
    lines.append(hr("-"))
    if not sensitive_file_enabled:
        lines.append("  Sensitive file hunter was not requested (use --sensitive to include).")
    elif sensitive_file_error:
        lines.append(f"  Sensitive file hunter error: {sensitive_file_error}")
    elif not sensitive_file_rows:
        lines.append("  No high-value paths returned interesting HTTP status codes.")
    else:
        lines.append(f"  Hits: {len(sensitive_file_rows)}")
        lines.append("")
        for i, r in enumerate(sensitive_file_rows, start=1):
            lines.append(
                f"  {i:>3}  {r.get('severity','Low'):<6}  "
                f"{str(r.get('state','')):<11} {str(r.get('status','')):>6}  "
                f"{_truncate(str(r.get('path','')), 200)}"
            )
            lines.append(f"        -> {_truncate(str(r.get('url','')), 200)}")
    lines.append("")

    lines.append(hr("-"))
    lines.append("  [9] HTML / COMMENT SOURCE RECON")
    lines.append(hr("-"))
    if not html_source_enabled:
        lines.append("  HTML source scan was not requested (use --source to include).")
    elif html_source_error:
        lines.append(f"  HTML source scanner error: {html_source_error}")
    elif not html_source_rows:
        lines.append("  No comments, meta hints, or URL-like attributes recovered.")
    else:
        lines.append(f"  Findings: {len(html_source_rows)}")
        lines.append("")
        for i, r in enumerate(html_source_rows, start=1):
            lines.append(
                f"  #{i:>3} [{r.get('severity','Low'):<6}] {r.get('type','?')}"
            )
            lines.append(f"       source : {_truncate(str(r.get('source_url','')), 200)}")
            lines.append(f"       match  : {_truncate(str(r.get('match','')), 200)}")
            note = r.get("note") or ""
            if note:
                lines.append(f"       note   : {_truncate(str(note), 200)}")
            lines.append("")
    lines.append("")

    lines.append(hr("-"))
    lines.append("  [10] BROKEN EXTERNAL LINKS (potential takeover)")
    lines.append(hr("-"))
    if not broken_link_enabled:
        lines.append("  Broken-link check was not requested (use --broken-links).")
    elif broken_link_error:
        lines.append(f"  Broken-link scanner error: {broken_link_error}")
    elif not broken_link_rows:
        lines.append(
            "  No dangling domains or dead social/profile signals from external links in source."
        )
    else:
        lines.append(f"  Potential takeover flags: {len(broken_link_rows)}")
        lines.append("")
        for i, r in enumerate(broken_link_rows, start=1):
            lines.append(
                f"  #{i:>3} [{r.get('severity','High'):<6}] {r.get('type','?')}  "
                f"evidence={r.get('evidence','')}"
            )
            lines.append(f"       url    : {_truncate(str(r.get('url','')), 200)}")
            lines.append(f"       host   : {_truncate(str(r.get('host','')), 120)}")
            lines.append(f"       page   : {_truncate(str(r.get('source_url','')), 200)}")
            lines.append(f"       note   : {_truncate(str(r.get('note','')), 240)}")
            lines.append("")
    lines.append("")

    lines.append(hr("-"))
    lines.append("  [11] API SCHEMA FUZZ (Swagger / OpenAPI / GraphQL)")
    lines.append(hr("-"))
    if not api_fuzz_enabled:
        lines.append(
            "  API schema fuzz was not requested (use --api-fuzz or --ai-fuzz)."
        )
    elif api_fuzz_error:
        lines.append(f"  API schema fuzz error: {api_fuzz_error}")
    else:
        disc = api_fuzz_bundle.get("discovered") or []
        gql = api_fuzz_bundle.get("graphql") or []
        aid = api_fuzz_bundle.get("idor") or []
        inj = api_fuzz_bundle.get("injection") or []
        if not disc and not gql and not aid and not inj:
            lines.append("  No public API documentation or fuzz signals (docs may require auth).")
        else:
            if disc:
                lines.append(f"  Specifications found: {len(disc)}")
                for i, r in enumerate(disc, start=1):
                    lines.append(
                        f"  #{i:>3} [{r.get('severity','Medium'):<6}] {r.get('flavor','?')}  "
                        f"{_truncate(str(r.get('url','')), 200)}"
                    )
                    lines.append(f"       {_truncate(str(r.get('note','')), 240)}")
                lines.append("")
            if gql:
                lines.append(f"  GraphQL signals: {len(gql)}")
                for i, r in enumerate(gql, start=1):
                    lines.append(
                        f"  #{i:>3} [{r.get('severity','High'):<6}] {r.get('type','?')}"
                    )
                    lines.append(f"       {_truncate(str(r.get('url','')), 200)}")
                    lines.append(f"       {_truncate(str(r.get('note','')), 240)}")
                lines.append("")
            if aid:
                lines.append(f"  IDOR from schema-derived GETs: {len(aid)}")
                for i, r in enumerate(aid[:40], start=1):
                    lines.append(
                        f"  #{i:>3} [{r.get('severity','High'):<6}] {r.get('kind','?')}  "
                        f"param={r.get('param','')}  ids {r.get('base_id')}→{r.get('test_id')}  "
                        f"HTTP {r.get('status','?')}"
                    )
                    lines.append(f"       {_truncate(str(r.get('url','')), 220)}")
                    lines.append(f"       {_truncate(str(r.get('note','')), 220)}")
                lines.append("")
            if inj:
                lines.append(f"  Injection heuristics: {len(inj)}")
                for i, r in enumerate(inj[:40], start=1):
                    lines.append(
                        f"  #{i:>3} [{r.get('severity','High'):<6}] {r.get('type','?')}  "
                        f"{r.get('method','?')} param={r.get('param','')}"
                    )
                    lines.append(f"       {_truncate(str(r.get('url','')), 220)}")
                    lines.append(f"       {_truncate(str(r.get('note','')), 240)}")
                lines.append("")
    lines.append("")

    lines.append(hr("-"))
    lines.append("  [12] HIDDEN PARAMETER PROBE (GET / POST / JSON)")
    lines.append(hr("-"))
    if not param_probe_enabled:
        lines.append("  Parameter probe was not requested (use --params to include).")
    elif param_probe_error:
        lines.append(f"  Parameter probe error: {param_probe_error}")
    elif not param_probe_rows:
        lines.append("  No response differences vs baseline for common parameter names.")
    else:
        lines.append(f"  Signals: {len(param_probe_rows)}")
        lines.append("")
        for i, r in enumerate(param_probe_rows, start=1):
            lines.append(
                f"  #{i:>3} [{r.get('severity','Low'):<6}] {r.get('method','?')}  "
                f"{r.get('param','')}=…"
            )
            lines.append(f"       url  : {_truncate(str(r.get('url','')), 200)}")
            lines.append(f"       note : {_truncate(str(r.get('note','')), 200)}")
            lines.append("")
    lines.append("")

    lines.append(hr("-"))
    lines.append("  [12A] ZERO-DAY HUNTER (HWID-gated logic-flaw fuzz)")
    lines.append(hr("-"))
    if not zero_day_enabled:
        lines.append("  Zero-Day Hunter was not requested (use --zero-day).")
    elif zero_day_error:
        lines.append(f"  Zero-Day Hunter: {zero_day_error}")
    elif not zero_day_rows:
        lines.append("  No rows returned.")
    else:
        fz = sum(1 for r in zero_day_rows if r.get("type") == "fuzz_hit")
        hv = sum(1 for r in zero_day_rows if str(r.get("type", "")).startswith("harvest"))
        lines.append(f"  Harvest + fuzz rows: {len(zero_day_rows)}  (fuzz signals={fz}, harvest={hv})")
        lines.append("")
        for i, r in enumerate(zero_day_rows, start=1):
            sev = r.get("severity", "Low")
            kind = r.get("type", "?")
            lines.append(f"  #{i:>3} [{sev:<8}] {kind}")
            if kind == "fuzz_hit":
                lines.append(
                    f"       param={r.get('param','')}  class={r.get('payload_class','')}  "
                    f"encoding={r.get('encoding','')}  HTTP {r.get('status','')}  "
                    f"{r.get('latency_ms','')}ms  phase={r.get('phase','')}"
                )
                lines.append(f"       url: {_truncate(str(r.get('url','')), 220)}")
            elif kind == "harvest_param":
                lines.append(
                    f"       param={r.get('param','')}  score={r.get('interest_score','')}  "
                    f"src={r.get('source','')}"
                )
            else:
                lines.append(f"       url: {_truncate(str(r.get('url','')), 220)}")
            note = r.get("note")
            if note:
                lines.append(f"       note: {_truncate(str(note), 240)}")
            lines.append("")
    lines.append("")

    lines.append(hr("-"))
    lines.append("  [12B] OAUTH / OIDC / SOCIAL LOGIN (PLAYTIKA BOUNTY MODE)")
    lines.append(hr("-"))
    if not oauth_social_enabled:
        lines.append(
            "  OAuth / social probes were not run (use --playtika-bounty for Playtika policy "
            "header + OAuth checks)."
        )
    elif oauth_social_error:
        lines.append(f"  OAuth / social scanner: {oauth_social_error}")
    elif not oauth_social_rows:
        lines.append("  No OAuth/OIDC/social signals in this pass (or target returned errors).")
    else:
        hi = sum(1 for r in oauth_social_rows if r.get("severity") == "High")
        lines.append(
            f"  Signals: {len(oauth_social_rows)}  (High={hi})  "
            "[dim]redirect_uri + linking surfaces; validate manually.[/dim]"
        )
        lines.append("")
        for i, r in enumerate(oauth_social_rows, start=1):
            sev = r.get("severity", "Low")
            kind = r.get("type", "?")
            lines.append(f"  #{i:>3} [{sev:<8}] {kind}")
            lines.append(f"       url  : {_truncate(str(r.get('url','')), 220)}")
            lines.append(f"       detail: {_truncate(str(r.get('detail','')), 260)}")
            note = r.get("note")
            if note:
                lines.append(f"       note : {_truncate(str(note), 220)}")
            lines.append("")
    lines.append("")

    lines.append(hr("-"))
    lines.append("  [13] CLOUD STORAGE EXPOSURE")
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
    lines.append("  [14] SENSITIVE PATH DISCOVERY")
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
    lines.append("  [15] OPEN TCP PORTS")
    lines.append(hr("-"))
    if not port_enabled:
        lines.append("  Port scan was not requested (use --port to include).")
    elif port_error:
        lines.append(f"  Port scanner error: {port_error}")
    elif not port_rows:
        lines.append("  No probed ports responded.")
    else:
        n_open = sum(1 for r in port_rows if str(r.get("state", "")) == "open")
        n_dec = sum(1 for r in port_rows if str(r.get("state", "")) == "decision")
        lines.append(
            f"  Open TCP port rows: {n_open}"
            + (f"  |  Decision-engine follow-ups: {n_dec}" if n_dec else "")
        )
        lines.append("")
        lines.append(f"  {'#':>3}  {'SEV':<6}  {'PORT':>6}  {'STATE':<10}  {'SERVICE':<22} HOST")
        for i, r in enumerate(port_rows, start=1):
            lines.append(
                f"  {i:>3}  {r.get('severity','Medium'):<6}  "
                f"{str(r.get('port','')):>6}  {str(r.get('state','open')):<10}  "
                f"{str(r.get('service','')):<22} "
                f"{_truncate(str(r.get('host','')), 200)}"
            )
            if r.get("decision_detail"):
                lines.append(
                    f"          → {_truncate(str(r.get('decision_detail','')), 240)}"
                )
    lines.append("")

    lines.append(hr("-"))
    lines.append("  [15b] NUCLEI VULNERABILITY SCAN (ProjectDiscovery)")
    lines.append(hr("-"))
    if not nuclei_enabled:
        lines.append("  Nuclei was not requested (use --nuclei to include).")
    elif nuclei_error and not _nuclei_txt:
        lines.append(f"  Nuclei error: {nuclei_error}")
    elif not _nuclei_txt:
        lines.append("  No template matches on this target (or empty run).")
        if nuclei_error:
            lines.append(f"  Note: {nuclei_error}")
    else:
        crit_n = sum(
            1
            for r in _nuclei_txt
            if str(r.get("severity", "")).strip().lower() == "critical"
        )
        hi_n = sum(
            1
            for r in _nuclei_txt
            if str(r.get("severity", "")).strip().lower() == "high"
        )
        lines.append(
            f"  Template matches: {len(_nuclei_txt)}  "
            f"(Critical={crit_n}  High={hi_n})"
        )
        if nuclei_error:
            lines.append(f"  Note: {nuclei_error}")
        lines.append("")
        lines.append(f"  {'#':>3}  {'SEV':<10}  {'TEMPLATE ID':<28}  URL")
        for i, r in enumerate(_nuclei_txt, start=1):
            tid = str(r.get("template_id", "") or "")
            url = str(r.get("matched_at", "") or r.get("host", "") or "")
            sev = str(r.get("severity", "") or "")
            lines.append(
                f"  {i:>3}  {sev:<10}  {_truncate(tid, 28):<28}  {_truncate(url, 120)}"
            )
            name = str(r.get("name", "") or "").strip()
            if name:
                lines.append(f"       name: {_truncate(name, 200)}")
    lines.append("")

    lines.append(hr("-"))
    lines.append("  [16] AUTONOMOUS INFILTRATION (smart follow-up)")
    lines.append(hr("-"))
    if not infiltration_enabled:
        lines.append("  Not requested (use --infiltrate).")
    elif infiltration_error:
        lines.append(f"  Engine error: {infiltration_error}")
    else:
        ce = infiltration_bundle.get("chain_extractions") or []
        fb = infiltration_bundle.get("forbidden_bypass") or []
        pa = infiltration_bundle.get("param_active") or []
        ck = infiltration_bundle.get("cookie_audit") or []
        ap = infiltration_bundle.get("alternate_port_hits") or []
        ar = infiltration_bundle.get("ai_recommendations") or []
        lines.append(
            f"  Chain extractions: {len(ce)}  |  403 bypass hits: {len(fb)}  |  "
            f"Active param probes: {len(pa)}  |  Cookies audited: {len(ck)}  |  "
            f"Alternate-port HTTP: {len(ap)}"
        )
        lines.append("")
        if ce:
            lines.append("  Credential-like extractions (heuristic):")
            for i, r in enumerate(ce[:20], start=1):
                lines.append(
                    f"  #{i:>3} [{r.get('severity','High'):<6}] {r.get('subtype','?')}"
                )
                lines.append(f"       preview: {_truncate(str(r.get('match_preview','')), 200)}")
                lines.append(f"       source : {_truncate(str(r.get('source_url','')), 200)}")
            lines.append("")
        if fb:
            lines.append("  Forbidden bypass (softer status):")
            for i, r in enumerate(fb[:20], start=1):
                lines.append(
                    f"  #{i:>3} HTTP {r.get('status','?')}  "
                    f"{_truncate(str(r.get('url','')), 200)}"
                )
                lines.append(f"       note: {_truncate(str(r.get('note','')), 200)}")
            lines.append("")
        if pa:
            lines.append("  Active parameter probes:")
            for i, r in enumerate(pa[:20], start=1):
                lines.append(
                    f"  #{i:>3} [{r.get('severity','Medium'):<6}] {r.get('type','?')}  "
                    f"param={r.get('param','')}"
                )
                lines.append(f"       {_truncate(str(r.get('note','')), 200)}")
                lines.append(f"       url: {_truncate(str(r.get('url','')), 200)}")
            lines.append("")
        if ck:
            lines.append("  Cookie flag audit:")
            for i, r in enumerate(ck[:24], start=1):
                lines.append(
                    f"  #{i:>3} {r.get('cookie_name','')}  "
                    f"HttpOnly={'yes' if r.get('httponly') else 'no'}  "
                    f"Secure={'yes' if r.get('secure') else 'no'}"
                )
                lines.append(f"       {_truncate(str(r.get('risk','')), 200)}")
            lines.append("")
        if ap:
            lines.append("  Alternate-port HTTP probes:")
            for i, r in enumerate(ap[:20], start=1):
                lines.append(
                    f"  #{i:>3} port {r.get('port','?')} HTTP {r.get('status','?')}  "
                    f"{_truncate(str(r.get('url','')), 200)}"
                )
            lines.append("")
        if ar:
            lines.append("  AI auditor — next moves (rule-based):")
            for i, r in enumerate(ar, start=1):
                lines.append(
                    f"  #{i:>3} [{str(r.get('priority','')).upper()}] "
                    f"{r.get('action','')}"
                )
                lines.append(f"       {_truncate(str(r.get('rationale','')), 240)}")
                lines.append(f"       {_truncate(str(r.get('execute_hint','')), 240)}")
            lines.append("")
        if not (ce or fb or pa or ck or ap):
            lines.append(
                "  No follow-up rows; combine --infiltrate with --brute, --sensitive, "
                "--params, and/or --port for richer signals."
            )
    lines.append("")

    _logic_rep = list(logic_scan_rows or [])
    _mut_rep = list(ai_mutator_rows or [])

    lines.append(hr("-"))
    lines.append("  [17] LOGIC SCAN (harvested IDOR / price manipulation surfaces)")
    lines.append(hr("-"))
    if not logic_scan_enabled:
        lines.append("  Not requested (use --logic-scan; best with --js, --brute, --params).")
    elif not _logic_rep:
        lines.append(
            "  No heuristic hits — harvest more endpoints (e.g. --js --brute --params) "
            "or confirm target exposes cart/order/id URLs."
        )
    else:
        lines.append(f"  Heuristic rows: {len(_logic_rep)}")
        lines.append("")
        for i, r in enumerate(_logic_rep[:48], start=1):
            lines.append(
                f"  #{i:>3} [{r.get('severity','Medium'):<6}] {r.get('subtype','?')}"
            )
            lines.append(f"       endpoint: {_truncate(str(r.get('endpoint','')), 220)}")
            lines.append(f"       note    : {_truncate(str(r.get('note','')), 220)}")
        lines.append("")

    lines.append(hr("-"))
    lines.append("  [18] AI-MUTATOR (WAF-oriented payload variants)")
    lines.append(hr("-"))
    if not ai_mutator_enabled:
        lines.append(
            "  Not run (use --ai-mutate with --params / --xss to discover parameter slots)."
        )
    else:
        lines.append(
            f"  Mode: per discovered parameter  |  slots: {ai_mutator_slots}  |  "
            f"total variants: {len(_mut_rep)}  |  kind hint: {ai_mutator_kind or 'auto'}"
        )
        if ai_mutator_input:
            lines.append(f"  Note: {_truncate(ai_mutator_input, 200)}")
        if ai_mutator_error:
            lines.append(f"  LLM / transport: {ai_mutator_error}")
        lines.append("")
        for row in _mut_rep[:36]:
            p = str(row.get("param") or "")
            pref = f"[{escape(p)[:32]}] " if p else ""
            lines.append(
                f"  #{row.get('index','?')} {pref}[{str(row.get('source','?')):<10}] "
                f"{_truncate(str(row.get('payload','')), 180)}"
            )
        lines.append("")

    lines.append(hr("-"))
    lines.append("  [19] AI / PROMPT-INJECTION REFERENCE")
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
    lines.append(
        "="
        + _center(
            f"Report generated by {PROJECT_NAME} v{APP_VERSION} ({APP_EDITION})"
        )
        + "="
    )
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
                    f"{PROJECT_NAME} v{APP_VERSION} ({APP_EDITION})  |  "
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
        (
            "Tool version",
            f"{PROJECT_NAME} v{json_body.get('version', APP_VERSION)} "
            f"({json_body.get('edition', APP_EDITION)})",
        ),
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
        f"Wayback live hits      : {summary.get('wayback_live_hits', 0)}",
        f"Sensitive file hits    : {summary.get('sensitive_file_findings', 0)}",
        f"HTML source hints      : {summary.get('html_source_findings', 0)}",
        f"Broken-link takeover   : {summary.get('broken_link_takeover_flags', 0)}",
        (
            "API schema fuzz        : "
            f"{'on' if summary.get('api_fuzz_scan') else 'off'}  "
            f"(specs={summary.get('api_fuzz_specs_found', 0)}, "
            f"idor={summary.get('api_fuzz_idor', 0)}, "
            f"inj={summary.get('api_fuzz_injection', 0)}, "
            f"gql={summary.get('api_fuzz_graphql', 0)})"
        ),
        f"Hidden param signals   : {summary.get('param_probe_findings', 0)}",
        (
            "Zero-Day Hunter        : "
            f"{'on' if summary.get('zero_day_scan') else 'off'}  "
            f"(fuzz_hits={summary.get('zero_day_fuzz_hits', 0)}, "
            f"harvest={summary.get('zero_day_harvest_rows', 0)})"
        ),
        (
            "OAuth / social (bounty): "
            f"{'on' if summary.get('oauth_social_scan') else 'off'}  "
            f"(signals={summary.get('oauth_social_signals', 0)}, "
            f"High={summary.get('oauth_social_high', 0)})"
        ),
        f"Cloud findings         : {summary.get('cloud_findings', 0)}",
        f"Sensitive path hits    : {summary.get('path_findings', 0)}",
        f"Open TCP ports         : {summary.get('ports_open', 0)}",
        (
            "Nuclei (templates)      : "
            f"{'on' if summary.get('nuclei_scan') else 'off'}  "
            f"(matches={summary.get('nuclei_findings', 0)}, "
            f"Critical={summary.get('nuclei_critical', 0)}, "
            f"High={summary.get('nuclei_high', 0)})"
        ),
        (
            "Autonomous infiltration : "
            f"{'on' if summary.get('infiltration_enabled') else 'off'}  "
            f"(chain={summary.get('infiltration_chain_extractions', 0)}, "
            f"bypass={summary.get('infiltration_bypass_hits', 0)}, "
            f"param={summary.get('infiltration_param_active', 0)}, "
            f"alt-port={summary.get('infiltration_port_hits', 0)})"
        ),
    ]
    for line in summary_lines:
        _mc(pdf, 5.5, line)
    pdf.ln(2)

    crit_pdf = json_body.get("critical_findings") or []
    if crit_pdf:
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(180, 0, 0)
        pdf.cell(0, 8, _ascii("Critical findings — priority review"), **NEXT_LINE)
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 5, _ascii(f"Total Critical items: {len(crit_pdf)}"), **NEXT_LINE)
        pdf.ln(1)
        for i, cr in enumerate(crit_pdf[:80], start=1):
            area = str(cr.get("area", ""))
            detail = str(cr.get("detail", ""))[:200]
            src = str(cr.get("source", ""))[:120]
            _mc(
                pdf,
                4.8,
                f"#{i} [{area}] {detail}"
                + (f"\n    source: {src}" if src else ""),
            )
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

    _section("7. Wayback Machine (historical URLs, live replay)")
    wb_block = json_body.get("wayback", {})
    if not wb_block.get("enabled"):
        _mc(pdf, 5, "Not requested (use --wayback).")
    elif wb_block.get("error"):
        _mc(pdf, 5, f"Scanner error: {wb_block['error']}")
    else:
        _render_rows(
            wb_block.get("results", []),
            lambda i, r: [
                f"#{i} [{r.get('severity','Low')}] HTTP {r.get('live_status','?')}",
                f"    path: {str(r.get('path',''))[:160]}",
                f"    live: {r.get('live_url','')}",
                f"    archive: {str(r.get('historical_url',''))[:180]}",
            ],
        )

    _section("8. Sensitive file hunter")
    sf_block = json_body.get("sensitive_files", {})
    if not sf_block.get("enabled"):
        _mc(pdf, 5, "Not requested (use --sensitive).")
    elif sf_block.get("error"):
        _mc(pdf, 5, f"Scanner error: {sf_block['error']}")
    else:
        _render_rows(
            sf_block.get("results", []),
            lambda i, r: [
                f"#{i} [{r.get('severity','Low')}] state={r.get('state','')}  "
                f"status={r.get('status','')}",
                f"    path: {r.get('path','')}",
                f"    url : {r.get('url','')}",
            ],
        )

    _section("9. HTML / comment source recon")
    html_block = json_body.get("html_source", {})
    if not html_block.get("enabled"):
        _mc(pdf, 5, "Not requested (use --source).")
    elif html_block.get("error"):
        _mc(pdf, 5, f"Scanner error: {html_block['error']}")
    else:
        _render_rows(
            html_block.get("results", []),
            lambda i, r: [
                f"#{i} [{r.get('severity','Low')}] {r.get('type','?')}",
                f"    source: {r.get('source_url','')}",
                f"    match : {str(r.get('match',''))[:160]}",
                f"    note  : {str(r.get('note',''))[:160]}",
            ],
        )

    _section("10. Broken external links (potential takeover)")
    bl_block = json_body.get("broken_links", {})
    if not bl_block.get("enabled"):
        _mc(pdf, 5, "Not requested (use --broken-links).")
    elif bl_block.get("error"):
        _mc(pdf, 5, f"Scanner error: {bl_block['error']}")
    else:
        _render_rows(
            bl_block.get("results", []),
            lambda i, r: [
                f"#{i} [{r.get('severity','High')}] {r.get('type','?')}  "
                f"evidence={r.get('evidence','')}",
                f"    url : {str(r.get('url',''))[:220]}",
                f"    host: {r.get('host','')}",
                f"    note: {str(r.get('note',''))[:220]}",
            ],
        )

    _section("11. API schema fuzz (Swagger / OpenAPI / GraphQL)")
    af_block = json_body.get("api_schema_fuzz", {}) or {}
    if not af_block.get("enabled"):
        _mc(pdf, 5, "Not requested (use --api-fuzz or --ai-fuzz).")
    elif af_block.get("error"):
        _mc(pdf, 5, f"Scanner error: {af_block['error']}")
    else:
        res = af_block.get("results") or {}
        disc = res.get("discovered") or []
        gql = res.get("graphql") or []
        aid = res.get("idor") or []
        inj = res.get("injection") or []
        if disc:
            _mc(pdf, 5, "API specifications discovered:")
            _render_rows(
                disc,
                lambda i, r: [
                    f"#{i} [{r.get('severity','Medium')}] {r.get('flavor','?')}",
                    f"    url: {str(r.get('url',''))[:200]}",
                    f"    note: {str(r.get('note',''))[:220]}",
                ],
            )
        if gql:
            _mc(pdf, 5, "GraphQL:")
            _render_rows(
                gql,
                lambda i, r: [
                    f"#{i} [{r.get('severity','High')}] {r.get('type','?')}",
                    f"    {str(r.get('note',''))[:240]}",
                ],
            )
        if aid:
            _mc(pdf, 5, "IDOR (schema-derived GET mutations):")
            _render_rows(
                aid,
                lambda i, r: [
                    f"#{i} [{r.get('severity','?')}] {r.get('kind','?')} param={r.get('param','')} "
                    f"ids {r.get('base_id')}->{r.get('test_id')} HTTP {r.get('status','?')}",
                    f"    url: {str(r.get('url',''))[:220]}",
                    f"    note: {str(r.get('note',''))[:220]}",
                ],
            )
        if inj:
            _mc(pdf, 5, "Injection heuristics (SQLi):")
            _render_rows(
                inj,
                lambda i, r: [
                    f"#{i} [{r.get('type','?')}] {r.get('method','?')} param={r.get('param','')}",
                    f"    url: {str(r.get('url',''))[:220]}",
                    f"    note: {str(r.get('note',''))[:240]}",
                ],
            )
        if not (disc or gql or aid or inj):
            _mc(pdf, 5, "No API documentation or fuzz signals in this pass.")

    _section("12. Hidden parameter probe (GET / POST / JSON)")
    pp_block = json_body.get("param_probe", {})
    if not pp_block.get("enabled"):
        _mc(pdf, 5, "Not requested (use --params).")
    elif pp_block.get("error"):
        _mc(pdf, 5, f"Scanner error: {pp_block['error']}")
    else:
        _render_rows(
            pp_block.get("results", []),
            lambda i, r: [
                f"#{i} [{r.get('severity','Low')}] {r.get('method','?')} param={r.get('param','')}",
                f"    url : {r.get('url','')}",
                f"    note: {str(r.get('note',''))[:180]}",
            ],
        )

    _section("12b. Zero-Day Hunter (logic-flaw fuzz)")
    zd_block = json_body.get("zero_day_hunter", {}) or {}
    if not zd_block.get("enabled"):
        _mc(pdf, 5, "Not requested (use --zero-day).")
    elif zd_block.get("error"):
        _mc(pdf, 5, str(zd_block.get("error", "")))
    else:
        _render_rows(
            zd_block.get("results", []),
            lambda i, r: [
                f"#{i} [{r.get('severity','Low')}] {r.get('type','?')}",
                f"    {str(r.get('url', r.get('param', r.get('note', ''))))[:200]}",
                f"    note: {str(r.get('note',''))[:200]}",
            ],
        )

    _section("12c. OAuth / OIDC / social login (Playtika bounty)")
    oauth_block = json_body.get("oauth_social", {}) or {}
    if not oauth_block.get("enabled"):
        _mc(pdf, 5, "Not requested (use --playtika-bounty).")
    elif oauth_block.get("error"):
        _mc(pdf, 5, str(oauth_block.get("error", "")))
    else:
        _render_rows(
            oauth_block.get("results", []),
            lambda i, r: [
                f"#{i} [{r.get('severity','Low')}] {r.get('type','?')}",
                f"    url: {str(r.get('url',''))[:200]}",
                f"    {str(r.get('detail',''))[:220]}",
            ],
        )

    _section("13. Cloud storage exposure")
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

    _section("14. Sensitive path discovery")
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

    _section("15. Open TCP ports")
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

    _section("16. Nuclei Vulnerability Scan (ProjectDiscovery)")
    nuc_block = json_body.get("nuclei_results") or {}
    if not nuc_block.get("enabled"):
        _mc(pdf, 5, "Not requested (use --nuclei).")
    elif nuc_block.get("error") and not (nuc_block.get("findings") or []):
        _mc(pdf, 5, f"Scanner note: {nuc_block.get('error', '')}")
    else:
        nuc_rows = nuc_block.get("findings") or []
        if nuc_block.get("error"):
            _mc(pdf, 5, f"Note: {nuc_block.get('error', '')}")
        if not nuc_rows:
            _mc(pdf, 5, "No template matches on this target.")
        else:
            _render_rows(
                nuc_rows,
                lambda i, r: [
                    f"#{i}  ID: {str(r.get('template_id','') or '')[:80]}",
                    f"    Severity: {str(r.get('severity','') or '')}",
                    f"    URL: {str(r.get('matched_at','') or r.get('host','') or '')[:220]}",
                ]
                + (
                    [f"    Name: {str(r.get('name',''))[:200]}"]
                    if str(r.get("name", "")).strip()
                    else []
                ),
            )

    inf_block = json_body.get("infiltration", {}) or {}
    if inf_block.get("enabled"):
        _section("17. Autonomous infiltration (smart follow-up)")
        if inf_block.get("error"):
            _mc(pdf, 5, f"Engine error: {inf_block['error']}")
        else:
            res = inf_block.get("results") or {}
            ce = res.get("chain_extractions") or []
            fb = res.get("forbidden_bypass") or []
            pa = res.get("param_active") or []
            ck = res.get("cookie_audit") or []
            ap = res.get("alternate_port_hits") or []
            ar = res.get("ai_recommendations") or []
            if ce:
                _mc(pdf, 5, "Credential-like extractions (heuristic):")
                _render_rows(
                    ce,
                    lambda i, r: [
                        f"#{i} [{r.get('subtype','?')}]",
                        f"    preview: {str(r.get('match_preview',''))[:200]}",
                        f"    source: {str(r.get('source_url',''))[:200]}",
                    ],
                )
            if fb:
                _mc(pdf, 5, "Forbidden bypass (softer HTTP status):")
                _render_rows(
                    fb,
                    lambda i, r: [
                        f"#{i} HTTP {r.get('status','?')}",
                        f"    url: {str(r.get('url',''))[:200]}",
                        f"    note: {str(r.get('note',''))[:200]}",
                    ],
                )
            if pa:
                _mc(pdf, 5, "Active parameter probes (SQLi / XSS / LFI heuristics):")
                _render_rows(
                    pa,
                    lambda i, r: [
                        f"#{i} [{r.get('type','?')}] param={r.get('param','')}",
                        f"    note: {str(r.get('note',''))[:220]}",
                        f"    url: {str(r.get('url',''))[:220]}",
                    ],
                )
            if ck:
                _mc(pdf, 5, "Set-Cookie flag audit:")
                _render_rows(
                    ck,
                    lambda i, r: [
                        f"#{i} {r.get('cookie_name','')}",
                        f"    HttpOnly={'yes' if r.get('httponly') else 'no'}  "
                        f"Secure={'yes' if r.get('secure') else 'no'}",
                        f"    {str(r.get('risk',''))[:220]}",
                    ],
                )
            if ap:
                _mc(pdf, 5, "Alternate-port HTTP probes:")
                _render_rows(
                    ap,
                    lambda i, r: [
                        f"#{i} port {r.get('port','?')} HTTP {r.get('status','?')}",
                        f"    url: {str(r.get('url',''))[:200]}",
                    ],
                )
            if ar:
                _mc(pdf, 5, "Rule-based next-move hints (AI auditor playbook):")
                _render_rows(
                    ar,
                    lambda i, r: [
                        f"#{i} [{r.get('priority','?')}] {r.get('action','')}",
                        f"    {str(r.get('rationale',''))[:240]}",
                        f"    hint: {str(r.get('execute_hint',''))[:240]}",
                    ],
                )
            if not (ce or fb or pa or ck or ap or ar):
                _mc(
                    pdf,
                    5,
                    "No follow-up rows; combine --infiltrate with --brute, --sensitive, "
                    "--params, and/or --port.",
                )

    log_block = json_body.get("logic_scan") or {}
    _section("18. Logic scan (IDOR / price triage)")
    if not log_block.get("enabled"):
        _mc(pdf, 5, "Not requested (use --logic-scan).")
    else:
        rows = log_block.get("results") or []
        if not rows:
            _mc(
                pdf,
                5,
                "No heuristic hits — combine --logic-scan with --js, --brute, and/or --params.",
            )
        else:
            _render_rows(
                rows,
                lambda i, r: [
                    f"#{i} [{r.get('severity','Medium')}] {r.get('subtype','?')}",
                    f"    endpoint: {str(r.get('endpoint',''))[:220]}",
                    f"    note: {str(r.get('note',''))[:240]}",
                ],
            )

    mut_block = json_body.get("ai_mutator") or {}
    _section("19. AI-Mutator payload variants")
    preview = mut_block.get("input_preview")
    variants = mut_block.get("variants") or []
    slots_n = int(mut_block.get("slots") or 0)
    if not mut_block.get("enabled"):
        _mc(pdf, 5, "Not run (use --ai-mutate with --params / --xss).")
    elif slots_n == 0 and not variants:
        _mc(
            pdf,
            5,
            "No parameter slots discovered (enable --params / --xss or add ?query to --url).",
        )
        if mut_block.get("error"):
            _mc(pdf, 5, str(mut_block.get("error"))[:400])
    else:
        _mc(
            pdf,
            5,
            f"Per-parameter mode: {slots_n} slot(s), {len(variants)} variant row(s).",
        )
        if mut_block.get("kind_hint"):
            _mc(pdf, 5, f"Kind hint: {mut_block.get('kind_hint')}")
        if preview:
            _mc(pdf, 5, f"Note: {str(preview)[:240]}")
        if mut_block.get("error"):
            _mc(pdf, 5, f"LLM / transport note: {mut_block.get('error')}")
        if variants:
            _render_rows(
                variants,
                lambda i, r: [
                    f"#{r.get('index', i)} param={r.get('param','?')} [{r.get('source','?')}]",
                    f"    {str(r.get('payload',''))[:500]}",
                ],
            )

    ai_block = json_body.get("ai_prompt_injection", []) or []
    if ai_block:
        _section("20. AI / prompt-injection reference")
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
    wayback_rows: list[dict],
    wayback_error: str | None,
    wayback_enabled: bool,
    sensitive_file_rows: list[dict],
    sensitive_file_error: str | None,
    sensitive_file_enabled: bool,
    html_source_rows: list[dict],
    html_source_error: str | None,
    html_source_enabled: bool,
    broken_link_rows: list[dict],
    broken_link_error: str | None,
    broken_link_enabled: bool,
    api_fuzz_bundle: dict,
    api_fuzz_error: str | None,
    api_fuzz_enabled: bool,
    param_probe_rows: list[dict],
    param_probe_error: str | None,
    param_probe_enabled: bool,
    zero_day_rows: list[dict],
    zero_day_error: str | None,
    zero_day_enabled: bool,
    oauth_social_rows: list[dict],
    oauth_social_error: str | None,
    oauth_social_enabled: bool,
    infiltration_bundle: dict,
    infiltration_error: str | None,
    infiltration_enabled: bool,
    xss_mutations: list[dict],
    include_ai: bool,
    logic_scan_rows: list[dict] | None = None,
    logic_scan_enabled: bool = False,
    ai_mutator_rows: list[dict] | None = None,
    ai_mutator_error: str | None = None,
    ai_mutator_input: str | None = None,
    ai_mutator_kind: str | None = None,
    ai_mutator_enabled: bool = False,
    ai_mutator_slots: int = 0,
    nuclei_rows: list[dict] | None = None,
    nuclei_error: str | None = None,
    nuclei_enabled: bool = False,
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
        wayback_rows=wayback_rows,
        wayback_error=wayback_error,
        wayback_enabled=wayback_enabled,
        sensitive_file_rows=sensitive_file_rows,
        sensitive_file_error=sensitive_file_error,
        sensitive_file_enabled=sensitive_file_enabled,
        html_source_rows=html_source_rows,
        html_source_error=html_source_error,
        html_source_enabled=html_source_enabled,
        broken_link_rows=broken_link_rows,
        broken_link_error=broken_link_error,
        broken_link_enabled=broken_link_enabled,
        api_fuzz_bundle=api_fuzz_bundle,
        api_fuzz_error=api_fuzz_error,
        api_fuzz_enabled=api_fuzz_enabled,
        param_probe_rows=param_probe_rows,
        param_probe_error=param_probe_error,
        param_probe_enabled=param_probe_enabled,
        zero_day_rows=zero_day_rows,
        zero_day_error=zero_day_error,
        zero_day_enabled=zero_day_enabled,
        oauth_social_rows=oauth_social_rows,
        oauth_social_error=oauth_social_error,
        oauth_social_enabled=oauth_social_enabled,
        infiltration_bundle=infiltration_bundle,
        infiltration_error=infiltration_error,
        infiltration_enabled=infiltration_enabled,
        xss_mutations=xss_mutations,
        include_ai=include_ai,
        logic_scan_rows=logic_scan_rows,
        logic_scan_enabled=logic_scan_enabled,
        ai_mutator_rows=ai_mutator_rows,
        ai_mutator_error=ai_mutator_error,
        ai_mutator_input=ai_mutator_input,
        ai_mutator_kind=ai_mutator_kind,
        ai_mutator_enabled=ai_mutator_enabled,
        ai_mutator_slots=ai_mutator_slots,
        nuclei_rows=nuclei_rows,
        nuclei_error=nuclei_error,
        nuclei_enabled=nuclei_enabled,
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
