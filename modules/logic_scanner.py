# Developed by Channa Sandeepa | OmniScan-AI v2.5 | Copyright 2026
"""Passive business-logic triage on harvested URLs (JS, paths, params).

Flags IDOR-shaped routes and checkout/price-style parameters for manual review.
Does not send exploit traffic. Authorized testing only.
"""

from __future__ import annotations

import re
from typing import Iterable
from urllib.parse import parse_qsl, urljoin, urlparse

from .idor_scanner import IDORScanner

SEVERITY_HIGH = "High"
SEVERITY_MEDIUM = "Medium"

_JS_ENDPOINT_TYPES: frozenset[str] = frozenset(
    {
        "endpoint_url",
        "endpoint_api_path",
        "fetch_call",
        "axios_call",
        "xhr_open",
        "websocket_url",
        "dynamic_import",
        "route_path_string",
        "base_url_concat",
        "relative_api_path",
    }
)

_CHECKOUT_PATH = re.compile(
    r"(?i)(/cart\b|/checkout\b|/basket\b|/payment\b|/pay/|/order\b|/orders\b|"
    r"/invoice\b|/subscribe|/subscription\b|/pricing\b|/quote\b)"
)
_PRICE_TOKEN = re.compile(
    r"(?i)\b(price|amount|total|cost|discount|coupon|promo|fee|tax|subtotal|"
    r"grand_?total|line_?total|qty|quantity)\b"
)
_PATH_DIGIT_SEG = re.compile(r"/(\d{1,12})(?=/|/?$|\?)")


def _abs_url(base: str, fragment: str) -> str:
    frag = (fragment or "").strip()
    if not frag or frag.startswith("#"):
        return ""
    root = base if "://" in base else f"https://{base}"
    if frag.startswith("http://") or frag.startswith("https://"):
        u = frag.split("?", 1)[0].strip()
        return u
    try:
        return urljoin(root if root.endswith("/") else root + "/", frag).split("?", 1)[0].strip()
    except Exception:
        return ""


def _iter_candidate_urls(
    target_url: str,
    js_rows: list[dict],
    path_rows: list[dict],
    param_rows: list[dict],
) -> Iterable[tuple[str, str]]:
    """Yield (url, source_label)."""
    base = target_url if "://" in target_url else f"https://{target_url}"
    seen: set[str] = set()

    def emit(u: str, label: str):
        u = (u or "").strip()
        if not u:
            return
        key = u.split("?", 1)[0]
        if key in seen:
            return
        seen.add(key)
        yield (u, label)

    for r in js_rows:
        if r.get("type") not in _JS_ENDPOINT_TYPES:
            continue
        m = str(r.get("match", "")).strip()
        abs_u = _abs_url(base, m)
        if abs_u:
            yield from emit(abs_u, "js_harvest")

    for r in path_rows:
        u = str(r.get("url", "") or "").strip()
        if u:
            yield from emit(u, "path_brute")

    for r in param_rows:
        u = str(r.get("url", "") or "").split("?", 1)[0].strip()
        if u:
            yield from emit(u, "param_probe")


def harvest_logic_signals(
    target_url: str,
    js_rows: list[dict],
    path_rows: list[dict],
    param_rows: list[dict],
) -> list[dict]:
    """Return High/Medium heuristic rows for IDOR-like or price/cart flows."""
    findings: list[dict] = []
    dedupe: set[tuple[str, str]] = set()
    scanner = IDORScanner()

    param_name_hits: set[str] = set()
    for r in param_rows:
        p = str(r.get("param", "") or "").strip()
        if p and _PRICE_TOKEN.search(p):
            param_name_hits.add(p.lower())

    for url, source in _iter_candidate_urls(target_url, js_rows, path_rows, param_rows):
        parsed = urlparse(url)
        path = parsed.path or ""
        query = parsed.query or ""

        q_params = [k for k, _ in parse_qsl(query, keep_blank_values=True)]
        price_in_query = any(
            _PRICE_TOKEN.search(k) for k in q_params
        )
        id_like_param = any(scanner.ID_PARAM_PATTERN.match(k) for k in q_params)

        digit_segments = _PATH_DIGIT_SEG.findall(path)
        checkoutish = bool(_CHECKOUT_PATH.search(path))
        price_in_path = bool(_PRICE_TOKEN.search(path))
        price_signal = price_in_query or price_in_path or checkoutish

        if digit_segments and (id_like_param or price_signal or checkoutish):
            sev = SEVERITY_HIGH if (checkoutish and digit_segments) else SEVERITY_MEDIUM
        elif id_like_param and digit_segments:
            sev = SEVERITY_HIGH
        elif id_like_param or price_signal:
            sev = SEVERITY_MEDIUM
        elif digit_segments and len(digit_segments) >= 1:
            sev = SEVERITY_MEDIUM
        else:
            sev = ""

        if sev:
            kinds: list[str] = []
            if digit_segments or id_like_param:
                kinds.append("idor_shape")
            if price_signal or checkoutish:
                kinds.append("price_or_cart_surface")
            key = (url, ",".join(sorted(kinds)))
            if key in dedupe:
                continue
            dedupe.add(key)
            note_bits = [
                f"source={source}",
                f"path_ids={','.join(digit_segments)}" if digit_segments else "",
                "id_like_query" if id_like_param else "",
                "price_related" if price_signal else "",
            ]
            findings.append(
                {
                    "type": "logic_scan",
                    "subtype": "+".join(kinds),
                    "severity": sev,
                    "endpoint": url[:2000],
                    "note": "; ".join(b for b in note_bits if b),
                }
            )

    for pname in sorted(param_name_hits):
        key = ("__param__", pname)
        if key in dedupe:
            continue
        dedupe.add(key)
        findings.append(
            {
                "type": "logic_scan",
                "subtype": "price_param_name",
                "severity": SEVERITY_HIGH,
                "endpoint": target_url.split("?", 1)[0],
                "note": f"Discovered parameter name `{pname}` suggests price manipulation tests "
                f"(body/query tampering); source=param_probe",
            }
        )

    return findings
