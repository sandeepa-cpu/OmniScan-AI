# Developed by Channa Sandeepa | OmniScan-AI v2.0 | Copyright 2026
"""WAF-oriented payload expansion: encodings + optional LLM-assisted variants.

Combines rule-based transforms (hex percent, double-URL, Unicode escapes, HTML numeric
entities) with :class:`AIAuditor` XSS mutations when ``kind="xss"``. Optional OpenAI-style
chat completion adds a few extra encoding-only suggestions when
``OMINSCAN_WAF_EVASION_LLM=1`` and an API key is set.

Use only in **authorized** assessments to validate detection and blocking behavior.
Encodings do not guarantee bypass.
"""

from __future__ import annotations

import os
from typing import Literal

from .ai_auditor import AIAuditor
from .payload_obfuscation import base64_utf8, double_url_encode, hex_percent_encode

PayloadKind = Literal["generic", "xss", "sqli"]

_LLM_SYSTEM = """You assist authorized security testers. Given one payload string, output
ONLY 3 to 6 transformed variants on separate lines. Each line must be the same logical
payload with different reversible encodings (URL, double-URL, Unicode escapes, case, etc.).
Do not add new attack primitives or destructive operations. No markdown, no numbering."""


def _unicode_js_escapes(value: str) -> str:
    """Unicode \\uXXXX escapes for non-ASCII and HTML-significant bytes (JS-string style)."""
    out: list[str] = []
    for ch in value:
        o = ord(ch)
        if ch in '<>"\'&\\' or o > 127:
            out.append(f"\\u{o:04x}")
        else:
            out.append(ch)
    return "".join(out)


def _html_decimal_entities(value: str) -> str:
    """Encode < > \" ' as &#NN; (leaves alphanumerics)."""
    return "".join(f"&#{ord(c)};" if c in "<>\"'" else c for c in value)


def _triple_url_encode(value: str) -> str:
    return double_url_encode(double_url_encode(value))


def _mixed_case_hex_percent(value: str) -> str:
    """Randomize hex letter case in percent-encoding (some WAFs normalize once)."""
    raw = hex_percent_encode(value)
    return "".join(c.upper() if c in "abcdef" and (ord(c) + i) % 2 else c for i, c in enumerate(raw))


def _llm_extra_variants(payload: str, *, max_lines: int = 6) -> list[str]:
    key = (
        os.environ.get("OPENAI_API_KEY")
        or os.environ.get("OMINSCAN_LLM_API_KEY")
        or ""
    ).strip()
    if not key:
        return []
    from .exploit_gen import call_openai_chat

    model = (os.environ.get("OMINSCAN_LLM_MODEL") or "gpt-4o-mini").strip()
    base = (
        os.environ.get("OMINSCAN_OPENAI_BASE_URL") or "https://api.openai.com/v1"
    ).strip()
    try:
        raw = call_openai_chat(
            _LLM_SYSTEM,
            f"Payload:\n{payload[:2000]}",
            api_key=key,
            model=model,
            base_url=base,
            timeout=60.0,
        )
    except Exception:
        return []
    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    return lines[:max_lines]


class WAFEvasionEngine:
    """Generate encoding-heavy variants of a probe string for WAF testing."""

    def expand(
        self,
        payload: str,
        *,
        kind: PayloadKind | str = "generic",
        max_variants: int = 48,
        use_llm: bool | None = None,
    ) -> list[str]:
        if not payload:
            return []
        if use_llm is None:
            use_llm = os.environ.get("OMINSCAN_WAF_EVASION_LLM", "").strip().lower() in (
                "1",
                "true",
                "yes",
                "on",
            )

        seen: set[str] = set()
        out: list[str] = []

        def add(s: str) -> None:
            if len(out) >= max_variants:
                return
            if s and s not in seen:
                seen.add(s)
                out.append(s)

        add(payload)
        for fn in (
            hex_percent_encode,
            double_url_encode,
            _triple_url_encode,
            lambda p: _mixed_case_hex_percent(p),
            _unicode_js_escapes,
            _html_decimal_entities,
            base64_utf8,
        ):
            try:
                add(fn(payload))
            except Exception:
                pass
            if len(out) >= max_variants:
                return out

        if kind == "xss" or str(kind).lower() == "xss":
            for row in AIAuditor.mutate_xss_payload(payload):
                add(str(row.get("payload", "")))
                if len(out) >= max_variants:
                    return out

        if use_llm:
            for line in _llm_extra_variants(payload):
                add(line[:8000])
                if len(out) >= max_variants:
                    break

        return out[:max_variants]
