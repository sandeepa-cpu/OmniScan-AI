# Developed by Channa Sandeepa | OmniScan-AI v2.0 | Copyright 2026
"""Probe payload transforms: extra encodings for active injection heuristics.

Activated with ``--obfuscate``. Does not guarantee WAF bypass; reduces static
signatures on XSS / SQLi / LFI test strings. Authorized testing only.
"""

from __future__ import annotations

import base64
import urllib.parse


def double_url_encode(value: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(value, safe=""), safe="")


def hex_percent_encode(value: str) -> str:
    return "".join(f"%{ord(c):02x}" for c in value)


def base64_utf8(value: str) -> str:
    return base64.b64encode(value.encode("utf-8", errors="replace")).decode("ascii")


def expand_probe_values(value: str, *, enabled: bool, max_variants: int = 6) -> list[str]:
    """Return ``value`` plus a small set of encoded variants (deduplicated, capped)."""
    if not value:
        return []
    if not enabled:
        return [value]
    seen: set[str] = {value}
    out: list[str] = [value]
    for fn in (double_url_encode, hex_percent_encode):
        v = fn(value)
        if v not in seen:
            seen.add(v)
            out.append(v)
        if len(out) >= max_variants:
            return out
    b = base64_utf8(value)
    if b not in seen:
        out.append(b)
    return out[:max_variants]
