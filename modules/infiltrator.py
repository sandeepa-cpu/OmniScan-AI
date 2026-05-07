"""403/forbidden-bypass probe loop (async).

Uses aiohttp with ``allow_redirects=False`` (same idea as ``requests.get(...,
allow_redirects=False)``): redirect responses keep their bodies so 301/302
content can be logged before any follow-up.

Used by :class:`smart_infiltration.SmartInfiltrationEngine`. The public coroutine
:func:`bypass_403_probes` performs header rotation with ``asyncio.wait_for`` on
each HTTP GET and ``await asyncio.sleep(0.1)`` between attempts so the event loop
stays responsive.

:class:`~smart_infiltration.SmartInfiltrationEngine` is available via lazy import
for backward compatibility: ``from modules.infiltrator import SmartInfiltrationEngine``.
"""

from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urlparse, urlunparse

import aiohttp

from .bypass_403 import (
    BYPASS_HEADER_SETS,
    default_header_subset_count,
    forbidden_path_variants,
    mega_header_set_for_path,
    path_rewrite_bypass_headers,
)
from .evasion import EvasionProfile, build_browser_headers

SEVERITY_MEDIUM = "Medium"

_MAX_403_BYPASS_DISTINCT_URLS = 28
_BYPASS_REQUEST_WAIT_FOR_SEC = 11.0
_BYPASS_LOOP_SLEEP_SEC = 0.1
_MAX_BYPASS_BODY_PRINT = 6000
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


async def bypass_403_probes(
    session: aiohttp.ClientSession,
    *,
    path_rows: list[dict],
    referer_base: str,
    extra_headers: dict[str, str],
    evasion: EvasionProfile,
    extended_403: bool,
) -> list[dict]:
    """Try path/header variants for rows that returned 401/403; each GET is wait_for-bounded."""
    target_statuses = (401, 403) if extended_403 else (403,)
    header_sets = (
        BYPASS_HEADER_SETS
        if extended_403
        else BYPASS_HEADER_SETS[: default_header_subset_count()]
    )
    max_bypass_hits = 24 if extended_403 else 12
    path_cap = 12 if extended_403 else 3
    extra = dict(extra_headers or {})

    bypass_source_rows: list[dict] = []
    seen_bypass_url: set[str] = set()
    for row in path_rows:
        if row.get("status") not in target_statuses:
            continue
        u = str(row.get("url", "")).strip()
        if not u or u in seen_bypass_url:
            continue
        seen_bypass_url.add(u)
        bypass_source_rows.append(row)
        if len(bypass_source_rows) >= _MAX_403_BYPASS_DISTINCT_URLS:
            break

    if not bypass_source_rows:
        return []

    total_hdr_attempts = 0
    for brow in bypass_source_rows:
        pth = urlparse(str(brow.get("url", ""))).path or "/"
        nvar = len(
            forbidden_path_variants(pth, extended=extended_403)[:path_cap]
        )
        per_path = 1 + len(header_sets)
        total_hdr_attempts += nvar * per_path

    print("[MODULE] START bypass_403 (header/path attempts)", flush=True)
    bypass: list[dict] = []
    hdr_idx = 0
    for row in bypass_source_rows:
        u = str(row.get("url", "")).strip()
        parsed = urlparse(u)
        path = parsed.path or "/"
        variants = forbidden_path_variants(path, extended=extended_403)[
            :path_cap
        ]
        for variant in variants:
            new_u = urlunparse(
                (
                    parsed.scheme,
                    parsed.netloc,
                    variant,
                    "",
                    parsed.query,
                    "",
                )
            )
            variant_headers = (mega_header_set_for_path(variant),) + header_sets
            variant_hit = False
            for hdr_extra in variant_headers:
                hdr_idx += 1
                hdr_keys = ", ".join(hdr_extra.keys())
                print(
                    f"[DEBUG] Testing header {hdr_idx}/{max(1, total_hdr_attempts)} "
                    f"(url variant={variant!r} + {hdr_keys})...",
                    flush=True,
                )
                await asyncio.sleep(_BYPASS_LOOP_SLEEP_SEC)
                merged = {
                    **build_browser_headers(
                        referer=referer_base, extra=extra, evasion=evasion
                    ),
                    **hdr_extra,
                    **path_rewrite_bypass_headers(variant),
                }

                async def _one_bypass_get(
                    nu: str = new_u,
                    hdrs: dict[str, str] = dict(merged),
                ) -> tuple[int, bytes, str | None]:
                    async with session.get(
                        nu, headers=hdrs, allow_redirects=False
                    ) as resp:
                        raw = await resp.content.read(262_144)
                        st = int(resp.status)
                        loc = resp.headers.get("Location")
                        if st in _REDIRECT_STATUSES:
                            snippet = raw.decode("utf-8", errors="replace")[
                                :_MAX_BYPASS_BODY_PRINT
                            ]
                            body_note = (
                                snippet
                                if snippet.strip()
                                else "(empty redirect body)"
                            )
                            print(
                                f"[BYPASS] HTTP {st} {nu} "
                                f"Location={loc!r}\n"
                                f"--- body (no auto-redirect) ---\n{body_note}\n"
                                f"--- end body ---",
                                flush=True,
                            )
                        return st, raw, loc

                try:
                    status, _raw, location = await asyncio.wait_for(
                        _one_bypass_get(),
                        timeout=_BYPASS_REQUEST_WAIT_FOR_SEC,
                    )
                except asyncio.TimeoutError:
                    continue
                except asyncio.CancelledError:
                    raise
                except (aiohttp.ClientError, TimeoutError, OSError):
                    continue
                except Exception:
                    continue

                if status in (200, *_REDIRECT_STATUSES, 401):
                    note_parts = [f"Headers: {hdr_keys}"]
                    if status in _REDIRECT_STATUSES and location:
                        note_parts.append(f"Location: {location[:400]}")
                    bypass.append(
                        {
                            "type": "forbidden_bypass",
                            "severity": SEVERITY_MEDIUM,
                            "url": new_u,
                            "status": status,
                            "note": " | ".join(note_parts),
                        }
                    )
                    variant_hit = True
                    break

            if variant_hit:
                break
        if len(bypass) >= max_bypass_hits:
            break

    print("[MODULE] END bypass_403 (header/path attempts)", flush=True)
    return bypass


def __getattr__(name: str) -> Any:
    if name == "SmartInfiltrationEngine":
        from .smart_infiltration import SmartInfiltrationEngine

        return SmartInfiltrationEngine
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ("bypass_403_probes", "SmartInfiltrationEngine")
