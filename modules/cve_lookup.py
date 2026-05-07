# Developed by Channa Sandeepa | OmniScan-AI v2.0 | Copyright 2026
"""Extract product/version hints from HTTP response headers and query NVD for CVEs.

Uses the public NVD CVE API 2.0 (keyword search). Optional ``NVD_API_KEY`` improves rate
limits. Authorized defensive use only — triage findings; verify matches manually.

API: https://nvd.nist.gov/developers/vulnerabilities
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Mapping

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# product/version in banners like nginx/1.22.1, Apache/2.4.59, Microsoft-IIS/10.0
_BANNER_VER = re.compile(
    r"^([A-Za-z][A-Za-z0-9._-]*)\s*/\s*([\d.]+[a-zA-Z0-9._-]*)",
    re.MULTILINE,
)
_PHP_VER = re.compile(r"PHP/([\d.]+)", re.I)
_ASPNET_VER = re.compile(r"ASP\.NET\s*(?:Core\s*)?([\d.]+)", re.I)


def headers_to_str_dict(headers: Mapping[str, Any]) -> dict[str, str]:
    """Normalize aiohttp-style or plain dict headers to lower-cased keys."""
    out: dict[str, str] = {}
    try:
        items = headers.items()
    except AttributeError:
        return out
    for k, v in items:
        key = str(k).lower()
        if isinstance(v, str):
            out[key] = v
        else:
            try:
                out[key] = ",".join(str(x) for x in v) if v else ""
            except TypeError:
                out[key] = str(v)
    return out


def extract_stack_components(headers: Mapping[str, Any]) -> list[dict[str, str]]:
    """
    Return ``[{"product", "version", "source"}]`` from Server, X-Powered-By, etc.
    """
    h = headers_to_str_dict(headers)
    found: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(product: str, version: str, source: str) -> None:
        p, v = product.strip().lower(), version.strip()
        if not p or not v:
            return
        key = (p, v)
        if key in seen:
            return
        seen.add(key)
        found.append(
            {"product": p, "version": v, "source": source}
        )

    server = h.get("server", "")
    if server:
        for part in server.split():
            m = _BANNER_VER.match(part.strip())
            if m:
                add(m.group(1), m.group(2), "Server")

    xpb = h.get("x-powered-by", "")
    if xpb:
        for m in _PHP_VER.finditer(xpb):
            add("php", m.group(1), "X-Powered-By")
        for m in _ASPNET_VER.finditer(xpb):
            add("aspnet", m.group(1), "X-Powered-By")
        if "/" in xpb and "php" not in xpb.lower():
            for seg in xpb.split(","):
                seg = seg.strip()
                m = _BANNER_VER.match(seg)
                if m:
                    add(m.group(1), m.group(2), "X-Powered-By")

    for hdr in ("x-aspnet-version", "x-aspnetmvc-version"):
        val = h.get(hdr, "").strip()
        if val:
            add("aspnet", val, hdr)

    return found


def _nvd_keyword_search(
    keyword: str,
    *,
    results_per_page: int = 15,
    timeout: float = 45.0,
) -> dict[str, Any]:
    api_key = (os.environ.get("NVD_API_KEY") or "").strip()
    params: dict[str, str] = {
        "keywordSearch": keyword[:400],
        "resultsPerPage": str(min(50, max(1, results_per_page))),
    }
    if api_key:
        params["apiKey"] = api_key
    url = f"{NVD_CVE_URL}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(
        url,
        headers={"Accept": "application/json"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"NVD HTTP {exc.code}: {body[:600]}") from exc


def _parse_nvd_vulnerabilities(data: dict[str, Any]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for wrap in data.get("vulnerabilities") or []:
        cve = wrap.get("cve") or {}
        cid = str(cve.get("id", ""))
        if not cid:
            continue
        desc = ""
        for d in cve.get("descriptions") or []:
            if str(d.get("lang", "")).lower() == "en":
                desc = str(d.get("value", ""))
                break
        if not desc and cve.get("descriptions"):
            desc = str(cve["descriptions"][0].get("value", ""))
        rows.append(
            {
                "cve_id": cid,
                "description": desc[:800],
                "url": f"https://nvd.nist.gov/vuln/detail/{cid}",
            }
        )
    return rows


def lookup_cves_for_component(
    product: str,
    version: str,
    *,
    max_results: int = 12,
) -> list[dict[str, str]]:
    """Run NVD keyword search for ``product`` + ``version``."""
    kw = f"{product} {version}".strip()
    if not kw:
        return []
    data = _nvd_keyword_search(kw, results_per_page=max_results)
    return _parse_nvd_vulnerabilities(data)[:max_results]


def lookup_cves_from_headers(
    headers: Mapping[str, Any],
    *,
    max_per_component: int = 8,
) -> list[dict[str, Any]]:
    """
    Extract stack components from headers and attach CVE candidates per component.

    Returns list of dicts: ``component`` (product/version/source) + ``cves``.
    """
    out: list[dict[str, Any]] = []
    for comp in extract_stack_components(headers):
        try:
            cves = lookup_cves_for_component(
                comp["product"],
                comp["version"],
                max_results=max_per_component,
            )
        except Exception as exc:
            cves = []
            err = str(exc)
        else:
            err = ""
        out.append(
            {
                "component": comp,
                "cves": cves,
                "lookup_error": err,
            }
        )
    return out
