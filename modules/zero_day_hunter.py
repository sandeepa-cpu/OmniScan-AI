# Developed by Channa Sandeepa | OmniScan-AI v2.0 | Copyright 2026
"""Zero-Day Hunter — logic-flaw fuzzing without CVE lists (HWID-gated).

Harvests client-side JS, API paths, and HTML parameters; scores ``interesting``
names with heuristic rules aligned with :class:`AIAuditor` bypass vocabulary;
fuzzes with type-juggling, array-style keys, null-byte trails, and
encoding-rotated payloads (URL, double-URL, hex bytes, unicode escapes).

**Hardware lock:** set environment variable ``OMINSCAN_ZERODAY_HWID`` to the
exact hex string returned by :func:`compute_machine_hwid` on this machine.

Authorized security testing only.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import platform
import re
import subprocess
import time
from typing import Callable
from urllib.parse import quote, urljoin, urlparse, urlunparse

import aiohttp
from bs4 import BeautifulSoup

from .ai_auditor import AIAuditor
from .evasion import EvasionProfile, build_browser_headers, friendly_network_error
from .scanner_engine import http_client_timeout
from .js_analyzer import JSAnalyzer

ENV_HWID_KEY = "OMINSCAN_ZERODAY_HWID"
ENV_SKIP_HWID_KEY = "OMINSCAN_ZERODAY_SKIP_HWID"

ProgressCallback = Callable[[], None]
PlanCallback = Callable[[int], None]

SEVERITY_CRITICAL = "Critical"
SEVERITY_HIGH = "High"
SEVERITY_MEDIUM = "Medium"
SEVERITY_LOW = "Low"

_JS_ENDPOINT_TYPES = frozenset(
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
        "firebase_realtime_url",
        "gcp_storage_url",
        "aws_s3_url",
        "amazonaws_generic",
        "staging_dev_host",
    }
)

_STACK_LEAK_HINTS: tuple[str, ...] = (
    "traceback",
    "stack trace",
    "exception in thread",
    "fatal error",
    "at org.springframework",
    "nil pointer",
    "referenceerror",
    "typeerror",
    "syntaxerror",
    'file "',
    "raise ",
    '.py", line',
    "caused by:",
    "nested exception",
)

_INTEREST_SUBSTRINGS: tuple[str, ...] = (
    "admin",
    "is_admin",
    "isadmin",
    "debug",
    "trace",
    "verbose",
    "internal",
    "config",
    "access",
    "level",
    "role",
    "priv",
    "secret",
    "token",
    "auth",
    "bypass",
    "dev",
    "staging",
    "god",
    "root",
    "sudo",
    "impersonate",
    "superuser",
    "permission",
    "acl",
    "scope",
    "feature",
    "flag",
    "toggle",
    "elevated",
)

_WAF_MODES: tuple[str, ...] = ("raw", "url", "double_url", "unicode_escape", "hex_bytes")

_MAX_BROAD_FUZZ = 1600
_MAX_FOCUS_FUZZ = 420
_SEV_RANK = {
    SEVERITY_CRITICAL: 0,
    SEVERITY_HIGH: 1,
    SEVERITY_MEDIUM: 2,
    SEVERITY_LOW: 3,
}


def _stack_like(body: str) -> bool:
    low = body.lower()[:120_000]
    return any(h in low for h in _STACK_LEAK_HINTS)


_BASE_PAYLOADS: tuple[tuple[str, str], ...] = (
    ("type_true", "true"),
    ("type_false", "false"),
    ("type_null", "null"),
    ("type_zero", "0"),
    ("type_int_one", "1"),
    ("juggle_sci", "0e0"),
    ("juggle_hexish", "0x0"),
    ("empty", ""),
    ("null_suffix", "x%00"),
    ("array_json", "[]"),
    ("array_json_str", '["a","b"]'),
    ("array_elem", "1"),
    ("tpl_dollar", "${7*7}"),
    ("tpl_mustache", "{{7*7}}"),
    ("cmd_pipe", "|id"),
    ("cmd_semi", ";id"),
)

_FOCUS_PAYLOADS: tuple[tuple[str, str], ...] = (
    ("subshell", "$(id)"),
    ("backtick", "`id`"),
    ("or_cmd", "||id"),
    ("and_cmd", "&&id"),
    ("newline_inj", "a%0a%0did"),
    ("mixed_case_true", "TrUe"),
    ("mixed_case_false", "FaLsE"),
    ("overflow_hint", "A" * 512),
    ("nested_array", "[[[]]]"),
)


def compute_machine_hwid() -> str:
    """Return a stable SHA-256 hex fingerprint for this workstation."""
    parts: list[str] = [
        platform.node(),
        platform.system(),
        platform.machine() or "",
        platform.processor() or "",
    ]
    sys = platform.system()
    if sys == "Windows":
        try:
            r = subprocess.run(
                ["wmic", "csproduct", "get", "uuid"],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            for ln in r.stdout.splitlines():
                ln = ln.strip()
                if ln and ln.upper() != "UUID":
                    parts.append(ln)
                    break
        except Exception:
            pass
        try:
            import winreg

            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Cryptography",
            ) as key:
                mg, _ = winreg.QueryValueEx(key, "MachineGuid")
                parts.append(str(mg))
        except Exception:
            pass
    elif sys == "Darwin":
        try:
            r = subprocess.run(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            for line in r.stdout.splitlines():
                if "IOPlatformUUID" in line:
                    parts.append(line.strip())
                    break
        except Exception:
            pass
    blob = "|".join(parts)
    return hashlib.sha256(blob.encode("utf-8", errors="replace")).hexdigest()


def zeroday_hwid_authorized() -> tuple[bool, str]:
    """Return (authorized, message). Message is the local HWID when authorized."""
    skip = (os.environ.get(ENV_SKIP_HWID_KEY) or "").strip().lower()
    if skip in ("1", "true", "yes", "on"):
        return True, "hwid_check_skipped_dev"
    expected = (os.environ.get(ENV_HWID_KEY) or "").strip().lower()
    actual = compute_machine_hwid().lower()
    if not expected:
        return False, (
            f"Zero-Day Hunter locked: set {ENV_HWID_KEY}={actual} "
            f"(this machine's fingerprint)."
        )
    if expected != actual:
        return False, (
            "Zero-Day Hunter locked: HWID mismatch — this device fingerprint "
            f"is {actual}; {ENV_HWID_KEY} must match exactly."
        )
    return True, actual


def score_param_interest(name: str, source: str) -> tuple[int, str]:
    """Score parameter ``name`` for fuzz priority (heuristic, AI-auditor-informed)."""
    n = name.strip()
    if not n:
        return 0, ""
    low = n.lower()
    score = 0
    tags: list[str] = []
    for sub in _INTEREST_SUBSTRINGS:
        if sub in low:
            score += 12
            tags.append(sub[:12])
    if re.match(r"^[a-z_]*(flag|toggle|mode|level|role|type|kind)$", low):
        score += 28
        tags.append("pattern")
    if source in ("form", "hidden"):
        score += 8
    if source == "js_literal":
        score += 15
    if source == "js_query":
        score += 20
    for tech, _desc in AIAuditor.WAF_BYPASS_TECHNIQUES:
        if tech and tech.split("_")[0] in low:
            score += 4
    score = min(100, score)
    return score, ",".join(dict.fromkeys(tags)) or "heuristic"


def waf_transform(value: str, mode: str) -> str:
    """Rotate payload representation to stress WAF normalization paths."""
    if mode == "raw":
        return value
    if mode == "url":
        return quote(value, safe="")
    if mode == "double_url":
        return quote(quote(value, safe=""), safe="")
    if mode == "hex_bytes":
        return "".join(f"%{b:02x}" for b in value.encode("utf-8", errors="replace"))
    if mode == "unicode_escape":
        out: list[str] = []
        for ch in value:
            o = ord(ch)
            if ch.isalnum() and o < 128:
                out.append(ch)
            elif o < 0x10000:
                out.append(f"\\u{o:04x}")
            else:
                out.append(ch)
        return "".join(out)
    return value


def _normalize_endpoint(page_url: str, raw: str) -> str | None:
    raw = (raw or "").strip().split("#")[0].strip()
    if not raw or raw.startswith("data:") or raw.startswith("javascript:"):
        return None
    if raw.startswith("http://") or raw.startswith("https://"):
        return raw
    if raw.startswith("//"):
        scheme = urlparse(page_url).scheme or "https"
        return f"{scheme}:{raw}"
    if raw.startswith("/"):
        return urljoin(page_url, raw)
    if raw.startswith("ws://") or raw.startswith("wss://"):
        return None
    return None


def _url_without_query(url: str) -> str:
    p = urlparse(url if "://" in url else f"https://{url}")
    return urlunparse((p.scheme, p.netloc, p.path or "/", "", "", ""))


def _extract_js_param_names(text: str) -> set[str]:
    out: set[str] = set()
    for rx in (
        r"""\.get\(\s*["']([a-zA-Z_][a-zA-Z0-9_]{0,63})["']""",
        r"""searchParams\.(?:get|append|set)\(\s*["']([a-zA-Z_][a-zA-Z0-9_]{0,63})["']""",
        r"""["']([a-zA-Z_][a-zA-Z0-9_]{1,63})["']\s*:\s*(?:true|false|null|\[)""",
    ):
        for m in re.finditer(rx, text):
            out.add(m.group(1))
    return out


class ZeroDayHunter:
    """Predictive fuzz engine: harvest → score → fuzz → anomaly-focused pass."""

    def __init__(
        self,
        extra_headers: dict[str, str] | None = None,
        evasion: EvasionProfile | None = None,
        timeout: aiohttp.ClientTimeout | None = None,
        concurrency: int = 8,
        max_scripts: int = 48,
    ) -> None:
        self._extra = dict(extra_headers or {})
        self._evasion = evasion or EvasionProfile()
        self._timeout = timeout or http_client_timeout()
        self._concurrency = max(1, concurrency)
        self._max_scripts = max_scripts

    async def scan(
        self,
        target_url: str,
        on_plan: PlanCallback | None = None,
        on_advance: ProgressCallback | None = None,
    ) -> tuple[list[dict], str | None]:
        def _advance() -> None:
            if on_advance is not None:
                try:
                    on_advance()
                except Exception:
                    pass

        ok, _msg = zeroday_hwid_authorized()
        if not ok:
            return [], _msg

        raw = target_url.strip()
        if "://" not in raw:
            raw = f"https://{raw}"
        page_ref = raw
        base_clean = _url_without_query(raw)

        try:
            connector = self._evasion.aiohttp_connector(ssl=True, limit=24)
        except RuntimeError:
            raise

        harvest_endpoints: set[str] = {base_clean}
        param_sources: dict[str, set[str]] = {}

        def _note_param(name: str, src: str) -> None:
            name = name.strip()
            if not name or len(name) > 96:
                return
            param_sources.setdefault(name, set()).add(src)

        findings: list[dict] = []

        async with aiohttp.ClientSession(
            timeout=self._timeout, connector=connector, trust_env=False
        ) as session:
            await self._evasion.apply_jitter()
            hdr = build_browser_headers(
                referer=page_ref,
                extra=self._extra,
                accept="text/html,*/*",
                evasion=self._evasion,
            )
            try:
                async with session.get(page_ref, headers=hdr, allow_redirects=True) as resp:
                    final_html_url = str(resp.url)
                    html = (await resp.read())[:2_000_000].decode("utf-8", errors="replace")
            except (aiohttp.ClientError, TimeoutError, OSError) as exc:
                return [], friendly_network_error(exc)

            try:
                soup = BeautifulSoup(html, "html.parser")
            except Exception:
                soup = None

            if soup:
                for tag in soup.find_all("input"):
                    name = tag.get("name")
                    if name:
                        src = "hidden" if (tag.get("type") or "").lower() == "hidden" else "form"
                        _note_param(str(name), src)
                for tag in soup.find_all(["select", "textarea"]):
                    name = tag.get("name")
                    if name:
                        _note_param(str(name), "form")
                for tag in soup.find_all(True):
                    for attr in ("data-param", "data-field", "data-key"):
                        v = tag.get(attr)
                        if v:
                            _note_param(str(v), "data_attr")

            script_urls: list[str] = []
            if soup:
                seen: set[str] = set()

                def _add_script(href: str | None) -> None:
                    if not href:
                        return
                    u = urljoin(final_html_url, str(href).strip())
                    if u in seen or not u.startswith("http"):
                        return
                    seen.add(u)
                    script_urls.append(u)

                for s in soup.find_all("script"):
                    _add_script(s.get("src"))
                for lk in soup.find_all("link"):
                    rel = " ".join(lk.get("rel") or []).lower()
                    if "modulepreload" in rel or (lk.get("as") or "").lower() == "script":
                        _add_script(lk.get("href"))

            script_urls = script_urls[: self._max_scripts]

            inline_blob = ""
            if soup:
                for s in soup.find_all("script"):
                    if not s.get("src"):
                        inline_blob += str(s.string or "") + "\n"
            for n in _extract_js_param_names(inline_blob):
                _note_param(n, "js_literal")

            js_analyzer = JSAnalyzer(
                extra_headers=self._extra,
                evasion=self._evasion,
                max_scripts=self._max_scripts,
            )
            js_rows = await js_analyzer.analyze(
                page_ref,
                on_plan=None,
                on_advance=_advance,
            )

            for row in js_rows:
                kind = row.get("type")
                match = str(row.get("match") or "")
                if kind in _JS_ENDPOINT_TYPES:
                    ep = _normalize_endpoint(page_ref, match)
                    if ep:
                        harvest_endpoints.add(_url_without_query(ep))

            sem = asyncio.Semaphore(min(4, self._concurrency))

            async def _fetch_js_text(u: str) -> str:
                async with sem:
                    try:
                        await self._evasion.apply_jitter()
                        h = build_browser_headers(
                            referer=final_html_url,
                            extra=self._extra,
                            accept="*/*",
                            evasion=self._evasion,
                        )
                        async with session.get(u, headers=h, allow_redirects=True) as r:
                            if r.status != 200:
                                return ""
                            raw = await r.content.read(1_200_000)
                            return raw.decode("utf-8", errors="replace")
                    except Exception:
                        return ""

            js_text_tasks = [asyncio.create_task(_fetch_js_text(u)) for u in script_urls]
            for coro in asyncio.as_completed(js_text_tasks):
                text = await coro
                _advance()
                for n in _extract_js_param_names(text):
                    _note_param(n, "js_query")

            scored: list[tuple[str, int, str, str]] = []
            for pname, srcs in param_sources.items():
                src = sorted(srcs)[0]
                sc, reason = score_param_interest(pname, src)
                if sc > 0 or src == "hidden":
                    scored.append((pname, sc, reason, src))
            scored.sort(key=lambda x: -x[1])
            chosen_params = [p[0] for p in scored[:40]]
            if not chosen_params:
                chosen_params = ["debug", "admin", "test", "format", "callback"]

            for p in harvest_endpoints:
                findings.append(
                    {
                        "type": "harvest_endpoint",
                        "severity": SEVERITY_LOW,
                        "url": p,
                        "note": "Harvested endpoint scope for fuzzing",
                    }
                )
            for pname, sc, reason, src in scored[:25]:
                findings.append(
                    {
                        "type": "harvest_param",
                        "severity": SEVERITY_LOW,
                        "param": pname,
                        "interest_score": sc,
                        "reason": reason,
                        "source": src,
                        "note": "Interesting parameter candidate (heuristic rank)",
                    }
                )

            endpoints_list = sorted(harvest_endpoints)[:18]
            fuzz_jobs: list[tuple[str, str, str, str, str, bool]] = []
            enc_cycle = list(_WAF_MODES)
            ei = 0
            _array_kinds = frozenset({"array_json", "array_json_str", "array_elem"})
            for ep in endpoints_list:
                for param in chosen_params[:12]:
                    for pkind, pval in _BASE_PAYLOADS:
                        if len(fuzz_jobs) >= _MAX_BROAD_FUZZ:
                            break
                        mode = enc_cycle[ei % len(enc_cycle)]
                        ei += 1
                        fuzz_jobs.append(
                            (ep, param, pkind, pval, mode, pkind in _array_kinds)
                        )
                    if len(fuzz_jobs) >= _MAX_BROAD_FUZZ:
                        break
                if len(fuzz_jobs) >= _MAX_BROAD_FUZZ:
                    break
            if on_plan is not None:
                try:
                    on_plan(len(fuzz_jobs) + len(endpoints_list) * 2 + 24)
                except Exception:
                    pass

            baselines: dict[str, tuple[float, int, int]] = {}
            hot: set[tuple[str, str]] = set()

            async def _timed_get(url: str) -> tuple[int, str, float]:
                t0 = time.perf_counter()
                await self._evasion.apply_jitter()
                h = build_browser_headers(
                    referer=page_ref,
                    extra=self._extra,
                    accept="*/*",
                    evasion=self._evasion,
                )
                try:
                    async with session.get(
                        url, headers=h, allow_redirects=True
                    ) as resp:
                        raw = await resp.content.read(350_000)
                        body = raw.decode("utf-8", errors="replace")
                        st = resp.status
                except Exception:
                    return 0, "", -1.0
                elapsed = (time.perf_counter() - t0) * 1000.0
                return st, body, elapsed

            for ep in endpoints_list:
                samples: list[float] = []
                last_st = 200
                last_len = 0
                for _ in range(2):
                    st, body, ms = await _timed_get(ep)
                    if ms >= 0:
                        samples.append(ms)
                        last_st = st
                        last_len = len(body)
                    _advance()
                if samples:
                    baselines[ep] = (
                        sum(samples) / len(samples),
                        last_st,
                        last_len,
                    )

            sem_f = asyncio.Semaphore(self._concurrency)

            async def _fuzz_one(
                ep: str,
                param: str,
                pkind: str,
                raw_val: str,
                enc_mode: str,
                as_array: bool,
            ) -> dict | None:
                async with sem_f:
                    transformed = waf_transform(raw_val, enc_mode)
                    if as_array:
                        q = f"{quote(param)}[]={transformed}"
                    else:
                        q = f"{quote(param)}={transformed}"
                    joiner = "&" if "?" in ep else "?"
                    url = f"{ep}{joiner}{q}"
                    st, body, elapsed = await _timed_get(url)
                    _advance()
                    if elapsed < 0:
                        return None
                    base_t = baselines.get(ep)
                    if base_t is None:
                        base_ms, base_st, base_body_len = elapsed, st, len(body)
                    else:
                        base_ms, base_st, base_body_len = base_t
                    body_l = len(body)
                    stackish = st >= 500 and _stack_like(body)
                    slow = elapsed > max(base_ms * 2.8, base_ms + 1800.0)
                    shape_delta = abs(body_l - base_body_len) > max(
                        120, int(max(base_body_len, 1) * 0.04)
                    )
                    if (
                        not stackish
                        and not slow
                        and st < 500
                        and st == base_st
                        and not shape_delta
                    ):
                        return None

                    note_parts: list[str] = []
                    sev = SEVERITY_MEDIUM
                    if stackish:
                        note_parts.append("500 with stack-like body")
                        sev = SEVERITY_CRITICAL
                        hot.add((ep, param))
                    elif slow:
                        note_parts.append(
                            f"latency spike ~{elapsed:.0f}ms vs baseline ~{base_ms:.0f}ms"
                        )
                        sev = SEVERITY_HIGH
                        hot.add((ep, param))
                    elif st >= 500:
                        note_parts.append(f"HTTP {st}")
                        sev = SEVERITY_HIGH
                        hot.add((ep, param))
                    elif st != base_st:
                        note_parts.append(f"status shift -> {st}")
                        sev = SEVERITY_MEDIUM
                    else:
                        note_parts.append("response shape delta")

                    return {
                        "type": "fuzz_hit",
                        "severity": sev,
                        "phase": "broad",
                        "url": url,
                        "endpoint": ep,
                        "param": param,
                        "payload_class": pkind,
                        "encoding": enc_mode,
                        "array_key": as_array,
                        "status": st,
                        "latency_ms": round(elapsed, 2),
                        "baseline_ms": round(base_ms, 2),
                        "note": "; ".join(note_parts),
                    }

            tasks = [
                asyncio.create_task(_fuzz_one(ep, param, pk, pv, em, arr))
                for ep, param, pk, pv, em, arr in fuzz_jobs
            ]
            for c in asyncio.as_completed(tasks):
                row = await c
                if row:
                    findings.append(row)

            focus_jobs: list[tuple[str, str, str, str, str, bool]] = []
            ei2 = 0
            for ep, param in hot:
                for pkind, pval in _FOCUS_PAYLOADS:
                    if len(focus_jobs) >= _MAX_FOCUS_FUZZ:
                        break
                    mode = enc_cycle[ei2 % len(enc_cycle)]
                    ei2 += 1
                    focus_jobs.append((ep, param, pkind, pval, mode, False))
                    focus_jobs.append((ep, param, f"{pkind}_arr", pval, mode, True))
                if len(focus_jobs) >= _MAX_FOCUS_FUZZ:
                    break

            if focus_jobs:
                if on_plan is not None:
                    try:
                        on_plan(
                            len(fuzz_jobs)
                            + len(focus_jobs)
                            + len(endpoints_list) * 2
                            + 24
                        )
                    except Exception:
                        pass
                ft = [
                    asyncio.create_task(_fuzz_one(ep, pr, pk, pv, em, arr))
                    for ep, pr, pk, pv, em, arr in focus_jobs[:_MAX_FOCUS_FUZZ]
                ]
                for c in asyncio.as_completed(ft):
                    row = await c
                    if row:
                        row["phase"] = "focus"
                        findings.append(row)

        findings.sort(
            key=lambda r: (
                _SEV_RANK.get(str(r.get("severity")), 9),
                0 if r.get("type") == "fuzz_hit" else 1,
                str(r.get("url", "")),
            )
        )
        return findings, None
