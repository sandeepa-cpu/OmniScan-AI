# Developed by Channa Sandeepa | OmniScan-AI v2.0 | Copyright 2026
"""Network evasion helpers: Tor (SOCKS5h), per-request User-Agent rotation, browser-like
headers, adaptive jitter, and WAF-aware throttling (Cloudflare, Akamai, Fastly, …).

Use only on targets you are authorized to test. Misuse may violate law and policy.
"""

from __future__ import annotations

import asyncio
import random
import re
from dataclasses import dataclass, field
from typing import Mapping
from urllib.parse import urlparse

import aiohttp

from .scanner_engine import (
    DEFAULT_MAX_RETRIES,
    USER_AGENTS,
    apply_playtika_headers_last,
    direct_tcp_connector,
    is_transient_network_failure,
    pick_random_user_agent,
    retry_pause,
    waf_probe_client_timeout,
)

ACCEPT_LANGUAGES: tuple[str, ...] = (
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9,en-US;q=0.8",
    "en-US,en;q=0.9,de;q=0.8",
    "en-US,en;q=0.9,fr;q=0.8",
    "en-US,en;q=0.9,es;q=0.8",
    "en-US,en;q=0.9,ja;q=0.8",
    "en-US,en;q=0.9,zh-CN;q=0.8",
    "en-CA,en;q=0.9,en-US;q=0.8",
    "en-AU,en;q=0.9",
)


def pick_user_agent() -> str:
    return pick_random_user_agent()


def pick_accept_language() -> str:
    return random.choice(ACCEPT_LANGUAGES)


def headers_to_lower_dict(headers: Mapping[str, str] | aiohttp.typedefs.LooseHeaders) -> dict[str, str]:
    """Normalize response headers to a single lower-cased key dict (last wins)."""
    out: dict[str, str] = {}
    try:
        items = headers.items()
    except AttributeError:
        return out
    for k, v in items:
        out[str(k).lower()] = str(v)
    return out


def classify_waf(headers: dict[str, str]) -> tuple[str, float]:
    """Return ``(waf_label, jitter_multiplier)`` from response headers.

    Multiplier scales inter-request delay when :class:`EvasionProfile` applies jitter.
    """
    blob = " ".join(f"{k} {v}" for k, v in headers.items()).lower()
    srv = headers.get("server", "").lower()
    via = headers.get("via", "").lower()
    xp = headers.get("x-powered-by", "").lower()

    if headers.get("cf-ray") or "cloudflare" in blob or srv.startswith("cloudflare"):
        return "cloudflare", 3.0
    if (
        "akamai" in blob
        or "akamaighost" in srv
        or "akamai" in srv
        or headers.get("x-akamai-request-id")
        or headers.get("x-akamai-transformed")
    ):
        return "akamai", 2.6
    xcdn = headers.get("x-cdn", "").lower()
    if "incapsula" in blob or ("x-cdn" in headers and "incap" in xcdn):
        return "incapsula", 2.4
    if "sucuri" in blob or "x-sucuri" in headers:
        return "sucuri", 2.3
    if "fastly" in blob or srv == "fastly":
        return "fastly", 2.0
    if "netlify" in blob or "x-nf-request-id" in headers:
        return "netlify", 1.7
    if "vercel" in blob or headers.get("x-vercel-id"):
        return "vercel", 1.7
    if "aws" in srv and "cloudfront" in srv:
        return "cloudfront", 1.9
    if "distil" in blob or "x-distil-wait" in headers:
        return "distil", 2.5
    if re.search(r"\b(waf|web.application.firewall)\b", blob):
        return "generic_waf", 2.0
    if "barrier" in via or "squid" in srv:
        return "proxy_cdn", 1.5
    if xp and any(t in xp for t in ("istio", "envoy",)):
        return "edge_hint", 1.25
    return "none", 1.0


def parse_socks_proxy(url: str) -> tuple[str, int, bool]:
    """Parse ``socks5://`` / ``socks5h://`` URL into (host, port, remote_dns).

    ``remote_dns`` is True for ``socks5h`` / ``socks5a`` schemes (resolve via Tor).
    """
    raw = url.strip()
    lowered = raw.lower()
    rdns = lowered.startswith("socks5h:") or lowered.startswith("socks5a:")
    if "://" not in raw:
        raw = f"socks5://{raw}"
    p = urlparse(raw)
    host = p.hostname or "127.0.0.1"
    port = p.port or 9050
    return host, port, rdns


async def adaptive_delay(
    base_sec: float,
    max_extra_sec: float,
) -> None:
    """Sleep for ``base_sec`` plus uniform jitter in ``[0, max_extra_sec]``."""
    if base_sec <= 0 and max_extra_sec <= 0:
        return
    total = max(0.0, float(base_sec)) + random.uniform(0.0, max(0.0, float(max_extra_sec)))
    if total > 0:
        await asyncio.sleep(total)


@dataclass
class EvasionProfile:
    """Tor, smart evasion (UA rotation, jitter, WAF-aware throttling)."""

    use_tor: bool = False
    tor_socks_url: str = "socks5h://127.0.0.1:9050"
    #: Explicit ``--jitter`` / ``--tor`` pacing (stronger defaults).
    jitter_enabled: bool = False
    jitter_base_sec: float = 0.08
    jitter_max_extra_sec: float = 0.42
    #: Baseline smart pacing when ``smart_evasion`` is on without explicit jitter.
    smart_jitter_base_sec: float = 0.06
    smart_jitter_max_extra_sec: float = 0.38
    #: Master switch: default jitter + WAF probe + per-request UA via ``build_browser_headers(..., evasion=)``.
    smart_evasion: bool = True
    #: Initial GET to fingerprint CDN/WAF (off with ``--no-waf-probe`` to avoid an extra hop).
    waf_probe: bool = True
    #: When True, ``apply_jitter`` is a no-op (``--no-jitter``).
    no_jitter: bool = False
    #: Stronger pacing + header variation for authorized low-noise probing (``--stealth``).
    stealth_mode: bool = False
    #: Set from ``classify_waf`` after :meth:`probe_target_waf`.
    detected_waf: str = "none"
    jitter_multiplier: float = 1.0
    _last_ua: str | None = field(default=None, repr=False)

    def next_user_agent(self) -> str:
        """Pick a new User-Agent, avoiding an immediate repeat when possible."""
        pool = [u for u in USER_AGENTS if u != self._last_ua] or list(USER_AGENTS)
        self._last_ua = random.choice(pool)
        return self._last_ua

    def next_accept_language(self) -> str:
        return random.choice(ACCEPT_LANGUAGES)

    def apply_waf_from_headers(self, headers: Mapping[str, str] | aiohttp.typedefs.LooseHeaders) -> None:
        """Tune :attr:`jitter_multiplier` and :attr:`detected_waf` from a response."""
        hd = headers_to_lower_dict(headers)
        name, mult = classify_waf(hd)
        self.detected_waf = name
        self.jitter_multiplier = mult

    async def probe_target_waf(self, target_url: str) -> None:
        """GET to classify CDN/WAF from response headers (retries; Tor only if ``use_tor``)."""
        if not self.smart_evasion or not self.waf_probe:
            return
        raw = target_url.strip()
        if "://" not in raw:
            raw = f"https://{raw}"
        referer = raw if raw.endswith("/") else f"{raw}/"
        try:
            connector = self.aiohttp_connector(ssl=True, limit=4)
        except RuntimeError:
            return
        timeout = waf_probe_client_timeout()
        max_tries = min(2, DEFAULT_MAX_RETRIES)
        for attempt in range(max_tries):
            try:
                async with aiohttp.ClientSession(
                    timeout=timeout, connector=connector, trust_env=False
                ) as session:
                    headers = build_browser_headers(referer=referer, evasion=self)
                    async with session.get(
                        raw, headers=headers, allow_redirects=True
                    ) as resp:
                        if resp.status >= 500 or resp.status in (408, 429):
                            if attempt < max_tries - 1:
                                await retry_pause(attempt)
                                continue
                        self.apply_waf_from_headers(resp.headers)
                        return
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                if attempt >= max_tries - 1 or not is_transient_network_failure(exc):
                    break
                await retry_pause(attempt)
        self.detected_waf = "none"
        self.jitter_multiplier = 1.0

    async def apply_jitter(self) -> None:
        """Random delay between requests; strength scales with WAF :attr:`jitter_multiplier`."""
        if self.no_jitter:
            return
        stealth_floor = self.stealth_mode and not (self.jitter_enabled or self.smart_evasion)
        if not (self.jitter_enabled or self.smart_evasion or stealth_floor):
            return
        if self.jitter_enabled:
            base, extra = self.jitter_base_sec, self.jitter_max_extra_sec
        else:
            base, extra = self.smart_jitter_base_sec, self.smart_jitter_max_extra_sec
        stealth_scale = 1.28 if self.stealth_mode else 1.0
        base = max(0.0, float(base)) * self.jitter_multiplier * stealth_scale
        extra = max(0.0, float(extra)) * self.jitter_multiplier * stealth_scale
        await adaptive_delay(base, extra)

    async def apply_infiltration_jitter(self) -> None:
        """Stronger random pacing for active probes (bypass, SQLi/XSS/LFI, chain fetches).

        Uses WAF-scaled :attr:`jitter_multiplier` and an extra random factor so bursts
        do not look machine-perfect. When global jitter is off but smart evasion is on,
        still applies the smart baseline with a bump. When both are off, applies a
        moderate infiltration-only floor (unless :attr:`no_jitter`).
        """
        if self.no_jitter:
            return
        bump = 1.22 + random.uniform(0.0, 0.48)
        mult = max(0.0, float(self.jitter_multiplier)) * bump
        if self.jitter_enabled:
            base, extra = self.jitter_base_sec, self.jitter_max_extra_sec
        elif self.smart_evasion:
            base, extra = self.smart_jitter_base_sec, self.smart_jitter_max_extra_sec
        else:
            base, extra = 0.11, 0.58
        stealth_scale = 1.2 if self.stealth_mode else 1.0
        base = max(0.0, float(base)) * mult * stealth_scale
        extra = max(0.0, float(extra)) * mult * stealth_scale
        await adaptive_delay(base, extra)

    def aiohttp_connector(self, *, ssl: bool | None = False, limit: int = 100) -> aiohttp.BaseConnector:
        """Direct ``TCPConnector`` by default; SOCKS only when ``use_tor`` is True (``--tor``).

        System proxy env vars are ignored via ``trust_env=False`` on sessions; strip proxies
        from the process environment with :func:`scanner_engine.apply_direct_http_environment`
        when not using Tor.
        """
        if self.use_tor:
            try:
                from aiohttp_socks import ProxyConnector  # type: ignore[import-untyped]
            except ImportError as exc:
                raise RuntimeError(
                    "Tor mode requires `aiohttp-socks`. Install: pip install aiohttp-socks"
                ) from exc
            return ProxyConnector.from_url(
                self.tor_socks_url,
                ssl=ssl,
                limit=limit,
            )
        return direct_tcp_connector(ssl=ssl if ssl is not None else True, limit=limit)


_ACCEPT_HTML_VARIANTS: tuple[str, ...] = (
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.75",
)


def build_browser_headers(
    *,
    referer: str,
    extra: dict[str, str] | None = None,
    accept: str | None = None,
    evasion: EvasionProfile | None = None,
) -> dict[str, str]:
    """Headers that mimic a normal browser session (merged last with ``extra``).

    When ``evasion`` is set, User-Agent and Accept-Language are taken from the
    profile so every call rotates like a distinct browser fingerprint. Sec-Fetch-*
    and Accept variants also rotate to reduce static WAF fingerprints on rapid probes.
    """
    ref = referer if referer.endswith("/") else f"{referer}/"
    if evasion is not None:
        ua = evasion.next_user_agent()
        lang = evasion.next_accept_language()
    else:
        ua = pick_user_agent()
        lang = pick_accept_language()
    accept_val = accept or random.choice(_ACCEPT_HTML_VARIANTS)
    base: dict[str, str] = {
        "User-Agent": ua,
        "Accept": accept_val,
        "Accept-Language": lang,
        "Accept-Encoding": "gzip, deflate, br",
        "Referer": ref,
        "DNT": "1",
        "Upgrade-Insecure-Requests": "1",
    }
    if evasion is not None:
        if evasion.stealth_mode:
            site = random.choices(
                ("same-origin", "same-site", "cross-site"),
                weights=(48, 26, 26),
                k=1,
            )[0]
            base["Accept-Encoding"] = random.choice(
                ("gzip, deflate, br", "gzip, deflate", "gzip, br", "identity")
            )
            if random.random() < 0.45:
                base["Viewport-Width"] = str(random.choice((390, 412, 768, 1280, 1440)))
            if random.random() < 0.4:
                base["X-Requested-With"] = "XMLHttpRequest"
        else:
            site = random.choices(
                ("same-origin", "same-site", "cross-site"),
                weights=(72, 18, 10),
                k=1,
            )[0]
        base["Sec-Fetch-Dest"] = "document"
        base["Sec-Fetch-Mode"] = "navigate"
        base["Sec-Fetch-Site"] = site
        base["Sec-Fetch-User"] = "?1"
        if random.random() < (0.5 if evasion.stealth_mode else 0.35):
            base["Cache-Control"] = random.choice(
                ("max-age=0", "no-cache", "max-age=0, no-cache")
            )
    if extra:
        base.update(extra)
    return apply_playtika_headers_last(base)


def friendly_network_error(exc: BaseException) -> str:
    """Short note for logs on failed HTTP/TCP (direct or SOCKS)."""
    raw = str(exc)
    msg = raw.lower()
    if any(x in msg for x in ("socks5", "socks", "proxy", "tunnel")):
        return f"proxy/SOCKS error (use direct mode without --tor, or fix proxy settings) — {raw[:100]}"
    if any(
        k in msg
        for k in (
            "connection refused",
            "network is unreachable",
            "no route to host",
            "timed out",
            "timeout",
            "certificate",
            "ssl",
            "0x",
        )
    ):
        return f"network error (firewall, timeout, DNS, or TLS) — {raw[:100]}"
    return raw[:120]
