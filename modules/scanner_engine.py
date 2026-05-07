# Developed by Channa Sandeepa | OmniScan-AI v2.0 | Copyright 2026
"""Shared HTTP timing, retries, transient errors, and direct (non-proxy) client defaults.

Playtika Bug Bounty (Social Login / OAuth–OIDC campaign): when
``OMNISCAN_PLAYTIKA_BOUNTY`` is set, :func:`playtika_bug_bounty_headers` injects
``X-Bug-Bounty: True`` and :data:`PLAYTIKA_SOCIAL_LOGIN_PATHS` drives OAuth/social
path discovery (see ``oauth_social_scanner``). Use :data:`PLAYTIKA_MAX_CONCURRENT_HTTP`
to cap simultaneous requests (policy-friendly pacing).
"""

from __future__ import annotations

import asyncio
import os
import random
from typing import Any, Mapping

import aiohttp

from .user_agents_pool import BROWSER_USER_AGENTS

# --- Playtika Social Login (OAuth/OIDC) campaign paths (merged into OAuth scanner wordlist) ---
PLAYTIKA_SOCIAL_LOGIN_PATHS: tuple[str, ...] = (
    "/login/social",
    "/oauth/callback",
    "/linking",
    "/api/login/social",
    "/api/oauth/callback",
    "/api/v1/oauth/callback",
    "/v1/oauth/callback",
    "/account/linking",
    "/social/linking",
    "/connect/linking",
)

# Max concurrent HTTP operations for Playtika-oriented probes (avoid accidental DoS).
PLAYTIKA_MAX_CONCURRENT_HTTP: int = 5

PLAYTIKA_BOUNTY_ENV_FLAG: str = "OMNISCAN_PLAYTIKA_BOUNTY"
X_BUG_BOUNTY_HEADER: str = "X-Bug-Bounty"
X_BUG_BOUNTY_VALUE: str = "True"

# Environment keys that steer aiohttp/requests/curl through HTTP(S) or SOCKS proxies.
_PROXY_ENV_KEYS_UPPER: frozenset[str] = frozenset(
    {
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "WS_PROXY",
        "WSS_PROXY",
        "FTP_PROXY",
        "GRPC_PROXY",
    }
)

# Default identity for engine HTTP clients (Chrome on Windows — avoids bare-bot blocks).
DEFAULT_BROWSER_USER_AGENT: str = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)

# 50+ real browser User-Agent strings (shared with evasion layer).
USER_AGENTS: tuple[str, ...] = BROWSER_USER_AGENTS


def pick_random_user_agent() -> str:
    return random.choice(USER_AGENTS)


def playtika_bug_bounty_active() -> bool:
    """True when Playtika / bug-bounty header mode is enabled via environment."""
    return os.environ.get(PLAYTIKA_BOUNTY_ENV_FLAG, "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def playtika_bug_bounty_headers() -> dict[str, str]:
    """``X-Bug-Bounty: True`` when :func:`playtika_bug_bounty_active` is True."""
    if playtika_bug_bounty_active():
        return {X_BUG_BOUNTY_HEADER: X_BUG_BOUNTY_VALUE}
    return {}


def apply_playtika_headers_last(headers: Mapping[str, str] | dict[str, str]) -> dict[str, str]:
    """Return a copy of ``headers`` with Playtika bounty headers forced last (cannot be overridden)."""
    out = dict(headers)
    out.update(playtika_bug_bounty_headers())
    return out


def playtika_connector_limit(default_limit: int = 100) -> int:
    """Cap aiohttp connector ``limit`` when Playtika mode is on (default 5)."""
    if playtika_bug_bounty_active():
        return min(PLAYTIKA_MAX_CONCURRENT_HTTP, max(1, int(default_limit)))
    return default_limit


def default_browser_headers() -> dict[str, str]:
    """Headers that match a typical Chrome desktop request (no proxy; used by fetch helpers)."""
    h = {
        "User-Agent": DEFAULT_BROWSER_USER_AGENT,
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8"
        ),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Cache-Control": "max-age=0",
        "Upgrade-Insecure-Requests": "1",
    }
    h.update(playtika_bug_bounty_headers())
    return h


def _google_public_dns_resolver() -> aiohttp.abc.AbstractResolver | None:
    """Prefer Google Public DNS for aiohttp lookups (bypass flaky ISP resolvers).

    Requires ``aiodns``; if unavailable, returns ``None`` and the connector uses the
    host default resolver.
    """
    try:
        from aiohttp.resolver import AsyncResolver
    except ImportError:
        return None
    try:
        return AsyncResolver(nameservers=["8.8.8.8", "8.8.4.4"])
    except Exception:
        return None


def direct_tcp_connector(
    *,
    ssl: bool | None = True,
    limit: int = 100,
) -> aiohttp.BaseConnector:
    """Plain TCP connector: no SOCKS/proxy; optional Google DNS unless disabled via env.

    Set ``OMNISCAN_DISABLE_GOOGLE_DNS=1`` to use the OS resolver only (helps some networks).
    """
    use_ssl = ssl if ssl is not None else True
    resolver = None
    if os.environ.get("OMNISCAN_DISABLE_GOOGLE_DNS", "").strip().lower() not in (
        "1",
        "true",
        "yes",
        "on",
    ):
        resolver = _google_public_dns_resolver()
    if resolver is not None:
        return aiohttp.TCPConnector(
            ssl=use_ssl,
            limit=limit,
            resolver=resolver,
            ttl_dns_cache=300,
        )
    return aiohttp.TCPConnector(ssl=use_ssl, limit=limit, ttl_dns_cache=300)


def copy_environ_for_direct_requests(base: dict[str, str]) -> dict[str, str]:
    """Return a copy of ``base`` with proxy-related variables removed (direct internet)."""
    env = dict(base)
    for key in list(env.keys()):
        if key.upper() in _PROXY_ENV_KEYS_UPPER:
            del env[key]
    env["NO_PROXY"] = "*"
    return env


def apply_direct_http_environment() -> None:
    """Strip proxy variables from :data:`os.environ` so scanners use direct connections.

    Also sets ``NO_PROXY=*`` so child processes (e.g. tools using ``requests``) skip proxies.
    Does not enable Tor or read ``HTTP_PROXY`` for aiohttp when sessions use ``trust_env=False``.
    """
    for key in list(os.environ.keys()):
        if key.upper() in _PROXY_ENV_KEYS_UPPER:
            del os.environ[key]
    os.environ["NO_PROXY"] = "*"

HTTP_TOTAL_SEC = 30.0
HTTP_CONNECT_SEC = 30.0
DEFAULT_MAX_RETRIES = 3
RETRY_BACKOFF_BASE_SEC = 0.45

# Initial WAF fingerprint GET must not stall the whole scan (bounded in evasion + asyncio.wait_for).
WAF_PROBE_WALL_CLOCK_SEC = 32.0

# Wayback CDX runs sequentially before parallel module gather; cap wall time so other work can start.
WAYBACK_PRE_GATHER_WALL_CLOCK_SEC = 95.0

# Nmap stealth path: subprocess + executor must not block the event loop for many minutes.
NMAP_STEALTH_SUBPROCESS_SEC = 150.0
NMAP_EXECUTOR_WALL_CLOCK_SEC = min(180.0, float(NMAP_STEALTH_SUBPROCESS_SEC) + 25.0)


def http_client_timeout() -> aiohttp.ClientTimeout:
    """Default per-request budget for scanner HTTP clients (30s total, connect, and read)."""
    return aiohttp.ClientTimeout(
        total=HTTP_TOTAL_SEC,
        connect=HTTP_CONNECT_SEC,
        sock_connect=HTTP_CONNECT_SEC,
        sock_read=HTTP_TOTAL_SEC,
    )


def short_module_http_timeout() -> aiohttp.ClientTimeout:
    """10s aiohttp budget for param probe / infiltration (avoids stall when stacked with other flags)."""
    t = 10.0
    return aiohttp.ClientTimeout(total=t, connect=t, sock_connect=t, sock_read=t)


def waf_probe_client_timeout() -> aiohttp.ClientTimeout:
    """Short per-attempt budget for :meth:`EvasionProfile.probe_target_waf`."""
    return aiohttp.ClientTimeout(
        total=12.0,
        connect=8.0,
        sock_connect=8.0,
        sock_read=12.0,
    )


def is_transient_network_failure(exc: BaseException) -> bool:
    """Return True if the failure is worth retrying (timeouts, 5xx, common socket errors)."""
    if isinstance(exc, (TimeoutError, asyncio.TimeoutError, aiohttp.ServerTimeoutError)):
        return True
    if isinstance(exc, aiohttp.ClientResponseError):
        return exc.status >= 500 or exc.status in (408, 425, 429)
    if isinstance(exc, (aiohttp.ClientConnectionError, aiohttp.ServerConnectionError)):
        return True
    if isinstance(exc, OSError):
        return True
    msg = str(exc).lower()
    transient_markers = (
        "timeout",
        "timed out",
        "semaphore",
        "winerror 121",
        "temporar",
        "connection reset",
        "broken pipe",
        "connection refused",
        "errno",
        "network is unreachable",
        "host unreachable",
    )
    return any(m in msg for m in transient_markers)


async def retry_pause(attempt_index: int) -> None:
    await asyncio.sleep(RETRY_BACKOFF_BASE_SEC * (2**attempt_index))


async def fetch_text_with_retry(
    session: aiohttp.ClientSession,
    url: str,
    *,
    max_retries: int = DEFAULT_MAX_RETRIES,
    **kwargs: Any,
) -> tuple[str, str]:
    """GET ``url`` and return ``(text, final_url)``, retrying transient failures.

    Merges :func:`default_browser_headers` first (Chrome on Windows + Accept*); caller
    ``headers`` override. Sessions should use ``trust_env=False`` and a
    :func:`direct_tcp_connector` so system HTTP(S)_PROXY and Tor env do not apply.
    """
    req_kwargs = dict(kwargs)
    caller_hdrs = dict(req_kwargs.pop("headers", None) or {})
    hdrs = {**default_browser_headers(), **caller_hdrs}
    # Playtika: X-Bug-Bounty must survive caller overrides.
    hdrs = apply_playtika_headers_last(hdrs)
    req_kwargs["headers"] = hdrs
    last: BaseException | None = None
    for attempt in range(max_retries):
        try:
            async with session.get(url, **req_kwargs) as resp:
                if resp.status >= 500 or resp.status in (408, 429):
                    if attempt < max_retries - 1:
                        await retry_pause(attempt)
                        continue
                resp.raise_for_status()
                ctype = (resp.headers.get("Content-Type") or "").lower()
                if ctype.startswith(("image/", "video/", "audio/")):
                    return "", str(resp.url)
                body = await resp.text(errors="replace")
                return body, str(resp.url)
        except (aiohttp.ClientError, TimeoutError, OSError, asyncio.CancelledError) as exc:
            last = exc
            if isinstance(exc, asyncio.CancelledError):
                raise
            if attempt >= max_retries - 1 or not is_transient_network_failure(exc):
                raise
            await retry_pause(attempt)
    raise RuntimeError(f"fetch failed after retries: {last!r}")
