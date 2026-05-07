# Developed by Channa Sandeepa | OmniScan-AI v2.0 | Copyright 2026
"""OAuth 2.0 / OpenID Connect and social-login probes for authorized bug-bounty testing.

Focus: redirect URI handling, OIDC discovery, and read-only checks on account linking
surfaces. Uses conservative concurrency and inter-request pacing (via
:class:`EvasionProfile`) to avoid placing excessive load on targets.

Playtika / general policy: pair with ``OMNISCAN_PLAYTIKA_BOUNTY`` and
``X-Bug-Bounty: True`` on requests.
"""

from __future__ import annotations

import asyncio
import re
from typing import Callable
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import aiohttp

from .evasion import EvasionProfile, build_browser_headers, friendly_network_error
from .scanner_engine import (
    PLAYTIKA_MAX_CONCURRENT_HTTP,
    PLAYTIKA_SOCIAL_LOGIN_PATHS,
    http_client_timeout,
    playtika_connector_limit,
)

PlanCallback = Callable[[int], None]
ProgressCallback = Callable[[], None]

# RFC 5737 / documentation-safe probe only (never a real victim host).
_EXTERNAL_REDIRECT_TEST = "https://example.com/omniscan-oauth-cb"
_INSECURE_REDIRECT_TEST = "http://127.0.0.1:9/omniscan-oauth-insecure-cb"
_REFERER_LEAK_MARKER = "omniscan_oauth_referer_probe_9f2a"

_OAUTH_URL_RE = re.compile(
    r"https?://[^\s\"'<>]+(?:"
    r"/oauth|/oidc|/openid|authorize\?|oauth2|openid-connect|"
    r"accounts\.google\.com/o/oauth2|facebook\.com/(?:v[\d.]*/)?dialog/oauth|"
    r"login\.microsoftonline\.com/[^\"\s]*"
    r")[^\s\"'<>]*",
    re.IGNORECASE,
)

_BASE_OAUTH_PATHS: tuple[str, ...] = (
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/oauth/authorize",
    "/oauth2/authorize",
    "/authorize",
    "/connect/authorize",
    "/login/oauth/authorize",
    "/auth/oauth/authorize",
    "/api/oauth/authorize",
    "/v1/oauth/authorize",
    "/signin/oauth",
    "/social/login",
    "/social/connect",
    "/account/link",
    "/account/unlink",
    "/account/connected-accounts",
    "/users/auth/facebook/callback",
    "/users/auth/google/callback",
    "/api/auth/oauth",
)

# Playtika Social Login paths first (campaign focus), then generic OAuth/OIDC paths (deduped).
_ALL_OAUTH_PATHS: tuple[str, ...] = tuple(
    dict.fromkeys([*PLAYTIKA_SOCIAL_LOGIN_PATHS, *_BASE_OAUTH_PATHS]).keys()
)

_MAX_CONCURRENT = PLAYTIKA_MAX_CONCURRENT_HTTP
_MAX_REDIRECT_URI_TESTS = 6
_MAX_HTML_CANDIDATES = 8
_MAX_REFERER_LEAK_PROBES = 4
_MAX_INSECURE_REDIRECT_TESTS = 2


class OAuthSocialScanner:
    """Low-volume OAuth/OIDC + social surface reconnaissance."""

    def __init__(
        self,
        evasion: EvasionProfile,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self._evasion = evasion
        self._extra = dict(extra_headers or {})

    async def scan(
        self,
        target_url: str,
        *,
        on_plan: PlanCallback | None = None,
        on_advance: ProgressCallback | None = None,
    ) -> tuple[list[dict], str | None]:
        rows: list[dict] = []
        raw = (target_url or "").strip()
        if "://" not in raw:
            raw = f"https://{raw}"
        base = raw if raw.endswith("/") else f"{raw}/"
        target_host = (urlparse(raw.rstrip("/")).hostname or "").lower()

        def _host_matches(u: str) -> bool:
            h = (urlparse(u).hostname or "").lower()
            return bool(target_host) and (
                h == target_host or h.endswith("." + target_host)
            )

        planned = (
            1
            + len(_ALL_OAUTH_PATHS)
            + _MAX_HTML_CANDIDATES
            + _MAX_REDIRECT_URI_TESTS
            + _MAX_REFERER_LEAK_PROBES
            + _MAX_INSECURE_REDIRECT_TESTS
        )
        if on_plan is not None:
            on_plan(planned)

        sem = asyncio.Semaphore(_MAX_CONCURRENT)
        timeout = http_client_timeout()
        connector = self._evasion.aiohttp_connector(
            ssl=True,
            limit=playtika_connector_limit(32),
        )

        async def _tick() -> None:
            if on_advance is not None:
                on_advance()

        async def _get(
            session: aiohttp.ClientSession,
            url: str,
            *,
            allow_redirects: bool = False,
        ) -> tuple[int, str, str]:
            await self._evasion.apply_jitter()
            headers = build_browser_headers(
                referer=base,
                extra=self._extra,
                evasion=self._evasion,
            )
            async with sem:
                try:
                    async with session.get(
                        url,
                        headers=headers,
                        allow_redirects=allow_redirects,
                        ssl=True,
                    ) as resp:
                        loc = resp.headers.get("Location", "") or ""
                        ct = (resp.headers.get("Content-Type") or "").lower()
                        return resp.status, loc, ct
                except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                    raise RuntimeError(friendly_network_error(exc)) from exc
                finally:
                    await _tick()

        try:
            async with aiohttp.ClientSession(
                timeout=timeout,
                connector=connector,
                trust_env=False,
            ) as session:
                # Landing page: discover authorize URLs in HTML (single GET, follows redirects).
                try:
                    await self._evasion.apply_jitter()
                    hdrs = build_browser_headers(
                        referer=base,
                        extra=self._extra,
                        evasion=self._evasion,
                    )
                    async with sem:
                        async with session.get(
                            raw.rstrip("/"),
                            headers=hdrs,
                            allow_redirects=True,
                            ssl=True,
                        ) as resp:
                            html = await resp.text(errors="replace")
                    await _tick()
                except Exception as exc:
                    return rows, str(exc)

                candidates: set[str] = set()
                for m in _OAUTH_URL_RE.findall(html or ""):
                    u = m.strip().rstrip(").,;\"'")
                    if u.startswith("http") and _host_matches(u):
                        candidates.add(u.split("#")[0])
                for path in _ALL_OAUTH_PATHS:
                    candidates.add(urljoin(base, path))

                # OIDC discovery GETs (metadata only).
                oidc_url = urljoin(base, "/.well-known/openid-configuration")
                try:
                    st, loc, ct = await _get(session, oidc_url, allow_redirects=False)
                    if st == 200 and "json" in ct:
                        rows.append(
                            {
                                "type": "oidc_metadata",
                                "severity": "Info",
                                "detail": "OpenID Provider metadata returned 200 (review issuer, registration, redirect URIs).",
                                "note": "Read-only discovery per authorized assessment.",
                                "url": oidc_url,
                                "source_url": raw,
                            }
                        )
                    elif st in (301, 302, 303, 307, 308) and loc:
                        rows.append(
                            {
                                "type": "oidc_metadata_redirect",
                                "severity": "Low",
                                "detail": f"OIDC discovery HTTP {st} → {loc[:200]}",
                                "note": "",
                                "url": oidc_url,
                                "source_url": raw,
                            }
                        )
                except Exception:
                    pass

                # Path + HTML-linked authorize endpoints (status only, no redirect follow).
                checked = 0
                for u in sorted(candidates):
                    if checked >= len(_ALL_OAUTH_PATHS) + _MAX_HTML_CANDIDATES:
                        break
                    try:
                        st, loc, ct = await _get(session, u, allow_redirects=False)
                        lowu = u.lower()
                        if (
                            st == 200
                            and "html" in ct
                            and (
                                "/login/social" in lowu
                                or lowu.rstrip("/").endswith("/linking")
                                or "/linking" in lowu
                            )
                        ):
                            rows.append(
                                {
                                    "type": "pre_auth_account_linking",
                                    "severity": "High",
                                    "detail": (
                                        "HTTP 200 on /login/social or /linking-style path without "
                                        "redirect to login — possible pre-authentication account linking "
                                        "or ATO via social (verify state/CSRF/session binding)."
                                    ),
                                    "note": "Read-only GET; confirm in program rules.",
                                    "url": u,
                                    "source_url": raw,
                                }
                            )
                        if any(
                            k in lowu
                            for k in (
                                "unlink",
                                "disconnect",
                                "link",
                                "connect",
                                "social",
                                "connected-account",
                            )
                        ):
                            if st == 200 and "html" in ct:
                                if "/login/social" in lowu or "/linking" in lowu:
                                    pass
                                else:
                                    rows.append(
                                        {
                                            "type": "social_linking_surface",
                                            "severity": "Medium",
                                            "detail": (
                                                "HTTP 200 on social linking-related path — verify auth, "
                                                "session binding, and CSRF for link/unlink (ATO via social)."
                                            ),
                                            "note": "Read-only GET; confirm in program scope.",
                                            "url": u,
                                            "source_url": raw,
                                        }
                                    )
                            elif st in (301, 302, 303, 307, 308):
                                rows.append(
                                    {
                                        "type": "social_linking_redirect",
                                        "severity": "Low",
                                        "detail": f"Redirect chain starts ({st}) for social-related URL.",
                                        "note": loc[:300] if loc else "",
                                        "url": u,
                                        "source_url": raw,
                                    }
                                )
                        if st in (301, 302, 303, 307, 308) and (
                            "oauth" in lowu
                            or "authorize" in lowu
                            or "openid" in lowu
                            or "oidc" in lowu
                        ):
                            rows.append(
                                {
                                    "type": "oauth_authorize_redirect",
                                    "severity": "Low",
                                    "detail": f"Authorize-style endpoint returns {st}",
                                    "note": (loc or "")[:400],
                                    "url": u,
                                    "source_url": raw,
                                }
                            )
                    except Exception:
                        pass
                    checked += 1

                # Redirect URI validation: swap redirect_uri to documentation-safe external URL.
                redirect_tests = 0
                for u in sorted(candidates):
                    if redirect_tests >= _MAX_REDIRECT_URI_TESTS:
                        break
                    if not _host_matches(u):
                        continue
                    parsed = urlparse(u)
                    if not parsed.query and not parsed.fragment:
                        continue
                    q_pairs = parse_qsl(parsed.query, keep_blank_values=True)
                    keys = {k.lower() for k, _ in q_pairs}
                    if "redirect_uri" not in keys and "redirect_uri" not in parsed.fragment.lower():
                        continue
                    new_pairs: list[tuple[str, str]] = []
                    mutated = False
                    for k, v in q_pairs:
                        if k.lower() == "redirect_uri" and v:
                            new_pairs.append((k, _EXTERNAL_REDIRECT_TEST))
                            mutated = True
                        else:
                            new_pairs.append((k, v))
                    if not mutated:
                        continue
                    new_query = urlencode(new_pairs, doseq=True)
                    test_url = urlunparse(
                        (
                            parsed.scheme,
                            parsed.netloc,
                            parsed.path,
                            parsed.params,
                            new_query,
                            "",
                        )
                    )
                    try:
                        st, loc, _ = await _get(session, test_url, allow_redirects=False)
                        loc_l = (loc or "").lower()
                        if st in (301, 302, 303, 307, 308) and loc_l.startswith(
                            "https://example.com/"
                        ):
                            rows.append(
                                {
                                    "type": "oauth_redirect_uri_external",
                                    "severity": "High",
                                    "detail": (
                                        "Authorization endpoint redirected to external redirect_uri "
                                        f"({_EXTERNAL_REDIRECT_TEST}) — possible weak redirect URI validation."
                                    ),
                                    "note": "Confirm against program rules; may be IdP-dependent false positive.",
                                    "url": test_url[:2000],
                                    "source_url": u,
                                }
                            )
                        elif st == 200:
                            rows.append(
                                {
                                    "type": "oauth_redirect_uri_probe",
                                    "severity": "Low",
                                    "detail": (
                                        "Authorize URL accepted altered redirect_uri (HTTP 200) — "
                                        "possible allowlist mismatch or error page; review manually."
                                    ),
                                    "note": "",
                                    "url": test_url[:2000],
                                    "source_url": u,
                                }
                            )
                        loc_o = (loc or "").strip()
                        if (
                            st in (301, 302, 303, 307, 308)
                            and loc_o
                            and urlparse(u).netloc
                            and urlparse(loc_o).netloc
                            and urlparse(loc_o).netloc != urlparse(u).netloc
                            and "example.com" not in loc_o.lower()
                        ):
                            rows.append(
                                {
                                    "type": "oauth_redirect_uri_mismatch",
                                    "severity": "Medium",
                                    "detail": (
                                        "Redirect after redirect_uri mutation points to a different host than "
                                        "the authorize endpoint — verify registered redirect URI validation."
                                    ),
                                    "note": f"Location: {loc_o[:500]}",
                                    "url": test_url[:2000],
                                    "source_url": u,
                                }
                            )
                    except Exception:
                        pass
                    redirect_tests += 1

                # Insecure redirect_uri (HTTP / loopback) — weak validation signal.
                insecure_tests = 0
                for u in sorted(candidates):
                    if insecure_tests >= _MAX_INSECURE_REDIRECT_TESTS:
                        break
                    if not _host_matches(u):
                        continue
                    parsed = urlparse(u)
                    if not parsed.query:
                        continue
                    q_pairs = parse_qsl(parsed.query, keep_blank_values=True)
                    keys = {k.lower() for k, _ in q_pairs}
                    if "redirect_uri" not in keys:
                        continue
                    new_pairs_i: list[tuple[str, str]] = []
                    mutated_i = False
                    for k, v in q_pairs:
                        if k.lower() == "redirect_uri" and v:
                            new_pairs_i.append((k, _INSECURE_REDIRECT_TEST))
                            mutated_i = True
                        else:
                            new_pairs_i.append((k, v))
                    if not mutated_i:
                        continue
                    test_url_i = urlunparse(
                        (
                            parsed.scheme,
                            parsed.netloc,
                            parsed.path,
                            parsed.params,
                            urlencode(new_pairs_i, doseq=True),
                            "",
                        )
                    )
                    try:
                        st_i, loc_i, _ = await _get(
                            session, test_url_i, allow_redirects=False
                        )
                        loc_il = (loc_i or "").lower()
                        if st_i in (301, 302, 303, 307, 308) and (
                            "127.0.0.1" in loc_il or loc_il.startswith("http://")
                        ):
                            rows.append(
                                {
                                    "type": "oauth_redirect_uri_insecure_scheme",
                                    "severity": "Medium",
                                    "detail": (
                                        "Authorization response redirects to loopback or HTTP redirect_uri — "
                                        "possible weak redirect URI / scheme validation."
                                    ),
                                    "note": (loc_i or "")[:400],
                                    "url": test_url_i[:2000],
                                    "source_url": u,
                                }
                            )
                    except Exception:
                        pass
                    insecure_tests += 1

                # Referer leakage: synthetic OAuth callback URL in Referer; flag if echoed in body.
                fake_referer = (
                    "https://example.com/oauth/callback?"
                    f"access_token={_REFERER_LEAK_MARKER}&token_type=Bearer&state=probe"
                )
                referer_tests = 0
                for u in sorted(candidates):
                    if referer_tests >= _MAX_REFERER_LEAK_PROBES:
                        break
                    if not _host_matches(u):
                        continue
                    lu = u.lower()
                    if "callback" not in lu and "/oauth/" not in lu:
                        continue
                    await self._evasion.apply_jitter()
                    hdrs = build_browser_headers(
                        referer=fake_referer,
                        extra=self._extra,
                        evasion=self._evasion,
                    )
                    body = ""
                    async with sem:
                        try:
                            async with session.get(
                                u,
                                headers=hdrs,
                                allow_redirects=False,
                                ssl=True,
                            ) as resp:
                                body = await resp.text(errors="replace")
                        except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
                            body = ""
                        finally:
                            await _tick()
                    if _REFERER_LEAK_MARKER in body:
                        rows.append(
                            {
                                "type": "oauth_token_referer_leak",
                                "severity": "High",
                                "detail": (
                                    "Response body reflects Referer query (synthetic access_token marker) — "
                                    "possible OAuth token leakage via Referer (e.g. logs, HTML, open redirect)."
                                ),
                                "note": "Verify with program scope; may be static error page quoting URL.",
                                "url": u,
                                "source_url": raw,
                            }
                        )
                    referer_tests += 1

        except Exception as exc:
            return rows, str(exc)

        return rows, None
