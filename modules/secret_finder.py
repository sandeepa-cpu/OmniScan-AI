# Developed by Channa Sandeepa | OmniScan-AI v2.0 | Copyright 2026
"""Async secret scanner: fetch HTML, parse <script> tags, regex-scan JS for common secrets."""

from __future__ import annotations

import asyncio
import re
from typing import Callable
from urllib.parse import urljoin

import aiohttp
from bs4 import BeautifulSoup

SEVERITY_CRITICAL = "Critical"
SEVERITY_HIGH = "High"
SEVERITY_MEDIUM = "Medium"
SEVERITY_LOW = "Low"
SEVERITY_INFO = "Info"

SEVERITY_COLORS: dict[str, str] = {
    SEVERITY_CRITICAL: "bright_red",
    SEVERITY_HIGH: "red",
    SEVERITY_MEDIUM: "yellow",
    SEVERITY_LOW: "cyan",
    SEVERITY_INFO: "dim",
}

# Mapping from finding kind -> severity tier.
SEVERITY_FOR_KIND: dict[str, str] = {
    "aws_access_key_id": SEVERITY_HIGH,
    "aws_secret_access_key": SEVERITY_HIGH,
    "aws_session_token": SEVERITY_HIGH,
    "stripe_secret_key": SEVERITY_HIGH,
    "stripe_restricted_key": SEVERITY_HIGH,
    "stripe_webhook_secret": SEVERITY_HIGH,
    "github_personal_access_token": SEVERITY_HIGH,
    "github_fine_grained_pat": SEVERITY_HIGH,
    "github_oauth_or_installation_token": SEVERITY_HIGH,
    "heroku_api_key": SEVERITY_HIGH,
    "heroku_api_key_inline": SEVERITY_HIGH,
    "heroku_oauth_token": SEVERITY_HIGH,
    "twilio_auth_token": SEVERITY_HIGH,
    "twilio_auth_token_json": SEVERITY_HIGH,
    "slack_webhook": SEVERITY_HIGH,
    "mailgun_api_key": SEVERITY_HIGH,
    "sendgrid_api_key": SEVERITY_HIGH,
    "private_key_pem": SEVERITY_HIGH,
    "discord_webhook": SEVERITY_HIGH,
    "telegram_bot_token": SEVERITY_HIGH,
    "npm_token": SEVERITY_HIGH,
    "mongodb_connection_string": SEVERITY_HIGH,
    "datadog_api_key": SEVERITY_HIGH,
    "google_oauth_client_secret": SEVERITY_HIGH,
    "firebase_config": SEVERITY_HIGH,
    "google_api_key": SEVERITY_MEDIUM,
    "twilio_account_sid": SEVERITY_MEDIUM,
    "stripe_publishable_key": SEVERITY_MEDIUM,
    "algolia_api_key": SEVERITY_MEDIUM,
    "jwt_compact": SEVERITY_MEDIUM,
}


def severity_for(kind: str) -> str:
    """Return the severity tier for a finding kind (defaults to Low)."""
    return SEVERITY_FOR_KIND.get(kind, SEVERITY_LOW)


ProgressCallback = Callable[[], None]
PlanCallback = Callable[[int], None]


class SecretFinder:
    """Fetch a page with aiohttp, collect script sources via BeautifulSoup, scan for secrets."""

    # Pattern kinds where the sensitive value is capture group 1 (not the full match).
    _GROUP_VALUE_KINDS: frozenset[str] = frozenset(
        {
            "aws_secret_access_key",
            "aws_session_token",
            "firebase_config",
            "google_oauth_client_secret",
            "heroku_api_key",
            "heroku_api_key_inline",
            "heroku_oauth_token",
            "twilio_auth_token",
            "twilio_auth_token_json",
            "datadog_api_key",
            "algolia_api_key",
            "mongodb_connection_string",
        }
    )

    _PATTERNS: list[tuple[str, re.Pattern[str]]] = [
        (
            "google_api_key",
            re.compile(
                r"(?<![0-9A-Za-z])AIza[0-9A-Za-z\-_]{35}(?![0-9A-Za-z])"
            ),
        ),
        (
            "aws_access_key_id",
            re.compile(
                r"(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[0-9A-Z]{16}"
            ),
        ),
        (
            "aws_secret_access_key",
            re.compile(
                r"(?i)(?:aws[_\s-]?secret[_\s-]?access[_\s-]?key|AWS_SECRET_ACCESS_KEY)"
                r"\s*[=:]\s*['\"`]?([A-Za-z0-9/+=]{40})['\"`]?"
            ),
        ),
        (
            "aws_session_token",
            re.compile(
                r"(?i)(?:aws[_\s-]?session[_\s-]?token|AWS_SESSION_TOKEN)"
                r"\s*[=:]\s*['\"`]?([A-Za-z0-9/+=]{100,2048})['\"`]?"
            ),
        ),
        (
            "firebase_config",
            re.compile(
                r"(?is)(?:firebase(?:\.initializeApp)?\s*\(\s*\{|"
                r"['\"]firebaseConfig['\"]\s*,\s*\{)"
                r"[\s\S]{0,4000}?"
                r"apiKey\s*:\s*['\"`]([^'\"\`\n]+)['\"`]"
            ),
        ),
        (
            "google_oauth_client_secret",
            re.compile(
                r"(?i)(?:client_secret|CLIENT_SECRET)\s*[=:]\s*"
                r"['\"`]([a-zA-Z0-9\-_]{16,128})['\"`]"
            ),
        ),
        (
            "slack_webhook",
            re.compile(
                r"https://hooks\.slack\.com/(?:"
                r"services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9_\-]+|"
                r"workflows/[A-Za-z0-9_\-/]+|"
                r"triggers/[A-Za-z0-9_\-/]+"
                r")"
            ),
        ),
        (
            "github_personal_access_token",
            re.compile(r"(?<![0-9a-zA-Z])ghp_[0-9a-zA-Z]{36}(?![0-9a-zA-Z])"),
        ),
        (
            "github_fine_grained_pat",
            re.compile(
                r"(?<![0-9a-zA-Z])github_pat_[0-9a-zA-Z_]{36,255}(?![0-9a-zA-Z_])"
            ),
        ),
        (
            "github_oauth_or_installation_token",
            re.compile(
                r"(?<![0-9a-zA-Z])(?:gho|ghu|ghs|ghr)_[0-9a-zA-Z]{20,255}"
                r"(?![0-9a-zA-Z])"
            ),
        ),
        (
            "mailgun_api_key",
            re.compile(r"(?i)(?<![0-9a-fA-F])key-[0-9a-f]{32}(?![0-9a-fA-F])"),
        ),
        (
            "stripe_secret_key",
            re.compile(
                r"(?i)(?<![0-9a-zA-Z])sk_(?:live|test)_[0-9a-zA-Z]{20,128}"
                r"(?![0-9a-zA-Z])"
            ),
        ),
        (
            "stripe_publishable_key",
            re.compile(
                r"(?i)(?<![0-9a-zA-Z])pk_(?:live|test)_[0-9a-zA-Z]{20,128}"
                r"(?![0-9a-zA-Z])"
            ),
        ),
        (
            "stripe_restricted_key",
            re.compile(
                r"(?i)(?<![0-9a-zA-Z])rk_(?:live|test)_[0-9a-zA-Z]{20,128}"
                r"(?![0-9a-zA-Z])"
            ),
        ),
        (
            "stripe_webhook_secret",
            re.compile(r"(?<![0-9a-zA-Z])whsec_[A-Za-z0-9+/=_\-]{16,256}\b"),
        ),
        (
            "heroku_api_key",
            re.compile(
                r"(?i)(?:HEROKU_API_KEY|heroku[_\s-]?api[_\s-]?key)\s*[:=]\s*"
                r"['\"]?([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})['\"]?"
            ),
        ),
        (
            "heroku_api_key_inline",
            re.compile(
                r"(?i)(?:export\s+)?HEROKU_API_KEY\s*=\s*"
                r"['\"]?([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})['\"]?"
            ),
        ),
        (
            "heroku_oauth_token",
            re.compile(
                r"(?i)(?<![0-9a-zA-Z])heroku[_\s-]?(?:oauth|access)[_\s-]?token\s*[:=]\s*"
                r"['\"]?([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})['\"]?"
            ),
        ),
        (
            "twilio_account_sid",
            re.compile(r"(?<![0-9a-fA-F])AC[0-9a-fA-F]{32}(?![0-9a-fA-F])"),
        ),
        (
            "twilio_auth_token",
            re.compile(
                r"(?i)(?:TWILIO_AUTH_TOKEN|twilioAuthToken|authToken)\s*[:=]\s*"
                r"['\"`]?([0-9a-f]{32})['\"`]?"
            ),
        ),
        (
            "twilio_auth_token_json",
            re.compile(
                r"(?i)['\"]authToken['\"]\s*:\s*['\"`]([0-9a-f]{32})['\"`]"
            ),
        ),
        (
            "discord_webhook",
            re.compile(
                r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+"
            ),
        ),
        (
            "telegram_bot_token",
            re.compile(
                r"(?<![0-9])(?:\b|^)\d{8,14}:[A-Za-z0-9_-]{30,40}(?![0-9A-Za-z_-])"
            ),
        ),
        (
            "sendgrid_api_key",
            re.compile(
                r"(?<![0-9A-Za-z])SG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{16,64}"
                r"(?![0-9A-Za-z._-])"
            ),
        ),
        (
            "npm_token",
            re.compile(
                r"(?<![0-9A-Za-z])npm_[A-Za-z0-9]{36,255}(?![0-9A-Za-z])"
            ),
        ),
        (
            "jwt_compact",
            re.compile(
                r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
            ),
        ),
        (
            "private_key_pem",
            re.compile(
                r"(?is)-----BEGIN[A-Z0-9 \n\r-]{0,40}PRIVATE KEY-----"
                r".{20,4000}?"
                r"-----END[A-Z0-9 \n\r-]{0,40}PRIVATE KEY-----"
            ),
        ),
        (
            "datadog_api_key",
            re.compile(
                r"(?i)(?:DD_API_KEY|DATADOG[_\s-]?API[_\s-]?KEY|datadogApiKey)\s*[:=]\s*"
                r"['\"`]?([a-f0-9]{32})['\"`]?"
            ),
        ),
        (
            "algolia_api_key",
            re.compile(
                r"(?i)(?:ALGOLIA[_\s-]?API[_\s-]?KEY|algoliaApiKey)\s*[:=]\s*"
                r"['\"`]?([a-f0-9]{32})['\"`]?"
            ),
        ),
        (
            "mongodb_connection_string",
            re.compile(
                r"(?i)mongodb(?:\+srv)?://[^\s'\"`]+:([^@\s'\"`]{3,256})@"
            ),
        ),
    ]

    def __init__(
        self,
        timeout: aiohttp.ClientTimeout | None = None,
        concurrency: int = 12,
    ) -> None:
        self._timeout = timeout or aiohttp.ClientTimeout(total=30)
        self._concurrency = max(1, concurrency)

    @staticmethod
    def _absolute_url(base: str, href: str) -> str:
        return urljoin(base, href)

    def _collect_scripts(
        self, html: str, page_url: str
    ) -> tuple[list[tuple[str, str]], list[str]]:
        """
        Parse HTML for <script> tags.

        Returns:
            inline: list of (source_label, javascript_text)
            external_urls: unique absolute URLs for ``src`` scripts
        """
        try:
            soup = BeautifulSoup(html, "html.parser")
        except Exception as exc:
            raise RuntimeError("Could not parse HTML for script tags.") from exc

        inline: list[tuple[str, str]] = []
        external: list[str] = []
        seen_urls: set[str] = set()
        inline_idx = 0

        for tag in soup.find_all("script"):
            try:
                raw_src = tag.get("src")
                if raw_src is not None:
                    href = str(raw_src).strip()
                    if not href or href.startswith(("data:", "javascript:")):
                        continue
                    abs_url = self._absolute_url(page_url, href)
                    if abs_url not in seen_urls:
                        seen_urls.add(abs_url)
                        external.append(abs_url)
                else:
                    text = tag.string
                    if text is None:
                        text = tag.get_text()
                    body = (text or "").strip()
                    if body:
                        inline_idx += 1
                        label = f"{page_url}#inline-script-{inline_idx}"
                        inline.append((label, body))
            except (TypeError, ValueError):
                continue

        return inline, external

    @staticmethod
    def _iter_js_string_literal_contents(js: str) -> list[str]:
        """
        Yield raw inner text of JavaScript string literals (double, single, simple templates).

        Used so secrets embedded only inside quoted strings are still matched by the same
        regexes (e.g. ``apiKey: \"sk_live_...\"``, ``const t = `ghp_...` ``).
        """
        chunks: list[str] = []

        for m in re.finditer(r'"(?:[^"\\\n]|\\.)*"', js):
            chunks.append(m.group(0)[1:-1])

        for m in re.finditer(r"'(?:[^'\\\n]|\\.)*'", js):
            chunks.append(m.group(0)[1:-1])

        for m in re.finditer(r"`([^`]*)`", js):
            chunks.append(m.group(1))

        return chunks

    def _match_value(self, kind: str, match: re.Match[str]) -> str:
        if kind in self._GROUP_VALUE_KINDS:
            return match.group(1)
        return match.group(0)

    def _match_patterns_on_chunk(self, chunk: str, source_url: str) -> list[dict]:
        findings: list[dict] = []
        for kind, pattern in self._PATTERNS:
            try:
                for m in pattern.finditer(chunk):
                    findings.append(
                        {
                            "type": kind,
                            "severity": severity_for(kind),
                            "source_url": source_url,
                            "match": self._match_value(kind, m),
                        }
                    )
            except re.error:
                continue
        return findings

    def _scan_text(self, text: str, source_url: str) -> list[dict]:
        """Scan full script text and each extracted string literal; dedupe identical hits."""
        seen: set[tuple[str, str, str]] = set()
        ordered: list[dict] = []

        def absorb(chunk: str) -> None:
            for item in self._match_patterns_on_chunk(chunk, source_url):
                key = (item["type"], item["match"], item["source_url"])
                if key not in seen:
                    seen.add(key)
                    ordered.append(item)

        absorb(text)
        for inner in self._iter_js_string_literal_contents(text):
            if len(inner) < 8:
                continue
            absorb(inner)

        return ordered

    async def find(
        self,
        target_url: str,
        on_plan: PlanCallback | None = None,
        on_advance: ProgressCallback | None = None,
    ) -> list[dict]:
        """
        Fetch ``target_url``, enumerate ``<script>`` tags, fetch external ``src`` resources,
        and return regex hits for common cloud/API secrets.

        Optional progress hooks:
            on_plan(total_units): total = 1 (page) + len(inline) + len(external).
            on_advance(): called after each unit completes.
        """
        results: list[dict] = []
        headers = {
            "User-Agent": "OmniScan-AI/1.0 (security research)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

        def _advance() -> None:
            if on_advance is not None:
                try:
                    on_advance()
                except Exception:
                    pass

        try:
            async with aiohttp.ClientSession(timeout=self._timeout) as session:
                try:
                    async with session.get(
                        target_url, headers=headers, allow_redirects=True
                    ) as resp:
                        resp.raise_for_status()
                        html = await resp.text()
                        page_url = str(resp.url)
                except aiohttp.ClientResponseError as exc:
                    raise RuntimeError(
                        f"HTTP {exc.status} while fetching page: {target_url}"
                    ) from exc
                except (aiohttp.ClientError, TimeoutError, OSError) as exc:
                    raise RuntimeError(
                        f"Network error while fetching page: {exc}"
                    ) from exc

                try:
                    inline_scripts, script_urls = self._collect_scripts(html, page_url)
                except RuntimeError:
                    raise
                except Exception as exc:
                    raise RuntimeError(f"Unexpected error parsing scripts: {exc}") from exc

                total_units = 1 + len(inline_scripts) + len(script_urls)
                if on_plan is not None:
                    try:
                        on_plan(total_units)
                    except Exception:
                        pass
                _advance()

                for label, body in inline_scripts:
                    try:
                        results.extend(self._scan_text(body, label))
                    except Exception:
                        pass
                    _advance()

                if script_urls:
                    sem = asyncio.Semaphore(self._concurrency)

                    async def _fetch_one(js_url: str) -> list[dict]:
                        async with sem:
                            try:
                                async with session.get(
                                    js_url, headers=headers, allow_redirects=True
                                ) as r:
                                    if r.status != 200:
                                        return []
                                    ctype = (r.headers.get("Content-Type") or "").lower()
                                    if ctype.startswith(("image/", "video/", "audio/")):
                                        return []
                                    text = await r.text(errors="replace")
                                    final_js = str(r.url)
                            except (aiohttp.ClientError, TimeoutError, OSError):
                                return []
                            except Exception:
                                return []
                        try:
                            return self._scan_text(text, final_js)
                        except Exception:
                            return []

                    tasks = [asyncio.create_task(_fetch_one(u)) for u in script_urls]
                    for coro in asyncio.as_completed(tasks):
                        try:
                            rows = await coro
                            results.extend(rows)
                        except Exception:
                            pass
                        _advance()

        except RuntimeError:
            raise
        except (aiohttp.ClientError, TimeoutError, OSError) as exc:
            raise RuntimeError(f"Session error: {exc}") from exc

        return results
