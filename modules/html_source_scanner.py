# Developed by Channa Sandeepa | OmniScan-AI v2.0 | Copyright 2026
"""HTML source recon: HTML comments, hidden URLs, and suspicious meta tags."""

from __future__ import annotations

import re
from typing import Callable
from urllib.parse import urljoin

import aiohttp
from bs4 import BeautifulSoup
from bs4.element import Comment

from .evasion import EvasionProfile, build_browser_headers, friendly_network_error
from .scanner_engine import http_client_timeout

ProgressCallback = Callable[[], None]
PlanCallback = Callable[[int], None]

SEVERITY_MEDIUM = "Medium"
SEVERITY_LOW = "Low"

# URLs inside comments or plain text (http(s), //, /path)
_URL_IN_TEXT = re.compile(
    r"""(?i)(https?://[^\s"'<>]{4,2048}|//[^\s"'<>]{2,2048}|/(?:api|admin|internal|v\d+|graphql|rest|oauth|assets|static|media|uploads|download|private|backup|debug|test|dev|staging)[^\s"'<>]{0,512})"""
)


class HtmlSourceScanner:
    """Extract developer comments, leaked URLs, and meta hints from HTML."""

    async def scan(
        self,
        target_url: str,
        on_plan: PlanCallback | None = None,
        on_advance: ProgressCallback | None = None,
        evasion: EvasionProfile | None = None,
    ) -> list[dict]:
        ev = evasion or EvasionProfile()
        findings: list[dict] = []

        def _advance() -> None:
            if on_advance is not None:
                try:
                    on_advance()
                except Exception:
                    pass

        if on_plan is not None:
            try:
                on_plan(1)
            except Exception:
                pass

        raw = target_url.strip()
        if "://" not in raw:
            raw = f"https://{raw}"
        page_ref = raw

        try:
            connector = ev.aiohttp_connector(ssl=True, limit=20)
        except RuntimeError:
            raise

        try:
            async with aiohttp.ClientSession(
                timeout=http_client_timeout(),
                connector=connector,
                trust_env=False,
            ) as session:
                await ev.apply_jitter()
                headers = build_browser_headers(referer=page_ref, evasion=ev)
                async with session.get(
                    target_url, headers=headers, allow_redirects=True
                ) as resp:
                    final_url = str(resp.url)
                    raw = await resp.read()
                    html = raw[:2_000_000].decode("utf-8", errors="replace")
        except (aiohttp.ClientError, TimeoutError, OSError) as exc:
            raise RuntimeError(friendly_network_error(exc)) from exc

        _advance()

        try:
            soup = BeautifulSoup(html, "html.parser")
        except Exception:
            return findings

        base_for_join = final_url

        for c in soup.find_all(string=lambda t: isinstance(t, Comment)):
            text = str(c).strip()
            if not text or len(text) > 8000:
                continue
            preview = text.replace("\n", " ")[:400]
            findings.append(
                {
                    "type": "html_comment",
                    "severity": SEVERITY_LOW,
                    "source_url": final_url,
                    "match": preview,
                    "note": f"HTML comment ({len(text)} chars)",
                }
            )
            for m in _URL_IN_TEXT.finditer(text):
                u = m.group(1).strip()
                if len(u) < 5:
                    continue
                abs_u = urljoin(base_for_join, u) if u.startswith("/") else u
                findings.append(
                    {
                        "type": "comment_url",
                        "severity": SEVERITY_MEDIUM,
                        "source_url": final_url,
                        "match": abs_u[:2048],
                        "note": "URL-like string inside HTML comment",
                    }
                )

        for tag in soup.find_all(True):
            for attr in ("href", "src", "data-src", "data-url", "data-endpoint", "data-api", "action"):
                val = tag.get(attr)
                if not val or not isinstance(val, str):
                    continue
                v = val.strip()
                if v.startswith("#") or v.startswith("javascript:"):
                    continue
                if _URL_IN_TEXT.search(v) or (
                    v.startswith("/")
                    and len(v) > 2
                    and any(
                        x in v.lower()
                        for x in (
                            "api",
                            "admin",
                            "internal",
                            "debug",
                            "backup",
                            "graphql",
                            "v1",
                            "v2",
                            "oauth",
                        )
                    )
                ):
                    abs_u = urljoin(base_for_join, v)
                    findings.append(
                        {
                            "type": f"attr_{attr}",
                            "severity": SEVERITY_LOW,
                            "source_url": final_url,
                            "match": abs_u[:2048],
                            "note": f"Interesting {attr} on <{tag.name}>",
                        }
                    )

        for meta in soup.find_all("meta"):
            name = (meta.get("name") or meta.get("property") or "").lower()
            content = meta.get("content") or ""
            if not content:
                continue
            if any(
                k in name
                for k in (
                    "generator",
                    "api",
                    "version",
                    "csrf",
                    "author",
                )
            ):
                findings.append(
                    {
                        "type": "meta_tag",
                        "severity": SEVERITY_LOW,
                        "source_url": final_url,
                        "match": f"{name}={content[:300]}",
                        "note": "Meta tag (possible tech / version leak)",
                    }
                )

        seen: set[tuple[str, str, str]] = set()
        deduped: list[dict] = []
        for r in findings:
            key = (r["type"], r["match"][:500], r["source_url"])
            if key in seen:
                continue
            seen.add(key)
            deduped.append(r)

        return deduped
