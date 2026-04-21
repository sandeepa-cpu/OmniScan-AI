# Developed by Channa Sandeepa | OmniScan-AI v2.0 | Copyright 2026
"""Cloud exposure scanner.

Enumerates candidate public storage buckets (AWS S3, Azure Blob, GCP Storage,
DigitalOcean Spaces) derived from the target's apex hostname, and reports which
ones exist and whether they are publicly listable. Authorized testing only.
"""

from __future__ import annotations

import asyncio
import re
from typing import Callable
from urllib.parse import urlparse

import aiohttp

ProgressCallback = Callable[[], None]
PlanCallback = Callable[[int], None]

SEVERITY_HIGH = "High"
SEVERITY_MEDIUM = "Medium"
SEVERITY_LOW = "Low"


class CloudScanner:
    """Probe cloud storage URLs derived from the apex hostname."""

    S3_TEMPLATES: tuple[str, ...] = (
        "https://{name}.s3.amazonaws.com/",
        "https://s3.amazonaws.com/{name}/",
        "https://{name}.s3.us-east-1.amazonaws.com/",
        "https://{name}.s3.eu-west-1.amazonaws.com/",
    )
    AZURE_TEMPLATES: tuple[str, ...] = (
        "https://{name}.blob.core.windows.net/?comp=list",
    )
    GCP_TEMPLATES: tuple[str, ...] = (
        "https://storage.googleapis.com/{name}/",
    )
    DO_TEMPLATES: tuple[str, ...] = (
        "https://{name}.nyc3.digitaloceanspaces.com/",
        "https://{name}.fra1.digitaloceanspaces.com/",
    )

    BUCKET_SUFFIXES: tuple[str, ...] = (
        "",
        "-assets",
        "-static",
        "-media",
        "-uploads",
        "-backup",
        "-backups",
        "-dev",
        "-test",
        "-stage",
        "-staging",
        "-prod",
        "-production",
        "-data",
        "-logs",
        "-private",
        "-public",
        "-files",
        "-images",
        "-cdn",
        "-reports",
    )

    _VALID_BUCKET = re.compile(r"^[a-z0-9][a-z0-9\-]{1,61}[a-z0-9]$")

    def __init__(
        self,
        timeout: aiohttp.ClientTimeout | None = None,
        concurrency: int = 25,
    ) -> None:
        self._timeout = timeout or aiohttp.ClientTimeout(total=10)
        self._concurrency = max(1, concurrency)

    @staticmethod
    def _apex_labels(url: str) -> list[str]:
        """Return candidate base names derived from the target hostname."""
        parsed = urlparse(url if "://" in url else f"https://{url}")
        host = (parsed.hostname or "").lower()
        if not host:
            return []
        host = host.split(":", 1)[0]
        labels = host.split(".")
        if len(labels) < 2:
            return [host] if host else []
        base = labels[-2]
        full = host.replace(".", "-")
        names: list[str] = []
        for candidate in (base, full):
            if candidate and candidate not in names:
                names.append(candidate)
        return names

    def _candidates(self, url: str) -> list[tuple[str, str, str]]:
        """Return [(provider, bucket_name, probe_url), ...]."""
        names: list[str] = []
        for base in self._apex_labels(url):
            for suffix in self.BUCKET_SUFFIXES:
                n = f"{base}{suffix}"
                if self._VALID_BUCKET.match(n) and n not in names:
                    names.append(n)

        out: list[tuple[str, str, str]] = []
        for name in names:
            for tpl in self.S3_TEMPLATES:
                out.append(("aws_s3", name, tpl.format(name=name)))
            for tpl in self.AZURE_TEMPLATES:
                out.append(("azure_blob", name, tpl.format(name=name)))
            for tpl in self.GCP_TEMPLATES:
                out.append(("gcp_storage", name, tpl.format(name=name)))
            for tpl in self.DO_TEMPLATES:
                out.append(("do_spaces", name, tpl.format(name=name)))
        return out

    @staticmethod
    def _classify(provider: str, status: int, body: str) -> tuple[str, str, str] | None:
        """Return (state, severity, note) or None if the finding should be dropped."""
        body_low = body.lower() if body else ""
        if provider == "aws_s3":
            if status == 200 and "<listbucketresult" in body_low:
                return ("public_listable", SEVERITY_HIGH, "S3 bucket is public and listable")
            if status == 200:
                return ("reachable", SEVERITY_MEDIUM, "S3 endpoint returned 200 (content accessible)")
            if status == 403 and "accessdenied" in body_low:
                return ("exists_private", SEVERITY_MEDIUM, "S3 bucket exists (access denied)")
            if status == 403:
                return ("exists_restricted", SEVERITY_LOW, "S3 endpoint restricted")
            if status == 301 or status == 307:
                return ("redirect_region", SEVERITY_LOW, "S3 redirect (likely wrong region)")
            return None
        if provider == "azure_blob":
            if status == 200 and "<enumerationresults" in body_low:
                return ("public_listable", SEVERITY_HIGH, "Azure container is publicly listable")
            if status == 200:
                return ("reachable", SEVERITY_MEDIUM, "Azure endpoint returned 200")
            if status in (400, 403) and "authenticationfailed" in body_low:
                return ("exists_private", SEVERITY_MEDIUM, "Azure container exists (auth required)")
            if status == 409:
                return ("exists_private", SEVERITY_LOW, "Azure container exists (conflict)")
            return None
        if provider == "gcp_storage":
            if status == 200 and "<listbucketresult" in body_low:
                return ("public_listable", SEVERITY_HIGH, "GCS bucket is public and listable")
            if status == 200:
                return ("reachable", SEVERITY_MEDIUM, "GCS endpoint returned 200")
            if status == 403:
                return ("exists_private", SEVERITY_MEDIUM, "GCS bucket exists (access denied)")
            return None
        if provider == "do_spaces":
            if status == 200 and "<listbucketresult" in body_low:
                return ("public_listable", SEVERITY_HIGH, "DO Space is public and listable")
            if status == 200:
                return ("reachable", SEVERITY_MEDIUM, "DO Space endpoint returned 200")
            if status == 403:
                return ("exists_private", SEVERITY_MEDIUM, "DO Space exists (access denied)")
            return None
        return None

    async def _probe(
        self,
        session: aiohttp.ClientSession,
        sem: asyncio.Semaphore,
        provider: str,
        name: str,
        url: str,
    ) -> dict | None:
        async with sem:
            try:
                async with session.get(url, allow_redirects=False) as resp:
                    body = ""
                    try:
                        raw = await resp.content.read(2048)
                        body = raw.decode("utf-8", errors="replace")
                    except Exception:
                        body = ""
                    result = self._classify(provider, resp.status, body)
                    if result is None:
                        return None
                    state, severity, note = result
                    return {
                        "severity": severity,
                        "provider": provider,
                        "bucket": name,
                        "state": state,
                        "status": resp.status,
                        "url": url,
                        "note": note,
                    }
            except (aiohttp.ClientError, TimeoutError, OSError):
                return None
            except Exception:
                return None

    async def scan(
        self,
        target_url: str,
        on_plan: PlanCallback | None = None,
        on_advance: ProgressCallback | None = None,
    ) -> list[dict]:
        candidates = self._candidates(target_url)
        total = max(len(candidates), 1)
        if on_plan is not None:
            try:
                on_plan(total)
            except Exception:
                pass
        if not candidates:
            if on_advance is not None:
                try:
                    on_advance()
                except Exception:
                    pass
            return []

        sem = asyncio.Semaphore(self._concurrency)
        headers = {"User-Agent": "OmniScan-AI/1.0 (cloud-recon)"}
        results: list[dict] = []
        async with aiohttp.ClientSession(timeout=self._timeout, headers=headers) as session:
            tasks = [
                asyncio.create_task(self._probe(session, sem, provider, name, url))
                for provider, name, url in candidates
            ]
            for coro in asyncio.as_completed(tasks):
                row = await coro
                if on_advance is not None:
                    try:
                        on_advance()
                    except Exception:
                        pass
                if row is not None:
                    results.append(row)

        sev_rank = {SEVERITY_HIGH: 0, SEVERITY_MEDIUM: 1, SEVERITY_LOW: 2}
        results.sort(key=lambda r: (sev_rank.get(r["severity"], 9), r["provider"], r["bucket"]))
        return results
