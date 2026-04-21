# Developed by Channa Sandeepa | OmniScan-AI v2.0 | Copyright 2026
"""Insecure Direct Object Reference (IDOR) scanner.

Finds numeric IDs in URL query parameters (``id``, ``user_id``, ``order_id``, ...)
and in resource-style path segments (``/users/123``, ``/orders/456``), then probes
neighbouring IDs (base +- 1/2/10) concurrently and diffs the responses.

A finding is flagged *Critical* when the probed URL still returns HTTP 200 *and*
the response leaks different PII (emails, phone numbers, or JSON "name"/"email"/
"username" field values). A non-PII body change on a 200 is *High*. Blocked
responses (401/403) are recorded as *Info* evidence that access control is
enforced on that resource.

Authorized testing only.
"""

from __future__ import annotations

import asyncio
import re
from typing import Callable
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import aiohttp

ProgressCallback = Callable[[], None]
PlanCallback = Callable[[int], None]


class IDORScanner:
    """Probe numeric IDs (query-param and path-segment) for horizontal IDOR."""

    ID_PARAM_PATTERN: re.Pattern[str] = re.compile(
        r"^(?:"
        r"id|uid|oid|pk|rid|nid|gid|sid|"
        r"user_?id|account_?id|profile_?id|member_?id|customer_?id|client_?id|"
        r"order_?id|invoice_?id|receipt_?id|cart_?id|item_?id|product_?id|"
        r"document_?id|doc_?id|record_?id|file_?id|post_?id|comment_?id|"
        r"ticket_?id|message_?id|msg_?id|transaction_?id|tx_?id|payment_?id|"
        r"session_?id|token_?id|booking_?id|reservation_?id|subscription_?id"
        r")$",
        re.IGNORECASE,
    )

    PATH_ID_PATTERN: re.Pattern[str] = re.compile(
        r"/(?P<resource>user|users|account|accounts|profile|profiles|"
        r"order|orders|invoice|invoices|receipt|receipts|"
        r"item|items|product|products|cart|carts|"
        r"document|documents|doc|docs|record|records|file|files|"
        r"customer|customers|client|clients|member|members|"
        r"post|posts|comment|comments|ticket|tickets|"
        r"message|messages|msg|msgs|report|reports|"
        r"booking|bookings|reservation|reservations|subscription|subscriptions|"
        r"payment|payments|transaction|transactions)"
        r"/(?P<id>\d{1,12})(?=/|\?|$)",
        re.IGNORECASE,
    )

    TEST_DELTAS: tuple[int, ...] = (1, -1, 2, -2, 10)

    _EMAIL_RE = re.compile(
        r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}"
    )
    _PHONE_RE = re.compile(
        r"(?<!\d)(?:\+?\d{1,3}[-. ]?)?(?:\(?\d{2,4}\)?[-. ]?)?\d{3}[-. ]?\d{4}(?!\d)"
    )
    _LABELED_PII_RE = re.compile(
        r'(?is)["\'](?P<k>name|full_?name|first_?name|last_?name|user_?name|'
        r'email|mail|phone|mobile|ssn|address|dob|birth_?date|'
        r'credit_?card|card_?number|iban)["\']\s*[:=]\s*["\']'
        r'(?P<v>[^"\'\n\r]{1,160})["\']'
    )

    def __init__(
        self,
        timeout: aiohttp.ClientTimeout | None = None,
        concurrency: int = 8,
    ) -> None:
        self._timeout = timeout or aiohttp.ClientTimeout(total=20)
        self._concurrency = max(1, concurrency)

    @classmethod
    def _extract_pii(cls, text: str | None) -> dict[str, set[str]]:
        if not text:
            return {"emails": set(), "phones": set(), "labeled": set()}
        emails = set(cls._EMAIL_RE.findall(text))
        phones = set(cls._PHONE_RE.findall(text))
        labeled: set[str] = set()
        for m in cls._LABELED_PII_RE.finditer(text):
            key = m.group("k").lower().replace("_", "")
            value = m.group("v").strip()
            if value:
                labeled.add(f"{key}={value[:80]}")
        return {"emails": emails, "phones": phones, "labeled": labeled}

    def _candidates(self, target_url: str) -> list[dict]:
        """Return every numeric ID candidate (query-param + path-segment)."""
        candidates: list[dict] = []
        parsed = urlparse(target_url)

        if parsed.query:
            pairs = parse_qsl(parsed.query, keep_blank_values=True)
            for idx, (name, value) in enumerate(pairs):
                if value.isdigit() and self.ID_PARAM_PATTERN.match(name):
                    candidates.append(
                        {
                            "kind": "query_param",
                            "location": name,
                            "label": f"?{name}={value}",
                            "base_value": int(value),
                            "_q_index": idx,
                            "_q_pairs": pairs,
                            "_parsed": parsed,
                        }
                    )

        for m in self.PATH_ID_PATTERN.finditer(parsed.path):
            candidates.append(
                {
                    "kind": "path_segment",
                    "location": f"/{m.group('resource')}/{{id}}",
                    "label": f"/{m.group('resource')}/{m.group('id')}",
                    "base_value": int(m.group("id")),
                    "_span": (m.start("id"), m.end("id")),
                    "_parsed": parsed,
                }
            )

        return candidates

    def _build_mutated_url(self, candidate: dict, new_value: int) -> str:
        parsed = candidate["_parsed"]
        if candidate["kind"] == "query_param":
            new_pairs = list(candidate["_q_pairs"])
            idx = candidate["_q_index"]
            new_pairs[idx] = (new_pairs[idx][0], str(new_value))
            new_query = urlencode(new_pairs, doseq=True)
            return urlunparse(
                (
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    new_query,
                    parsed.fragment,
                )
            )
        start, end = candidate["_span"]
        new_path = parsed.path[:start] + str(new_value) + parsed.path[end:]
        return urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                new_path,
                parsed.params,
                parsed.query,
                parsed.fragment,
            )
        )

    async def _fetch(
        self, session: aiohttp.ClientSession, url: str
    ) -> tuple[int | None, str | None, str | None]:
        try:
            async with session.get(url, allow_redirects=True) as resp:
                text = await resp.text(errors="replace")
                return resp.status, text, str(resp.url)
        except (aiohttp.ClientError, TimeoutError, OSError):
            return None, None, None
        except Exception:
            return None, None, None

    @staticmethod
    def _similarity(a: str | None, b: str | None) -> float:
        """Length-ratio proxy: 1.0 = same size, 0.0 = one empty / very different."""
        if not a or not b:
            return 0.0
        la, lb = len(a), len(b)
        if max(la, lb) == 0:
            return 1.0
        return min(la, lb) / max(la, lb)

    def _classify(
        self,
        baseline: tuple[int | None, str | None, str | None],
        mutated: tuple[int | None, str | None, str | None],
    ) -> dict | None:
        b_status, b_text, _ = baseline
        m_status, m_text, _ = mutated
        if m_status is None:
            return None

        b_pii = self._extract_pii(b_text)
        m_pii = self._extract_pii(m_text)

        emails_new = m_pii["emails"] - b_pii["emails"]
        phones_new = m_pii["phones"] - b_pii["phones"]
        labeled_new = m_pii["labeled"] - b_pii["labeled"]

        pii_changed = bool(emails_new or phones_new or labeled_new)

        similarity = self._similarity(b_text, m_text)
        body_changed = b_text != m_text and similarity < 0.98

        if m_status == 200 and pii_changed:
            evidence_bits: list[str] = []
            if emails_new:
                evidence_bits.append(f"emails={sorted(emails_new)[:3]}")
            if phones_new:
                evidence_bits.append(f"phones={sorted(phones_new)[:3]}")
            if labeled_new:
                evidence_bits.append(f"fields={sorted(labeled_new)[:3]}")
            return {
                "severity": "Critical",
                "status": m_status,
                "similarity": round(similarity, 3),
                "note": "HTTP 200 returns different PII than baseline -> "
                + "; ".join(evidence_bits),
            }

        if m_status == 200 and body_changed:
            return {
                "severity": "High",
                "status": m_status,
                "similarity": round(similarity, 3),
                "note": (
                    f"HTTP 200 but body differs (similarity={similarity:.2f}); "
                    "manually confirm whether a different object was served."
                ),
            }

        if m_status in (401, 403):
            return {
                "severity": "Info",
                "status": m_status,
                "similarity": round(similarity, 3),
                "note": "access control enforced on neighbouring ID (good).",
            }

        return None

    async def scan(
        self,
        target_url: str,
        on_plan: PlanCallback | None = None,
        on_advance: ProgressCallback | None = None,
    ) -> list[dict]:
        """Probe every discovered numeric ID for horizontal IDOR.

        Returns rows with: severity, kind, param, base_id, test_id, status,
        similarity, url, note.
        """
        headers = {
            "User-Agent": "OmniScan-AI/2.0 (idor-probe)",
            "Accept": "*/*",
        }

        def _advance() -> None:
            if on_advance is not None:
                try:
                    on_advance()
                except Exception:
                    pass

        candidates = self._candidates(target_url)

        plan_total = 1
        for cand in candidates:
            for delta in self.TEST_DELTAS:
                if cand["base_value"] + delta > 0:
                    plan_total += 1

        if on_plan is not None:
            try:
                on_plan(plan_total)
            except Exception:
                pass

        if not candidates:
            _advance()
            return []

        async with aiohttp.ClientSession(timeout=self._timeout, headers=headers) as session:
            baseline = await self._fetch(session, target_url)
            _advance()
            if baseline[0] is None:
                return []

            sem = asyncio.Semaphore(self._concurrency)

            async def _probe(cand: dict, new_value: int) -> tuple[dict, int, str, tuple]:
                async with sem:
                    mutated_url = self._build_mutated_url(cand, new_value)
                    mutated = await self._fetch(session, mutated_url)
                return cand, new_value, mutated_url, mutated

            tasks: list[asyncio.Task] = []
            for cand in candidates:
                base = cand["base_value"]
                for delta in self.TEST_DELTAS:
                    new_val = base + delta
                    if new_val <= 0:
                        continue
                    tasks.append(asyncio.create_task(_probe(cand, new_val)))

            results: list[dict] = []
            for coro in asyncio.as_completed(tasks):
                try:
                    cand, new_value, mutated_url, mutated = await coro
                except Exception:
                    _advance()
                    continue
                classification = self._classify(baseline, mutated)
                if classification is not None:
                    results.append(
                        {
                            "severity": classification["severity"],
                            "kind": cand["kind"],
                            "param": cand["location"],
                            "base_id": cand["base_value"],
                            "test_id": new_value,
                            "status": classification["status"],
                            "similarity": classification["similarity"],
                            "url": mutated_url,
                            "note": classification["note"],
                        }
                    )
                _advance()

        sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        results.sort(
            key=lambda r: (
                sev_order.get(r.get("severity", "Low"), 9),
                r.get("param", ""),
                r.get("test_id", 0),
            )
        )
        return results
