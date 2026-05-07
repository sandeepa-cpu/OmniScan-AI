# Developed by Channa Sandeepa | OmniScan-AI v2.5 | Copyright 2026
"""Minimal HTTP login credential checks using ``requests`` (authorized testing only).

Tries a short list of username/password pairs against a login URL. If the page
contains an HTML form with a password field, field names are taken from that
form; otherwise common parameter pairs (e.g. ``username`` / ``password``) are used.
"""

from __future__ import annotations

import time
from typing import Any, Sequence
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

DEFAULT_CREDENTIALS: tuple[tuple[str, str], ...] = (
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "1234"),
    ("administrator", "administrator"),
    ("root", "root"),
)

# Fallback (field name, field name) when no form is parsed.
_FALLBACK_FIELD_PAIRS: tuple[tuple[str, str], ...] = (
    ("username", "password"),
    ("user", "password"),
    ("login", "password"),
    ("email", "password"),
    ("uname", "pass"),
)


def _normalize_url(url: str) -> str:
    u = (url or "").strip()
    if not u:
        return u
    if not urlparse(u).scheme:
        u = "https://" + u
    return u


def _find_login_form(html: str, page_url: str) -> tuple[str, str, dict[str, str], list[str]] | None:
    """Return (method, action_url, hidden_inputs, [user_field, pass_field]) or None."""
    soup = BeautifulSoup(html, "html.parser")
    for form in soup.find_all("form"):
        inputs = form.find_all("input")
        hidden: dict[str, str] = {}
        text_names: list[str] = []
        pass_name: str | None = None
        for inp in inputs:
            name = inp.get("name")
            if not name:
                continue
            itype = (inp.get("type") or "text").lower()
            if itype == "hidden":
                hidden[name] = inp.get("value") or ""
            elif itype == "password":
                if pass_name is None:
                    pass_name = name
            elif itype in ("text", "email", "tel", ""):
                nl = name.lower()
                if any(x in nl for x in ("user", "login", "email", "name", "account")):
                    text_names.append(name)
                elif not text_names and itype == "text":
                    text_names.append(name)
        if not pass_name:
            continue
        user_field = text_names[0] if text_names else "username"
        method = (form.get("method") or "GET").upper()
        action = form.get("action") or ""
        action_url = urljoin(page_url, action) if action else page_url
        return method, action_url, hidden, [user_field, pass_name]
    return None


def _baseline_failure_heuristic(
    r: requests.Response, baseline_len: int, baseline_url: str
) -> bool:
    """Heuristic: response still looks like a login failure (not authoritative)."""
    text = (r.text or "").lower()
    if r.status_code == 401:
        return True
    markers = (
        "invalid",
        "incorrect",
        "failed",
        "error",
        "wrong",
        "denied",
        "try again",
        "authentication",
        "bad credential",
    )
    if any(m in text for m in markers):
        return True
    # Same URL and very similar length as first GET → likely still on login page
    if str(r.url).rstrip("/") == baseline_url.rstrip("/") and abs(len(r.text) - baseline_len) < 50:
        return True
    return False


def attempt_simple_login_bruteforce(
    url: str,
    *,
    credentials: Sequence[tuple[str, str]] | None = None,
    timeout: float = 12.0,
    verify: bool = True,
    headers: dict[str, str] | None = None,
    delay_sec: float = 0.35,
    max_attempts: int = 36,
) -> list[dict[str, Any]]:
    """
    POST a small set of credentials to ``url`` (or the form's action).

    Returns a list of result dicts with keys: ``attempt``, ``user``, ``password``,
    ``status_code``, ``url``, ``note``, ``possible_success`` (bool heuristic).

    Use only on targets you are explicitly authorized to test.
    """
    page_url = _normalize_url(url)
    if not page_url:
        return [{"note": "empty url", "possible_success": False}]

    creds = tuple(credentials) if credentials is not None else DEFAULT_CREDENTIALS
    hdrs = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        **(headers or {}),
    }

    session = requests.Session()
    session.headers.update(hdrs)

    try:
        g = session.get(page_url, timeout=timeout, verify=verify, allow_redirects=True)
    except requests.RequestException as exc:
        return [
            {
                "note": f"GET failed: {exc}",
                "possible_success": False,
                "url": page_url,
            }
        ]

    baseline_len = len(g.text or "")
    baseline_final = str(g.url)

    parsed_form = _find_login_form(g.text, page_url)
    attempts: list[dict[str, Any]] = []
    n = 0

    if parsed_form:
        method, post_url, hidden, pair_names = parsed_form
        user_f, pass_f = pair_names[0], pair_names[1]
        if method == "GET":
            attempts.append(
                {
                    "attempt": 0,
                    "note": "Form uses GET; skipping credential POST (unsafe / nonstandard for login).",
                    "possible_success": False,
                    "url": post_url,
                }
            )
            return attempts

        for user, password in creds:
            if n >= max_attempts:
                break
            n += 1
            data = {**hidden, user_f: user, pass_f: password}
            try:
                time.sleep(delay_sec)
                r = session.post(
                    post_url,
                    data=data,
                    timeout=timeout,
                    verify=verify,
                    allow_redirects=True,
                )
            except requests.RequestException as exc:
                attempts.append(
                    {
                        "attempt": n,
                        "user": user,
                        "password": "***",
                        "note": str(exc),
                        "possible_success": False,
                        "url": post_url,
                    }
                )
                continue

            ok_hint = not _baseline_failure_heuristic(r, baseline_len, baseline_final)
            if r.status_code in (301, 302, 303, 307, 308):
                ok_hint = True
            attempts.append(
                {
                    "attempt": n,
                    "user": user,
                    "password": "***",
                    "status_code": r.status_code,
                    "url": str(r.url),
                    "note": "Form-based POST",
                    "possible_success": ok_hint,
                }
            )
        return attempts

    # No form: try POST to page URL with common field name pairs.
    for user, password in creds:
        for uf, pf in _FALLBACK_FIELD_PAIRS:
            if n >= max_attempts:
                return attempts
            n += 1
            data = {uf: user, pf: password}
            try:
                time.sleep(delay_sec)
                r = session.post(
                    page_url,
                    data=data,
                    timeout=timeout,
                    verify=verify,
                    allow_redirects=True,
                )
            except requests.RequestException as exc:
                attempts.append(
                    {
                        "attempt": n,
                        "user": user,
                        "password": "***",
                        "note": str(exc),
                        "possible_success": False,
                        "url": page_url,
                    }
                )
                continue

            ok_hint = not _baseline_failure_heuristic(r, baseline_len, baseline_final)
            if r.status_code in (301, 302, 303, 307, 308):
                ok_hint = True
            attempts.append(
                {
                    "attempt": n,
                    "user": user,
                    "password": "***",
                    "status_code": r.status_code,
                    "url": str(r.url),
                    "note": f"fields={uf!r},{pf!r}",
                    "possible_success": ok_hint,
                }
            )

    return attempts
