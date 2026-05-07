# Developed by Channa Sandeepa | OmniScan-AI v2.5 | Copyright 2026
"""Run ProjectDiscovery Nuclei via subprocess; parse JSONL (one JSON object per line).

Requires the ``nuclei`` binary on PATH. Set ``NUCLEI_NO_UPDATE=1`` in the environment
to reduce interactive update prompts (applied by default for child process).

Authorized testing only.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Any, Sequence

_DEFAULT_TIMEOUT_SEC = 900.0


def _resolve_nuclei_binary(explicit: str | None) -> str | None:
    if explicit and str(explicit).strip():
        return str(explicit).strip()
    return shutil.which("nuclei")


def _normalize_finding(obj: dict[str, Any]) -> dict[str, Any]:
    info = obj.get("info")
    if not isinstance(info, dict):
        info = {}
    sev = str(info.get("severity") or obj.get("severity") or "info")
    name = str(info.get("name") or obj.get("name") or "")
    tid = str(obj.get("template-id") or obj.get("template_id") or "")
    matched = str(
        obj.get("matched-at")
        or obj.get("matched_at")
        or obj.get("url")
        or obj.get("host")
        or ""
    )
    host = str(obj.get("host") or "")
    typ = str(obj.get("type") or "")
    return {
        "template_id": tid,
        "severity": sev,
        "name": name,
        "matched_at": matched,
        "host": host,
        "type": typ,
        "raw": obj,
    }


def run_nuclei_scan(
    target_url: str,
    *,
    nuclei_path: str | None = None,
    timeout_sec: float = _DEFAULT_TIMEOUT_SEC,
    extra_args: Sequence[str] | None = None,
) -> tuple[list[dict[str, Any]], str | None]:
    """
    Run ``nuclei -u <target> -silent -jsonl`` and return normalized rows plus an error note.

    Returns ``(findings, error)``. ``error`` is ``None`` on a clean run with exit code 0.
    If the binary is missing, returns ``([], message)``. On timeout, returns ``([], message)``.
    If nuclei exits non-zero but emitted JSON lines, returns those rows and a short warning.
    """
    target = (target_url or "").strip()
    if not target:
        return [], "empty target URL"

    if "://" not in target:
        target = f"https://{target}"

    binary = _resolve_nuclei_binary(nuclei_path)
    if not binary:
        return [], (
            "Nuclei is not installed or not on PATH. Install: "
            "https://github.com/projectdiscovery/nuclei/releases — "
            "then ensure `nuclei` is available in your shell."
        )

    cmd: list[str] = [
        binary,
        "-u",
        target,
        "-silent",
        "-jsonl",
    ]
    if extra_args:
        cmd.extend(str(x) for x in extra_args if str(x).strip())

    env = os.environ.copy()
    env.setdefault("NUCLEI_NO_UPDATE", "1")

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=float(timeout_sec),
            env=env,
            check=False,
        )
    except FileNotFoundError:
        return [], f"could not execute nuclei binary: {binary!r}"
    except subprocess.TimeoutExpired:
        return [], f"Nuclei timed out after {timeout_sec:.0f}s"

    findings: list[dict[str, Any]] = []
    if proc.stdout:
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                findings.append(_normalize_finding(obj))

    err_note: str | None = None
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "").strip()
        if tail:
            tail = tail[:480] + ("…" if len(tail) > 480 else "")
        if not findings:
            return [], err_note or (
                f"nuclei exited with code {proc.returncode}"
                + (f": {tail}" if tail else "")
            )
        err_note = f"nuclei exited {proc.returncode} (partial JSONL parsed){(': ' + tail) if tail else ''}"

    return findings, err_note
