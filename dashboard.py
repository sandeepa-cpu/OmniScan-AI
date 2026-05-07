#!/usr/bin/env python3
# Developed by Channa Sandeepa | OmniScan-AI v2.0 | Copyright 2026
"""Real-time web dashboard for OmniScan-AI (Flask + Socket.IO).

Run (authorized lab use only):

  pip install flask flask-socketio
  python dashboard.py

Open http://127.0.0.1:8080 — single-page control panel (``index.html`` only).

Scans spawn ``main.py`` with ``OMNISCAN_DASHBOARD=1`` so structured stats/lines
are parsed from stdout.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, render_template, request, send_file
from flask_socketio import SocketIO

from modules.scanner_engine import copy_environ_for_direct_requests

PROJECT_ROOT = Path(__file__).resolve().parent
MAIN_PY = PROJECT_ROOT / "main.py"

try:
    from dotenv import load_dotenv

    load_dotenv(PROJECT_ROOT / ".env", override=False)
except ImportError:
    pass

try:
    import psutil
except ImportError:
    psutil = None  # type: ignore[assignment, misc]

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]|\x1b\]8;;.*?\x1b\\")

app = Flask(__name__)
# Framework signing only (Socket.IO / Werkzeug). No user accounts, sessions, or login routes.
app.config["SECRET_KEY"] = "omniscan-dashboard-internal-socketio-signing-key"
socketio = SocketIO(
    app,
    async_mode="threading",
    cors_allowed_origins=[
        "http://127.0.0.1:8080",
        "http://localhost:8080",
    ],
)

_scan_lock = threading.Lock()
_scan_process: subprocess.Popen[str] | None = None
_scan_reader_thread: threading.Thread | None = None

DASHBOARD_PREFIX = "__OMNISCAN_DASHBOARD__"
LOOT_PREFIX = "__OMNISCAN_LOOT__"
LOOT_RESULTS_PATH = PROJECT_ROOT / "loot_results.txt"


def _find_latest_pdf() -> Path | None:
    reports_dir = PROJECT_ROOT / "reports"
    if not reports_dir.is_dir():
        return None
    pdfs = [p for p in reports_dir.rglob("*.pdf") if p.is_file()]
    if not pdfs:
        return None
    return max(pdfs, key=lambda p: p.stat().st_mtime)


def _system_monitor_loop() -> None:
    """Broadcast host CPU/RAM to all Socket.IO clients (daemon thread)."""
    import time

    while True:
        try:
            if psutil is None:
                _emit_raw(
                    "system_stats",
                    {"cpu": None, "memory": None, "error": "install psutil"},
                )
            else:
                cpu = float(psutil.cpu_percent(interval=0.12))
                mem = float(psutil.virtual_memory().percent)
                _emit_raw(
                    "system_stats",
                    {
                        "cpu": round(cpu, 1),
                        "memory": round(mem, 1),
                        "error": None,
                    },
                )
        except Exception as exc:
            _emit_raw(
                "system_stats",
                {"cpu": None, "memory": None, "error": str(exc)[:120]},
            )
        time.sleep(1.25)


@app.after_request
def _disable_cache_for_dashboard_html(response):
    """Avoid stale cached HTML for the main dashboard."""
    if request.path == "/" and request.method == "GET":
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
    return response


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def _emit_raw(event: str, payload: dict | list) -> None:
    """Emit on namespace ``/`` from a background thread; broadcast to every connected client."""
    try:
        with app.app_context():
            try:
                socketio.emit(event, payload, namespace="/", broadcast=True)
            except TypeError:
                socketio.emit(event, payload, namespace="/")
    except Exception as exc:
        print(f"[dashboard] socket emit failed ({event}): {exc}", file=sys.stderr)


def _emit_socket(event: str, data: dict | list | None) -> None:
    """Broadcast to all browsers from the scan reader thread (non-request context)."""
    _emit_raw(event, data if data is not None else {})


def _broadcast_log_line(text: str) -> None:
    """Push one stdout line to the live terminal (``log_update`` + ``terminal_line``)."""
    clean = _strip_ansi(text or "")
    if not clean.strip():
        return
    payload: dict = {"text": clean, "line": clean}
    _emit_raw("log_update", payload)
    _emit_raw("terminal_line", payload)


def _normalize_loot_payload(raw: dict) -> dict:
    return {
        "category": str(raw.get("category") or raw.get("kind") or "").strip(),
        "severity": str(raw.get("severity") or "").strip(),
        "detail": str(raw.get("detail") or raw.get("match") or "").strip(),
        "source": str(raw.get("source") or raw.get("source_url") or "").strip(),
    }


def _persist_loot_record(record: dict) -> None:
    line = {"ts": datetime.now(timezone.utc).isoformat(), **record}
    try:
        with LOOT_RESULTS_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(line, ensure_ascii=False) + "\n")
    except OSError as exc:
        print(f"[dashboard] loot_results.txt append failed: {exc}", file=sys.stderr)


def _emit_new_loot_event(payload: dict) -> None:
    """Append to disk and broadcast ``new_loot`` to all browsers (server-side Socket.IO)."""
    _persist_loot_record(payload)
    _emit_socket("new_loot", payload)


def _consume_loot_stdout_line(line: str) -> bool:
    """If ``line`` is a loot payload from ``main.py``, persist + ``emit('new_loot')``; return True if consumed."""
    if not line.startswith(LOOT_PREFIX):
        return False
    try:
        raw = json.loads(line[len(LOOT_PREFIX) :])
    except json.JSONDecodeError:
        return True
    if isinstance(raw, dict):
        _emit_new_loot_event(_normalize_loot_payload(raw))
    return True


@app.route("/")
def index():
    return render_template("index.html")


@app.get("/api/reports/latest-pdf")
def api_reports_latest_pdf():
    """JSON metadata for the newest PDF under ``reports/`` (by mtime)."""
    p = _find_latest_pdf()
    if p is None:
        return {"ok": False, "error": "No PDF reports found. Run a scan with --report --pdf."}, 404
    try:
        st = p.stat()
    except OSError:
        return {"ok": False, "error": "Report file unreadable"}, 500
    return {
        "ok": True,
        "filename": p.name,
        "path": str(p.relative_to(PROJECT_ROOT)),
        "mtime": st.st_mtime,
        "download_url": "/reports/download/latest",
    }


@app.get("/reports/download/latest")
def download_latest_pdf():
    """Attachment download of the latest ``reports/**/*.pdf``."""
    p = _find_latest_pdf()
    if p is None:
        return (
            "No PDF found under reports/. Generate one with: "
            "python main.py --url … --report --pdf",
            404,
        )
    try:
        return send_file(
            p,
            as_attachment=True,
            download_name=p.name,
            mimetype="application/pdf",
        )
    except OSError as exc:
        return str(exc), 500


@app.get("/api/env/status")
def api_env_status():
    """Report whether `.env` exists and key vars are visible (after load_dotenv)."""
    env_file = PROJECT_ROOT / ".env"
    keys = (
        "OMNISCAN_DASHBOARD_SECRET",
        "OMINSCAN_ZERODAY_HWID",
        "OMINSCAN_ZERODAY_SKIP_HWID",
    )
    return {
        "ok": True,
        "dotenv_path": str(env_file),
        "dotenv_file_exists": env_file.is_file(),
        "keys_present": {k: bool((os.environ.get(k) or "").strip()) for k in keys},
    }


@app.post("/api/scan/start")
def api_scan_start():
    global _scan_process
    global _scan_reader_thread

    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return {"ok": False, "error": "url required"}, 400

    use_ai = bool(data.get("ai"))
    use_zero_day = bool(data.get("zero_day"))
    use_infiltrate = bool(data.get("infiltrate"))
    use_playtika = bool(data.get("playtika_bounty"))

    headers_obj: dict[str, str] | None = None
    raw_headers = data.get("custom_headers")
    if raw_headers is not None:
        if isinstance(raw_headers, str):
            raw_headers = raw_headers.strip()
            if raw_headers:
                try:
                    parsed = json.loads(raw_headers)
                except json.JSONDecodeError as exc:
                    return {"ok": False, "error": f"custom_headers JSON: {exc}"}, 400
                if not isinstance(parsed, dict):
                    return {
                        "ok": False,
                        "error": "custom_headers must be a JSON object",
                    }, 400
                headers_obj = {str(k): str(v) for k, v in parsed.items()}
        elif isinstance(raw_headers, dict):
            headers_obj = {str(k): str(v) for k, v in raw_headers.items()}

    env_file = PROJECT_ROOT / ".env"
    _broadcast_log_line(
        "[dashboard] Ready — "
        + (
            f".env found; variables passed to the scan subprocess."
            if env_file.is_file()
            else ".env missing; scan uses OS environment only."
        )
    )
    _broadcast_log_line(f"[dashboard] Starting scan → {url}")

    with _scan_lock:
        if _scan_process is not None and _scan_process.poll() is None:
            return {"ok": False, "error": "Scan already running"}, 409

        cmd: list[str] = [
            sys.executable,
            "-u",
            str(MAIN_PY),
            "--url",
            url,
            "--report",
            "--pdf",
            "--js",
            "--xss",
            "--params",
            "--brute",
            "--sensitive",
            "--source",
            "--api-fuzz",
            "--cloud",
            "--port",
            "--idor",
            "--subdomain",
            "--broken-links",
        ]
        if use_ai:
            cmd.append("--ai")
        if use_zero_day:
            cmd.append("--zero-day")
        if use_infiltrate:
            cmd.append("--infiltrate")
        if use_playtika:
            cmd.append("--playtika-bounty")
            headers_obj = dict(headers_obj or {})
            headers_obj.setdefault("X-Bug-Bounty", "True")
        if headers_obj:
            cmd.extend(
                ["--headers", json.dumps(headers_obj, separators=(",", ":"), ensure_ascii=False)]
            )

        env = copy_environ_for_direct_requests(os.environ)
        env["OMNISCAN_DASHBOARD"] = "1"
        env["PYTHONUNBUFFERED"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"

        try:
            _scan_process = subprocess.Popen(
                cmd,
                cwd=str(PROJECT_ROOT),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                bufsize=0,
            )
        except OSError as exc:
            return {"ok": False, "error": str(exc)}, 500

        _broadcast_log_line(
            f"[dashboard] Engine subprocess started (PID {_scan_process.pid}). Streaming live logs…"
        )

        def _reader() -> None:
            global _scan_process
            proc = _scan_process
            if proc is None or proc.stdout is None:
                return

            def _handle_prefixed_line(line: str) -> None:
                if not line.startswith(DASHBOARD_PREFIX):
                    return
                try:
                    payload = json.loads(line[len(DASHBOARD_PREFIX) :])
                except json.JSONDecodeError:
                    return
                _emit_socket("dashboard_event", payload)
                evt = payload.get("event")
                if evt == "scan_complete":
                    _emit_socket("loot_update", payload.get("loot") or [])
                    _emit_socket("stats_update", payload.get("stats") or {})

            def _dispatch_line(line: str) -> None:
                if line.startswith(DASHBOARD_PREFIX):
                    _handle_prefixed_line(line)
                elif _consume_loot_stdout_line(line):
                    return
                else:
                    _broadcast_log_line(line)

            try:
                stdout = proc.stdout
                while True:
                    raw_line = stdout.readline()
                    if raw_line:
                        line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
                        _dispatch_line(line)
                        continue
                    if proc.poll() is not None:
                        break
            finally:
                try:
                    proc.wait(timeout=120)
                except Exception:
                    pass
                code = proc.returncode if proc.returncode is not None else -1
                _emit_socket("scan_finished", {"exit_code": code})
                with _scan_lock:
                    _scan_process = None

        try:
            _scan_reader_thread = socketio.start_background_task(_reader)
        except Exception:
            _scan_reader_thread = threading.Thread(target=_reader, daemon=True)
            _scan_reader_thread.start()

    return {"ok": True}


@app.post("/api/scan/stop")
def api_scan_stop():
    global _scan_process
    with _scan_lock:
        proc = _scan_process
    if proc is None or proc.poll() is not None:
        return {"ok": True, "message": "No active scan"}
    proc.terminate()
    try:
        proc.wait(timeout=8)
    except subprocess.TimeoutExpired:
        proc.kill()
    return {"ok": True}


@app.get("/api/scan/status")
def api_scan_status():
    with _scan_lock:
        running = _scan_process is not None and _scan_process.poll() is None
    return {"ok": True, "running": running}


@socketio.on("connect")
def socket_connect() -> None:
    """Confirm to the browser that the live log channel is up as soon as the page loads."""
    _broadcast_log_line("[dashboard] Socket.IO connected — live log stream ready.")


@socketio.on("new_loot")
def on_new_loot_client(data: dict | None) -> None:
    """Optional: relay loot from a Socket.IO client (e.g. future tools); same as stdout pipeline."""
    if not isinstance(data, dict):
        return
    _emit_new_loot_event(_normalize_loot_payload(data))


@socketio.on("main_log")
def on_main_log(data: dict | str | None) -> None:
    """Relay live lines from ``main.py`` (Socket.IO client) to all dashboard clients."""
    if isinstance(data, dict):
        line = data.get("text") or data.get("line") or ""
    else:
        line = str(data or "")
    _broadcast_log_line(line)


def main() -> None:
    threading.Thread(target=_system_monitor_loop, daemon=True).start()
    print(
        "OmniScan-AI dashboard: http://127.0.0.1:8080",
        file=sys.stderr,
    )
    socketio.run(
        app,
        host="127.0.0.1",
        port=8080,
        debug=False,
        allow_unsafe_werkzeug=True,
    )


if __name__ == "__main__":
    main()
