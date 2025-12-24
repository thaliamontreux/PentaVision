from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import subprocess
import threading
import time
from datetime import datetime, timezone
from typing import Any

from flask import Flask, Response, abort, jsonify, render_template, request
from sqlalchemy import text

from .db import get_record_engine
from .logging_utils import pv_log, pv_rotate_logs_on_startup, record_invalid_url_attempt_for_ip


def _client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        ip = forwarded.split(",")[0].strip()
        if ip:
            return ip
    return request.remote_addr or ""


def _ip_allowed(ip: str) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False

    if addr.is_loopback:
        return True

    allowed_cidr = os.environ.get("PENTAVISION_LOG_ALLOWED_CIDR", "192.168.250.0/24")
    try:
        net = ipaddress.ip_network(allowed_cidr, strict=False)
    except ValueError:
        net = ipaddress.ip_network("192.168.250.0/24", strict=False)

    return addr in net


def _run_journalctl(unit: str, lines: int) -> str:
    if not unit:
        return ""
    lines = max(1, min(int(lines or 200), 5000))
    journalctl = shutil.which("journalctl")
    if not journalctl:
        for cand in ("/usr/bin/journalctl", "/bin/journalctl"):
            if os.path.exists(cand):
                journalctl = cand
                break
    if not journalctl:
        return "journalctl not found on this system"

    cmd = [
        journalctl,
        "-u",
        unit,
        "-n",
        str(lines),
        "--no-pager",
        "-o",
        "short-iso",
    ]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=5)
    except Exception as exc:  # noqa: BLE001
        return f"Failed to read journal for {unit}: {exc}"
    return out


def create_log_server() -> Flask:
    app = Flask(__name__)
    app.config["TEMPLATES_AUTO_RELOAD"] = True

    def _start_apache_log_ingestion() -> None:
        access_path = (os.environ.get("PENTAVISION_APACHE_ACCESS_LOG") or "").strip()
        error_path = (os.environ.get("PENTAVISION_APACHE_ERROR_LOG") or "").strip()

        if not access_path:
            for cand in (
                "/var/log/apache2/pentavision_access.log",
                "/var/log/apache2/access.log",
                "/var/log/httpd/access_log",
                "/var/log/httpd/access.log",
            ):
                if os.path.exists(cand):
                    access_path = cand
                    break
        if not error_path:
            for cand in (
                "/var/log/apache2/pentavision_error.log",
                "/var/log/apache2/error.log",
                "/var/log/httpd/error_log",
                "/var/log/httpd/error.log",
            ):
                if os.path.exists(cand):
                    error_path = cand
                    break

        access_path = access_path.strip()
        error_path = error_path.strip()

        access_enabled = bool(access_path) and os.path.exists(access_path)
        error_enabled = bool(error_path) and os.path.exists(error_path)
        if not (access_enabled or error_enabled):
            return

        access_re = re.compile(r"^(?P<ip>\S+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+\"(?P<method>[A-Z]+)\s+(?P<path>[^\s\"]+)\s+[^\"]+\"\s+(?P<status>\d{3})\s+")

        def follow(path: str, handler) -> None:
            pos = 0
            last_inode = None
            while True:
                try:
                    st = os.stat(path)
                    inode = getattr(st, "st_ino", None)
                    if last_inode is not None and inode is not None and inode != last_inode:
                        pos = 0
                    last_inode = inode
                    with open(path, "r", encoding="utf-8", errors="replace") as f:
                        try:
                            f.seek(pos)
                        except Exception:
                            f.seek(0)
                            pos = 0
                        while True:
                            line = f.readline()
                            if not line:
                                break
                            pos = f.tell()
                            handler(line.rstrip("\n"))
                except Exception:
                    pass
                time.sleep(0.5)

        def handle_access(line: str) -> None:
            if not line:
                return
            try:
                pv_log("system", "info", "apache_access", component="apache", line=line[:1500])
            except Exception:
                pass
            try:
                m = access_re.match(line)
                if not m:
                    return
                ip = (m.group("ip") or "").strip()
                path = (m.group("path") or "").strip()
                status = int(m.group("status") or 0)
                if not ip or not path:
                    return
                if status >= 400:
                    clean_path = path.split("?", 1)[0].strip().lower()
                    if clean_path in {"/favicon.ico", "/index.html", "/index.php", "/robots.txt"}:
                        return
                    record_invalid_url_attempt_for_ip(ip, path)
            except Exception:
                return

        def handle_error(line: str) -> None:
            if not line:
                return
            try:
                pv_log("system", "warn", "apache_error", component="apache", line=line[:1500])
            except Exception:
                pass

        try:
            if access_enabled:
                threading.Thread(
                    target=follow,
                    args=(access_path, handle_access),
                    daemon=True,
                    name="pv_apache_access_tail",
                ).start()
                pv_log(
                    "system",
                    "info",
                    "apache_access_tail_started",
                    component="log_server",
                    path=str(access_path),
                )
        except Exception:
            pass

        try:
            if error_enabled:
                threading.Thread(
                    target=follow,
                    args=(error_path, handle_error),
                    daemon=True,
                    name="pv_apache_error_tail",
                ).start()
                pv_log(
                    "system",
                    "info",
                    "apache_error_tail_started",
                    component="log_server",
                    path=str(error_path),
                )
        except Exception:
            pass

    try:
        pv_rotate_logs_on_startup()
    except Exception:  # noqa: BLE001
        pass

    try:
        _start_apache_log_ingestion()
    except Exception:  # noqa: BLE001
        pass

    @app.before_request
    def _restrict_network() -> None:
        ip = _client_ip()
        if not _ip_allowed(ip):
            abort(403)

    @app.get("/")
    def index():
        return render_template("log_server.html")

    def _cat_path(cat: str) -> str:
        cat = (cat or "").strip().lower()
        if cat not in {"system", "modules", "rtsp", "rtmp", "security"}:
            cat = "system"
        return f"/dev/shm/pentavision/logs/{cat}/logfile"

    @app.get("/view")
    def view_category():
        cat = (request.args.get("cat") or "system").strip().lower()
        if cat not in {"system", "modules", "rtsp", "rtmp", "security"}:
            cat = "system"
        return render_template("log_category.html", category=cat)

    @app.get("/api/tail")
    def api_tail():
        cat = (request.args.get("cat") or "system").strip().lower()
        if cat not in {"system", "modules", "rtsp", "rtmp", "security"}:
            cat = "system"
        path = _cat_path(cat)
        try:
            start_raw = request.args.get("start")
            start_pos = int(start_raw) if start_raw is not None else None
        except Exception:
            start_pos = None

        def gen():
            # Simple best-effort tail that polls for changes.
            # SSE framing: 'data: ...\n\n'
            pos = 0
            try:
                if start_pos is not None and start_pos >= 0:
                    pos = start_pos
            except Exception:
                pos = 0
            while True:
                try:
                    with open(path, "rb") as f:
                        try:
                            f.seek(pos)
                        except Exception:
                            f.seek(0)
                            pos = 0
                        chunk = f.read()
                        if chunk:
                            pos = f.tell()
                            text_chunk = chunk.decode("utf-8", errors="replace")
                            for line in text_chunk.splitlines():
                                if not line.strip():
                                    continue
                                yield f"data: {line}\n\n"
                except FileNotFoundError:
                    yield "data: {\"ts\":\"\",\"level\":\"warn\",\"category\":\"system\",\"message\":\"log file not found\"}\n\n"
                except Exception:
                    # Do not break the SSE stream.
                    yield "data: {\"ts\":\"\",\"level\":\"warn\",\"category\":\"system\",\"message\":\"tail error\"}\n\n"
                time.sleep(0.5)

        return Response(gen(), mimetype="text/event-stream")

    @app.get("/api/journal")
    def api_journal():
        unit = (request.args.get("unit") or "").strip()
        lines_raw = request.args.get("lines") or "200"
        try:
            lines = int(lines_raw)
        except ValueError:
            lines = 200
        text = _run_journalctl(unit, lines)
        return Response(text, mimetype="text/plain; charset=utf-8")

    @app.get("/api/audit/storage")
    def api_audit_storage():
        limit_raw = request.args.get("limit") or "200"
        try:
            limit = int(limit_raw)
        except ValueError:
            limit = 200
        limit = max(1, min(limit, 2000))

        engine = get_record_engine()
        if engine is None:
            return jsonify({"error": "RecordDB is not configured"}), 503

        events: list[dict[str, Any]] = []
        health: list[dict[str, Any]] = []
        writes: list[dict[str, Any]] = []
        user_events: list[dict[str, Any]] = []
        try:
            with engine.connect() as conn:
                ev_rows = conn.execute(
                    text(
                        """
                        SELECT created_at, level, action, message, module_id, module_name
                        FROM storage_module_events
                        ORDER BY created_at DESC
                        LIMIT :lim
                        """
                    ),
                    {"lim": limit},
                ).mappings().all()
                events = [dict(r) for r in ev_rows]

                hc_rows = conn.execute(
                    text(
                        """
                        SELECT created_at, module_id, module_name, provider_type, ok, message, duration_ms
                        FROM storage_module_health_checks
                        ORDER BY created_at DESC
                        LIMIT :lim
                        """
                    ),
                    {"lim": limit},
                ).mappings().all()
                health = [dict(r) for r in hc_rows]

                ws_rows = conn.execute(
                    text(
                        """
                        SELECT created_at, module_id, module_name, provider_type, ok, storage_key, bytes, duration_ms, error
                        FROM storage_module_write_stats
                        ORDER BY created_at DESC
                        LIMIT :lim
                        """
                    ),
                    {"lim": limit},
                ).mappings().all()
                writes = [dict(r) for r in ws_rows]

                try:
                    ue_rows = conn.execute(
                        text(
                            """
                            SELECT created_at, event_type, severity, message, user_id, ip
                            FROM audit_events
                            ORDER BY created_at DESC
                            LIMIT :lim
                            """
                        ),
                        {"lim": limit},
                    ).mappings().all()
                    user_events = [dict(r) for r in ue_rows]
                except Exception:  # noqa: BLE001
                    user_events = []
        except Exception as exc:  # noqa: BLE001
            return jsonify({"error": f"Failed to load audit tables: {exc}"}), 500

        def _dt(val: Any) -> str:
            if not val:
                return ""
            try:
                if isinstance(val, datetime):
                    return val.astimezone(timezone.utc).isoformat()
            except Exception:  # noqa: BLE001
                pass
            return str(val)

        return jsonify(
            {
                "events": [
                    {
                        "created_at": _dt(r.get("created_at")),
                        "level": str(r.get("level") or ""),
                        "action": str(r.get("action") or ""),
                        "message": str(r.get("message") or ""),
                        "module_id": r.get("module_id"),
                        "module_name": str(r.get("module_name") or ""),
                    }
                    for r in events
                ],
                "health": [
                    {
                        "created_at": _dt(r.get("created_at")),
                        "module_id": r.get("module_id"),
                        "module_name": str(r.get("module_name") or ""),
                        "provider_type": str(r.get("provider_type") or ""),
                        "ok": bool(r.get("ok") or 0),
                        "message": str(r.get("message") or ""),
                        "duration_ms": r.get("duration_ms"),
                    }
                    for r in health
                ],
                "writes": [
                    {
                        "created_at": _dt(r.get("created_at")),
                        "module_id": r.get("module_id"),
                        "module_name": str(r.get("module_name") or ""),
                        "provider_type": str(r.get("provider_type") or ""),
                        "ok": bool(r.get("ok") or 0),
                        "storage_key": str(r.get("storage_key") or ""),
                        "bytes": int(r.get("bytes") or 0),
                        "duration_ms": r.get("duration_ms"),
                        "error": str(r.get("error") or ""),
                    }
                    for r in writes
                ],
                "user_events": [
                    {
                        "created_at": _dt(r.get("created_at")),
                        "event_type": str(r.get("event_type") or ""),
                        "severity": str(r.get("severity") or ""),
                        "message": str(r.get("message") or ""),
                        "user_id": r.get("user_id"),
                        "ip": str(r.get("ip") or ""),
                    }
                    for r in user_events
                ],
            }
        )

    @app.get("/api/ping")
    def ping():
        return jsonify({"ok": True})

    return app
