from __future__ import annotations

import ipaddress
import json
import os
import subprocess
from datetime import datetime, timezone
from typing import Any

from flask import Flask, Response, abort, jsonify, render_template, request
from sqlalchemy.orm import Session

from .db import get_record_engine
from .models import StorageModuleEvent, StorageModuleHealthCheck


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
    cmd = [
        "journalctl",
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

    @app.before_request
    def _restrict_network() -> None:
        ip = _client_ip()
        if not _ip_allowed(ip):
            abort(403)

    @app.get("/")
    def index():
        return render_template("log_server.html")

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

        StorageModuleEvent.__table__.create(bind=engine, checkfirst=True)
        StorageModuleHealthCheck.__table__.create(bind=engine, checkfirst=True)

        with Session(engine) as session_db:
            events = (
                session_db.query(StorageModuleEvent)
                .order_by(StorageModuleEvent.created_at.desc())
                .limit(limit)
                .all()
            )
            health = (
                session_db.query(StorageModuleHealthCheck)
                .order_by(StorageModuleHealthCheck.created_at.desc())
                .limit(limit)
                .all()
            )

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
                        "created_at": _dt(getattr(r, "created_at", None)),
                        "level": str(getattr(r, "level", "")),
                        "action": str(getattr(r, "action", "")),
                        "message": str(getattr(r, "message", "")),
                        "module_id": getattr(r, "module_id", None),
                        "module_name": str(getattr(r, "module_name", "")),
                    }
                    for r in events
                ],
                "health": [
                    {
                        "created_at": _dt(getattr(r, "created_at", None)),
                        "module_id": getattr(r, "module_id", None),
                        "module_name": str(getattr(r, "module_name", "")),
                        "provider_type": str(getattr(r, "provider_type", "")),
                        "ok": bool(getattr(r, "ok", 0)),
                        "message": str(getattr(r, "message", "")),
                        "duration_ms": getattr(r, "duration_ms", None),
                    }
                    for r in health
                ],
            }
        )

    @app.get("/api/ping")
    def ping():
        return jsonify({"ok": True})

    return app
