from __future__ import annotations

import json
import socket
import threading
import time
from typing import Optional
from urllib.parse import urlparse

from flask import Flask
from sqlalchemy.orm import Session

from .camera_utils import build_camera_url
from .db import get_record_engine
from .models import CameraDevice, CameraUrlPattern


def _send_log_server(app: Flask, payload: dict) -> None:
    host = str(app.config.get("LOG_SERVER_HOST", "127.0.0.1") or "127.0.0.1")
    try:
        port = int(app.config.get("LOG_SERVER_PORT", 8123) or 8123)
    except (TypeError, ValueError):
        port = 8123

    data = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8", errors="replace")

    # Best-effort UDP first (non-blocking for server availability).
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(data, (host, port))
            return
    except Exception:
        pass

    # Fallback TCP.
    try:
        with socket.create_connection((host, port), timeout=2.0) as s:
            s.sendall(data)
    except Exception:
        return


def _tcp_connectivity_check(url: str) -> tuple[bool, str]:
    try:
        parsed = urlparse(url)
    except Exception as exc:  # noqa: BLE001
        return False, f"url parse failed: {exc}"

    scheme = (parsed.scheme or "").lower()
    if scheme not in {"rtsp", "rtsps", "http", "https"}:
        return False, f"unsupported scheme '{scheme}'"

    host = parsed.hostname
    if not host:
        return False, "missing hostname"

    port = parsed.port
    if port is None:
        if scheme in {"http"}:
            port = 80
        elif scheme in {"https"}:
            port = 443
        else:
            port = 554

    try:
        with socket.create_connection((host, int(port)), timeout=2.0):
            return True, "ok"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def _emit_serious_url_problem(app: Flask, *, url: str, where: str, hint: str, err: str) -> None:
    masked = url
    try:
        if "@" in url and ":" in url.split("@", 1)[0]:
            userinfo, rest = url.split("@", 1)
            if ":" in userinfo:
                user, _ = userinfo.split(":", 1)
                masked = f"{user}:***@{rest}"
    except Exception:
        masked = url

    payload = {
        "level": "critical",
        "type": "SERIOUS_URL_PROBLEM",
        "where": where,
        "url": masked,
        "error": err,
        "hint": hint,
        "ts": time.time(),
    }

    try:
        app.logger.error(
            "SERIOUS_URL_PROBLEM where=%s url=%s error=%s hint=%s",
            where,
            masked,
            err,
            hint,
        )
    except Exception:
        pass

    _send_log_server(app, payload)


def run_startup_url_healthcheck(app: Flask) -> None:
    engine = get_record_engine()
    if engine is None:
        return

    with Session(engine) as session:
        devices = session.query(CameraDevice).all()
        patterns = session.query(CameraUrlPattern).all()

    patterns_index = {p.id: p for p in patterns}

    for device in devices:
        if not getattr(device, "is_active", 1):
            continue
        pattern = patterns_index.get(device.pattern_id) if getattr(device, "pattern_id", None) else None
        url = build_camera_url(device, pattern)
        if not url:
            continue

        ok, err = _tcp_connectivity_check(url)
        if ok:
            continue

        where = f"camera_devices.id={getattr(device, 'id', None)} name={getattr(device, 'name', '')} ip={getattr(device, 'ip_address', '')}"
        hint = (
            "Verify the camera IP/port is reachable from the server, the RTSP port is open, "
            "credentials are correct, and that the camera is not rejecting connections due to session limits. "
            "If you see 503 errors, ensure only one RTSP consumer is connected."
        )
        _emit_serious_url_problem(app, url=url, where=where, hint=hint, err=err)


def start_startup_url_healthcheck(app: Flask) -> None:
    try:
        enabled = bool(app.config.get("URL_HEALTHCHECK_ENABLED", True))
    except Exception:
        enabled = True
    if not enabled:
        return

    def _runner() -> None:
        try:
            # Wait for app startup to settle.
            time.sleep(3.0)
            with app.app_context():
                run_startup_url_healthcheck(app)
        except Exception:
            return

    t = threading.Thread(target=_runner, name="pv-url-healthcheck", daemon=True)
    t.start()
