from __future__ import annotations

import csv
import ipaddress
import socket
import threading
import time
import uuid
from typing import Callable, List, Optional, Tuple

from flask import (
    Blueprint,
    abort,
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from sqlalchemy.orm import Session

from .db import get_record_engine
from .models import CameraDevice, CameraStoragePolicy, CameraUrlPattern
from .stream_service import get_stream_manager
from .camera_utils import build_camera_url


bp = Blueprint("camera_admin", __name__, url_prefix="/admin/cameras")


_SCAN_JOBS: dict[str, dict] = {}
_SCAN_JOBS_LOCK = threading.Lock()


def _ensure_csrf_token() -> str:
    token = session.get("camera_admin_csrf")
    if not token:
        import secrets

        token = secrets.token_urlsafe(32)
        session["camera_admin_csrf"] = token
    return token


def _validate_csrf_token(token: Optional[str]) -> bool:
    if not token:
        return False
    return token == session.get("camera_admin_csrf")


def _parse_ports(default_ports: List[int], extra_ports: str) -> List[int]:
    ports = set(default_ports)
    for part in (extra_ports or "").split(","):
        value = part.strip()
        if not value:
            continue
        try:
            port_int = int(value)
        except ValueError:
            continue
        if 1 <= port_int <= 65535:
            ports.add(port_int)
    return sorted(ports)


def _next_cam_index(session_db: Session) -> int:
    max_index = 0
    rows = session_db.query(CameraDevice.name).all()
    for (name,) in rows:
        if not name or not name.startswith("CAM"):
            continue
        suffix = name[3:]
        if suffix.isdigit():
            max_index = max(max_index, int(suffix))
    return max_index + 1


def _ip_already_configured(session_db: Session, ip_address: str) -> bool:
    existing = (
        session_db.query(CameraDevice)
        .filter(CameraDevice.ip_address == ip_address)
        .first()
    )
    return existing is not None


def _upsert_storage_policy(
    session_db: Session,
    device_id: int,
    storage_targets: str,
    retention_days: Optional[int],
) -> None:
    # Ensure the storage policy table exists before querying/updating.
    bind = session_db.get_bind()
    if bind is not None:
        CameraStoragePolicy.__table__.create(bind=bind, checkfirst=True)
    policy = (
        session_db.query(CameraStoragePolicy)
        .filter(CameraStoragePolicy.device_id == device_id)
        .first()
    )
    if not storage_targets and retention_days is None:
        if policy is not None:
            session_db.delete(policy)
        return
    if policy is None:
        policy = CameraStoragePolicy(
            device_id=device_id,
            storage_targets=storage_targets or None,
            retention_days=retention_days,
        )
        session_db.add(policy)
    else:
        policy.storage_targets = storage_targets or None
        policy.retention_days = retention_days
        session_db.add(policy)


def _is_port_open(ip: str, port: int, timeout: float = 0.5) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((ip, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def _build_url_for_pattern(
    pattern: CameraUrlPattern,
    ip: str,
    port: int,
) -> Optional[str]:
    url = pattern.rtsp_url_pattern or ""

    if "<USERNAME>" in url or "<PASSWORD>" in url:
        return None

    replacements = {
        "<IP>": ip,
        "<PORT>": str(port),
        "<CHANNEL>": "1",
        "<STREAM>": "0",
        "<STREAM#>": "0",
    }
    for token, value in replacements.items():
        url = url.replace(token, value)
    return url


def _test_rtsp_url(url: str) -> bool:
    try:
        import cv2

        cap = cv2.VideoCapture(url)
        if not cap.isOpened():
            cap.release()
            return False
        try:
            success, _ = cap.read()
        finally:
            cap.release()
        return bool(success)
    except Exception:  # noqa: BLE001
        return False


def _scan_network_for_cameras(
    session_db: Session,
    base_ip: str,
    prefix_len: int,
    ports: List[int],
    progress_cb: Optional[
        Callable[
            [str, int, str, Optional[CameraUrlPattern], Optional[CameraDevice]], None
        ]
    ] = None,
    should_stop: Optional[Callable[[], bool]] = None,
) -> Tuple[List[CameraDevice], List[str]]:
    messages: List[str] = []
    found: List[CameraDevice] = []

    try:
        network = ipaddress.ip_network(f"{base_ip}/{prefix_len}", strict=False)
    except ValueError:
        return found, ["Invalid network specification."]

    patterns = (
        session_db.query(CameraUrlPattern)
        .filter(CameraUrlPattern.protocol == "RTSP")
        .all()
    )

    cam_index = _next_cam_index(session_db)

    for host in network.hosts():
        if should_stop is not None and should_stop():
            messages.append("Scan cancelled by user.")
            return found, messages
        ip_str = str(host)
        if _ip_already_configured(session_db, ip_str):
            continue
        for port in ports:
            if not _is_port_open(ip_str, port):
                continue
            if progress_cb is not None:
                progress_cb(ip_str, port, "port_open", None, None)
            for pattern in patterns:
                url = _build_url_for_pattern(pattern, ip_str, port)
                if not url:
                    continue
                if progress_cb is not None:
                    progress_cb(ip_str, port, "trying_pattern", pattern, None)
                if not _test_rtsp_url(url):
                    continue
                name = f"CAM{cam_index}"
                cam_index += 1
                device = CameraDevice(
                    name=name,
                    pattern_id=pattern.id,
                    ip_address=ip_str,
                    port=port,
                    username=None,
                    password=None,
                    notes="Discovered via network scan",
                    is_active=1,
                )
                session_db.add(device)
                session_db.commit()
                found.append(device)
                label = pattern.model_or_note or ""
                if progress_cb is not None:
                    progress_cb(ip_str, port, "pattern_success", pattern, device)
                messages.append(
                    f"Added {name} at {ip_str}:{port} using {pattern.manufacturer} {label}"
                )
                break
            if _ip_already_configured(session_db, ip_str):
                break
        else:
            # No ports succeeded for this host.
            if progress_cb is not None:
                progress_cb(ip_str, 0, "no_working_port", None, None)

    if not found and not messages:
        messages.append("No new cameras were discovered on the selected network.")

    return found, messages


def _guess_protocol(url: str) -> str:
    lower = url.lower()
    if "://" in lower:
        proto = lower.split("://", 1)[0]
    else:
        proto = "rtsp"

    mapping = {
        "rtsp": "RTSP",
        "rtmp": "RTMP",
        "srt": "SRT",
        "rist": "RIST",
        "http": "HTTP",
        "https": "HTTPS",
    }
    return mapping.get(proto, "RTSP")


def _create_scan_job() -> str:
    job_id = uuid.uuid4().hex
    with _SCAN_JOBS_LOCK:
        _SCAN_JOBS[job_id] = {
            "id": job_id,
            "status": "running",
            "error": None,
            "events": [],
            "results": [],
            "messages": [],
            "started_at": time.time(),
            "cancel_requested": False,
        }
    return job_id


def _append_scan_event(
    job_id: str,
    ip: str,
    port: int,
    phase: str,
    pattern: Optional[CameraUrlPattern],
    device: Optional[CameraDevice],
) -> None:
    label = None
    if pattern is not None:
        extra = pattern.model_or_note or ""
        label = f"{pattern.manufacturer} {extra}".strip()
    status = "running"
    if phase in {"pattern_success"}:
        status = "success"
    elif phase in {"no_working_port"}:
        status = "failed"
    event = {
        "ip": ip,
        "port": port,
        "phase": phase,
        "pattern_id": pattern.id if pattern is not None else None,
        "pattern_label": label,
        "device_id": device.id if device is not None else None,
        "device_name": device.name if device is not None else None,
        "status": status,
    }
    with _SCAN_JOBS_LOCK:
        job = _SCAN_JOBS.get(job_id)
        if not job:
            return
        job["events"].append(event)


def _run_scan_job(
    job_id: str,
    engine,
    base_ip: str,
    prefix_int: int,
    ports: List[int],
) -> None:
    def progress_cb(
        ip: str,
        port: int,
        phase: str,
        pattern: Optional[CameraUrlPattern],
        device: Optional[CameraDevice],
    ) -> None:
        _append_scan_event(job_id, ip, port, phase, pattern, device)

    def should_stop() -> bool:
        with _SCAN_JOBS_LOCK:
            job = _SCAN_JOBS.get(job_id)
            if not job:
                return True
            return bool(job.get("cancel_requested"))

    try:
        with Session(engine) as session_db:
            results, messages = _scan_network_for_cameras(
                session_db,
                base_ip,
                prefix_int,
                ports,
                progress_cb=progress_cb,
                should_stop=should_stop,
            )
        results_payload = [
            {
                "id": d.id,
                "name": d.name,
                "ip": d.ip_address,
                "port": d.port,
                "pattern_id": d.pattern_id,
            }
            for d in results
        ]
        with _SCAN_JOBS_LOCK:
            job = _SCAN_JOBS.get(job_id)
            if not job:
                return
            if job.get("cancel_requested"):
                job["status"] = "cancelled"
            else:
                job["status"] = "completed"
            job["results"] = results_payload
            job["messages"] = messages
    except Exception as exc:  # noqa: BLE001
        with _SCAN_JOBS_LOCK:
            job = _SCAN_JOBS.get(job_id)
            if not job:
                return
            job["status"] = "error"
            job["error"] = str(exc)


@bp.route("/scan", methods=["GET", "POST"])
def scan():
    engine = get_record_engine()
    errors: List[str] = []
    messages: List[str] = []
    results: List[CameraDevice] = []
    form = {
        "base_ip": "",
        "prefix": "24",
        "extra_ports": "",
    }
    csrf_token = _ensure_csrf_token()

    patterns_index: dict[int, CameraUrlPattern] = {}

    if engine is None:
        errors.append("Record database is not configured.")
    else:
        if request.method == "POST":
            if not _validate_csrf_token(request.form.get("csrf_token")):
                errors.append("Invalid or missing CSRF token.")

            base_ip = (request.form.get("base_ip") or "").strip()
            prefix_str = (request.form.get("prefix") or "24").strip()
            extra_ports = (request.form.get("extra_ports") or "").strip()

            form["base_ip"] = base_ip
            form["prefix"] = prefix_str
            form["extra_ports"] = extra_ports

            if not base_ip:
                errors.append("Base IP address is required.")

            prefix_int: Optional[int]
            try:
                prefix_int = int(prefix_str)
            except ValueError:
                prefix_int = None
                errors.append("Subnet prefix must be a number.")

            if prefix_int is not None and not (16 <= prefix_int <= 32):
                errors.append("Subnet prefix must be between 16 and 32.")

            if not errors and base_ip and prefix_int is not None:
                try:
                    ipaddress.ip_network(f"{base_ip}/{prefix_int}", strict=False)
                except ValueError:
                    errors.append("Invalid network specification.")

            if prefix_int is None:
                prefix_int = 24

            ports = _parse_ports([554, 8554], extra_ports)

            if not errors:
                with Session(engine) as session_db:
                    results, messages = _scan_network_for_cameras(
                        session_db,
                        base_ip,
                        prefix_int,
                        ports,
                    )
                    patterns = session_db.query(CameraUrlPattern).all()
                    patterns_index = {p.id: p for p in patterns}

        if not patterns_index:
            with Session(engine) as session_db:
                patterns = session_db.query(CameraUrlPattern).all()
                patterns_index = {p.id: p for p in patterns}

    return render_template(
        "cameras/scan.html",
        form=form,
        errors=errors,
        messages=messages,
        results=results,
        patterns=patterns_index,
        csrf_token=csrf_token,
    )


@bp.post("/scan/start")
def scan_start():
    engine = get_record_engine()
    if engine is None:
        return jsonify({"error": "Record database is not configured."}), 400

    if not _validate_csrf_token(request.form.get("csrf_token")):
        return jsonify({"error": "Invalid or missing CSRF token."}), 400

    base_ip = (request.form.get("base_ip") or "").strip()
    prefix_str = (request.form.get("prefix") or "24").strip()
    extra_ports = (request.form.get("extra_ports") or "").strip()

    if not base_ip:
        return jsonify({"error": "Base IP address is required."}), 400

    try:
        prefix_int = int(prefix_str)
    except ValueError:
        return jsonify({"error": "Subnet prefix must be a number."}), 400

    if not (16 <= prefix_int <= 32):
        return jsonify({"error": "Subnet prefix must be between 16 and 32."}), 400

    try:
        ipaddress.ip_network(f"{base_ip}/{prefix_int}", strict=False)
    except ValueError:
        return jsonify({"error": "Invalid network specification."}), 400

    ports = _parse_ports([554, 8554], extra_ports)

    job_id = _create_scan_job()
    thread = threading.Thread(
        target=_run_scan_job,
        args=(job_id, engine, base_ip, prefix_int, ports),
        daemon=True,
    )
    thread.start()

    return jsonify({"job_id": job_id})


@bp.get("/scan/status/<job_id>")
def scan_status(job_id: str):
    with _SCAN_JOBS_LOCK:
        job = _SCAN_JOBS.get(job_id)
        if job is None:
            abort(404)
        # Shallow copy to avoid exposing internal references.
        payload = {
            "id": job["id"],
            "status": job["status"],
            "error": job["error"],
            "events": list(job["events"]),
            "results": list(job["results"]),
            "messages": list(job["messages"]),
            "cancel_requested": bool(job.get("cancel_requested")),
        }
    return jsonify(payload)


@bp.post("/scan/cancel/<job_id>")
def scan_cancel(job_id: str):
    if not _validate_csrf_token(request.form.get("csrf_token")):
        return jsonify({"error": "Invalid or missing CSRF token."}), 400

    with _SCAN_JOBS_LOCK:
        job = _SCAN_JOBS.get(job_id)
        if job is None:
            return jsonify({"error": "Scan job not found."}), 404
        if job["status"] not in {"running", "cancelling"}:
            return jsonify({"error": "Scan job is not running."}), 400
        job["cancel_requested"] = True
        job["status"] = "cancelling"

    return jsonify({"status": "cancel_requested"})


@bp.get("/")
def list_patterns():
    engine = get_record_engine()
    errors: List[str] = []
    patterns: List[CameraUrlPattern] = []
    if engine is None:
        errors.append("Record database is not configured.")
    else:
        with Session(engine) as session_db:
            patterns = (
                session_db.query(CameraUrlPattern)
                .order_by(CameraUrlPattern.manufacturer, CameraUrlPattern.model_or_note)
                .all()
            )

    csrf_token = _ensure_csrf_token()
    return render_template(
        "cameras/list.html",
        patterns=patterns,
        errors=errors,
        csrf_token=csrf_token,
    )


@bp.route("/new", methods=["GET", "POST"])
def create_pattern():
    engine = get_record_engine()
    errors: List[str] = []
    form = {
        "manufacturer": "",
        "model_or_note": "",
        "protocol": "RTSP",
        "rtsp_url_pattern": "",
        "is_active": True,
    }
    csrf_token = _ensure_csrf_token()

    if engine is None:
        errors.append("Record database is not configured.")
        return render_template(
            "cameras/edit.html",
            form=form,
            errors=errors,
            csrf_token=csrf_token,
            is_edit=False,
        )

    if request.method == "POST":
        if not _validate_csrf_token(request.form.get("csrf_token")):
            errors.append("Invalid or missing CSRF token.")
        form["manufacturer"] = (request.form.get("manufacturer") or "").strip()
        form["model_or_note"] = (request.form.get("model_or_note") or "").strip()
        form["protocol"] = (
            (request.form.get("protocol") or "RTSP").strip().upper()
        )
        form["rtsp_url_pattern"] = (request.form.get("rtsp_url_pattern") or "").strip()
        form["is_active"] = request.form.get("is_active") == "1"

        if not form["manufacturer"]:
            errors.append("Manufacturer is required.")
        if not form["rtsp_url_pattern"]:
            errors.append("RTSP URL pattern is required.")

        if not errors:
            with Session(engine) as session_db:
                pattern = CameraUrlPattern(
                    manufacturer=form["manufacturer"],
                    model_or_note=form["model_or_note"] or None,
                    protocol=form["protocol"],
                    rtsp_url_pattern=form["rtsp_url_pattern"],
                    is_active=1 if form["is_active"] else 0,
                )
                session_db.add(pattern)
                session_db.commit()
            return redirect(url_for("camera_admin.list_patterns"))
    return render_template(
        "cameras/edit.html",
        form=form,
        errors=errors,
        csrf_token=csrf_token,
        is_edit=False,
    )

@bp.get("/devices")
def list_devices():
    engine = get_record_engine()
    errors: List[str] = []
    devices: List[CameraDevice] = []
    patterns_index: dict[int, CameraUrlPattern] = {}
    stream_status: dict[int, dict] = {}

    if engine is None:
        errors.append("Record database is not configured.")
    else:
        with Session(engine) as session_db:
            devices = (
                session_db.query(CameraDevice)
                .order_by(CameraDevice.name)
                .all()
            )
            patterns = session_db.query(CameraUrlPattern).all()
            patterns_index = {p.id: p for p in patterns}

        manager = get_stream_manager(current_app)
        if manager is not None:
            try:
                stream_status = manager.get_status()
            except Exception:  # noqa: BLE001
                stream_status = {}

    csrf_token = _ensure_csrf_token()
    return render_template(
        "cameras/devices_list.html",
        devices=devices,
        patterns=patterns_index,
        errors=errors,
        csrf_token=csrf_token,
        stream_status=stream_status,
    )


@bp.route("/devices/new", methods=["GET", "POST"])
def create_device():
    engine = get_record_engine()
    errors: List[str] = []
    form = {
        "name": "",
        "pattern_id": "",
        "ip_address": "",
        "port": "554",
        "username": "",
        "password": "",
        "notes": "",
        "is_active": True,
        "storage_targets": "",
        "retention_days": "",
    }
    csrf_token = _ensure_csrf_token()

    raw_targets = str(current_app.config.get("STORAGE_TARGETS", "") or "")
    if not raw_targets:
        raw_targets = "local_fs"
    storage_targets_default = ",".join(
        [item.strip() for item in raw_targets.split(",") if item.strip()]
    )

    if engine is None:
        errors.append("Record database is not configured.")
        patterns: List[CameraUrlPattern] = []
    else:
        with Session(engine) as session_db:
            patterns = (
                session_db.query(CameraUrlPattern)
                .order_by(CameraUrlPattern.manufacturer, CameraUrlPattern.model_or_note)
                .all()
            )

    if request.method == "POST" and engine is not None:
        if not _validate_csrf_token(request.form.get("csrf_token")):
            errors.append("Invalid or missing CSRF token.")

        form["name"] = (request.form.get("name") or "").strip()
        form["pattern_id"] = (request.form.get("pattern_id") or "").strip()
        form["ip_address"] = (request.form.get("ip_address") or "").strip()
        form["port"] = (request.form.get("port") or "").strip()
        form["username"] = (request.form.get("username") or "").strip()
        form["password"] = (request.form.get("password") or "").strip()
        form["notes"] = (request.form.get("notes") or "").strip()
        form["is_active"] = request.form.get("is_active") == "1"
        form["storage_targets"] = (
            request.form.get("storage_targets") or ""
        ).strip()
        form["retention_days"] = (
            request.form.get("retention_days") or ""
        ).strip()

        if not form["name"]:
            errors.append("Name is required.")
        if not form["ip_address"]:
            errors.append("IP address is required.")

        pattern_id_int: Optional[int]
        if form["pattern_id"]:
            try:
                pattern_id_int = int(form["pattern_id"])
            except ValueError:
                errors.append("Invalid template selection.")
                pattern_id_int = None
        else:
            pattern_id_int = None

        port_int: Optional[int]
        if form["port"]:
            try:
                port_int = int(form["port"])
            except ValueError:
                errors.append("Port must be a number.")
                port_int = None
        else:
            port_int = None

        retention_days_int: Optional[int]
        if form["retention_days"]:
            try:
                retention_days_int = int(form["retention_days"])
            except ValueError:
                errors.append("Retention days must be a number.")
                retention_days_int = None
            else:
                if retention_days_int <= 0:
                    errors.append("Retention days must be a positive number.")
        else:
            retention_days_int = None

        if not errors:
            with Session(engine) as session_db:
                device = CameraDevice(
                    name=form["name"],
                    pattern_id=pattern_id_int,
                    ip_address=form["ip_address"],
                    port=port_int,
                    username=form["username"] or None,
                    password=form["password"] or None,
                    notes=form["notes"] or None,
                    is_active=1 if form["is_active"] else 0,
                )
                session_db.add(device)
                session_db.commit()
                _upsert_storage_policy(
                    session_db,
                    device.id,
                    form["storage_targets"],
                    retention_days_int,
                )
                session_db.commit()
            return redirect(url_for("camera_admin.list_devices"))

    return render_template(
        "cameras/devices_edit.html",
        form=form,
        patterns=patterns,
        errors=errors,
        csrf_token=csrf_token,
        is_edit=False,
        storage_targets_default=storage_targets_default,
    )


@bp.route("/devices/<int:device_id>/edit", methods=["GET", "POST"])
def edit_device(device_id: int):
    engine = get_record_engine()
    errors: List[str] = []
    csrf_token = _ensure_csrf_token()

    raw_targets = str(current_app.config.get("STORAGE_TARGETS", "") or "")
    if not raw_targets:
        raw_targets = "local_fs"
    storage_targets_default = ",".join(
        [item.strip() for item in raw_targets.split(",") if item.strip()]
    )

    if engine is None:
        errors.append("Record database is not configured.")
        return render_template(
            "cameras/devices_edit.html",
            form=None,
            patterns=[],
            errors=errors,
            csrf_token=csrf_token,
            is_edit=True,
            storage_targets_default=storage_targets_default,
        )

    with Session(engine) as session_db:
        # Ensure the storage policy table exists before querying.
        CameraStoragePolicy.__table__.create(bind=engine, checkfirst=True)
        device = session_db.get(CameraDevice, device_id)
        patterns = (
            session_db.query(CameraUrlPattern)
            .order_by(CameraUrlPattern.manufacturer, CameraUrlPattern.model_or_note)
            .all()
        )
        policy = (
            session_db.query(CameraStoragePolicy)
            .filter(CameraStoragePolicy.device_id == device_id)
            .first()
        )

        if device is None:
            errors.append("Camera device not found.")
            return render_template(
                "cameras/devices_edit.html",
                form=None,
                patterns=patterns,
                errors=errors,
                csrf_token=csrf_token,
                is_edit=True,
                storage_targets_default=storage_targets_default,
            )

        form = {
            "name": device.name,
            "pattern_id": str(device.pattern_id or ""),
            "ip_address": device.ip_address,
            "port": str(device.port) if device.port is not None else "",
            "username": device.username or "",
            "password": device.password or "",
            "notes": device.notes or "",
            "is_active": bool(getattr(device, "is_active", 1)),
            "storage_targets": policy.storage_targets if policy else "",
            "retention_days": (
                str(policy.retention_days)
                if policy and policy.retention_days is not None
                else ""
            ),
        }

        if request.method == "POST":
            if not _validate_csrf_token(request.form.get("csrf_token")):
                errors.append("Invalid or missing CSRF token.")

            form["name"] = (request.form.get("name") or "").strip()
            form["pattern_id"] = (request.form.get("pattern_id") or "").strip()
            form["ip_address"] = (request.form.get("ip_address") or "").strip()
            form["port"] = (request.form.get("port") or "").strip()
            form["username"] = (request.form.get("username") or "").strip()
            form["password"] = (request.form.get("password") or "").strip()
            form["notes"] = (request.form.get("notes") or "").strip()
            form["is_active"] = request.form.get("is_active") == "1"
            form["storage_targets"] = (
                request.form.get("storage_targets") or ""
            ).strip()
            form["retention_days"] = (
                request.form.get("retention_days") or ""
            ).strip()

            if not form["name"]:
                errors.append("Name is required.")
            if not form["ip_address"]:
                errors.append("IP address is required.")

            pattern_id_int: Optional[int]
            if form["pattern_id"]:
                try:
                    pattern_id_int = int(form["pattern_id"])
                except ValueError:
                    errors.append("Invalid template selection.")
                    pattern_id_int = None
            else:
                pattern_id_int = None

            port_int: Optional[int]
            if form["port"]:
                try:
                    port_int = int(form["port"])
                except ValueError:
                    errors.append("Port must be a number.")
                    port_int = None
            else:
                port_int = None

            retention_days_int: Optional[int]
            if form["retention_days"]:
                try:
                    retention_days_int = int(form["retention_days"])
                except ValueError:
                    errors.append("Retention days must be a number.")
                    retention_days_int = None
                else:
                    if retention_days_int <= 0:
                        errors.append("Retention days must be a positive number.")
            else:
                retention_days_int = None

            if not errors:
                device.name = form["name"]
                device.pattern_id = pattern_id_int
                device.ip_address = form["ip_address"]
                device.port = port_int
                device.username = form["username"] or None
                device.password = form["password"] or None
                device.notes = form["notes"] or None
                device.is_active = 1 if form["is_active"] else 0
                session_db.add(device)
                session_db.commit()
                _upsert_storage_policy(
                    session_db,
                    device.id,
                    form["storage_targets"],
                    retention_days_int,
                )
                session_db.commit()
                return redirect(url_for("camera_admin.list_devices"))

    return render_template(
        "cameras/devices_edit.html",
        form=form,
        patterns=patterns,
        errors=errors,
        csrf_token=csrf_token,
        is_edit=True,
        storage_targets_default=storage_targets_default,
    )


@bp.post("/devices/test")
def test_device_connection():
    engine = get_record_engine()
    if engine is None:
        return jsonify({"ok": False, "error": "Record database is not configured."})

    if not _validate_csrf_token(request.form.get("csrf_token")):
        return jsonify({"ok": False, "error": "Invalid or missing CSRF token."})

    ip_address = (request.form.get("ip_address") or "").strip()
    port_str = (request.form.get("port") or "").strip()
    pattern_id_str = (request.form.get("pattern_id") or "").strip()
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()

    errors: List[str] = []

    if not ip_address:
        errors.append("IP address is required.")

    pattern_id_int: Optional[int]
    if pattern_id_str:
        try:
            pattern_id_int = int(pattern_id_str)
        except ValueError:
            pattern_id_int = None
            errors.append("Invalid template selection.")
    else:
        pattern_id_int = None

    port_int: Optional[int]
    if port_str:
        try:
            port_int = int(port_str)
        except ValueError:
            port_int = None
            errors.append("Port must be a number.")
    else:
        port_int = None

    if errors:
        return jsonify({"ok": False, "error": "; ".join(errors)})

    pattern: Optional[CameraUrlPattern] = None
    if pattern_id_int is not None:
        with Session(engine) as session_db:
            pattern = session_db.get(CameraUrlPattern, pattern_id_int)

    class _TempDevice:
        pass

    temp = _TempDevice()
    temp.ip_address = ip_address
    temp.port = port_int
    temp.username = username or None
    temp.password = password or None

    url = build_camera_url(temp, pattern)
    if not url:
        return jsonify(
            {
                "ok": False,
                "error": "Unable to construct a camera URL from these settings.",
            }
        )

    if not _test_rtsp_url(url):
        return jsonify(
            {
                "ok": False,
                "error": "Connection test failed. Check IP, port, credentials, and template.",
            }
        )

    return jsonify({"ok": True})


@bp.post("/devices/<int:device_id>/delete")
def delete_device(device_id: int):
    engine = get_record_engine()
    if engine is None:
        return redirect(url_for("camera_admin.list_devices"))

    if not _validate_csrf_token(request.form.get("csrf_token")):
        return redirect(url_for("camera_admin.list_devices"))

    with Session(engine) as session_db:
        device = session_db.get(CameraDevice, device_id)
        if device is not None:
            session_db.delete(device)
            session_db.commit()

    return redirect(url_for("camera_admin.list_devices"))


@bp.route("/<int:pattern_id>/edit", methods=["GET", "POST"])
def edit_pattern(pattern_id: int):
    engine = get_record_engine()
    errors: List[str] = []
    csrf_token = _ensure_csrf_token()

    if engine is None:
        errors.append("Record database is not configured.")
        return render_template(
            "cameras/edit.html",
            form=None,
            errors=errors,
            csrf_token=csrf_token,
            is_edit=True,
        )

    with Session(engine) as session_db:
        pattern = session_db.get(CameraUrlPattern, pattern_id)
        if pattern is None:
            errors.append("Camera URL pattern not found.")
            return render_template(
                "cameras/edit.html",
                form=None,
                errors=errors,
                csrf_token=csrf_token,
                is_edit=True,
            )

        form = {
            "manufacturer": pattern.manufacturer,
            "model_or_note": pattern.model_or_note or "",
            "protocol": (pattern.protocol or "RTSP"),
            "rtsp_url_pattern": pattern.rtsp_url_pattern,
            "is_active": bool(getattr(pattern, "is_active", 1)),
        }

        if request.method == "POST":
            if not _validate_csrf_token(request.form.get("csrf_token")):
                errors.append("Invalid or missing CSRF token.")

            form["manufacturer"] = (request.form.get("manufacturer") or "").strip()
            form["model_or_note"] = (request.form.get("model_or_note") or "").strip()
            form["protocol"] = (
                (request.form.get("protocol") or "RTSP").strip().upper()
            )
            form["rtsp_url_pattern"] = (
                request.form.get("rtsp_url_pattern") or ""
            ).strip()
            form["is_active"] = request.form.get("is_active") == "1"

            if not form["manufacturer"]:
                errors.append("Manufacturer is required.")
            if not form["rtsp_url_pattern"]:
                errors.append("RTSP URL pattern is required.")

            if not errors:
                pattern.manufacturer = form["manufacturer"]
                pattern.model_or_note = form["model_or_note"] or None
                pattern.protocol = form["protocol"]
                pattern.rtsp_url_pattern = form["rtsp_url_pattern"]
                pattern.is_active = 1 if form["is_active"] else 0
                session_db.add(pattern)
                session_db.commit()
                return redirect(url_for("camera_admin.list_patterns"))

    return render_template(
        "cameras/edit.html",
        form=form,
        errors=errors,
        csrf_token=csrf_token,
        is_edit=True,
    )


@bp.post("/<int:pattern_id>/delete")
def delete_pattern(pattern_id: int):
    engine = get_record_engine()
    errors: List[str] = []
    if engine is None:
        errors.append("Record database is not configured.")
        return redirect(url_for("camera_admin.list_patterns"))

    if not _validate_csrf_token(request.form.get("csrf_token")):
        return redirect(url_for("camera_admin.list_patterns"))

    with Session(engine) as session_db:
        pattern = session_db.get(CameraUrlPattern, pattern_id)
        if pattern is not None:
            session_db.delete(pattern)
            session_db.commit()

    return redirect(url_for("camera_admin.list_patterns"))


@bp.post("/import")
def import_csv():
    engine = get_record_engine()
    errors: List[str] = []
    patterns: List[CameraUrlPattern] = []

    if engine is None:
        errors.append("Record database is not configured.")
    else:
        if not _validate_csrf_token(request.form.get("csrf_token")):
            errors.append("Invalid or missing CSRF token.")
        upload = request.files.get("file")
        clear_existing = request.form.get("clear_existing") == "1"

        if not errors:
            if upload is None or not upload.filename:
                errors.append("CSV file is required.")
            else:
                try:
                    # Expect a header row with: manufacturer,model_or_note,rtsp_url_pattern,source
                    text_stream = upload.stream.read().decode("utf-8", errors="ignore")
                    rows = csv.DictReader(text_stream.splitlines())
                    with Session(engine) as session_db:
                        if clear_existing:
                            session_db.query(CameraUrlPattern).delete()
                        for row in rows:
                            manufacturer = (
                                row.get("manufacturer") or ""
                            ).strip()
                            rtsp_pattern = (
                                row.get("rtsp_url_pattern") or ""
                            ).strip()
                            if not manufacturer or not rtsp_pattern:
                                continue
                            protocol = _guess_protocol(rtsp_pattern)
                            pattern = CameraUrlPattern(
                                manufacturer=manufacturer,
                                model_or_note=(row.get("model_or_note") or "").strip() or None,
                                protocol=protocol,
                                rtsp_url_pattern=rtsp_pattern,
                                is_active=1,
                            )
                            session_db.add(pattern)
                        session_db.commit()
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"CSV import failed: {exc}")

        with Session(engine) as session_db:
            patterns = (
                session_db.query(CameraUrlPattern)
                .order_by(CameraUrlPattern.manufacturer, CameraUrlPattern.model_or_note)
                .all()
            )

    csrf_token = _ensure_csrf_token()
    return render_template(
        "cameras/list.html",
        patterns=patterns,
        errors=errors,
        csrf_token=csrf_token,
    )
