from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from pathlib import Path
import base64
import hashlib
import io
import json
import pickle
import secrets
import time

from flask import (
    Blueprint,
    Response,
    abort,
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
import requests
from sqlalchemy import func, text
from sqlalchemy.orm import Session

try:
    import face_recognition  # type: ignore[import]
    _face_recognition_error = None
except (SystemExit, ImportError, Exception) as exc:  # noqa: BLE001
    # Some environments may lack the face_recognition models or native deps.
    # In that case, we disable recognition endpoints but keep the app running.
    face_recognition = None  # type: ignore[assignment]
    _face_recognition_error = exc

from .auth import _authenticate_primary_factor, _authenticate_user, _verify_totp
from .db import get_face_engine, get_record_engine, get_user_engine
from .logging_utils import log_event
from .models import (
    AuditEvent,
    CameraDevice,
    CameraPropertyLink,
    CameraRecording,
    CameraRecordingSchedule,
    CameraStoragePolicy,
    CameraUrlPattern,
    DlnaSettings,
    FaceEmbedding,
    FacePrivacySetting,
    RecordingData,
    StorageModule,
    StorageModuleEvent,
    StorageModuleHealthCheck,
    StorageModuleWriteStat,
    StorageSettings,
    UploadQueueItem,
    User,
    UserNotificationSettings,
    WebAuthnCredential,
)
from .security import (
    get_current_user,
    login_user,
    logout_user,
    require_login,
    user_has_property_access,
    user_has_role,
    validate_global_csrf_token,
)
from .stream_service import get_stream_manager
from .storage_providers import build_storage_providers, _load_storage_settings
from .storage_csal import get_storage_router, StorageError
from .net_utils import get_ipv4_interfaces


bp = Blueprint("main", __name__)


FACE_MATCH_THRESHOLD = 0.6


def _get_face_match_threshold() -> float:
    value = current_app.config.get("FACE_MATCH_THRESHOLD")
    if value is None or value == "":
        return FACE_MATCH_THRESHOLD
    try:
        return float(value)
    except (TypeError, ValueError):
        return FACE_MATCH_THRESHOLD


def _load_camera_property_map(record_engine) -> dict[int, int]:
    if record_engine is None:
        return {}
    CameraPropertyLink.__table__.create(bind=record_engine, checkfirst=True)
    with Session(record_engine) as session_db:
        rows = session_db.query(
            CameraPropertyLink.device_id, CameraPropertyLink.property_id
        ).all()
    return {int(device_id): int(property_id) for device_id, property_id in rows}


def _user_can_access_camera(
    user: User | None,
    device_id: int,
    record_engine=None,
    property_map: dict[int, int] | None = None,
) -> bool:
    if user is None:
        return False
    if user_has_role(user, "System Administrator"):
        return True

    if property_map is None:
        if record_engine is None:
            record_engine = get_record_engine()
        property_map = _load_camera_property_map(record_engine)

    prop_id = property_map.get(device_id)
    if not prop_id:
        return False
    return user_has_property_access(user, prop_id)


@bp.get("/health")
def health():
    db_status = {}

    for label, getter in (
        ("user", get_user_engine),
        ("face", get_face_engine),
        ("record", get_record_engine),
    ):
        engine = getter()
        if engine is None:
            db_status[label] = "not_configured"
            continue
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
        except Exception:  # noqa: BLE001
            db_status[label] = "error"
        else:
            db_status[label] = "ok"

    all_ok = all(value != "error" for value in db_status.values())
    overall = "ok" if all_ok else "degraded"

    return jsonify({"status": overall, "databases": db_status})


@bp.get("/")
@require_login
def index():
    user = get_current_user()
    # Reuse the same DB health logic for the dashboard.
    db_status = {}
    for label, getter in (
        ("user", get_user_engine),
        ("face", get_face_engine),
        ("record", get_record_engine),
    ):
        engine = getter()
        if engine is None:
            db_status[label] = "not_configured"
            continue
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
        except Exception:  # noqa: BLE001
            db_status[label] = "error"
        else:
            db_status[label] = "ok"

    all_ok = all(value != "error" for value in db_status.values())
    overall = "ok" if all_ok else "degraded"

    # Load configured cameras from the RecordDB.
    devices = []
    patterns_index: dict[int, CameraUrlPattern] = {}
    camera_status: dict[int, str] = {}
    camera_last_seen: dict[int, datetime] = {}
    record_engine = get_record_engine()
    camera_property_map: dict[int, int] = {}
    if record_engine is not None:
        with Session(record_engine) as session_db:
            CameraPropertyLink.__table__.create(bind=record_engine, checkfirst=True)
            CameraRecording.__table__.create(bind=record_engine, checkfirst=True)
            devices = (
                session_db.query(CameraDevice)
                .order_by(CameraDevice.name)
                .all()
            )
            pattern_ids = {
                d.pattern_id for d in devices if getattr(d, "pattern_id", None)
            }
            if pattern_ids:
                patterns = (
                    session_db.query(CameraUrlPattern)
                    .filter(CameraUrlPattern.id.in_(pattern_ids))
                    .all()
                )
                patterns_index = {p.id: p for p in patterns}

            rows = (
                session_db.query(
                    CameraRecording.device_id,
                    func.max(CameraRecording.created_at),
                )
                .group_by(CameraRecording.device_id)
                .all()
            )

            links = session_db.query(CameraPropertyLink).all()
            camera_property_map = {
                int(link.device_id): int(link.property_id) for link in links
            }

        now = datetime.now(timezone.utc)
        threshold = now - timedelta(minutes=3)
        for device_id, last_time in rows:
            if last_time is None:
                continue
            camera_last_seen[device_id] = last_time
            if last_time >= threshold:
                camera_status[device_id] = "online"
            else:
                camera_status[device_id] = "offline"

        for device in devices:
            camera_status.setdefault(device.id, "unknown")

    # Apply property-level RBAC: unauthenticated users see no cameras; non-admin
    # users only see cameras for properties they are associated with.
    if user is None:
        devices = []
    elif not user_has_role(user, "System Administrator"):
        filtered_devices: list[CameraDevice] = []
        for d in devices:
            prop_id = camera_property_map.get(d.id)
            if not prop_id:
                continue
            if user_has_property_access(user, prop_id):
                filtered_devices.append(d)
        devices = filtered_devices

    dashboard_display_size = "320x240"
    if user is not None:
        pref = getattr(user, "dashboard_display_size", None)
        if pref in {"320x240", "720x480"}:
            dashboard_display_size = pref

    preview_low_fps = current_app.config.get("PREVIEW_LOW_FPS", 2.0)

    return render_template(
        "index.html",
        db_status=db_status,
        overall_status=overall,
        devices=devices,
        patterns=patterns_index,
        camera_status=camera_status,
        camera_last_seen=camera_last_seen,
        dashboard_display_size=dashboard_display_size,
        preview_low_fps=preview_low_fps,
    )


@bp.get("/faces-demo")
@require_login
def faces_demo():
    return render_template("faces_demo.html")


@bp.get("/auth-demo")
@require_login
def auth_demo():
    return render_template("auth_demo.html")


@bp.route("/login", methods=["GET", "POST"])
def login():
    errors: list[str] = []
    email = ""
    next_url = (
        request.args.get("next")
        or request.form.get("next")
        or url_for("main.index")
    )
    if not next_url.startswith("/"):
        next_url = url_for("main.index")

    if request.method == "POST":
        if not validate_global_csrf_token(request.form.get("csrf_token")):
            errors.append("Invalid or missing CSRF token.")

        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        if not errors:
            user, error, status, requires_totp = _authenticate_primary_factor(
                email, password
            )
            if user is None:
                errors.append(error or f"Login failed (status {status}).")
            else:
                if requires_totp:
                    session["pending_totp_user_id"] = int(user.id)
                    session["pending_totp_next"] = next_url
                    return redirect(url_for("main.login_totp"))
                else:
                    # No TOTP configured: complete login immediately.
                    engine = get_user_engine()
                    if engine is not None:
                        with Session(engine) as session_db:
                            db_user = session_db.get(User, int(user.id))
                            if db_user is not None:
                                db_user.last_login_at = datetime.now(timezone.utc)
                                session_db.add(db_user)
                                session_db.commit()
                    login_user(user)
                    log_event("AUTH_LOGIN_SUCCESS", user_id=user.id, details="html_login")
                    return redirect(next_url)

    return render_template(
        "login.html",
        errors=errors,
        email=email,
        next=next_url,
        totp_pending=False,
        totp_error=None,
    )


@bp.route("/login/totp", methods=["GET", "POST"])
def login_totp():
    """Second step of HTML login: prompt for TOTP if enabled for the user."""

    pending_user_id = session.get("pending_totp_user_id")
    if not pending_user_id:
        # No pending TOTP challenge; send the user back to the primary login.
        return redirect(url_for("main.login"))

    next_url = session.get("pending_totp_next") or url_for("main.index")
    if not str(next_url).startswith("/"):
        next_url = url_for("main.index")

    totp_error: str | None = None
    email = ""

    engine = get_user_engine()
    user_obj: User | None = None
    if engine is not None:
        with Session(engine) as session_db:
            user_obj = session_db.get(User, int(pending_user_id))
            if user_obj is not None:
                email = user_obj.email or ""

    if user_obj is None:
        # User disappeared between steps; clear state and restart login.
        session.pop("pending_totp_user_id", None)
        session.pop("pending_totp_next", None)
        return redirect(url_for("main.login"))

    if request.method == "POST":
        if not validate_global_csrf_token(request.form.get("csrf_token")):
            totp_error = "Invalid or missing CSRF token."
        else:
            totp_code = (request.form.get("totp_code") or "").strip()
            if not totp_code:
                totp_error = "TOTP code is required."
            else:
                if not _verify_totp(user_obj, totp_code):
                    log_event("AUTH_LOGIN_2FA_FAILURE", user_id=user_obj.id)
                    totp_error = "Invalid authentication code."
                else:
                    # Mark successful 2FA and complete the login.
                    if engine is not None:
                        with Session(engine) as session_db:
                            db_user = session_db.get(User, int(user_obj.id))
                            if db_user is not None:
                                db_user.last_login_at = datetime.now(timezone.utc)
                                session_db.add(db_user)
                                session_db.commit()
                    login_user(user_obj)
                    log_event("AUTH_LOGIN_SUCCESS", user_id=user_obj.id, details="html_login_totp")
                    session.pop("pending_totp_user_id", None)
                    session.pop("pending_totp_next", None)
                    return redirect(next_url)

    return render_template(
        "login.html",
        errors=[],
        email=email,
        next=next_url,
        totp_pending=True,
        totp_error=totp_error,
    )


@bp.post("/logout")
def logout():
    if not validate_global_csrf_token(request.form.get("csrf_token")):
        abort(400)
    user = get_current_user()
    if user is not None:
        log_event("AUTH_LOGOUT", user_id=user.id)
    logout_user()
    return redirect(url_for("main.index"))


@bp.route("/profile", methods=["GET", "POST"])
def profile():
    user = get_current_user()
    if user is None:
        next_url = request.path or url_for("main.index")
        return redirect(url_for("main.login", next=next_url))

    engine = get_user_engine()
    errors: list[str] = []
    saved = False
    test_result: dict | None = None
    test_result: dict | None = None

    if engine is None:
        errors.append("User database is not configured.")
        return render_template(
            "profile.html",
            errors=errors,
            form={},
            notif={},
            mfa_status={
                "totp_enabled": False,
                "passkey_count": 0,
            },
            saved=saved,
        )

    with Session(engine) as session_db:
        db_user = session_db.get(User, user.id)
        if db_user is None:
            abort(404)

        settings = (
            session_db.query(UserNotificationSettings)
            .filter(UserNotificationSettings.user_id == db_user.id)
            .first()
        )
        if settings is None:
            settings = UserNotificationSettings(user_id=db_user.id)
            session_db.add(settings)
            session_db.commit()

        WebAuthnCredential.__table__.create(bind=engine, checkfirst=True)
        passkey_count = (
            session_db.query(WebAuthnCredential)
            .filter(WebAuthnCredential.user_id == db_user.id)
            .count()
        )

        if request.method == "POST":
            if not validate_global_csrf_token(request.form.get("csrf_token")):
                errors.append("Invalid or missing CSRF token.")

            full_name = (request.form.get("full_name") or "").strip()
            preferred_name = (request.form.get("preferred_name") or "").strip()
            pronouns = (request.form.get("pronouns") or "").strip()
            country_code = (request.form.get("primary_phone_country") or "").strip()
            national_phone = (request.form.get("primary_phone_national") or "").strip()
            timezone_val = (
                request.form.get("timezone")
                or request.form.get("timezone_fallback")
                or ""
            ).strip()
            mfa_pref = (request.form.get("mfa_preference") or "").strip()

            if not errors:
                db_user.full_name = full_name or None
                db_user.preferred_name = preferred_name or None
                db_user.pronouns = pronouns or None

                if country_code and national_phone:
                    phone_compact = national_phone.replace(" ", "").replace("-", "")
                    db_user.primary_phone = f"+{country_code}{phone_compact}"
                else:
                    raw_phone = (request.form.get("primary_phone") or "").strip()
                    db_user.primary_phone = raw_phone or None
                db_user.timezone = timezone_val or None
                db_user.mfa_preference = mfa_pref or None

                def _flag(name: str) -> int:
                    return 1 if request.form.get(name) == "1" else 0

                settings.intrusion_alerts = _flag("intrusion_alerts")
                settings.fire_alerts = _flag("fire_alerts")
                settings.system_faults = _flag("system_faults")
                settings.camera_motion_events = _flag("camera_motion_events")
                settings.door_window_activity = _flag("door_window_activity")
                settings.environmental_alerts = _flag("environmental_alerts")
                settings.escalation_level = (
                    (request.form.get("escalation_level") or "").strip() or None
                )

                session_db.add(db_user)
                session_db.add(settings)
                session_db.commit()
                saved = True
                log_event("PROFILE_UPDATE", user_id=db_user.id)

        display_phone = db_user.primary_phone or ""

        form = {
            "full_name": db_user.full_name or "",
            "preferred_name": db_user.preferred_name or "",
            "pronouns": db_user.pronouns or "",
            "primary_phone": display_phone,
            "timezone": db_user.timezone or "",
            "mfa_preference": db_user.mfa_preference or "",
        }
        notif = {
            "intrusion_alerts": bool(getattr(settings, "intrusion_alerts", 0)),
            "fire_alerts": bool(getattr(settings, "fire_alerts", 0)),
            "system_faults": bool(getattr(settings, "system_faults", 0)),
            "camera_motion_events": bool(
                getattr(settings, "camera_motion_events", 0)
            ),
            "door_window_activity": bool(
                getattr(settings, "door_window_activity", 0)
            ),
            "environmental_alerts": bool(
                getattr(settings, "environmental_alerts", 0)
            ),
            "escalation_level": getattr(settings, "escalation_level", "") or "",
        }

        mfa_status = {
            "totp_enabled": bool(getattr(db_user, "totp_secret", None)),
            "passkey_count": int(passkey_count or 0),
        }

    return render_template(
        "profile.html",
        errors=errors,
        form=form,
        notif=notif,
        mfa_status=mfa_status,
        saved=saved,
    )


@bp.get("/audit")
def audit_events():
    user = get_current_user()
    if user is None:
        next_url = request.path or url_for("main.index")
        return redirect(url_for("main.login", next=next_url))
    if not user_has_role(user, "System Administrator"):
        abort(403)

    user_engine = get_user_engine()
    events = []
    if user_engine is not None:
        with Session(user_engine) as session:
            AuditEvent.__table__.create(bind=user_engine, checkfirst=True)
            events = (
                session.query(AuditEvent)
                .order_by(AuditEvent.when.desc())
                .limit(200)
                .all()
            )

    return render_template("audit.html", events=events)


def _camera_preview_response(
    device_id: int,
    fps: float,
    use_full_resolution: bool = False,
) -> Response:
    user = get_current_user()
    record_engine = get_record_engine()
    if not _user_can_access_camera(user, device_id, record_engine):
        return jsonify({"error": "camera not found"}), 404

    manager = get_stream_manager(current_app)
    fps_value = fps
    override = request.args.get("fps")
    if override:
        try:
            override_fps = float(override)
        except (TypeError, ValueError):
            override_fps = fps_value
        else:
            if override_fps > 0.0:
                fps_value = override_fps

    interval = 1.0 / fps_value if fps_value > 0 else 0.5

    # Capture the preview cache directory while we still have an application
    # context; the streaming generator will run after the request context has
    # been torn down under Gunicorn.
    preview_base = str(
        current_app.config.get("PREVIEW_CACHE_DIR", "/var/lib/pentavision/previews")
    )

    def _load_frame() -> bytes | None:
        # Preferred path: use in-process CameraStreamManager (dev/local).
        if manager is not None:
            if use_full_resolution and hasattr(manager, "get_full_frame"):
                frame = manager.get_full_frame(device_id)
            else:
                frame = manager.get_frame(device_id)
            if frame is not None:
                return frame

        # Fallback for production where streams run in a separate worker:
        # read the most recent preview frame from the shared cache directory
        # written by the video worker. Full-resolution frames are not cached
        # to disk, so when use_full_resolution is requested but no in-process
        # stream manager exists we gracefully fall back to the scaled preview.
        try:
            path = Path(preview_base) / f"{device_id}.jpg"
            return path.read_bytes()
        except FileNotFoundError:
            return None
        except Exception:
            return None

    def generate():  # pragma: no cover - realtime streaming
        import time

        while True:
            frame = _load_frame()
            if not frame:
                time.sleep(interval)
                continue
            yield (
                b"--frame\r\n"
                b"Content-Type: image/jpeg\r\n\r\n" + frame + b"\r\n"
            )
            time.sleep(interval)

    return Response(
        generate(),
        mimetype="multipart/x-mixed-replace; boundary=frame",
    )


@bp.get("/cameras/<int:device_id>/preview_low.mjpg")
def camera_preview_low(device_id: int):
    user = get_current_user()
    record_engine = get_record_engine()
    if not _user_can_access_camera(user, device_id, record_engine):
        abort(404)
    fps = current_app.config.get("PREVIEW_LOW_FPS", 2.0)
    try:
        fps_value = float(fps)
    except (TypeError, ValueError):
        fps_value = 2.0
    return _camera_preview_response(device_id, fps=fps_value)


@bp.get("/cameras/<int:device_id>/preview_low.jpg")
def camera_preview_low_jpeg(device_id: int):
    user = get_current_user()
    record_engine = get_record_engine()
    if not _user_can_access_camera(user, device_id, record_engine):
        abort(404)
    base = current_app.config.get("PREVIEW_CACHE_DIR", "/var/lib/pentavision/previews")
    try:
        path = Path(str(base)) / f"{device_id}.jpg"
        if not path.exists():
            abort(404)
        return send_file(path, mimetype="image/jpeg")
    except Exception:
        abort(404)


@bp.get("/cameras/<int:device_id>/preview.mjpg")
def camera_preview(device_id: int):
    user = get_current_user()
    record_engine = get_record_engine()
    if not _user_can_access_camera(user, device_id, record_engine):
        abort(404)
    fps = current_app.config.get("PREVIEW_HIGH_FPS", 10.0)
    try:
        fps_value = float(fps)
    except (TypeError, ValueError):
        fps_value = 10.0
    return _camera_preview_response(device_id, fps=fps_value)


@bp.get("/cameras/<int:device_id>/session_stream.mjpg")
def camera_session_stream(device_id: int):
    user = get_current_user()
    record_engine = get_record_engine()
    if not _user_can_access_camera(user, device_id, record_engine):
        abort(404)
    fps = current_app.config.get("PREVIEW_HIGH_FPS", 10.0)
    try:
        fps_value = float(fps)
    except (TypeError, ValueError):
        fps_value = 10.0
    return _camera_preview_response(device_id, fps=fps_value, use_full_resolution=True)


@bp.get("/cameras/<int:device_id>")
def camera_detail(device_id: int):
    record_engine = get_record_engine()
    if record_engine is None:
        abort(404)

    user = get_current_user()
    if not _user_can_access_camera(user, device_id, record_engine):
        abort(404)

    with Session(record_engine) as session_db:
        CameraRecording.__table__.create(bind=record_engine, checkfirst=True)
        device = session_db.get(CameraDevice, device_id)
        if device is None:
            abort(404)
        pattern = None
        if getattr(device, "pattern_id", None):
            pattern = session_db.get(CameraUrlPattern, device.pattern_id)

        recent_recordings = (
            session_db.query(CameraRecording)
            .filter(CameraRecording.device_id == device_id)
            .order_by(CameraRecording.created_at.desc())
            .limit(20)
            .all()
        )

        last_seen = None
        status = "unknown"
        if recent_recordings:
            last_seen = recent_recordings[0].created_at
            now = datetime.now(timezone.utc)
            threshold = now - timedelta(minutes=3)
            if last_seen >= threshold:
                status = "online"
            else:
                status = "offline"

    return render_template(
        "cameras/device_detail.html",
        device=device,
        pattern=pattern,
        status=status,
        last_seen=last_seen,
        recordings=recent_recordings,
    )


@bp.get("/cameras/<int:device_id>/session")
def camera_session(device_id: int):
    record_engine = get_record_engine()
    if record_engine is None:
        abort(404)

    user = get_current_user()
    if not _user_can_access_camera(user, device_id, record_engine):
        abort(404)

    with Session(record_engine) as session_db:
        CameraRecording.__table__.create(bind=record_engine, checkfirst=True)
        device = session_db.get(CameraDevice, device_id)
        if device is None:
            abort(404)
        pattern = None
        if getattr(device, "pattern_id", None):
            pattern = session_db.get(CameraUrlPattern, device.pattern_id)

        recent_recordings = (
            session_db.query(CameraRecording)
            .filter(CameraRecording.device_id == device_id)
            .order_by(CameraRecording.created_at.desc())
            .limit(1)
            .all()
        )

        last_seen = None
        status = "unknown"
        if recent_recordings:
            last_seen = recent_recordings[0].created_at
            now = datetime.now(timezone.utc)
            threshold = now - timedelta(minutes=3)
            if last_seen >= threshold:
                status = "online"
            else:
                status = "offline"

    session_display_size = "1280x720"
    if user is not None:
        pref = getattr(user, "session_display_size", None)
        if pref in {
            "320x240",
            "720x240",
            "720x480",
            "800x600",
            "1024x768",
            "1280x720",
            "1920x1080",
        }:
            session_display_size = pref

    return render_template(
        "cameras/session.html",
        device=device,
        pattern=pattern,
        status=status,
        last_seen=last_seen,
        session_display_size=session_display_size,
    )


@bp.get("/streams/status")
def streams_status():
    user = get_current_user()
    record_engine = get_record_engine()
    property_map = _load_camera_property_map(record_engine)
    manager = get_stream_manager(current_app)
    if manager is None:
        return jsonify({"ok": False, "error": "stream manager not available", "streams": []})

    raw = manager.get_status()
    now_ts = datetime.now(timezone.utc).timestamp()
    streams = []
    for device_id, info in raw.items():
        try:
            device_id_int = int(device_id)
        except (TypeError, ValueError):
            device_id_int = None

        if user is not None and device_id_int is not None:
            if not _user_can_access_camera(
                user,
                device_id_int,
                record_engine,
                property_map,
            ):
                continue
        last_ts = info.get("last_frame_ts")
        last_iso = None
        age_seconds = None
        if last_ts is not None:
            try:
                last_ts_float = float(last_ts)
            except (TypeError, ValueError):
                last_ts_float = None
            if last_ts_float is not None:
                last_iso = datetime.fromtimestamp(last_ts_float, tz=timezone.utc).isoformat()
                age_seconds = max(0.0, now_ts - last_ts_float)
        last_error = info.get("last_error") or None
        error_iso = None
        error_age_seconds = None
        if last_error and isinstance(last_error, dict):
            err_ts = last_error.get("timestamp")
            try:
                err_ts_float = float(err_ts) if err_ts is not None else None
            except (TypeError, ValueError):
                err_ts_float = None
            if err_ts_float is not None:
                error_iso = datetime.fromtimestamp(err_ts_float, tz=timezone.utc).isoformat()
                error_age_seconds = max(0.0, now_ts - err_ts_float)
        streams.append(
            {
                "device_id": device_id,
                "url": info.get("url"),
                "thread_alive": bool(info.get("thread_alive")),
                "last_frame_ts": last_ts,
                "last_frame_iso": last_iso,
                "age_seconds": age_seconds,
                "last_error": last_error,
                "last_error_iso": error_iso,
                "last_error_age_seconds": error_age_seconds,
            }
        )

    return jsonify({"ok": True, "streams": streams})

def _decode_image_from_request(data):
    image_b64 = data.get("image") or ""
    if not image_b64:
        return None, "image field is required"
    if image_b64.startswith("data:"):
        _, _, image_b64 = image_b64.partition(",")
    try:
        image_bytes = base64.b64decode(image_b64)
    except Exception:  # noqa: BLE001
        return None, "invalid image data"
    return image_bytes, None


@bp.post("/api/user/display-size")
def set_user_display_size():
    user = get_current_user()
    if user is None:
        return jsonify({"error": "not authenticated"}), 401

    engine = get_user_engine()
    if engine is None:
        return jsonify({"error": "user database not configured"}), 500

    payload = request.get_json(silent=True) or {}
    scope = (payload.get("scope") or "").strip().lower()
    size = (payload.get("size") or "").strip().lower()

    session_sizes = {
        "320x240",
        "720x240",
        "720x480",
        "800x600",
        "1024x768",
        "1280x720",
        "1920x1080",
    }
    dashboard_sizes = {
        "320x240",
        "720x480",
    }

    if scope == "session":
        if size not in session_sizes:
            return jsonify({"error": "invalid size"}), 400
        field = "session_display_size"
    elif scope == "dashboard":
        if size not in dashboard_sizes:
            return jsonify({"error": "invalid size"}), 400
        field = "dashboard_display_size"
    else:
        return jsonify({"error": "invalid scope"}), 400

    with Session(engine) as session_db:
        db_user = session_db.get(User, user.id)
        if db_user is None:
            return jsonify({"error": "user not found"}), 404
        setattr(db_user, field, size)
        session_db.add(db_user)
        session_db.commit()

    setattr(user, field, size)

    return jsonify({"ok": True, "scope": scope, "size": size})


@bp.post("/api/face/enroll")
def face_enroll():
    face_engine = get_face_engine()
    user_engine = get_user_engine()
    if face_engine is None or user_engine is None:
        return jsonify({"error": "face or user database not configured"}), 500

    payload = request.get_json(silent=True) or {}
    email = (payload.get("email") or "").strip().lower()
    if not email:
        return jsonify({"error": "email is required"}), 400

    image_bytes, error = _decode_image_from_request(payload)
    if error:
        return jsonify({"error": error}), 400

    with Session(user_engine) as session_user:
        user = session_user.query(User).filter(User.email == email).first()
        if user is None:
            return jsonify({"error": "user not found"}), 404

    image_file = io.BytesIO(image_bytes)
    try:
        image = face_recognition.load_image_file(image_file)
        locations = face_recognition.face_locations(image)
        encodings = face_recognition.face_encodings(image, known_face_locations=locations)
    except Exception:  # noqa: BLE001
        return jsonify({"error": "failed to process image"}), 500

    if not encodings:
        return jsonify({"error": "no face detected"}), 400

    primary_encoding = encodings[0]
    embedding_bytes = pickle.dumps(primary_encoding)

    with Session(face_engine) as session_face:
        FaceEmbedding.__table__.create(bind=face_engine, checkfirst=True)
        row = FaceEmbedding(user_id=user.id, embedding=embedding_bytes)
        session_face.add(row)
        session_face.commit()

    return jsonify(
        {
            "ok": True,
            "user_id": user.id,
            "faces_detected": len(encodings),
            "stored_embeddings": 1,
        }
    )


@bp.post("/api/face/recognize")
def face_recognize():
    face_engine = get_face_engine()
    user_engine = get_user_engine()
    if face_engine is None or user_engine is None:
        return jsonify({"error": "face or user database not configured"}), 500

    payload = request.get_json(silent=True) or {}
    image_bytes, error = _decode_image_from_request(payload)
    if error:
        return jsonify({"error": error}), 400

    image_file = io.BytesIO(image_bytes)
    try:
        image = face_recognition.load_image_file(image_file)
        locations = face_recognition.face_locations(image)
        encodings = face_recognition.face_encodings(image, known_face_locations=locations)
    except Exception:  # noqa: BLE001
        return jsonify({"error": "failed to process image"}), 500

    if not encodings:
        return jsonify({"faces": [], "message": "no faces detected"}), 200

    with Session(face_engine) as session_face:
        FaceEmbedding.__table__.create(bind=face_engine, checkfirst=True)
        FacePrivacySetting.__table__.create(bind=face_engine, checkfirst=True)
        all_rows = session_face.query(FaceEmbedding).all()
        privacy_rows = session_face.query(FacePrivacySetting).all()

    if not all_rows:
        return jsonify({"faces": [], "message": "no enrolled embeddings"}), 200

    opted_out_ids = {
        row.user_id for row in privacy_rows if getattr(row, "is_opted_out", None)
    }

    threshold = _get_face_match_threshold()

    known_encodings = []
    known_user_ids = []
    for row in all_rows:
        if row.user_id in opted_out_ids:
            continue
        try:
            enc = pickle.loads(row.embedding)
        except Exception:  # noqa: BLE001
            continue
        known_encodings.append(enc)
        known_user_ids.append(row.user_id)

    if not known_encodings:
        return jsonify({"faces": [], "message": "no valid embeddings"}), 200

    user_id_set = {uid for uid in known_user_ids if uid is not None}
    email_map: dict[int, str] = {}
    if user_id_set and user_engine is not None:
        with Session(user_engine) as session_user:
            rows = (
                session_user.query(User.id, User.email)
                .filter(User.id.in_(user_id_set))
                .all()
            )
            email_map = {uid: email for uid, email in rows}

    threshold = _get_face_match_threshold()

    faces_out = []
    for loc, enc in zip(locations, encodings):
        distances = face_recognition.face_distance(known_encodings, enc)
        dist_list = [float(d) for d in distances]
        best_index, best_distance = min(
            enumerate(dist_list), key=lambda t: t[1]
        )
        match_user_id = None
        if best_distance <= threshold:
            match_user_id = known_user_ids[best_index]
        top, right, bottom, left = loc
        faces_out.append(
            {
                "top": int(top),
                "right": int(right),
                "bottom": int(bottom),
                "left": int(left),
                "user_id": match_user_id,
                "email": email_map.get(match_user_id),
                "distance": best_distance,
            }
        )

    return jsonify({"faces": faces_out, "threshold": threshold})


@bp.post("/api/face/privacy/opt-out")
def face_opt_out():
    face_engine = get_face_engine()
    user_engine = get_user_engine()
    if face_engine is None or user_engine is None:
        return jsonify({"error": "face or user database not configured"}), 500

    payload = request.get_json(silent=True) or {}
    email = (payload.get("email") or "").strip().lower()
    if not email:
        return jsonify({"error": "email is required"}), 400

    with Session(user_engine) as session_user:
        user = session_user.query(User).filter(User.email == email).first()
        if user is None:
            return jsonify({"error": "user not found"}), 404

    deleted_count = 0
    with Session(face_engine) as session_face:
        FaceEmbedding.__table__.create(bind=face_engine, checkfirst=True)
        FacePrivacySetting.__table__.create(bind=face_engine, checkfirst=True)
        deleted_count = (
            session_face.query(FaceEmbedding)
            .filter(FaceEmbedding.user_id == user.id)
            .delete(synchronize_session=False)
        )
        policy = (
            session_face.query(FacePrivacySetting)
            .filter(FacePrivacySetting.user_id == user.id)
            .first()
        )
        if policy is None:
            policy = FacePrivacySetting(user_id=user.id, is_opted_out=1)
            session_face.add(policy)
        else:
            policy.is_opted_out = 1
            session_face.add(policy)
        session_face.commit()

    return jsonify(
        {
            "ok": True,
            "user_id": user.id,
            "email": user.email,
            "opted_out": True,
            "deleted_embeddings": int(deleted_count or 0),
        }
    )


@bp.post("/api/face/privacy/opt-in")
def face_opt_in():
    face_engine = get_face_engine()
    user_engine = get_user_engine()
    if face_engine is None or user_engine is None:
        return jsonify({"error": "face or user database not configured"}), 500

    payload = request.get_json(silent=True) or {}
    email = (payload.get("email") or "").strip().lower()
    if not email:
        return jsonify({"error": "email is required"}), 400

    with Session(user_engine) as session_user:
        user = session_user.query(User).filter(User.email == email).first()
        if user is None:
            return jsonify({"error": "user not found"}), 404

    with Session(face_engine) as session_face:
        FacePrivacySetting.__table__.create(bind=face_engine, checkfirst=True)
        policy = (
            session_face.query(FacePrivacySetting)
            .filter(FacePrivacySetting.user_id == user.id)
            .first()
        )
        if policy is None:
            policy = FacePrivacySetting(user_id=user.id, is_opted_out=0)
            session_face.add(policy)
        else:
            policy.is_opted_out = 0
            session_face.add(policy)
        session_face.commit()

    return jsonify(
        {
            "ok": True,
            "user_id": user.id,
            "email": user.email,
            "opted_out": False,
        }
    )


@bp.post("/api/cameras/<int:device_id>/face-recognize")
def camera_face_recognize(device_id: int):
    """Run face recognition against the latest preview frame for a camera.

    This uses the shared CameraStreamManager to grab the last JPEG frame, so we
    avoid opening additional RTSP connections. The result can be overlaid on
    the dashboard preview using the returned face boxes and image dimensions.
    """

    manager = get_stream_manager(current_app)
    if manager is None:
        return jsonify({"error": "stream manager not available"}), 503

    frame = manager.get_frame(device_id)
    if not frame:
        return jsonify(
            {"faces": [], "message": "no frame available for device"}
        ), 200

    face_engine = get_face_engine()
    user_engine = get_user_engine()
    if face_engine is None or user_engine is None:
        return jsonify({"error": "face or user database not configured"}), 500

    image_file = io.BytesIO(frame)
    try:
        image = face_recognition.load_image_file(image_file)
        height, width = image.shape[:2]
        locations = face_recognition.face_locations(image)
        encodings = face_recognition.face_encodings(
            image,
            known_face_locations=locations,
        )
    except Exception:  # noqa: BLE001
        return jsonify({"error": "failed to process frame"}), 500

    if not encodings:
        return jsonify(
            {
                "faces": [],
                "message": "no faces detected",
                "image_width": width,
                "image_height": height,
            }
        ), 200

    with Session(face_engine) as session_face:
        FaceEmbedding.__table__.create(bind=face_engine, checkfirst=True)
        FacePrivacySetting.__table__.create(bind=face_engine, checkfirst=True)
        all_rows = session_face.query(FaceEmbedding).all()
        privacy_rows = session_face.query(FacePrivacySetting).all()

    if not all_rows:
        return jsonify(
            {
                "faces": [],
                "message": "no enrolled embeddings",
                "image_width": width,
                "image_height": height,
            }
        ), 200

    opted_out_ids = {
        row.user_id for row in privacy_rows if getattr(row, "is_opted_out", None)
    }

    known_encodings = []
    known_user_ids = []
    for row in all_rows:
        if row.user_id in opted_out_ids:
            continue
        try:
            enc = pickle.loads(row.embedding)
        except Exception:  # noqa: BLE001
            continue
        known_encodings.append(enc)
        known_user_ids.append(row.user_id)

    if not known_encodings:
        return jsonify(
            {
                "faces": [],
                "message": "no valid embeddings",
                "image_width": width,
                "image_height": height,
            }
        ), 200

    threshold = _get_face_match_threshold()

    user_id_set = {uid for uid in known_user_ids if uid is not None}
    email_map: dict[int, str] = {}
    if user_id_set and user_engine is not None:
        with Session(user_engine) as session_user:
            rows = (
                session_user.query(User.id, User.email)
                .filter(User.id.in_(user_id_set))
                .all()
            )
            email_map = {uid: email for uid, email in rows}

    faces_out = []
    for loc, enc in zip(locations, encodings):
        distances = face_recognition.face_distance(known_encodings, enc)
        dist_list = [float(d) for d in distances]
        best_index, best_distance = min(
            enumerate(dist_list), key=lambda t: t[1]
        )
        match_user_id = None
        if best_distance <= threshold:
            match_user_id = known_user_ids[best_index]
        top, right, bottom, left = loc
        faces_out.append(
            {
                "top": int(top),
                "right": int(right),
                "bottom": int(bottom),
                "left": int(left),
                "user_id": match_user_id,
                "email": email_map.get(match_user_id),
                "distance": best_distance,
            }
        )

    return jsonify(
        {
            "device_id": device_id,
            "faces": faces_out,
            "threshold": threshold,
            "image_width": width,
            "image_height": height,
        }
    )


@bp.route("/storage", methods=["GET", "POST"])
def storage_settings():
    user = get_current_user()
    if user is None:
        next_url = request.path or url_for("main.index")
        return redirect(url_for("main.login", next=next_url))
    if not user_has_role(user, "System Administrator"):
        abort(403)

    cfg = current_app.config
    errors: list[str] = []
    saved = False
    module_test_result: dict | None = None
    module_test_ready = False
    wizard_draft: dict[str, object] | None = None
    wizard_step = 1

    # Load any existing DB-backed storage settings so we can merge them with
    # environment defaults for the form and summaries.
    db_settings = _load_storage_settings() or {}

    raw_targets = db_settings.get("storage_targets") or str(
        cfg.get("STORAGE_TARGETS", "local_fs") or "local_fs"
    )

    form = {
        "storage_targets": raw_targets,
        "local_storage_path": db_settings.get("local_storage_path")
        or str(
            cfg.get("LOCAL_STORAGE_PATH")
            or cfg.get("RECORDING_BASE_DIR")
            or ""
        ),
        "recording_base_dir": db_settings.get("recording_base_dir")
        or str(cfg.get("RECORDING_BASE_DIR") or ""),
        "s3_bucket": db_settings.get("s3_bucket")
        or str(cfg.get("S3_BUCKET") or ""),
        "s3_endpoint": db_settings.get("s3_endpoint")
        or str(cfg.get("S3_ENDPOINT") or ""),
        "s3_region": db_settings.get("s3_region")
        or str(cfg.get("S3_REGION") or ""),
        # Secrets are never echoed back in the form; admins can enter new
        # values to override the current effective configuration.
        "s3_access_key": "",
        "s3_secret_key": "",
        "gcs_bucket": db_settings.get("gcs_bucket")
        or str(cfg.get("GCS_BUCKET") or ""),
        "azure_blob_connection_string": "",
        "azure_blob_container": db_settings.get("azure_blob_container")
        or str(cfg.get("AZURE_BLOB_CONTAINER") or ""),
        "dropbox_access_token": "",
        "webdav_base_url": db_settings.get("webdav_base_url")
        or str(cfg.get("WEBDAV_BASE_URL") or ""),
        "webdav_username": db_settings.get("webdav_username")
        or str(cfg.get("WEBDAV_USERNAME") or ""),
        "webdav_password": "",
    }

    record_engine = get_record_engine()

    edit_module = None
    edit_module_id: int | None = None
    edit_module_name: str | None = None
    edit_module_config: dict[str, object] | None = None
    if record_engine is not None:
        edit_id_raw = request.args.get("edit_module") or ""
        try:
            edit_id = int(edit_id_raw) if edit_id_raw else None
        except ValueError:
            edit_id = None
        if edit_id is not None:
            with Session(record_engine) as session_db:
                StorageModule.__table__.create(
                    bind=record_engine,
                    checkfirst=True,
                )
                row = session_db.get(StorageModule, edit_id)
            if row is not None:
                edit_module = row
                try:
                    edit_module_id = int(row.id)
                except Exception:  # noqa: BLE001
                    edit_module_id = None
                try:
                    edit_module_name = str(row.name)
                except Exception:  # noqa: BLE001
                    edit_module_name = None
                if row.config_json:
                    try:
                        edit_module_config = json.loads(row.config_json)
                    except Exception:  # noqa: BLE001
                        edit_module_config = {}

                try:
                    if edit_module_config is None:
                        edit_module_config = {}
                    provider_type = (row.provider_type or "").strip().lower()
                    if provider_type == "local_drive":
                        if (
                            isinstance(edit_module_config, dict)
                            and "base_dir" not in edit_module_config
                            and "local_drive_path" in edit_module_config
                        ):
                            edit_module_config["base_dir"] = edit_module_config.get(
                                "local_drive_path"
                            )
                except Exception:  # noqa: BLE001
                    pass

    if request.method == "POST":
        action = (request.form.get("action") or "").strip()

        if not validate_global_csrf_token(request.form.get("csrf_token")):
            errors.append("Invalid or missing CSRF token.")
        else:
            # Legacy global StorageSettings update when no explicit action is
            # provided (for backwards compatibility) or when the action is
            # save_legacy.
            if not action or action == "save_legacy":
                # Update form values from submitted data so we can re-render on
                # error.
                for key in form.keys():
                    form[key] = (request.form.get(key) or "").strip()

                if not form["storage_targets"]:
                    form["storage_targets"] = "local_fs"

                if record_engine is None:
                    errors.append("Record database is not configured.")

                if not errors and record_engine is not None:
                    with Session(record_engine) as session_db:
                        StorageSettings.__table__.create(
                            bind=record_engine, checkfirst=True
                        )
                        settings = (
                            session_db.query(StorageSettings)
                            .order_by(StorageSettings.id)
                            .first()
                        )
                        if settings is None:
                            settings = StorageSettings()
                            session_db.add(settings)

                        settings.storage_targets = form["storage_targets"] or None
                        settings.local_storage_path = (
                            form["local_storage_path"] or None
                        )
                        settings.recording_base_dir = (
                            form["recording_base_dir"] or None
                        )
                        settings.s3_bucket = form["s3_bucket"] or None
                        settings.s3_endpoint = form["s3_endpoint"] or None
                        settings.s3_region = form["s3_region"] or None
                        # Secret fields: only update when a non-empty value is
                        # provided, so leaving the field blank keeps the
                        # existing secret or environment-backed value.
                        if form["s3_access_key"]:
                            settings.s3_access_key = form["s3_access_key"]
                        if form["s3_secret_key"]:
                            settings.s3_secret_key = form["s3_secret_key"]
                        settings.gcs_bucket = form["gcs_bucket"] or None
                        if form["azure_blob_connection_string"]:
                            settings.azure_blob_connection_string = form[
                                "azure_blob_connection_string"
                            ]
                        settings.azure_blob_container = (
                            form["azure_blob_container"] or None
                        )
                        if form["dropbox_access_token"]:
                            settings.dropbox_access_token = form[
                                "dropbox_access_token"
                            ]
                        settings.webdav_base_url = (
                            form["webdav_base_url"] or None
                        )
                        settings.webdav_username = (
                            form["webdav_username"] or None
                        )
                        if form["webdav_password"]:
                            settings.webdav_password = form["webdav_password"]
                        settings.updated_at = datetime.now(timezone.utc)

                        session_db.add(settings)
                        session_db.commit()

                    saved = True
                    # Reload DB settings so the provider summary reflects the
                    # new configuration.
                    db_settings = _load_storage_settings() or {}

                    raw_targets = db_settings.get("storage_targets") or str(
                        cfg.get("STORAGE_TARGETS", "local_fs") or "local_fs"
                    )
                    form["storage_targets"] = raw_targets
                    form["local_storage_path"] = db_settings.get(
                        "local_storage_path"
                    ) or str(
                        cfg.get("LOCAL_STORAGE_PATH")
                        or cfg.get("RECORDING_BASE_DIR")
                        or ""
                    )
                    form["recording_base_dir"] = db_settings.get(
                        "recording_base_dir"
                    ) or str(cfg.get("RECORDING_BASE_DIR") or "")
                    form["s3_bucket"] = db_settings.get("s3_bucket") or str(
                        cfg.get("S3_BUCKET") or ""
                    )
                    form["s3_endpoint"] = db_settings.get("s3_endpoint") or str(
                        cfg.get("S3_ENDPOINT") or ""
                    )
                    form["s3_region"] = db_settings.get("s3_region") or str(
                        cfg.get("S3_REGION") or ""
                    )
                    form["gcs_bucket"] = db_settings.get("gcs_bucket") or str(
                        cfg.get("GCS_BUCKET") or ""
                    )
                    form["azure_blob_container"] = db_settings.get(
                        "azure_blob_container"
                    ) or str(cfg.get("AZURE_BLOB_CONTAINER") or "")
                    form["webdav_base_url"] = db_settings.get(
                        "webdav_base_url"
                    ) or str(cfg.get("WEBDAV_BASE_URL") or "")
                    form["webdav_username"] = db_settings.get(
                        "webdav_username"
                    ) or str(cfg.get("WEBDAV_USERNAME") or "")
                    # Secret fields remain blank after save so that we never
                    # echo sensitive values back to the browser.
                    form["s3_access_key"] = ""
                    form["s3_secret_key"] = ""
                    form["azure_blob_connection_string"] = ""
                    form["dropbox_access_token"] = ""
                    form["webdav_password"] = ""

            # New path: module management actions for StorageModule rows.
            elif action in {
                "module_create",
                "module_update",
                "module_delete",
                "module_toggle",
                "module_test",
                "module_draft_test",
                "module_clone",
            }:
                if record_engine is None:
                    errors.append("Record database is not configured.")

                if not errors and record_engine is not None:
                    with Session(record_engine) as session_db:
                        StorageModule.__table__.create(
                            bind=record_engine, checkfirst=True
                        )

                        def _fingerprint_module_payload(
                            provider_type: str,
                            name: str,
                            config: dict[str, object],
                            module_id: int | None = None,
                        ) -> str:
                            payload = {
                                "provider_type": (provider_type or "").strip().lower(),
                                "name": (name or "").strip(),
                                "module_id": int(module_id) if module_id is not None else None,
                                "config": config,
                            }
                            raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
                            return hashlib.sha256(raw.encode("utf-8")).hexdigest()

                        def _load_provider_definition(provider_type: str) -> dict:
                            provider_type = (provider_type or "").strip().lower()
                            if not provider_type:
                                return {}
                            try:
                                from .modules.storage.registry import (  # noqa: PLC0415
                                    _safe_read_json,
                                )
                            except Exception:  # noqa: BLE001
                                return {}
                            try:
                                base_dir = os.path.join(
                                    os.path.dirname(__file__),
                                    "modules",
                                    "storage",
                                    provider_type,
                                    "definition.json",
                                )
                                return _safe_read_json(base_dir)
                            except Exception:  # noqa: BLE001
                                return {}

                        def _default_form_key(provider_type: str, key: str) -> str:
                            provider_type = (provider_type or "").strip().lower()
                            key = (key or "").strip()
                            if provider_type == "local_fs" and key == "base_dir":
                                return "module_cfg_base_dir"
                            if provider_type == "local_drive" and key == "base_dir":
                                return "module_cfg_local_drive_path"
                            return f"module_cfg_{provider_type}_{key}"

                        def _coerce_value(raw: str, field_type: str):
                            field_type = (field_type or "text").strip().lower()
                            if field_type in {"number", "int", "integer"}:
                                try:
                                    return int(str(raw).strip())
                                except Exception:  # noqa: BLE001
                                    return None
                            if field_type in {"bool", "boolean"}:
                                if raw is None:
                                    return False
                                sval = str(raw).strip().lower()
                                if sval in {"1", "true", "on", "yes"}:
                                    return True
                                if sval in {"0", "false", "off", "no"}:
                                    return False
                                return bool(sval)
                            return str(raw)

                        def _build_module_config_from_form(
                            provider_type: str,
                        ) -> dict[str, object]:
                            provider_type = (provider_type or "").strip().lower()
                            definition = _load_provider_definition(provider_type)
                            fields = list(definition.get("fields") or [])
                            config: dict[str, object] = {}

                            for f in fields:
                                if not isinstance(f, dict):
                                    continue
                                key = str(f.get("key") or "").strip()
                                if not key:
                                    continue
                                form_key = str(f.get("form_key") or "").strip() or _default_form_key(provider_type, key)
                                ftype = str(f.get("type") or "text").strip().lower()

                                if ftype in {"bool", "boolean"}:
                                    raw = request.form.get(form_key)
                                    if raw is None:
                                        present = request.form.get(f"{form_key}_present")
                                        if present is None:
                                            continue
                                        config[key] = False
                                        continue
                                    config[key] = bool(_coerce_value(raw, ftype))
                                    continue

                                raw_val = request.form.get(form_key)
                                if raw_val is None:
                                    continue
                                raw_val = str(raw_val).strip()
                                if raw_val == "":
                                    continue

                                coerced = _coerce_value(raw_val, ftype)
                                if coerced is None:
                                    continue

                                config[key] = coerced

                            if not fields:
                                return config

                            try:
                                if provider_type == "local_drive" and "base_dir" not in config:
                                    raw_base_dir = request.form.get("module_cfg_local_drive_path")
                                    if raw_base_dir is not None:
                                        raw_base_dir = str(raw_base_dir).strip()
                                        if raw_base_dir:
                                            config["base_dir"] = raw_base_dir
                            except Exception:  # noqa: BLE001
                                pass

                            return config

                        def _get_last_module_test() -> dict[str, object] | None:
                            try:
                                raw = session.get("storage_module_last_test")
                            except Exception:  # noqa: BLE001
                                raw = None
                            if not isinstance(raw, dict):
                                return None
                            return raw

                        def _set_last_module_test(
                            fingerprint: str,
                            ok: bool,
                        ) -> None:
                            try:
                                session["storage_module_last_test"] = {
                                    "fingerprint": fingerprint,
                                    "ok": bool(ok),
                                    "at": datetime.now(timezone.utc).isoformat(),
                                }
                            except Exception:  # noqa: BLE001
                                return

                        def _log_health_check(
                            module_id: int | None,
                            module_name: str,
                            provider_type: str | None,
                            ok: bool,
                            message: str,
                            duration_ms: int | None,
                        ) -> None:
                            try:
                                session_db.add(
                                    StorageModuleHealthCheck(
                                        module_id=(int(module_id) if module_id is not None else None),
                                        module_name=str(module_name or "")[:160],
                                        provider_type=(str(provider_type or "")[:64] if provider_type else None),
                                        ok=1 if ok else 0,
                                        message=str(message or "")[:512] if message else None,
                                        duration_ms=int(duration_ms) if duration_ms is not None else None,
                                    )
                                )
                                session_db.commit()
                            except Exception:  # noqa: BLE001
                                return

                        def _validate_provider_config(
                            provider_type: str,
                            config: dict[str, object],
                        ) -> list[str]:
                            provider_type = (provider_type or "").strip().lower()
                            definition = _load_provider_definition(provider_type)
                            fields = list(definition.get("fields") or [])
                            missing: list[str] = []
                            for f in fields:
                                if not isinstance(f, dict):
                                    continue
                                if not f.get("required"):
                                    continue
                                key = str(f.get("key") or "").strip()
                                if not key:
                                    continue
                                ftype = str(f.get("type") or "text").strip().lower()
                                val = config.get(key)
                                if ftype in {"bool", "boolean"}:
                                    if val is None:
                                        missing.append(str(f.get("label") or key))
                                    continue
                                if not str(val or "").strip():
                                    missing.append(str(f.get("label") or key))
                            return missing

                        StorageModuleEvent.__table__.create(
                            bind=record_engine, checkfirst=True
                        )

                        StorageModuleHealthCheck.__table__.create(
                            bind=record_engine, checkfirst=True
                        )

                        def _log_module_event(
                            level: str,
                            event_type: str,
                            message: str,
                            module_row: StorageModule | None = None,
                            module_name: str | None = None,
                        ) -> None:
                            try:
                                name_val = module_name or (
                                    (module_row.name if module_row is not None else "")
                                )
                                mod_id = int(module_row.id) if module_row is not None else None
                                session_db.add(
                                    StorageModuleEvent(
                                        module_id=mod_id,
                                        module_name=str(name_val or ""),
                                        level=str(level or "info"),
                                        event_type=str(event_type or "event"),
                                        message=str(message or "")[:1024],
                                    )
                                )
                                session_db.commit()
                            except Exception:  # noqa: BLE001
                                return

                        if action == "module_create":
                            name = (request.form.get("module_name") or "").strip()
                            label = (request.form.get("module_label") or "").strip()
                            provider_type = (
                                request.form.get("module_provider") or ""
                            ).strip().lower()

                            if provider_type == "gdrive":
                                errors.append("Google Drive storage module is not supported.")
                            enabled_flag = (
                                1 if request.form.get("module_enabled") == "1" else 0
                            )
                            priority_raw = (request.form.get("module_priority") or "").strip()
                            try:
                                priority_val = int(priority_raw) if priority_raw else 100
                            except ValueError:
                                priority_val = 100

                            if not name:
                                errors.append("Module name is required.")
                            if not provider_type:
                                errors.append("Provider type is required.")

                            existing = None
                            if not errors:
                                existing = (
                                    session_db.query(StorageModule)
                                    .filter(StorageModule.name == name)
                                    .first()
                                )
                                if existing is not None:
                                    errors.append(
                                        "A storage module with this name already exists."
                                    )

                            if not errors:
                                config = _build_module_config_from_form(provider_type)

                                fp_expected = _fingerprint_module_payload(
                                    provider_type,
                                    name,
                                    config,
                                    None,
                                )
                                last_test = _get_last_module_test() or {}
                                client_ok = (request.form.get("module_test_ok") or "").strip() == "1"
                                client_fp = (request.form.get("module_test_fingerprint") or "").strip()
                                client_matches = bool(client_ok and client_fp and client_fp == fp_expected)

                                if client_matches:
                                    _set_last_module_test(fp_expected, True)
                                elif not last_test or not last_test.get("ok"):
                                    errors.append(
                                        "Please test this storage provider successfully before saving."
                                    )
                                elif str(last_test.get("fingerprint") or "") != fp_expected:
                                    errors.append(
                                        "The storage provider configuration changed. Please test again before saving."
                                    )

                            if not errors:
                                now_dt = datetime.now(timezone.utc)
                                module = StorageModule(
                                    name=name,
                                    label=label or None,
                                    provider_type=provider_type,
                                    is_enabled=enabled_flag,
                                    priority=int(priority_val),
                                    config_json=json.dumps(config) if config else None,
                                    updated_at=now_dt,
                                )
                                session_db.add(module)
                                session_db.commit()
                                saved = True
                                try:
                                    session.pop("storage_wizard_draft", None)
                                except Exception:  # noqa: BLE001
                                    pass
                                _log_module_event(
                                    "info",
                                    "module_create",
                                    f"Created storage module '{module.name}' ({module.provider_type}).",
                                    module_row=module,
                                )

                        elif action == "module_update":
                            module_id_raw = request.form.get("module_id") or ""
                            try:
                                module_id = int(module_id_raw)
                            except ValueError:
                                module_id = None

                            if module_id is None:
                                errors.append("Invalid storage module id.")
                                module = None
                            else:
                                module = session_db.get(StorageModule, module_id)
                                if module is None:
                                    errors.append("Storage module not found.")

                            if not errors and module is not None:
                                new_name = (
                                    request.form.get("module_name") or ""
                                ).strip()
                                new_label = (
                                    request.form.get("module_label") or ""
                                ).strip()
                                enabled_flag = (
                                    1
                                    if request.form.get("module_enabled") == "1"
                                    else 0
                                )
                                priority_raw = (request.form.get("module_priority") or "").strip()
                                try:
                                    priority_val = int(priority_raw) if priority_raw else 100
                                except ValueError:
                                    priority_val = 100

                                if not new_name:
                                    errors.append("Module name is required.")
                                else:
                                    existing = (
                                        session_db.query(StorageModule)
                                        .filter(StorageModule.name == new_name)
                                        .filter(StorageModule.id != module.id)
                                        .first()
                                    )
                                    if existing is not None:
                                        errors.append(
                                            "A storage module with this name already exists."
                                        )

                                if not errors:
                                    provider_type = (
                                        (module.provider_type or "").strip().lower()
                                    )
                                    if provider_type == "gdrive":
                                        errors.append("Google Drive storage module is not supported.")
                                    try:
                                        current_cfg = (
                                            json.loads(module.config_json)
                                            if module.config_json
                                            else {}
                                        )
                                    except Exception:  # noqa: BLE001
                                        current_cfg = {}

                                    try:
                                        if provider_type == "local_drive":
                                            if (
                                                isinstance(current_cfg, dict)
                                                and "base_dir" not in current_cfg
                                                and "local_drive_path" in current_cfg
                                            ):
                                                current_cfg["base_dir"] = current_cfg.get(
                                                    "local_drive_path"
                                                )
                                    except Exception:  # noqa: BLE001
                                        pass

                                    new_cfg = _build_module_config_from_form(
                                        provider_type
                                    )
                                    merged_cfg = dict(current_cfg)
                                    merged_cfg.update(new_cfg)

                                    try:
                                        if provider_type == "local_drive":
                                            raw_base_dir = request.form.get(
                                                "module_cfg_local_drive_path"
                                            )
                                            if raw_base_dir is not None:
                                                raw_base_dir = str(raw_base_dir).strip()
                                                if raw_base_dir:
                                                    merged_cfg["base_dir"] = raw_base_dir
                                    except Exception:  # noqa: BLE001
                                        pass

                                    try:
                                        if provider_type == "local_drive":
                                            if (
                                                isinstance(merged_cfg, dict)
                                                and "base_dir" not in merged_cfg
                                                and "local_drive_path" in merged_cfg
                                            ):
                                                merged_cfg["base_dir"] = merged_cfg.get(
                                                    "local_drive_path"
                                                )
                                    except Exception:  # noqa: BLE001
                                        pass

                                    fp_expected = _fingerprint_module_payload(
                                        provider_type,
                                        new_name,
                                        merged_cfg,
                                        int(module.id),
                                    )
                                    last_test = _get_last_module_test() or {}

                                    client_ok = (
                                        request.form.get("module_test_ok") or ""
                                    ).strip() == "1"
                                    client_fp = (
                                        request.form.get("module_test_fingerprint") or ""
                                    ).strip()
                                    client_matches = bool(
                                        client_ok
                                        and client_fp
                                        and client_fp == fp_expected
                                    )

                                    if client_matches:
                                        _set_last_module_test(client_fp, True)
                                    elif not last_test or not last_test.get("ok"):
                                        errors.append(
                                            "Please test this storage provider successfully before saving."
                                        )
                                    elif str(last_test.get("fingerprint") or "") != fp_expected:
                                        errors.append(
                                            "The storage provider configuration changed. Please test again before saving."
                                        )

                                if not errors:
                                    module.name = new_name
                                    module.label = new_label or None
                                    module.is_enabled = enabled_flag
                                    module.priority = int(priority_val)
                                    module.config_json = (
                                        json.dumps(merged_cfg) if merged_cfg else None
                                    )
                                    module.updated_at = datetime.now(timezone.utc)
                                    session_db.add(module)
                                    session_db.commit()
                                    saved = True

                                    try:
                                        edit_module = module
                                        edit_module_config = dict(merged_cfg)
                                        try:
                                            edit_module_id = int(module.id)
                                        except Exception:  # noqa: BLE001
                                            edit_module_id = None
                                        try:
                                            edit_module_name = str(module.name)
                                        except Exception:  # noqa: BLE001
                                            edit_module_name = None
                                    except Exception:  # noqa: BLE001
                                        pass
                                    _log_module_event(
                                        "info",
                                        "module_update",
                                        f"Updated storage module '{module.name}'.",
                                        module_row=module,
                                    )

                        elif action == "module_clone":
                            module_id_raw = request.form.get("module_id") or ""
                            new_name = (request.form.get("clone_name") or "").strip()
                            try:
                                module_id = int(module_id_raw)
                            except ValueError:
                                module_id = None

                            if module_id is None:
                                errors.append("Invalid storage module id.")
                            if not new_name:
                                errors.append("Clone name is required.")

                            src = session_db.get(StorageModule, module_id) if module_id is not None else None
                            if src is None and not errors:
                                errors.append("Storage module not found.")

                            if not errors:
                                existing = (
                                    session_db.query(StorageModule)
                                    .filter(StorageModule.name == new_name)
                                    .first()
                                )

                                if existing is not None:
                                    errors.append(
                                        "A storage module with this name already exists."
                                    )

                            if not errors and src is not None:
                                now_dt = datetime.now(timezone.utc)
                                clone_row = StorageModule(
                                    name=new_name,
                                    label=(src.label or None),
                                    provider_type=src.provider_type,
                                    is_enabled=0,
                                    priority=int(getattr(src, "priority", 100) or 100),
                                    config_json=src.config_json,
                                    updated_at=now_dt,
                                )
                                session_db.add(clone_row)
                                session_db.commit()
                                saved = True
                                _log_module_event(
                                    "info",
                                    "module_clone",
                                    f"Cloned module '{src.name}' to '{clone_row.name}' (disabled by default).",
                                    module_row=clone_row,
                                )

                        elif action == "module_delete":
                            module_id_raw = request.form.get("module_id") or ""
                            force_delete = (request.form.get("force_delete") or "").strip()
                            try:
                                module_id = int(module_id_raw)
                            except ValueError:
                                module_id = None
                            if module_id is not None:
                                module = session_db.get(StorageModule, module_id)
                                if module is not None:
                                    CameraRecording.__table__.create(
                                        bind=record_engine, checkfirst=True
                                    )
                                    cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
                                    active_streams = (
                                        session_db.query(
                                            func.count(func.distinct(CameraRecording.device_id))
                                        )
                                        .filter(
                                            CameraRecording.storage_provider == module.name,
                                            CameraRecording.created_at >= cutoff,
                                        )
                                        .scalar()
                                        or 0
                                    )
                                    any_segments = (
                                        session_db.query(func.count(CameraRecording.id))
                                        .filter(
                                            CameraRecording.storage_provider == module.name
                                        )
                                        .scalar()
                                        or 0
                                    )
                                    if (int(active_streams) > 0 or int(any_segments) > 0) and force_delete != "1":
                                        errors.append(
                                            "This module has existing recordings or active streams. Tick 'Force delete' and submit again to confirm."
                                        )
                                        module = None

                                if module is not None:
                                    deleted_name = module.name
                                    deleted_id = module.id
                                    session_db.delete(module)
                                    session_db.commit()
                                    saved = True
                                    _log_module_event(
                                        "warn",
                                        "module_delete",
                                        f"Deleted storage module '{deleted_name}'.",
                                        module_row=None,
                                        module_name=str(deleted_name or f"#{deleted_id}"),
                                    )

                        elif action == "module_toggle":
                            module_id_raw = request.form.get("module_id") or ""
                            enable_raw = request.form.get("enable") or ""
                            force_disable = (request.form.get("force_disable") or "").strip()
                            try:
                                module_id = int(module_id_raw)
                            except ValueError:
                                module_id = None
                            enable_flag = 1 if str(enable_raw) == "1" else 0
                            if module_id is not None:
                                module = session_db.get(StorageModule, module_id)
                                if module is not None:
                                    if enable_flag == 0:
                                        CameraRecording.__table__.create(
                                            bind=record_engine, checkfirst=True
                                        )
                                        cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
                                        active_streams = (
                                            session_db.query(
                                                func.count(
                                                    func.distinct(CameraRecording.device_id)
                                                )
                                            )
                                            .filter(
                                                CameraRecording.storage_provider == module.name,
                                                CameraRecording.created_at >= cutoff,
                                            )
                                            .scalar()
                                            or 0
                                        )
                                        if int(active_streams) > 0 and force_disable != "1":
                                            errors.append(
                                                "This module has active streams. Tick 'Force disable' and submit again to confirm."
                                            )
                                            module = None

                                if module is not None:
                                    module.is_enabled = enable_flag
                                    module.updated_at = datetime.now(timezone.utc)
                                    session_db.add(module)
                                    session_db.commit()
                                    saved = True
                                    _log_module_event(
                                        "info",
                                        "module_toggle",
                                        (
                                            f"Enabled storage module '{module.name}'."
                                            if enable_flag
                                            else f"Disabled storage module '{module.name}'."
                                        ),
                                        module_row=module,
                                    )
                        elif action == "module_test":
                            module_id_raw = request.form.get("module_id") or ""
                            try:
                                module_id = int(module_id_raw)
                            except ValueError:
                                module_id = None

                            if module_id is not None:
                                module = session_db.get(StorageModule, module_id)
                            else:
                                module = None

                            if module is None:
                                module_test_result = {
                                    "ok": False,
                                    "module_name": f"#{module_id_raw}",
                                    "message": "Storage module not found.",
                                }
                            else:
                                router = get_storage_router(current_app)
                                instance_key = str(module.id)
                                started = time.monotonic()
                                try:
                                    status = router.health_check(instance_key)
                                except StorageError as exc:  # pragma: no cover - error path
                                    module_test_result = {
                                        "ok": False,
                                        "module_name": module.name,
                                        "message": str(exc)[:300],
                                    }
                                    duration_ms = int((time.monotonic() - started) * 1000)
                                    _log_health_check(
                                        int(module.id),
                                        str(module.name or ""),
                                        str(module.provider_type or "") if getattr(module, "provider_type", None) else None,
                                        False,
                                        str(exc)[:512],
                                        duration_ms,
                                    )
                                    _log_module_event(
                                        "error",
                                        "health_check_error",
                                        str(exc)[:1024],
                                        module_row=module,
                                    )
                                except Exception as exc:  # noqa: BLE001
                                    module_test_result = {
                                        "ok": False,
                                        "module_name": module.name,
                                        "message": str(exc)[:300],
                                    }
                                    duration_ms = int((time.monotonic() - started) * 1000)
                                    _log_health_check(
                                        int(module.id),
                                        str(module.name or ""),
                                        str(module.provider_type or "") if getattr(module, "provider_type", None) else None,
                                        False,
                                        str(exc)[:512],
                                        duration_ms,
                                    )
                                    _log_module_event(
                                        "error",
                                        "health_check_error",
                                        str(exc)[:1024],
                                        module_row=module,
                                    )
                                else:
                                    status_text = str(status.get("status") or "ok")
                                    message = status.get("message") or (
                                        f"Health check status: {status_text}"
                                    )
                                    module_test_result = {
                                        "ok": status_text == "ok",
                                        "module_name": module.name,
                                        "message": str(message)[:300],
                                    }
                                    duration_ms = int((time.monotonic() - started) * 1000)
                                    _log_health_check(
                                        int(module.id),
                                        str(module.name or ""),
                                        str(module.provider_type or "") if getattr(module, "provider_type", None) else None,
                                        status_text == "ok",
                                        str(message)[:512],
                                        duration_ms,
                                    )

                            try:
                                wants_json = False
                                hdr = (request.headers.get("X-Requested-With") or "").strip().lower()
                                if hdr == "xmlhttprequest":
                                    wants_json = True
                                accept = (request.headers.get("Accept") or "").lower()
                                if "application/json" in accept:
                                    wants_json = True
                                if wants_json:
                                    return jsonify(
                                        {
                                            "ok": bool(module_test_result.get("ok")) if isinstance(module_test_result, dict) else False,
                                            "module_name": (str(module_test_result.get("module_name") or "") if isinstance(module_test_result, dict) else ""),
                                            "message": (str(module_test_result.get("message") or "") if isinstance(module_test_result, dict) else ""),
                                        }
                                    )
                            except Exception:  # noqa: BLE001
                                pass

                        elif action == "module_draft_test":
                            module_id_raw = (request.form.get("module_id") or "").strip()
                            try:
                                module_id = int(module_id_raw) if module_id_raw else None
                            except ValueError:
                                module_id = None

                            try:
                                draft: dict[str, object] = {}
                                for k in request.form.keys():
                                    if not k:
                                        continue
                                    if k in {
                                        "csrf_token",
                                        "action",
                                    }:
                                        continue
                                    if k.startswith("module_") or k.startswith("module_cfg_"):
                                        draft[k] = request.form.get(k)
                                draft["_step"] = 3
                                session["storage_wizard_draft"] = draft
                                wizard_draft = draft
                                wizard_step = 3
                            except Exception:  # noqa: BLE001
                                pass

                            name = (request.form.get("module_name") or "").strip()
                            label = (request.form.get("module_label") or "").strip()
                            provider_type = (
                                request.form.get("module_provider") or ""
                            ).strip().lower()

                            existing_module: StorageModule | None = None
                            if module_id is not None:
                                existing_module = session_db.get(StorageModule, module_id)
                                if existing_module is None:
                                    errors.append("Storage module not found.")
                                else:
                                    provider_type = (
                                        (existing_module.provider_type or "").strip().lower()
                                    )
                                    if not name:
                                        name = existing_module.name
                                    if not label:
                                        label = existing_module.label or ""

                            if not name:
                                errors.append("Module name is required.")
                            if not provider_type:
                                errors.append("Provider type is required.")

                            config = _build_module_config_from_form(provider_type)
                            if existing_module is not None:
                                try:
                                    current_cfg = (
                                        json.loads(existing_module.config_json)
                                        if existing_module.config_json
                                        else {}
                                    )
                                except Exception:  # noqa: BLE001
                                    current_cfg = {}
                                merged_cfg = dict(current_cfg)
                                merged_cfg.update(config)
                                config = merged_cfg

                            try:
                                if provider_type == "local_drive":
                                    raw_base_dir = request.form.get("module_cfg_local_drive_path")
                                    if raw_base_dir is not None:
                                        raw_base_dir = str(raw_base_dir).strip()
                                        if raw_base_dir:
                                            config["base_dir"] = raw_base_dir
                            except Exception:  # noqa: BLE001
                                pass

                            if not errors:
                                missing_fields = _validate_provider_config(provider_type, config)
                                if missing_fields:
                                    errors.append(
                                        "Missing required fields: " + ", ".join(missing_fields)
                                    )

                            started = time.monotonic()
                            duration_ms: int | None = None

                            if errors:
                                module_test_result = {
                                    "ok": False,
                                    "module_name": name,
                                    "message": "; ".join(errors)[:300],
                                }
                                duration_ms = int((time.monotonic() - started) * 1000)
                                _set_last_module_test("", False)
                                _log_health_check(
                                    int(existing_module.id) if existing_module is not None else None,
                                    str(name or ""),
                                    str(provider_type or "") if provider_type else None,
                                    False,
                                    "; ".join(errors)[:512],
                                    duration_ms,
                                )
                                _log_module_event(
                                    "error",
                                    "draft_test_invalid",
                                    "; ".join(errors)[:1024],
                                    module_row=existing_module,
                                    module_name=str(name or ""),
                                )
                                errors = []

                            if module_test_result is None and not errors:
                                tmp_module = StorageModule(
                                    name=name,
                                    label=label or None,
                                    provider_type=provider_type,
                                    is_enabled=1,
                                    config_json=None,
                                )
                                try:
                                    from .storage_providers import (  # noqa: PLC0415
                                        _LegacyProviderAdapter,
                                        _build_provider_for_module,
                                    )

                                    provider = _build_provider_for_module(
                                        current_app,
                                        tmp_module,
                                        config,
                                    )
                                    if provider is None:
                                        missing_bits: list[str] = []
                                        try:
                                            if provider_type == "s3":
                                                if not str(config.get("bucket") or "").strip():
                                                    missing_bits.append("bucket")
                                                if not str(config.get("access_key") or "").strip():
                                                    missing_bits.append("access_key")
                                                if not str(config.get("secret_key") or "").strip():
                                                    missing_bits.append("secret_key")
                                        except Exception:  # noqa: BLE001
                                            missing_bits = []
                                        if missing_bits:
                                            raise StorageError(
                                                "Failed to build provider (missing: "
                                                + ", ".join(missing_bits)
                                                + ")"
                                            )
                                        raise StorageError("Failed to build provider")
                                    provider.name = name
                                    adapter = _LegacyProviderAdapter(provider)
                                    status = adapter.health_check()
                                except StorageError as exc:
                                    module_test_result = {
                                        "ok": False,
                                        "module_name": name,
                                        "message": str(exc)[:300],
                                    }
                                    _set_last_module_test("", False)
                                    duration_ms = int((time.monotonic() - started) * 1000)
                                    _log_health_check(
                                        int(existing_module.id) if existing_module is not None else None,
                                        str(name or ""),
                                        str(provider_type or "") if provider_type else None,
                                        False,
                                        str(exc)[:512],
                                        duration_ms,
                                    )
                                    _log_module_event(
                                        "error",
                                        "draft_test_error",
                                        str(exc)[:1024],
                                        module_row=existing_module,
                                        module_name=str(name or ""),
                                    )
                                except Exception as exc:  # noqa: BLE001
                                    module_test_result = {
                                        "ok": False,
                                        "module_name": name,
                                        "message": str(exc)[:300],
                                    }
                                    _set_last_module_test("", False)
                                    duration_ms = int((time.monotonic() - started) * 1000)
                                    _log_health_check(
                                        int(existing_module.id) if existing_module is not None else None,
                                        str(name or ""),
                                        str(provider_type or "") if provider_type else None,
                                        False,
                                        str(exc)[:512],
                                        duration_ms,
                                    )
                                    _log_module_event(
                                        "error",
                                        "draft_test_error",
                                        str(exc)[:1024],
                                        module_row=existing_module,
                                        module_name=str(name or ""),
                                    )
                                else:
                                    status_text = str(status.get("status") or "ok")
                                    ok = status_text == "ok"
                                    message = status.get("message") or (
                                        f"Health check status: {status_text}"
                                    )
                                    module_test_result = {
                                        "ok": ok,
                                        "module_name": name,
                                        "message": str(message)[:300],
                                    }
                                    fp = _fingerprint_module_payload(
                                        provider_type,
                                        name,
                                        config,
                                        int(existing_module.id) if existing_module is not None else None,
                                    )
                                    _set_last_module_test(fp, ok)
                                    module_test_ready = bool(ok)
                                    try:
                                        if wizard_draft is not None and isinstance(wizard_draft, dict):
                                            wizard_draft["_step"] = 4 if ok else 3
                                            session["storage_wizard_draft"] = wizard_draft
                                            wizard_step = int(wizard_draft.get("_step") or 3)
                                    except Exception:  # noqa: BLE001
                                        pass
                                    duration_ms = int((time.monotonic() - started) * 1000)
                                    _log_health_check(
                                        int(existing_module.id) if existing_module is not None else None,
                                        str(name or ""),
                                        str(provider_type or "") if provider_type else None,
                                        ok,
                                        str(message)[:512],
                                        duration_ms,
                                    )

                            try:
                                wants_json = False
                                hdr = (request.headers.get("X-Requested-With") or "").strip().lower()
                                if hdr == "xmlhttprequest":
                                    wants_json = True
                                accept = (request.headers.get("Accept") or "").lower()
                                if "application/json" in accept:
                                    wants_json = True
                                if wants_json:
                                    fp_out = ""
                                    try:
                                        fp_out = _fingerprint_module_payload(
                                            provider_type,
                                            name,
                                            config,
                                            int(existing_module.id) if existing_module is not None else None,
                                        )
                                    except Exception:  # noqa: BLE001
                                        fp_out = ""
                                    return jsonify(
                                        {
                                            "ok": bool(module_test_result.get("ok")) if isinstance(module_test_result, dict) else False,
                                            "module_name": (str(module_test_result.get("module_name") or "") if isinstance(module_test_result, dict) else name),
                                            "message": (str(module_test_result.get("message") or "") if isinstance(module_test_result, dict) else ""),
                                            "module_test_ready": bool(module_test_ready),
                                            "wizard_step": int(wizard_step or 3),
                                            "fingerprint": fp_out,
                                        }
                                    )
                            except Exception:  # noqa: BLE001
                                pass

    providers_raw = build_storage_providers(current_app)
    providers = []
    for p in providers_raw:
        name = getattr(p, "name", "?")
        details = ""
        p_type = "Custom"
        if name == "local_fs" and hasattr(p, "base_path"):
            p_type = "Local filesystem"
            details = f"Base directory: {p.base_path}"
        elif name == "db":
            p_type = "Database"
            details = "Stores recording bytes directly in the RecordDB (RecordingData table)."
        elif name == "s3":
            p_type = "S3-compatible"
            bucket = getattr(p, "bucket", "")
            endpoint = getattr(p, "endpoint", "") or "(default AWS endpoint)"
            region = getattr(p, "region", "") or "(none)"
            details = f"Bucket: {bucket}, Endpoint: {endpoint}, Region: {region}"
        elif name == "gcs":
            p_type = "Google Cloud Storage"
            bucket = getattr(p, "bucket", "")
            details = f"Bucket: {bucket}"
        elif name == "azure_blob":
            p_type = "Azure Blob Storage"
            container = getattr(p, "container", "")
            details = f"Container: {container}"
        elif name == "dropbox":
            p_type = "Dropbox"
            details = "Uploads recordings into the configured Dropbox account under /recordings."
        elif name == "webdav":
            p_type = "WebDAV / Nextcloud"
            base_url = getattr(p, "base_url", "")
            details = f"Base URL: {base_url}"
        providers.append({"name": name, "type": p_type, "details": details})

    def _mask(value: str, keep: int = 4) -> str:
        if not value:
            return ""
        if len(value) <= keep:
            return "*" * len(value)
        return "*" * (len(value) - keep) + value[-keep:]

    # Effective config for summary blocks: DB overrides env, otherwise env is
    # used. Secrets are masked.
    s3_bucket = db_settings.get("s3_bucket") or str(cfg.get("S3_BUCKET") or "")
    s3_endpoint = db_settings.get("s3_endpoint") or str(
        cfg.get("S3_ENDPOINT") or ""
    )
    s3_region = db_settings.get("s3_region") or str(cfg.get("S3_REGION") or "")
    s3_access_key_effective = db_settings.get("s3_access_key") or str(
        cfg.get("S3_ACCESS_KEY") or ""
    )
    s3_secret_key_effective = db_settings.get("s3_secret_key") or str(
        cfg.get("S3_SECRET_KEY") or ""
    )

    s3_info = {
        "bucket": s3_bucket,
        "endpoint": s3_endpoint,
        "region": s3_region,
        "access_key_masked": _mask(s3_access_key_effective),
        "secret_key_masked": _mask(s3_secret_key_effective),
    }

    gcs_bucket = db_settings.get("gcs_bucket") or str(cfg.get("GCS_BUCKET") or "")
    gcs_info = {
        "bucket": gcs_bucket,
    }

    azure_conn_effective = db_settings.get("azure_blob_connection_string") or str(
        cfg.get("AZURE_BLOB_CONNECTION_STRING") or ""
    )
    azure_container = db_settings.get("azure_blob_container") or str(
        cfg.get("AZURE_BLOB_CONTAINER") or ""
    )
    azure_info = {
        "container": azure_container,
        "connection_string_masked": _mask(azure_conn_effective),
    }

    dropbox_token_effective = db_settings.get("dropbox_access_token") or str(
        cfg.get("DROPBOX_ACCESS_TOKEN") or ""
    )
    dropbox_info = {
        "access_token_masked": _mask(dropbox_token_effective),
    }

    webdav_base = db_settings.get("webdav_base_url") or str(
        cfg.get("WEBDAV_BASE_URL") or ""
    )
    webdav_username = db_settings.get("webdav_username") or str(
        cfg.get("WEBDAV_USERNAME") or ""
    )
    webdav_password_effective = db_settings.get("webdav_password") or str(
        cfg.get("WEBDAV_PASSWORD") or ""
    )
    webdav_info = {
        "base_url": webdav_base,
        "username": webdav_username,
        "password_masked": _mask(webdav_password_effective),
    }

    # CSAL storage modules: logical storage instances backed by StorageModule.
    modules: list[dict] = []
    if record_engine is not None:
        with Session(record_engine) as session_db:
            StorageModule.__table__.create(bind=record_engine, checkfirst=True)
            module_rows = (
                session_db.query(StorageModule)
                .order_by(getattr(StorageModule, "priority", StorageModule.id), StorageModule.id)
                .all()
            )
        router = get_storage_router(current_app)
        for m in module_rows:
            try:
                if (str(getattr(m, "provider_type", "") or "").strip().lower()) == "gdrive":
                    continue
            except Exception:  # noqa: BLE001
                pass
            is_enabled = bool(getattr(m, "is_enabled", 0))
            status_text = "disabled" if not is_enabled else "unknown"
            status_message = ""
            if is_enabled:
                try:
                    status = router.health_check(str(m.id))
                    status_text = str(status.get("status") or "ok")
                    status_message = str(status.get("message") or "").strip()
                except StorageError as exc:  # pragma: no cover - error path
                    status_text = "error"
                    status_message = str(exc)[:300]
                except Exception:  # noqa: BLE001
                    status_text = "error"
                    status_message = "Unexpected error during health check."

            modules.append(
                {
                    "id": m.id,
                    "name": m.name,
                    "label": m.label or "",
                    "provider_type": m.provider_type,
                    "is_enabled": is_enabled,
                    "priority": int(getattr(m, "priority", 100) or 100),
                    "status": status_text,
                    "status_message": status_message,
                }
            )

    # When rendering the split-view UI, always pass selected_module as a plain
    # dict (not a detached SQLAlchemy object), because templates read
    # attributes like selected_module.name and selected_module.id.
    selected_module = None
    if edit_module_id is not None:
        for m in modules:
            try:
                if int(m.get("id") or 0) == int(edit_module_id):
                    selected_module = m
                    break
            except Exception:  # noqa: BLE001
                continue

    open_wizard = False
    try:
        open_wizard = bool(request.args.get("wizard"))
    except Exception:  # noqa: BLE001
        open_wizard = False
    try:
        raw_draft = session.get("storage_wizard_draft")
    except Exception:  # noqa: BLE001
        raw_draft = None
    if isinstance(raw_draft, dict):
        wizard_draft = raw_draft
        try:
            wizard_step = int(raw_draft.get("_step") or 1)
        except Exception:  # noqa: BLE001
            wizard_step = 1
    if request.method == "POST":
        try:
            if (request.form.get("action") or "").strip() == "module_draft_test" and edit_module is None:
                open_wizard = True
        except Exception:  # noqa: BLE001
            pass

    # Metrics for split-view UI
    selected_metrics = None
    streams_rows = []
    upload_rows = []
    logs_rows = []
    recent_error_rows = []
    if selected_module is not None:
        selected_module_id = edit_module_id
        if selected_module_id is None:
            try:
                selected_module_id = int(getattr(selected_module, "id", 0) or 0)
            except Exception:  # noqa: BLE001
                selected_module_id = None
        selected_module_name = edit_module_name
        if not selected_module_name:
            try:
                selected_module_name = str(getattr(selected_module, "name", "") or "")
            except Exception:  # noqa: BLE001
                selected_module_name = ""

        engine = get_record_engine()
        if engine is not None:
            CameraRecording.__table__.create(bind=engine, checkfirst=True)
            UploadQueueItem.__table__.create(bind=engine, checkfirst=True)
            StorageModuleEvent.__table__.create(bind=engine, checkfirst=True)
            StorageModuleWriteStat.__table__.create(bind=engine, checkfirst=True)
            with Session(engine) as session:
                last_row = (
                    session.query(CameraRecording)
                    .filter(CameraRecording.storage_provider == selected_module_name)
                    .order_by(CameraRecording.created_at.desc())
                    .first()
                )
                last_write_text = "n/a"
                last_write_stat = (
                    session.query(StorageModuleWriteStat)
                    .filter(StorageModuleWriteStat.module_name == selected_module_name)
                    .order_by(StorageModuleWriteStat.created_at.desc())
                    .first()
                )
                if last_write_stat is not None and getattr(last_write_stat, "created_at", None):
                    last_write_text = str(last_write_stat.created_at)
                elif last_row is not None and getattr(last_row, "created_at", None):
                    last_write_text = str(last_row.created_at)
                cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
                active_streams = (
                    session.query(func.count(func.distinct(CameraRecording.device_id)))
                    .filter(
                        CameraRecording.storage_provider == selected_module_name,
                        CameraRecording.created_at >= cutoff,
                    )
                    .scalar()
                    or 0
                )

                cutoff_15m = datetime.now(timezone.utc) - timedelta(minutes=15)
                last_ok_row = (
                    session.query(StorageModuleWriteStat)
                    .filter(
                        StorageModuleWriteStat.module_name == selected_module_name,
                        StorageModuleWriteStat.ok == 1,
                    )
                    .order_by(StorageModuleWriteStat.created_at.desc())
                    .first()
                )
                last_err_row = (
                    session.query(StorageModuleWriteStat)
                    .filter(
                        StorageModuleWriteStat.module_name == selected_module_name,
                        StorageModuleWriteStat.ok == 0,
                    )
                    .order_by(StorageModuleWriteStat.created_at.desc())
                    .first()
                )
                recent_ok = (
                    session.query(
                        func.count(StorageModuleWriteStat.id),
                        func.coalesce(func.sum(StorageModuleWriteStat.bytes_written), 0),
                    )
                    .filter(
                        StorageModuleWriteStat.module_name == selected_module_name,
                        StorageModuleWriteStat.ok == 1,
                        StorageModuleWriteStat.created_at >= cutoff_15m,
                    )
                    .first()
                )
                writes_15m = int(recent_ok[0] or 0) if recent_ok else 0
                bytes_15m = int(recent_ok[1] or 0) if recent_ok else 0

                recent_error_rows = (
                    session.query(StorageModuleEvent)
                    .filter(
                        (StorageModuleEvent.module_id == int(selected_module_id or 0))
                        | (StorageModuleEvent.module_name == selected_module_name)
                    )
                    .filter(StorageModuleEvent.level == "error")
                    .order_by(StorageModuleEvent.created_at.desc())
                    .limit(5)
                    .all()
                )

                selected_metrics = {
                    "last_write_text": last_write_text,
                    "active_streams": int(active_streams),
                    "last_ok_text": str(last_ok_row.created_at) if last_ok_row is not None and getattr(last_ok_row, "created_at", None) else "n/a",
                    "last_error_text": str(last_err_row.created_at) if last_err_row is not None and getattr(last_err_row, "created_at", None) else "n/a",
                    "last_error_message": str(last_err_row.error)[:200] if last_err_row is not None and getattr(last_err_row, "error", None) else "",
                    "writes_15m": writes_15m,
                    "bytes_15m": bytes_15m,
                }
                streams_rows = (
                    session.query(CameraRecording)
                    .filter(CameraRecording.storage_provider == selected_module_name)
                    .order_by(CameraRecording.created_at.desc())
                    .limit(25)
                    .all()
                )
                upload_rows = (
                    session.query(UploadQueueItem)
                    .filter(UploadQueueItem.provider_name == selected_module_name)
                    .order_by(UploadQueueItem.created_at.desc())
                    .limit(25)
                    .all()
                )
                logs_rows = (
                    session.query(StorageModuleEvent)
                    .filter(
                        (StorageModuleEvent.module_id == int(selected_module_id or 0))
                        | (StorageModuleEvent.module_name == selected_module_name)
                    )
                    .order_by(StorageModuleEvent.created_at.desc())
                    .limit(25)
                    .all()
                )

    module_definitions = []
    try:
        record_engine = get_record_engine()
    except Exception:  # noqa: BLE001
        record_engine = None

    if record_engine is not None:
        try:
            from .models import StorageProviderModule  # noqa: PLC0415
            from .modules.storage.registry import (  # noqa: PLC0415
                StorageModuleDefinition,
            )

            with Session(record_engine) as session_db:
                rows = (
                    session_db.query(StorageProviderModule)
                    .filter(StorageProviderModule.is_installed == 1)
                    .order_by(
                        StorageProviderModule.category,
                        StorageProviderModule.display_name,
                        StorageProviderModule.provider_type,
                    )
                    .all()
                )

            for r in rows:
                try:
                    def_obj = json.loads(r.definition_json) if getattr(r, "definition_json", None) else {}
                except Exception:  # noqa: BLE001
                    def_obj = {}
                fields = list(def_obj.get("fields") or []) if isinstance(def_obj, dict) else []
                module_definitions.append(
                    StorageModuleDefinition(
                        provider_type=str(r.provider_type),
                        display_name=str(r.display_name or r.provider_type),
                        category=str(r.category or "Custom"),
                        fields=fields,
                        template=str(r.template_path or ""),
                        module_dir="",
                    )
                )
        except Exception:  # noqa: BLE001
            module_definitions = []

    if not module_definitions:
        try:
            from .modules.storage.registry import (  # noqa: PLC0415
                discover_storage_module_definitions,
            )

            module_definitions = discover_storage_module_definitions()
        except Exception:  # noqa: BLE001
            module_definitions = []

    try:
        module_definitions = [
            d
            for d in (module_definitions or [])
            if str(getattr(d, "provider_type", "") or "").strip().lower() != "gdrive"
        ]
    except Exception:  # noqa: BLE001
        pass

    return render_template(
        "storage_modules.html",
        providers=providers,
        modules=modules,
        module_test_result=module_test_result,
        module_test_ready=module_test_ready,
        open_wizard=open_wizard,
        wizard_draft=wizard_draft,
        wizard_step=wizard_step,
        selected_module=selected_module,
        selected_metrics=selected_metrics,
        streams_rows=streams_rows,
        upload_rows=upload_rows,
        logs_rows=logs_rows,
        recent_error_rows=recent_error_rows,
        s3=s3_info,
        gcs=gcs_info,
        azure=azure_info,
        dropbox=dropbox_info,
        webdav=webdav_info,
        form=form,
        errors=errors,
        saved=saved,
        edit_module=edit_module,
        edit_module_config=edit_module_config,
        module_definitions=module_definitions,
    )


@bp.route("/recording-settings", methods=["GET", "POST"])
def recording_settings():
    user = get_current_user()
    if user is None:
        next_url = request.path or url_for("main.index")
        return redirect(url_for("main.login", next=next_url))
    if not user_has_role(user, "System Administrator"):
        abort(403)

    errors: list[str] = []
    saved = False
    record_engine = get_record_engine()
    if record_engine is None:
        errors.append("Record database is not configured.")

    tz_name = getattr(user, "timezone", None) or "UTC"
    try:
        tz = ZoneInfo(str(tz_name))
    except Exception:  # noqa: BLE001
        tz = timezone.utc
        tz_name = "UTC"
    now_local = datetime.now(timezone.utc).astimezone(tz)

    if request.method == "POST" and record_engine is not None:
        if not validate_global_csrf_token(request.form.get("csrf_token")):
            errors.append("Invalid or missing CSRF token.")
        else:
            action = (request.form.get("action") or "").strip() or "update_schedule"

            if action == "test_module":
                module_id_raw = request.form.get("module_id") or ""
                try:
                    module_id = int(module_id_raw)
                except ValueError:
                    module_id = None

                if module_id is not None:
                    with Session(record_engine) as session_db:
                        StorageModule.__table__.create(
                            bind=record_engine,
                            checkfirst=True,
                        )
                        module = session_db.get(StorageModule, module_id)
                    if module is None:
                        test_result = {
                            "ok": False,
                            "module_name": f"#{module_id_raw}",
                            "message": "Storage module not found.",
                        }
                    else:
                        router = get_storage_router(current_app)
                        instance_key = str(module.id)
                        try:
                            status = router.health_check(instance_key)
                        except StorageError as exc:  # pragma: no cover - error path
                            test_result = {
                                "ok": False,
                                "module_name": module.name,
                                "message": str(exc)[:300],
                            }
                        except Exception as exc:  # noqa: BLE001
                            test_result = {
                                "ok": False,
                                "module_name": module.name,
                                "message": str(exc)[:300],
                            }
                        else:
                            status_text = str(status.get("status") or "ok")
                            message = status.get("message") or f"Health check status: {status_text}"
                            test_result = {
                                "ok": status_text == "ok",
                                "module_name": module.name,
                                "message": str(message)[:300],
                            }

            elif action == "update_storage":
                device_id_raw = request.form.get("device_id") or ""
                try:
                    device_id = int(device_id_raw)
                except ValueError:
                    device_id = None

                targets = request.form.getlist("targets")
                clean_targets = [name.strip() for name in targets if name.strip()]
                targets_str = ",".join(sorted(set(clean_targets))) if clean_targets else None

                if device_id is not None:
                    with Session(record_engine) as session_db:
                        CameraStoragePolicy.__table__.create(
                            bind=record_engine,
                            checkfirst=True,
                        )
                        pol = (
                            session_db.query(CameraStoragePolicy)
                            .filter(CameraStoragePolicy.device_id == device_id)
                            .first()
                        )
                        if pol is None:
                            pol = CameraStoragePolicy(device_id=device_id)

                        pol.storage_targets = targets_str
                        session_db.add(pol)
                        session_db.commit()
                        saved = True

            else:
                device_id_raw = request.form.get("device_id") or ""
                mode = (request.form.get("mode") or "").strip().lower()
                start_time = (request.form.get("start_time") or "").strip()
                end_time = (request.form.get("end_time") or "").strip()

                try:
                    device_id = int(device_id_raw)
                except ValueError:
                    device_id = None

                valid_modes = {
                    "always",
                    "scheduled",
                    "motion_only",
                    "scheduled_motion",
                }
                if mode not in valid_modes:
                    mode = "always"

                if device_id is not None:
                    with Session(record_engine) as session_db:
                        CameraRecordingSchedule.__table__.create(
                            bind=record_engine,
                            checkfirst=True,
                        )
                        sched = (
                            session_db.query(CameraRecordingSchedule)
                            .filter(CameraRecordingSchedule.device_id == device_id)
                            .first()
                        )
                        if sched is None:
                            sched = CameraRecordingSchedule(device_id=device_id)

                        sched.mode = mode
                        sched.days_of_week = "*"
                        # Persist the schedule timezone so evaluation in
                        # _should_record_now can use it directly. We use the
                        # user's effective timezone from the current view.
                        sched.timezone = tz_name
                        if mode == "always":
                            sched.start_time = None
                            sched.end_time = None
                        else:
                            sched.start_time = start_time or None
                            sched.end_time = end_time or None
                        sched.updated_at = datetime.now(timezone.utc)

                        session_db.add(sched)
                        session_db.commit()
                        saved = True

    modules: list[dict] = []
    if record_engine is not None:
        with Session(record_engine) as session_db:
            StorageModule.__table__.create(bind=record_engine, checkfirst=True)
            rows = (
                session_db.query(StorageModule)
                .order_by(getattr(StorageModule, "priority", StorageModule.id), StorageModule.id)
                .all()
            )
        for m in rows:
            try:
                if (str(getattr(m, "provider_type", "") or "").strip().lower()) == "gdrive":
                    continue
            except Exception:  # noqa: BLE001
                pass
            modules.append(
                {
                    "id": m.id,
                    "name": m.name,
                    "label": m.label or "",
                    "provider_type": m.provider_type,
                    "is_enabled": bool(getattr(m, "is_enabled", 0)),
                    "priority": int(getattr(m, "priority", 100) or 100),
                }
            )

    camera_rows: list[dict] = []
    if record_engine is not None:
        with Session(record_engine) as session_db:
            CameraDevice.__table__.create(bind=record_engine, checkfirst=True)
            CameraStoragePolicy.__table__.create(bind=record_engine, checkfirst=True)
            CameraRecordingSchedule.__table__.create(
                bind=record_engine,
                checkfirst=True,
            )
            devices = (
                session_db.query(CameraDevice)
                .order_by(CameraDevice.name)
                .all()
            )
            policies = session_db.query(CameraStoragePolicy).all()
            schedules = session_db.query(CameraRecordingSchedule).all()

        policies_index = {int(p.device_id): p for p in policies}
        schedules_index = {int(s.device_id): s for s in schedules}

        for dev in devices:
            pol = policies_index.get(int(dev.id))
            sched = schedules_index.get(int(dev.id))
            storage_targets = getattr(pol, "storage_targets", None) or ""
            selected_targets = {
                name.strip()
                for name in storage_targets.split(",")
                if name.strip()
            }
            retention_days = getattr(pol, "retention_days", None)
            mode = getattr(sched, "mode", None) or "always"
            start_time = getattr(sched, "start_time", None) or ""
            end_time = getattr(sched, "end_time", None) or ""

            if mode == "always":
                schedule_summary = "24 hours (always recording)"
            elif start_time and end_time:
                schedule_summary = f"Daily {start_time}–{end_time}"
            elif start_time or end_time:
                schedule_summary = f"From {start_time or '??'} to {end_time or '??'}"
            else:
                schedule_summary = "No window configured"

            camera_rows.append(
                {
                    "id": dev.id,
                    "name": dev.name,
                    "storage_targets": storage_targets,
                    "selected_targets": selected_targets,
                    "retention_days": retention_days,
                    "mode": mode,
                    "start_time": start_time,
                    "end_time": end_time,
                    "schedule_summary": schedule_summary,
                }
            )

    return render_template(
        "recording_settings.html",
        errors=errors,
        saved=saved,
        modules=modules,
        cameras=camera_rows,
        test_result=test_result,
        current_time_local=now_local,
        current_timezone=tz_name,
    )


@bp.route("/dlna", methods=["GET", "POST"])
def dlna_settings():
	abort(404)
	user = get_current_user()
	if user is None:
		next_url = request.path or url_for("main.index")
		return redirect(url_for("main.login", next=next_url))
	if not user_has_role(user, "System Administrator"):
		abort(403)

	errors: list[str] = []
	saved = False
	record_engine = get_record_engine()
	if record_engine is None:
		errors.append("Record database is not configured.")

	if request.method == "POST":
		if not validate_global_csrf_token(request.form.get("csrf_token")):
			errors.append("Invalid or missing CSRF token.")
		action = (request.form.get("action") or "").strip() or "save"
		interface_name_form = (request.form.get("interface_name") or "").strip()
		if not errors and record_engine is not None:
			with Session(record_engine) as session_db:
				DlnaSettings.__table__.create(bind=record_engine, checkfirst=True)
				settings_row = (
					session_db.query(DlnaSettings)
					.order_by(DlnaSettings.id)
					.first()
				)
				if settings_row is None:
					settings_row = DlnaSettings(enabled=0)
					session_db.add(settings_row)
					session_db.flush()
				if action == "save":
					settings_row.interface_name = interface_name_form or None
				elif action == "start":
					settings_row.enabled = 1
				elif action == "stop":
					settings_row.enabled = 0
				elif action == "restart":
					settings_row.enabled = 0
					session_db.add(settings_row)
					session_db.commit()
					settings_row.enabled = 1
				settings_row.updated_at = datetime.now(timezone.utc)
				session_db.add(settings_row)
				session_db.commit()
				saved = True

	settings = {
		"enabled": 0,
		"interface_name": "",
		"bind_address": "",
		"network_cidr": "",
		"last_started_at": None,
		"last_error": "",
	}
	if record_engine is not None:
		with Session(record_engine) as session_db:
			DlnaSettings.__table__.create(bind=record_engine, checkfirst=True)
			row = (
				session_db.query(DlnaSettings)
				.order_by(DlnaSettings.id)
				.first()
			)
			if row is not None:
				settings = {
					"enabled": int(getattr(row, "enabled", 0) or 0),
					"interface_name": row.interface_name or "",
					"bind_address": row.bind_address or "",
					"network_cidr": row.network_cidr or "",
					"last_started_at": row.last_started_at,
					"last_error": row.last_error or "",
				}

	interfaces = get_ipv4_interfaces()
	selected_name = settings["interface_name"] or ""
	if not selected_name and interfaces:
		selected_name = interfaces[0]["name"]
	current_interface = None
	for item in interfaces:
		if item.get("name") == selected_name:
			current_interface = item
			break

	form = {
		"interface_name": selected_name,
	}

	dlna_enabled_env = str(current_app.config.get("DLNA_ENABLED", "0") or "0").strip().lower() not in {
		"0",
		"false",
		"no",
		"",
	}

	return render_template(
		"dlna.html",
		form=form,
		interfaces=interfaces,
		current_interface=current_interface,
		settings=settings,
		errors=errors,
		saved=saved,
		dlna_enabled_env=dlna_enabled_env,
	)


@bp.get("/recordings")
def recordings():
    user = get_current_user()
    if user is None:
        next_url = request.path or url_for("main.index")
        return redirect(url_for("main.login", next=next_url))

    record_engine = get_record_engine()
    if record_engine is None:
        return render_template(
            "recordings.html",
            recordings=[],
            device=None,
            devices_index={},
        )

    device_filter = (request.args.get("device_id") or "").strip()
    device = None

    with Session(record_engine) as session_db:
        CameraRecording.__table__.create(bind=record_engine, checkfirst=True)
        query = session_db.query(CameraRecording)
        if device_filter:
            try:
                device_id = int(device_filter)
            except ValueError:
                device_id = None
            if device_id is not None:
                query = query.filter(CameraRecording.device_id == device_id)
                device = session_db.get(CameraDevice, device_id)

        recordings_list = (
            query.order_by(CameraRecording.created_at.desc())
            .limit(100)
            .all()
        )

        device_ids = {r.device_id for r in recordings_list}
        devices_index: dict[int, CameraDevice] = {}
        if device_ids:
            devices = (
                session_db.query(CameraDevice)
                .filter(CameraDevice.id.in_(device_ids))
                .all()
            )
            devices_index = {d.id: d for d in devices}

    return render_template(
        "recordings.html",
        recordings=recordings_list,
        device=device,
        devices_index=devices_index,
    )


@bp.get("/recordings/<int:recording_id>")
def recording_detail(recording_id: int):
    """Playback view for a single recording, suitable for face overlays."""

    user = get_current_user()
    if user is None:
        next_url = request.path or url_for("main.index")
        return redirect(url_for("main.login", next=next_url))

    record_engine = get_record_engine()
    if record_engine is None:
        return render_template(
            "recording_detail.html",
            recording=None,
            device=None,
        ), 500

    with Session(record_engine) as session_db:
        CameraRecording.__table__.create(bind=record_engine, checkfirst=True)
        recording = session_db.get(CameraRecording, recording_id)
        device = None
        if recording is not None and recording.device_id is not None:
            device = session_db.get(CameraDevice, recording.device_id)

    if recording is None:
        return render_template(
            "recording_detail.html",
            recording=None,
            device=None,
        ), 404

    return render_template(
        "recording_detail.html",
        recording=recording,
        device=device,
    )


@bp.get("/recordings/<int:recording_id>/download")
def download_camera_recording(recording_id: int):
    user = get_current_user()
    if user is None:
        next_url = request.path or url_for("main.index")
        return redirect(url_for("main.login", next=next_url))

    record_engine = get_record_engine()
    if record_engine is None:
        abort(404)

    with Session(record_engine) as session_db:
        rec = session_db.get(CameraRecording, recording_id)
        if rec is None:
            abort(404)

        provider_name = rec.storage_provider
        key = rec.storage_key or ""

        if provider_name == "local_fs":
            path = Path(key)
            if not path.exists():
                abort(404)
            return send_file(
                str(path),
                as_attachment=True,
                download_name=path.name,
                mimetype="video/mp4",
            )

        if provider_name == "db":
            db_id = None
            if key.startswith("recording_data:"):
                try:
                    db_id = int(key.split(":", 1)[1])
                except ValueError:
                    db_id = None
            if db_id is None:
                abort(404)
            data_row = session_db.get(RecordingData, db_id)
            if data_row is None:
                abort(404)
            response = Response(data_row.data, mimetype="video/mp4")
            response.headers[
                "Content-Disposition"
            ] = f"attachment; filename=recording-{recording_id}.mp4"
            return response

        # For other providers (e.g. S3), attempt to get a signed URL and redirect.
        providers = build_storage_providers(current_app)
        provider_obj = next(
            (p for p in providers if getattr(p, "name", None) == provider_name),
            None,
        )
        if provider_obj is not None:
            url = provider_obj.get_url(key)
            if url:
                return redirect(url)

    abort(404)
