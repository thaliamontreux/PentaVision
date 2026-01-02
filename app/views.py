from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from pathlib import Path
import base64
import io
import json
import platform
import pickle
import subprocess
import tempfile
import time
import re

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

from .auth import _authenticate_primary_factor, _verify_totp, _verify_totp_with_secret
from .db import get_face_engine, get_record_engine, get_user_engine
from .db import get_property_engine
from .logging_utils import log_event, pv_log
from .models import (
    AuditEvent,
    CameraDevice,
    CameraGroupLink,
    CameraPropertyLink,
    CameraRecording,
    CameraRecordingSchedule,
    CameraStorageScheduleEntry,
    CameraStoragePolicy,
    CameraUrlPattern,
    FaceEmbedding,
    FacePrivacySetting,
    Property,
    PropertyGroupMember,
    PropertyUser,
    RecordingData,
    SiteTheme,
    StorageModule,
    StorageModuleWriteStat,
    User,
    UserNotificationSettings,
    WebAuthnCredential,
)
from .security import (
    get_current_user,
    get_current_property_user,
    login_user,
    login_property_user,
    logout_property_user,
    logout_user,
    require_login,
    user_has_property_access,
    user_has_role,
    validate_global_csrf_token,
)
from .stream_service import get_stream_manager
from .preview_history import find_frame_by_age
from .storage_providers import (
    DatabaseStorageProvider,
    ExternalSQLDatabaseStorageProvider,
    LocalFilesystemStorageProvider,
    build_storage_providers,
)
from .storage_csal import get_storage_router, StorageError

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError


bp = Blueprint("main", __name__)


def _get_face_recognition_lib():
    # face_recognition can call sys.exit() if face_recognition_models is missing.
    # To avoid killing gunicorn workers during app import, we only import it
    # inside request handlers.
    try:
        import face_recognition  # type: ignore[import]

        return face_recognition, None
    except (SystemExit, ImportError, Exception) as exc:  # noqa: BLE001
        return None, exc


FACE_MATCH_THRESHOLD = 0.6


def _hex_color(value: str | None, fallback: str) -> str:
    raw = str(value or "").strip()
    if re.fullmatch(r"#[0-9a-fA-F]{6}", raw) is None:
        return fallback
    return raw


def _theme_css_from_json(scope: str, theme_json: str) -> str:
    try:
        data = json.loads(theme_json or "{}")
    except Exception:  # noqa: BLE001
        data = {}
    colors = data.get("colors") if isinstance(data, dict) else None
    if not isinstance(colors, dict):
        colors = {}

    bg = _hex_color(colors.get("bg"), "#0b1120")
    text = _hex_color(colors.get("text"), "#e5e7eb")
    surface = _hex_color(colors.get("surface"), "#0f172a")
    card = _hex_color(colors.get("card"), "#0f172a")
    border = _hex_color(colors.get("border"), "#1f2937")
    muted = _hex_color(colors.get("muted_text"), "#9ca3af")
    primary_bg = _hex_color(colors.get("primary_bg"), "#2563eb")
    primary_text = _hex_color(colors.get("primary_text"), "#0b1120")
    secondary_bg = _hex_color(colors.get("secondary_bg"), "#111827")
    secondary_text = _hex_color(colors.get("secondary_text"), "#e5e7eb")
    link = _hex_color(colors.get("link"), "#93c5fd")

    admin_tile_link = _hex_color(colors.get("admin_tile_link"), "#22D3EE")
    admin_tile_text = _hex_color(colors.get("admin_tile_text"), "#E5E7EB")

    prefix = ".pv-is-admin " if scope == "admin" else ""
    admin_vars = ""
    if scope == "admin":
        admin_vars = f";--pv-admin-tile-link:{admin_tile_link};--pv-admin-tile-text:{admin_tile_text}"
    return (
        f"{prefix}body{{background:{bg};color:{text}{admin_vars};}}\n"
        f"{prefix}.pv-section{{background:{surface};border-color:{border};}}\n"
        f"{prefix}.pv-card{{background:{card};border-color:{border};}}\n"
        f"{prefix}.pv-card-subtitle{{color:{muted};}}\n"
        f"{prefix}.pv-table th{{color:{muted};}}\n"
        f"{prefix}.pv-table th,{prefix}.pv-table td{{border-bottom-color:{border};}}\n"
        f"{prefix}.pv-table tr:nth-child(even){{background-color:{secondary_bg};}}\n"
        f"{prefix}.pv-button-primary{{background:{primary_bg};color:{primary_text};}}\n"
        f"{prefix}.pv-button-secondary{{background:{secondary_bg};color:{secondary_text};border-color:{border};}}\n"
        f"{prefix}.pv-link-muted{{color:{link};}}\n"
    )


@bp.get("/theme-css/<scope>/<slug>.css")
def theme_css(scope: str, slug: str):
    scope_norm = str(scope or "").strip().lower()
    if scope_norm not in ("main", "admin"):
        abort(404)
    slug_norm = str(slug or "").strip().lower()
    if re.fullmatch(r"[a-z0-9_\-]{1,64}", slug_norm) is None:
        abort(404)

    engine = get_user_engine()
    if engine is not None:
        with Session(engine) as db:
            try:
                SiteTheme.__table__.create(bind=engine, checkfirst=True)
            except Exception:  # noqa: BLE001
                pass
            row = (
                db.query(SiteTheme)
                .filter(SiteTheme.scope == scope_norm, SiteTheme.slug == slug_norm)
                .first()
            )
            if row is not None and getattr(row, "theme_json", None):
                css = _theme_css_from_json(scope_norm, str(row.theme_json or ""))
                resp = Response(css, mimetype="text/css")
                resp.headers["Cache-Control"] = "no-store"
                return resp

    base_dir = Path(__file__).resolve().parent / "static" / "css" / "themes"
    theme_path = base_dir / scope_norm / f"{slug_norm}.css"
    if theme_path.exists():
        resp = send_file(str(theme_path), mimetype="text/css", conditional=True)
        resp.headers["Cache-Control"] = "no-store"
        return resp
    abort(404)


_pv_status_cache: dict[str, object] = {
    "ts": 0.0,
    "data": None,
}


def _get_face_match_threshold() -> float:
    value = current_app.config.get("FACE_MATCH_THRESHOLD")
    if value is None or value == "":
        return FACE_MATCH_THRESHOLD
    try:
        return float(value)
    except (TypeError, ValueError):
        return FACE_MATCH_THRESHOLD


@bp.get("/api/status")
def api_status() -> Response:
    user = get_current_user()
    if user is None:
        return jsonify({"overall_status": "signed_out"})

    now = time.time()
    try:
        cached_ts = float(_pv_status_cache.get("ts") or 0.0)
    except Exception:  # noqa: BLE001
        cached_ts = 0.0

    cached_data = _pv_status_cache.get("data")
    if cached_data is not None and (now - cached_ts) < 5.0:
        return jsonify(cached_data)

    db_status: dict[str, str] = {}
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

    payload = {
        "overall_status": overall,
        "db_status": db_status,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    _pv_status_cache["ts"] = now
    _pv_status_cache["data"] = payload
    return jsonify(payload)


def _load_camera_property_map(record_engine) -> dict[int, int]:
    if record_engine is None:
        return {}
    CameraPropertyLink.__table__.create(bind=record_engine, checkfirst=True)
    with Session(record_engine) as session_db:
        rows = session_db.query(
            CameraPropertyLink.device_id, CameraPropertyLink.property_id
        ).all()
    return {int(device_id): int(property_id) for device_id, property_id in rows}


def _load_camera_group_map(record_engine) -> dict[int, tuple[int, int]]:
    if record_engine is None:
        return {}
    CameraGroupLink.__table__.create(bind=record_engine, checkfirst=True)
    with Session(record_engine) as session_db:
        rows = session_db.query(
            CameraGroupLink.device_id,
            CameraGroupLink.property_id,
            CameraGroupLink.property_group_id,
        ).all()
    return {
        int(device_id): (int(property_id), int(group_id))
        for device_id, property_id, group_id in rows
    }


def _user_can_access_camera(
    user: User | None,
    device_id: int,
    record_engine=None,
    property_map: dict[int, int] | None = None,
    group_map: dict[int, tuple[int, int]] | None = None,
    prop_user_group_ids: set[int] | None = None,
) -> bool:
    if user is not None and user_has_role(user, "System Administrator"):
        return True

    prop_user = get_current_property_user()
    if user is None and prop_user is None:
        return False

    # Property-local users: group-based camera visibility.
    if prop_user is not None and user is None:
        if record_engine is None:
            record_engine = get_record_engine()
        if group_map is None:
            group_map = _load_camera_group_map(record_engine)
        link = group_map.get(device_id)
        if not link:
            return False
        cam_property_id, cam_group_id = link
        if int(getattr(prop_user, "property_id", 0) or 0) != int(cam_property_id):
            return False
        if prop_user_group_ids is not None:
            return int(cam_group_id) in prop_user_group_ids
        engine = get_user_engine()
        if engine is None:
            return False
        with Session(engine) as db:
            exists = (
                db.query(PropertyGroupMember.id)
                .filter(
                    PropertyGroupMember.group_id == cam_group_id,
                    PropertyGroupMember.property_user_id == int(prop_user.id),
                )
                .first()
            )
            return exists is not None

    if property_map is None:
        if record_engine is None:
            record_engine = get_record_engine()
        property_map = _load_camera_property_map(record_engine)

    prop_id = property_map.get(device_id)
    if not prop_id:
        return False
    return user_has_property_access(user, prop_id)


@bp.route("/property-login", methods=["GET", "POST"])
def property_login():
    errors: list[str] = []
    username = ""
    property_id_raw = ""
    next_url = (
        request.args.get("next")
        or request.form.get("next")
        or url_for("main.index")
    )
    if not next_url.startswith("/"):
        next_url = url_for("main.index")

    engine = get_user_engine()
    properties: list[Property] = []
    if engine is not None:
        with Session(engine) as db:
            try:
                Property.__table__.create(bind=db.get_bind(), checkfirst=True)
                properties = db.query(Property).order_by(Property.name).all()
            except Exception:
                properties = []

    if request.method == "POST":
        if not validate_global_csrf_token(request.form.get("csrf_token")):
            errors.append("Invalid or missing CSRF token.")
        username = (request.form.get("username") or "").strip().lower()
        property_id_raw = (request.form.get("property_id") or "").strip()
        password = request.form.get("password") or ""
        pin = (request.form.get("pin") or "").strip()

        try:
            property_id = int(property_id_raw)
        except (TypeError, ValueError):
            property_id = 0
        if not username:
            errors.append("Username is required.")
        if property_id <= 0:
            errors.append("Property is required.")

        use_pin = bool(pin)
        if use_pin:
            if re.fullmatch(r"\d{8}", pin) is None:
                errors.append("PIN must be exactly 8 digits.")
        else:
            if not password:
                errors.append("Password is required.")

        if not errors:
            if engine is None:
                errors.append("User database is not configured.")
            else:
                with Session(engine) as db:
                    prop = db.get(Property, property_id)
                    if prop is None or not getattr(prop, "uid", None):
                        errors.append("Login failed.")
                        user_obj = None
                        prop_uid = None
                    else:
                        prop_uid = str(prop.uid)

                if not errors:
                    tenant_engine = get_property_engine(str(prop_uid))
                    if tenant_engine is None:
                        errors.append("Login failed.")
                        user_obj = None
                    else:
                        with Session(tenant_engine) as db:
                            PropertyUser.__table__.create(
                                bind=db.get_bind(),
                                checkfirst=True,
                            )
                            user_obj = (
                                db.query(PropertyUser)
                                .filter(
                                    PropertyUser.property_id == property_id,
                                    PropertyUser.username == username,
                                    PropertyUser.is_active == 1,
                                )
                                .first()
                            )
                    if user_obj is None:
                        errors.append("Login failed.")
                        log_event(
                            "PROPERTY_LOGIN_FAILED",
                            details=(
                                f"property_id={property_id}, username={username}, "
                                f"method={'pin' if use_pin else 'password'}"
                            ),
                        )
                    else:
                        ph = PasswordHasher()
                        now_dt = datetime.now(timezone.utc)

                        if use_pin:
                            locked_until = getattr(user_obj, "pin_locked_until", None)
                            if locked_until is not None and locked_until > now_dt:
                                errors.append("Login failed.")
                                log_event(
                                    "PROPERTY_PIN_LOCKED",
                                    details=(
                                        f"property_id={property_id}, username={username}"
                                    ),
                                )
                            else:
                                pin_hash = getattr(user_obj, "pin_hash", None)
                                if not pin_hash:
                                    errors.append("Login failed.")
                                else:
                                    try:
                                        ph.verify(pin_hash, pin)
                                    except VerifyMismatchError:
                                        errors.append("Login failed.")
                                        try:
                                            user_obj.failed_pin_attempts = int(
                                                getattr(
                                                    user_obj,
                                                    "failed_pin_attempts",
                                                    0,
                                                )
                                                or 0
                                            ) + 1
                                            if int(user_obj.failed_pin_attempts) >= 5:
                                                user_obj.pin_locked_until = (
                                                    now_dt
                                                    + timedelta(minutes=10)
                                                )
                                                user_obj.failed_pin_attempts = 0
                                            db.add(user_obj)
                                            db.commit()
                                        except Exception:  # noqa: BLE001
                                            pass
                                        log_event(
                                            "PROPERTY_LOGIN_FAILED",
                                            details=(
                                                f"property_id={property_id}, username={username}, method=pin"
                                            ),
                                        )
                                    except Exception:  # noqa: BLE001
                                        errors.append("Login failed.")
                                    else:
                                        user_obj.failed_pin_attempts = 0
                                        user_obj.pin_locked_until = None
                                        user_obj.last_pin_use_at = now_dt
                                        user_obj.last_login_at = now_dt
                                        db.add(user_obj)
                                        db.commit()
                                        log_event(
                                            "PROPERTY_LOGIN_SUCCESS",
                                            details=(
                                                f"property_id={property_id}, username={username}, method=pin"
                                            ),
                                        )
                                        db.expunge(user_obj)
                                        login_property_user(
                                            user_obj,
                                            property_uid=str(prop_uid),
                                        )
                                        return redirect(next_url)
                        else:
                            try:
                                ph.verify(user_obj.password_hash, password)
                            except VerifyMismatchError:
                                errors.append("Login failed.")
                                log_event(
                                    "PROPERTY_LOGIN_FAILED",
                                    details=(
                                        f"property_id={property_id}, username={username}, method=password"
                                    ),
                                )
                            except Exception:  # noqa: BLE001
                                errors.append("Login failed.")
                            else:
                                try:
                                    user_obj.last_login_at = now_dt
                                    db.add(user_obj)
                                    db.commit()
                                except Exception:  # noqa: BLE001
                                    pass
                                log_event(
                                    "PROPERTY_LOGIN_SUCCESS",
                                    details=(
                                        f"property_id={property_id}, username={username}, method=password"
                                    ),
                                )
                                db.expunge(user_obj)
                                login_property_user(
                                    user_obj,
                                    property_uid=str(prop_uid),
                                )
                                return redirect(next_url)

    return render_template(
        "property_login.html",
        errors=errors,
        username=username,
        properties=properties,
        property_id=property_id_raw,
        next=next_url,
    )


@bp.get("/property-logout")
def property_logout():
    logout_property_user()
    return redirect(url_for("main.login"))


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


@bp.get("/live-feeds")
@require_login
def live_feeds():
    errors: list[str] = []
    devices: list[CameraDevice] = []
    patterns_index: dict[int, CameraUrlPattern] = {}

    user = get_current_user()
    prop_user = get_current_property_user()

    record_engine = get_record_engine()
    if record_engine is None:
        errors.append("Record database is not configured.")
        return render_template(
            "live_feeds.html",
            errors=errors,
            devices=devices,
            patterns=patterns_index,
        )

    property_map = _load_camera_property_map(record_engine)
    group_map = _load_camera_group_map(record_engine)

    prop_user_group_ids: set[int] | None = None
    if prop_user is not None and user is None:
        engine = get_user_engine()
        if engine is not None:
            with Session(engine) as db:
                rows = (
                    db.query(PropertyGroupMember.group_id)
                    .filter(
                        PropertyGroupMember.property_user_id
                        == int(getattr(prop_user, "id", 0) or 0)
                    )
                    .all()
                )
            prop_user_group_ids = {int(gid) for (gid,) in rows}

    with Session(record_engine) as session_db:
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
            patterns_index = {int(p.id): p for p in patterns}

    visible_devices: list[CameraDevice] = []
    for device in devices:
        try:
            device_id = int(getattr(device, "id", 0) or 0)
        except Exception:  # noqa: BLE001
            continue
        if device_id <= 0:
            continue
        if not _user_can_access_camera(
            user,
            device_id,
            record_engine=record_engine,
            property_map=property_map,
            group_map=group_map,
            prop_user_group_ids=prop_user_group_ids,
        ):
            continue
        visible_devices.append(device)

    return render_template(
        "live_feeds.html",
        errors=errors,
        devices=visible_devices,
        patterns=patterns_index,
    )


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
    recording_status: dict[int, str] = {}
    record_engine = get_record_engine()
    camera_property_map: dict[int, int] = {}
    if record_engine is not None:
        with Session(record_engine) as session_db:
            CameraPropertyLink.__table__.create(bind=record_engine, checkfirst=True)
            CameraGroupLink.__table__.create(bind=record_engine, checkfirst=True)
            CameraRecording.__table__.create(bind=record_engine, checkfirst=True)
            StorageModuleWriteStat.__table__.create(bind=record_engine, checkfirst=True)
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

            last_recording_map: dict[int, datetime] = {}
            for device_id, last_time in rows:
                if last_time is None:
                    continue
                try:
                    last_recording_map[int(device_id)] = last_time
                except Exception:  # noqa: BLE001
                    continue

            ok_rows = (
                session_db.query(
                    StorageModuleWriteStat.device_id,
                    func.max(StorageModuleWriteStat.created_at),
                )
                .filter(StorageModuleWriteStat.ok != 0)
                .group_by(StorageModuleWriteStat.device_id)
                .all()
            )
            err_rows = (
                session_db.query(
                    StorageModuleWriteStat.device_id,
                    func.max(StorageModuleWriteStat.created_at),
                )
                .filter(StorageModuleWriteStat.ok == 0)
                .group_by(StorageModuleWriteStat.device_id)
                .all()
            )
            last_ok_map: dict[int, datetime] = {}
            last_err_map: dict[int, datetime] = {}
            for device_id, ts in ok_rows:
                if ts is None:
                    continue
                try:
                    last_ok_map[int(device_id)] = ts
                except Exception:  # noqa: BLE001
                    continue
            for device_id, ts in err_rows:
                if ts is None:
                    continue
                try:
                    last_err_map[int(device_id)] = ts
                except Exception:  # noqa: BLE001
                    continue

            links = session_db.query(CameraPropertyLink).all()
            camera_property_map = {
                int(link.device_id): int(link.property_id) for link in links
            }

        def _as_utc(dt: datetime | None) -> datetime | None:
            if dt is None:
                return None
            try:
                if getattr(dt, "tzinfo", None) is None:
                    return dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            except Exception:  # noqa: BLE001
                return None

        for device_id, last_time in rows:
            if last_time is None:
                continue
            camera_last_seen[device_id] = last_time

        now_utc = datetime.now(timezone.utc)
        try:
            segment_seconds = int(current_app.config.get("RECORD_SEGMENT_SECONDS", 60) or 60)
        except (TypeError, ValueError):
            segment_seconds = 60
        if segment_seconds <= 0:
            segment_seconds = 60
        active_window = timedelta(seconds=int(segment_seconds) * 2 + 30)
        error_window = timedelta(minutes=10)

        for device in devices:
            try:
                device_id = int(getattr(device, "id", 0) or 0)
            except Exception:  # noqa: BLE001
                continue
            if not bool(getattr(device, "is_active", 0)):
                recording_status[device_id] = "not_active"
                continue

            last_ok = _as_utc(last_ok_map.get(device_id))
            last_err = _as_utc(last_err_map.get(device_id))
            if (
                last_err is not None
                and (last_ok is None or last_err > last_ok)
                and (now_utc - last_err) <= error_window
            ):
                recording_status[device_id] = "error"
                continue

            last_rec = _as_utc(last_recording_map.get(device_id))
            if last_rec is not None and (now_utc - last_rec) <= active_window:
                recording_status[device_id] = "active"
            else:
                recording_status[device_id] = "not_active"

    def _ping_host(host: str) -> bool:
        host = str(host or "").strip()
        if not host:
            return False
        sysname = (platform.system() or "").strip().lower()
        if "windows" in sysname:
            cmd = ["ping", "-n", "1", "-w", "750", host]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", host]
        try:
            res = subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2,
                check=False,
            )
            return res.returncode == 0
        except Exception:  # noqa: BLE001
            return False

    # Dashboard camera status should be ONLINE/OFFLINE based on reachability.
    # Use a short in-memory cache so we don't ping every camera on every request.
    try:
        cache = current_app.extensions.setdefault("pv_ping_cache", {})
    except Exception:  # noqa: BLE001
        cache = {}
    now_ts = time.time()
    ttl_seconds = 10.0
    for device in devices:
        try:
            device_id = int(getattr(device, "id", 0) or 0)
        except Exception:  # noqa: BLE001
            continue

        ip = str(getattr(device, "ip_address", "") or "").strip()
        is_active = bool(getattr(device, "is_active", 0))
        if not ip:
            camera_status[device_id] = "unknown"
            continue
        if not is_active:
            camera_status[device_id] = "offline"
            continue

        key = f"{device_id}:{ip}"
        cached = cache.get(key)
        if isinstance(cached, dict):
            ts = cached.get("ts")
            ok = cached.get("ok")
            try:
                ts_val = float(ts) if ts is not None else None
            except (TypeError, ValueError):
                ts_val = None
            if ts_val is not None and (now_ts - ts_val) <= ttl_seconds:
                camera_status[device_id] = "online" if bool(ok) else "offline"
                continue

        ok = _ping_host(ip)
        try:
            cache[key] = {"ts": now_ts, "ok": bool(ok)}
        except Exception:  # noqa: BLE001
            pass
        camera_status[device_id] = "online" if ok else "offline"

    # Apply property-level RBAC: unauthenticated users see no cameras; non-admin
    # users only see cameras for properties they are associated with.
    if user is None:
        devices = []
    elif not (
        user_has_role(user, "System Administrator")
        or user_has_role(user, "Property Administrator")
    ):
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
        recording_status=recording_status,
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
                try:
                    pv_log(
                        "security",
                        "warn",
                        "auth_html_login_failure",
                        component="views",
                        email=str(email or "")[:256],
                        status=int(status or 0),
                    )
                except Exception:
                    pass
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
                    try:
                        pv_log(
                            "security",
                            "info",
                            "auth_html_login_success",
                            component="views",
                            user_id=int(user.id),
                            email=str(getattr(user, "email", "") or "")[:256],
                        )
                    except Exception:
                        pass
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
    totp_secret_cached: str = ""
    if engine is not None:
        with Session(engine) as session_db:
            user_obj = session_db.get(User, int(pending_user_id))
            if user_obj is not None:
                email = user_obj.email or ""
                # Cache totp_secret before session closes to avoid detached instance issues
                totp_secret_cached = user_obj.totp_secret or ""

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
                if not _verify_totp_with_secret(totp_secret_cached, totp_code):
                    log_event("AUTH_LOGIN_2FA_FAILURE", user_id=user_obj.id)
                    try:
                        pv_log(
                            "security",
                            "warn",
                            "auth_html_login_totp_failure",
                            component="views",
                            user_id=int(user_obj.id),
                            email=str(getattr(user_obj, "email", "") or "")[:256],
                        )
                    except Exception:
                        pass
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
                    try:
                        pv_log(
                            "security",
                            "info",
                            "auth_html_login_totp_success",
                            component="views",
                            user_id=int(user_obj.id),
                            email=str(getattr(user_obj, "email", "") or "")[:256],
                        )
                    except Exception:
                        pass
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
            raw_country_code = (request.form.get("primary_phone_country") or "").strip()
            raw_national_phone = (request.form.get("primary_phone_national") or "").strip()
            timezone_val = (
                request.form.get("timezone")
                or request.form.get("timezone_fallback")
                or ""
            ).strip()
            mfa_pref = (request.form.get("mfa_preference") or "").strip()

            if timezone_val:
                if len(timezone_val) > 64:
                    errors.append("Time zone name is too long.")
                else:
                    try:
                        ZoneInfo(str(timezone_val))
                    except Exception:  # noqa: BLE001
                        errors.append(
                            "Invalid time zone. Use an IANA time zone like America/Chicago."
                        )

            if not errors:
                db_user.full_name = full_name or None
                db_user.preferred_name = preferred_name or None
                db_user.pronouns = pronouns or None

                cc = "".join(ch for ch in raw_country_code if ch.isdigit())
                nn = "".join(ch for ch in raw_national_phone if ch.isdigit())
                if cc and nn:
                    db_user.primary_phone = f"+{cc}{nn}"
                else:
                    raw_phone = (request.form.get("primary_phone") or "").strip()
                    digits_only = "".join(ch for ch in raw_phone if ch.isdigit())
                    db_user.primary_phone = f"+{digits_only}" if digits_only else None
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

        next_tick = time.monotonic()
        while True:
            frame = _load_frame()
            if frame:
                size = len(frame)
                yield (
                    b"--frame\r\n"
                    b"Content-Type: image/jpeg\r\n"
                    + f"Content-Length: {size}\r\n\r\n".encode("ascii")
                    + frame
                    + b"\r\n"
                )

            next_tick += interval
            delay = next_tick - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            else:
                next_tick = time.monotonic()

    resp = Response(
        generate(),
        mimetype="multipart/x-mixed-replace; boundary=frame",
    )
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    resp.headers["X-Accel-Buffering"] = "no"
    return resp


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


@bp.get("/cameras/<int:device_id>/preview_history.jpg")
def camera_preview_history_jpeg(device_id: int):
    user = get_current_user()
    record_engine = get_record_engine()
    if not _user_can_access_camera(user, device_id, record_engine):
        abort(404)
    age_raw = request.args.get("age", "0")
    try:
        age = float(age_raw)
    except (TypeError, ValueError):
        age = 0.0
    path = find_frame_by_age(current_app, device_id, age)
    if path is None or not path.exists():
        abort(404)
    try:
        return send_file(path, mimetype="image/jpeg")
    except Exception:
        abort(404)


@bp.get("/cameras/<int:device_id>/preview_history.mjpg")
def camera_preview_history_mjpg(device_id: int):
    user = get_current_user()
    record_engine = get_record_engine()
    if not _user_can_access_camera(user, device_id, record_engine):
        abort(404)
    fps_raw = request.args.get("fps", "10")
    try:
        fps = float(fps_raw)
    except (TypeError, ValueError):
        fps = 10.0
    if fps <= 0.0:
        fps = 10.0
    fps = min(30.0, fps)
    interval = 1.0 / fps

    def generate():  # pragma: no cover - realtime streaming
        import time

        start = time.time()
        while True:
            age = time.time() - start
            if age > 60.0:
                break
            path = find_frame_by_age(current_app, device_id, age)
            if path is not None:
                try:
                    frame = path.read_bytes()
                except Exception:
                    frame = b""
                if frame:
                    yield (
                        b"--frame\r\n"
                        b"Content-Type: image/jpeg\r\n\r\n" + frame + b"\r\n"
                    )
            time.sleep(interval)

    return Response(
        generate(),
        mimetype="multipart/x-mixed-replace; boundary=frame",
    )


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
            if last_seen is not None:
                try:
                    if getattr(last_seen, "tzinfo", None) is None:
                        last_seen = last_seen.replace(tzinfo=timezone.utc)
                    else:
                        last_seen = last_seen.astimezone(timezone.utc)
                except Exception:
                    last_seen = None
            if last_seen is not None and last_seen >= threshold:
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
            if last_seen is not None:
                try:
                    if getattr(last_seen, "tzinfo", None) is None:
                        last_seen = last_seen.replace(tzinfo=timezone.utc)
                    else:
                        last_seen = last_seen.astimezone(timezone.utc)
                except Exception:
                    last_seen = None
            if last_seen is not None and last_seen >= threshold:
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
    face_recognition, fr_err = _get_face_recognition_lib()
    if face_recognition is None:
        msg = str(fr_err) if fr_err is not None else "face recognition unavailable"
        return jsonify({"error": msg[:200]}), 503

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
    face_recognition, fr_err = _get_face_recognition_lib()
    if face_recognition is None:
        msg = str(fr_err) if fr_err is not None else "face recognition unavailable"
        return jsonify({"error": msg[:200]}), 503

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
    face_recognition, fr_err = _get_face_recognition_lib()
    if face_recognition is None:
        msg = str(fr_err) if fr_err is not None else "face recognition unavailable"
        return jsonify({"error": msg[:200]}), 503

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
    face_recognition, fr_err = _get_face_recognition_lib()
    if face_recognition is None:
        msg = str(fr_err) if fr_err is not None else "face recognition unavailable"
        return jsonify({"error": msg[:200]}), 503

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
    face_recognition, fr_err = _get_face_recognition_lib()
    if face_recognition is None:
        msg = str(fr_err) if fr_err is not None else "face recognition unavailable"
        return jsonify({"error": msg[:200]}), 503

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
    args = {}
    try:
        for key in ("edit_module", "wizard"):
            val = request.args.get(key)
            if val is not None and str(val).strip() != "":
                args[key] = val
    except Exception:  # noqa: BLE001
        args = {}
    return redirect(url_for("admin.storage_settings", **args))


@bp.route("/recording-settings", methods=["GET", "POST"])
def recording_settings():
    user = get_current_user()
    if user is None:
        next_url = request.path or url_for("main.index")
        return redirect(url_for("main.login", next=next_url))

    errors: list[str] = []
    saved = False
    test_result = None
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

                # If the client requested JSON (AJAX), return the test result immediately.
                accept_header = (request.headers.get("Accept") or "").lower()
                if "application/json" in accept_header:
                    return jsonify(test_result or {"ok": False, "message": "no result"})

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

            elif action == "create_storage_schedule":
                device_id_raw = request.form.get("device_id") or ""
                try:
                    device_id = int(device_id_raw)
                except ValueError:
                    device_id = None

                targets = request.form.getlist("targets")
                clean_targets = [name.strip() for name in targets if name.strip()]
                targets_str = ",".join(sorted(set(clean_targets))) if clean_targets else None

                retention_raw = (request.form.get("retention_days") or "").strip()
                retention_days = None
                if retention_raw:
                    try:
                        retention_days = int(retention_raw)
                    except ValueError:
                        retention_days = None

                mode = (request.form.get("mode") or "always").strip().lower() or "always"
                start_time = (request.form.get("start_time") or "").strip() or None
                end_time = (request.form.get("end_time") or "").strip() or None

                valid_modes = {
                    "always",
                    "scheduled",
                    "motion_only",
                    "scheduled_motion",
                }
                if mode not in valid_modes:
                    mode = "always"
                if mode == "always" or (start_time is None and end_time is None):
                    start_time = None
                    end_time = None

                if device_id is not None:
                    with Session(record_engine) as session_db:
                        CameraStorageScheduleEntry.__table__.create(
                            bind=record_engine,
                            checkfirst=True,
                        )
                        entry = CameraStorageScheduleEntry(
                            device_id=device_id,
                            storage_targets=targets_str,
                            retention_days=retention_days,
                            mode=mode,
                            days_of_week="*",
                            start_time=start_time,
                            end_time=end_time,
                            is_enabled=1,
                            priority=None,
                        )
                        session_db.add(entry)
                        session_db.commit()
                        saved = True

            elif action == "update_storage_schedule":
                entry_id_raw = request.form.get("entry_id") or ""
                device_id_raw = request.form.get("device_id") or ""
                try:
                    entry_id = int(entry_id_raw)
                except ValueError:
                    entry_id = None
                try:
                    device_id = int(device_id_raw)
                except ValueError:
                    device_id = None

                targets = request.form.getlist("targets")
                clean_targets = [name.strip() for name in targets if name.strip()]
                targets_str = ",".join(sorted(set(clean_targets))) if clean_targets else None

                retention_raw = (request.form.get("retention_days") or "").strip()
                retention_days = None
                if retention_raw:
                    try:
                        retention_days = int(retention_raw)
                    except ValueError:
                        retention_days = None

                mode = (request.form.get("mode") or "always").strip().lower() or "always"
                start_time = (request.form.get("start_time") or "").strip() or None
                end_time = (request.form.get("end_time") or "").strip() or None

                valid_modes = {
                    "always",
                    "scheduled",
                    "motion_only",
                    "scheduled_motion",
                }
                if mode not in valid_modes:
                    mode = "always"
                if mode == "always" or (start_time is None and end_time is None):
                    start_time = None
                    end_time = None

                if entry_id is not None and device_id is not None:
                    with Session(record_engine) as session_db:
                        CameraStorageScheduleEntry.__table__.create(
                            bind=record_engine,
                            checkfirst=True,
                        )
                        row = session_db.get(CameraStorageScheduleEntry, entry_id)
                        if row is not None:
                            row.device_id = device_id
                            row.storage_targets = targets_str
                            row.retention_days = retention_days
                            row.mode = mode
                            row.days_of_week = "*"
                            row.start_time = start_time
                            row.end_time = end_time
                            session_db.add(row)
                            session_db.commit()
                            saved = True

            elif action == "test_storage_schedule":
                targets = request.form.getlist("targets")
                clean_targets = [name.strip() for name in targets if name.strip()]
                targets_set = {name for name in clean_targets if name}
                if not targets_set:
                    test_result = {
                        "ok": False,
                        "module_name": "Schedule targets",
                        "message": "No storage locations selected.",
                    }
                else:
                    with Session(record_engine) as session_db:
                        StorageModule.__table__.create(
                            bind=record_engine,
                            checkfirst=True,
                        )
                        modules = (
                            session_db.query(StorageModule)
                            .filter(StorageModule.name.in_(sorted(targets_set)))
                            .all()
                        )
                    found = {m.name for m in modules}
                    missing = sorted([t for t in targets_set if t not in found])

                    router = get_storage_router(current_app)
                    results: list[str] = []
                    ok_all = True
                    for module in modules:
                        instance_key = str(module.id)
                        try:
                            status = router.health_check(instance_key)
                        except StorageError as exc:  # pragma: no cover - error path
                            ok_all = False
                            results.append(f"{module.name}: {str(exc)[:180]}")
                        except Exception as exc:  # noqa: BLE001
                            ok_all = False
                            results.append(f"{module.name}: {str(exc)[:180]}")
                        else:
                            status_text = str(status.get("status") or "ok")
                            message = status.get("message") or f"Health check status: {status_text}"
                            if status_text != "ok":
                                ok_all = False
                            results.append(f"{module.name}: {str(message)[:180]}")

                    if missing:
                        ok_all = False
                        results.append("Missing: " + ", ".join(missing))

                    test_result = {
                        "ok": bool(ok_all),
                        "module_name": "Schedule targets",
                        "message": " | ".join(results)[:300],
                    }

                # If the client requested JSON (AJAX), return the test result immediately.
                accept_header = (request.headers.get("Accept") or "").lower()
                if "application/json" in accept_header:
                    return jsonify(test_result or {"ok": False, "message": "no result"})

            elif action == "toggle_storage_schedule":
                entry_id_raw = request.form.get("entry_id") or ""
                enable_raw = request.form.get("enable") or ""
                try:
                    entry_id = int(entry_id_raw)
                except ValueError:
                    entry_id = None
                try:
                    enable = int(enable_raw)
                except ValueError:
                    enable = None
                if entry_id is not None and enable is not None:
                    with Session(record_engine) as session_db:
                        CameraStorageScheduleEntry.__table__.create(
                            bind=record_engine,
                            checkfirst=True,
                        )
                        row = session_db.get(CameraStorageScheduleEntry, entry_id)
                        if row is not None:
                            row.is_enabled = 1 if enable else 0
                            session_db.add(row)
                            session_db.commit()
                            saved = True

            elif action == "delete_storage_schedule":
                entry_id_raw = request.form.get("entry_id") or ""
                try:
                    entry_id = int(entry_id_raw)
                except ValueError:
                    entry_id = None
                if entry_id is not None:
                    with Session(record_engine) as session_db:
                        CameraStorageScheduleEntry.__table__.create(
                            bind=record_engine,
                            checkfirst=True,
                        )
                        row = session_db.get(CameraStorageScheduleEntry, entry_id)
                        if row is not None:
                            session_db.delete(row)
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
    schedule_rows: list[dict] = []
    if record_engine is not None:
        with Session(record_engine) as session_db:
            CameraDevice.__table__.create(bind=record_engine, checkfirst=True)
            CameraStoragePolicy.__table__.create(bind=record_engine, checkfirst=True)
            CameraRecordingSchedule.__table__.create(
                bind=record_engine,
                checkfirst=True,
            )
            CameraStorageScheduleEntry.__table__.create(
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
            schedule_entries = session_db.query(CameraStorageScheduleEntry).all()

        policies_index = {int(p.device_id): p for p in policies}
        schedules_index = {int(s.device_id): s for s in schedules}

        devices_index = {int(d.id): d for d in devices}
        for entry in schedule_entries:
            dev = devices_index.get(int(getattr(entry, "device_id", 0) or 0))
            schedule_rows.append(
                {
                    "id": int(entry.id),
                    "device_id": int(getattr(entry, "device_id", 0) or 0),
                    "camera_name": (getattr(dev, "name", None) or f"#{getattr(entry, 'device_id', '')}"),
                    "storage_targets": getattr(entry, "storage_targets", None) or "",
                    "retention_days": getattr(entry, "retention_days", None),
                    "mode": (getattr(entry, "mode", None) or "always"),
                    "start_time": getattr(entry, "start_time", None) or "",
                    "end_time": getattr(entry, "end_time", None) or "",
                    "is_enabled": bool(getattr(entry, "is_enabled", 1)),
                }
            )

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
        storage_schedules=schedule_rows,
        test_result=test_result,
        current_time_local=now_local,
        current_timezone=tz_name,
    )


@bp.route("/dlna", methods=["GET", "POST"])
def dlna_settings():
    abort(404)


@bp.get("/recordings")
def recordings():
    """Camera-centric recordings overview - shows all cameras with recording counts."""
    user = get_current_user()
    if user is None:
        next_url = request.path or url_for("main.index")
        return redirect(url_for("main.login", next=next_url))

    record_engine = get_record_engine()
    cameras_with_counts: list[dict] = []

    if record_engine is not None:
        with Session(record_engine) as session_db:
            CameraRecording.__table__.create(bind=record_engine, checkfirst=True)
            CameraDevice.__table__.create(bind=record_engine, checkfirst=True)

            # Get all cameras with their recording counts
            from sqlalchemy import func

            results = (
                session_db.query(
                    CameraDevice,
                    func.count(CameraRecording.id).label("recording_count"),
                )
                .outerjoin(
                    CameraRecording, CameraDevice.id == CameraRecording.device_id
                )
                .group_by(CameraDevice.id)
                .order_by(CameraDevice.name)
                .all()
            )

            for device, count in results:
                cameras_with_counts.append(
                    {
                        "id": device.id,
                        "name": device.name,
                        "recording_count": count,
                    }
                )

    return render_template(
        "recordings.html",
        cameras=cameras_with_counts,
    )


@bp.get("/recordings/camera/<int:device_id>")
def camera_recordings(device_id: int):
    """Per-camera recordings view with date/time filtering and sorting."""
    user = get_current_user()
    if user is None:
        next_url = request.path or url_for("main.index")
        return redirect(url_for("main.login", next=next_url))

    record_engine = get_record_engine()
    if record_engine is None:
        return render_template(
            "camera_recordings.html",
            device=None,
            recordings=[],
            available_dates=[],
            selected_date=None,
            start_hour=None,
            end_hour=None,
            sort_order="desc",
            page=1,
            total_pages=1,
            total_count=0,
        )

    # Get filter parameters
    selected_date = (request.args.get("date") or "").strip()
    start_hour = request.args.get("start_hour", "")
    end_hour = request.args.get("end_hour", "")
    sort_order = request.args.get("sort", "desc")
    if sort_order not in ("asc", "desc"):
        sort_order = "desc"

    # Pagination
    per_page = 50
    try:
        page = max(1, int(request.args.get("page", 1)))
    except (ValueError, TypeError):
        page = 1

    with Session(record_engine) as session_db:
        CameraRecording.__table__.create(bind=record_engine, checkfirst=True)
        CameraDevice.__table__.create(bind=record_engine, checkfirst=True)

        device = session_db.get(CameraDevice, device_id)
        if device is None:
            from flask import abort

            abort(404)

        # Get all available dates for this camera
        from sqlalchemy import func

        date_results = (
            session_db.query(func.date(CameraRecording.created_at))
            .filter(CameraRecording.device_id == device_id)
            .distinct()
            .order_by(func.date(CameraRecording.created_at).desc())
            .all()
        )
        available_dates = [str(d[0]) for d in date_results if d[0]]

        # Build query
        query = session_db.query(CameraRecording).filter(
            CameraRecording.device_id == device_id
        )

        # Apply date filter
        if selected_date:
            try:
                from datetime import datetime

                date_obj = datetime.strptime(selected_date, "%Y-%m-%d").date()
                query = query.filter(
                    func.date(CameraRecording.created_at) == date_obj
                )
            except ValueError:
                pass

        # Apply time range filter
        if start_hour:
            try:
                sh = int(start_hour)
                if 0 <= sh <= 23:
                    query = query.filter(
                        func.hour(CameraRecording.created_at) >= sh
                    )
            except ValueError:
                pass

        if end_hour:
            try:
                eh = int(end_hour)
                if 0 <= eh <= 23:
                    query = query.filter(
                        func.hour(CameraRecording.created_at) <= eh
                    )
            except ValueError:
                pass

        # Get total count
        total_count = query.count()
        total_pages = max(1, (total_count + per_page - 1) // per_page)
        page = min(page, total_pages)

        # Apply sorting
        if sort_order == "asc":
            query = query.order_by(CameraRecording.created_at.asc())
        else:
            query = query.order_by(CameraRecording.created_at.desc())

        recordings_list = query.offset((page - 1) * per_page).limit(per_page).all()

    return render_template(
        "camera_recordings.html",
        device=device,
        recordings=recordings_list,
        available_dates=available_dates,
        selected_date=selected_date,
        start_hour=start_hour,
        end_hour=end_hour,
        sort_order=sort_order,
        page=page,
        total_pages=total_pages,
        total_count=total_count,
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
            next_recording_id=None,
            prev_recording_id=None,
            autoplay=False,
        ), 500

    # Get autoplay preference from query string
    autoplay = (request.args.get("autoplay") or "").lower() in ("1", "true", "on")

    with Session(record_engine) as session_db:
        CameraRecording.__table__.create(bind=record_engine, checkfirst=True)
        recording = session_db.get(CameraRecording, recording_id)
        device = None
        next_recording_id = None
        prev_recording_id = None

        if recording is not None:
            if recording.device_id is not None:
                device = session_db.get(CameraDevice, recording.device_id)

            # Find next recording (same camera, created after this one, oldest first)
            next_rec = (
                session_db.query(CameraRecording)
                .filter(CameraRecording.device_id == recording.device_id)
                .filter(CameraRecording.created_at > recording.created_at)
                .order_by(CameraRecording.created_at.asc())
                .first()
            )
            if next_rec:
                next_recording_id = next_rec.id

            # Find previous recording (same camera, created before this one, newest first)
            prev_rec = (
                session_db.query(CameraRecording)
                .filter(CameraRecording.device_id == recording.device_id)
                .filter(CameraRecording.created_at < recording.created_at)
                .order_by(CameraRecording.created_at.desc())
                .first()
            )
            if prev_rec:
                prev_recording_id = prev_rec.id

    if recording is None:
        return render_template(
            "recording_detail.html",
            recording=None,
            device=None,
            next_recording_id=None,
            prev_recording_id=None,
            autoplay=False,
        ), 404

    return render_template(
        "recording_detail.html",
        recording=recording,
        device=device,
        next_recording_id=next_recording_id,
        prev_recording_id=prev_recording_id,
        autoplay=autoplay,
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

        download_raw = (request.args.get("download") or "").strip().lower()
        download = download_raw in {"1", "true", "yes", "on"}
        transcode_raw = (request.args.get("transcode") or "").strip().lower()
        force_transcode = transcode_raw in {"1", "true", "yes", "on"}

        providers = build_storage_providers(current_app)
        provider_obj = next(
            (p for p in providers if getattr(p, "name", None) == provider_name),
            None,
        )

        def _serve_video_bytes(data: bytes, filename: str) -> Response:
            payload = bytes(data or b"")
            size = len(payload)
            disposition = "attachment" if download else "inline"
            range_header = request.headers.get("Range")

            if range_header and str(range_header).startswith("bytes=") and size:
                spec = (
                    str(range_header)
                    .split("=", 1)[1]
                    .split(",", 1)[0]
                    .strip()
                )
                try:
                    if spec.startswith("-"):
                        suffix_len = int(spec[1:].strip() or "0")
                        if suffix_len <= 0:
                            raise ValueError
                        if suffix_len > size:
                            suffix_len = size
                        start = size - suffix_len
                        end = size - 1
                    else:
                        start_s, end_s = spec.split("-", 1)
                        start = int(start_s.strip() or "0")
                        end = int(end_s.strip()) if end_s.strip() else size - 1
                        if start < 0 or start >= size:
                            raise ValueError
                        if end < start:
                            raise ValueError
                        if end >= size:
                            end = size - 1
                except Exception:
                    resp = Response(status=416)
                    resp.headers["Content-Range"] = f"bytes */{size}"
                    resp.headers["Accept-Ranges"] = "bytes"
                    return resp

                chunk = payload[start:end+1]
                resp = Response(chunk, status=206, mimetype="video/mp4")
                resp.headers["Content-Range"] = f"bytes {start}-{end}/{size}"
                resp.headers["Accept-Ranges"] = "bytes"
                resp.headers["Content-Length"] = str(len(chunk))
                resp.headers["Content-Disposition"] = f"{disposition}; filename={filename}"
                return resp

            resp = Response(payload, mimetype="video/mp4")
            resp.headers["Accept-Ranges"] = "bytes"
            resp.headers["Content-Length"] = str(size)
            resp.headers["Content-Disposition"] = f"{disposition}; filename={filename}"
            return resp

        def _tmp_dir() -> Path:
            # Prefer tmpfs if available
            for cand in (Path("/dev/shm/pentavision"), Path("/dev/shm")):
                try:
                    cand.mkdir(parents=True, exist_ok=True)
                    return cand
                except Exception:
                    continue
            try:
                return Path(tempfile.gettempdir())
            except Exception:
                return Path("/tmp")

        def _transcode_file_to_temp(src_path: Path) -> Path | None:
            out_path = _tmp_dir() / f"recording-{recording_id}-{int(time.time())}.mp4"
            x264_preset = str(current_app.config.get("RECORD_FFMPEG_X264_PRESET", "veryfast") or "veryfast")
            try:
                x264_crf = int(current_app.config.get("RECORD_FFMPEG_X264_CRF", 23) or 23)
            except Exception:
                x264_crf = 23
            aac_bitrate = str(current_app.config.get("RECORD_FFMPEG_AAC_BITRATE", "128k") or "128k")
            cmd = [
                "ffmpeg",
                "-hide_banner",
                "-loglevel",
                "error",
                "-i",
                str(src_path),
                "-c:v",
                "libx264",
                "-preset",
                x264_preset,
                "-crf",
                str(x264_crf),
                "-pix_fmt",
                "yuv420p",
                "-movflags",
                "+faststart",
                "-c:a",
                "aac",
                "-b:a",
                aac_bitrate,
                str(out_path),
            ]
            try:
                r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, check=False)
            except FileNotFoundError:
                return None
            if r.returncode != 0 or not out_path.exists():
                return None
            return out_path

        if provider_name == "local_fs" or isinstance(provider_obj, LocalFilesystemStorageProvider):
            path = Path(key)
            if isinstance(provider_obj, LocalFilesystemStorageProvider):
                try:
                    target = Path(str(key)).expanduser()
                    if not target.is_absolute():
                        target = provider_obj.base_path / target
                    target = target.resolve()
                    try:
                        target.relative_to(provider_obj.base_path)
                    except ValueError:
                        abort(404)
                    path = target
                except Exception:
                    abort(404)
            if not path.exists():
                abort(404)
            if force_transcode:
                out_path = _transcode_file_to_temp(path)
                if out_path is None or not out_path.exists():
                    abort(404)
                from flask import after_this_request

                @after_this_request
                def _cleanup_temp(response):  # noqa: ANN001
                    try:
                        out_path.unlink(missing_ok=True)
                    except Exception:
                        pass
                    return response

                return send_file(
                    str(out_path),
                    mimetype="video/mp4",
                    conditional=True,
                )
            if download:
                return send_file(
                    str(path),
                    as_attachment=True,
                    download_name=path.name,
                    mimetype="video/mp4",
                    conditional=True,
                )
            return send_file(
                str(path),
                mimetype="video/mp4",
                conditional=True,
            )

        if (
            provider_name == "db"
            or isinstance(provider_obj, DatabaseStorageProvider)
            or key.startswith("recording_data:")
        ):
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
            if force_transcode:
                tmp_in = _tmp_dir() / f"recin-{recording_id}-{int(time.time())}.bin"
                try:
                    tmp_in.write_bytes(bytes(data_row.data or b""))
                    out_path = _transcode_file_to_temp(tmp_in)
                finally:
                    try:
                        tmp_in.unlink(missing_ok=True)
                    except Exception:
                        pass
                if out_path is None or not out_path.exists():
                    abort(404)
                from flask import after_this_request

                @after_this_request
                def _cleanup_temp2(response):  # noqa: ANN001
                    try:
                        out_path.unlink(missing_ok=True)
                    except Exception:
                        pass
                    return response

                return send_file(str(out_path), mimetype="video/mp4", conditional=True)
            return _serve_video_bytes(data_row.data, f"recording-{recording_id}.mp4")

        if key.startswith("external_recording_data:") or isinstance(
            provider_obj, ExternalSQLDatabaseStorageProvider
        ):
            raw = str(key or "").strip()
            row_id = None
            if raw.startswith("external_recording_data:"):
                try:
                    row_id = int(raw.split(":", 1)[1])
                except ValueError:
                    row_id = None
            if row_id is None:
                abort(404)
            if not isinstance(provider_obj, ExternalSQLDatabaseStorageProvider):
                abort(404)

            try:
                provider_obj._ensure_table()
                if provider_obj._engine is None:
                    abort(404)
                with provider_obj._engine.connect() as conn:
                    row = conn.execute(
                        text(
                            "SELECT data FROM external_recording_data WHERE id = :id"
                        ),
                        {"id": int(row_id)},
                    ).first()
            except Exception:
                abort(404)

            if row is None:
                abort(404)
            blob_raw = row[0]
            if blob_raw is None:
                abort(404)
            try:
                blob = bytes(blob_raw)
            except Exception:
                blob = blob_raw if isinstance(blob_raw, (bytes, bytearray)) else None
            if blob is None:
                abort(404)
            if force_transcode:
                tmp_in = _tmp_dir() / f"recin-{recording_id}-{int(time.time())}.bin"
                try:
                    tmp_in.write_bytes(bytes(blob or b""))
                    out_path = _transcode_file_to_temp(tmp_in)
                finally:
                    try:
                        tmp_in.unlink(missing_ok=True)
                    except Exception:
                        pass
                if out_path is None or not out_path.exists():
                    abort(404)
                from flask import after_this_request

                @after_this_request
                def _cleanup_temp3(response):  # noqa: ANN001
                    try:
                        out_path.unlink(missing_ok=True)
                    except Exception:
                        pass
                    return response

                return send_file(str(out_path), mimetype="video/mp4", conditional=True)
            return _serve_video_bytes(blob, f"recording-{recording_id}.mp4")

        # For other providers (e.g. S3): if transcode requested, fetch via signed URL and transcode on the fly.
        if provider_obj is not None:
            url = provider_obj.get_url(key)
            if url:
                if force_transcode:
                    tmp_in = _tmp_dir() / f"recin-{recording_id}-{int(time.time())}.bin"
                    try:
                        with requests.get(url, stream=True, timeout=30) as r:
                            if r.status_code >= 400:
                                abort(404)
                            with open(tmp_in, "wb") as fh:
                                for chunk in r.iter_content(chunk_size=1024 * 1024):
                                    if chunk:
                                        fh.write(chunk)
                        out_path = _transcode_file_to_temp(tmp_in)
                    finally:
                        try:
                            tmp_in.unlink(missing_ok=True)
                        except Exception:
                            pass
                    if out_path is None or not out_path.exists():
                        abort(404)
                    from flask import after_this_request

                    @after_this_request
                    def _cleanup_temp4(response):  # noqa: ANN001
                        try:
                            out_path.unlink(missing_ok=True)
                        except Exception:
                            pass
                        return response

                    return send_file(str(out_path), mimetype="video/mp4", conditional=True)
                # Default: let the browser stream from provider directly.
                return redirect(url)

    abort(404)
