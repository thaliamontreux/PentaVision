from datetime import datetime, timedelta, timezone
from pathlib import Path
import base64
import io
import pickle

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
)
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

from .db import get_face_engine, get_record_engine, get_user_engine
from .models import (
    AuditEvent,
    CameraDevice,
    CameraRecording,
    CameraUrlPattern,
    FaceEmbedding,
    FacePrivacySetting,
    RecordingData,
    User,
)
from .stream_service import get_stream_manager
from .storage_providers import build_storage_providers


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
def index():
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
    if record_engine is not None:
        with Session(record_engine) as session_db:
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

    return render_template(
        "index.html",
        db_status=db_status,
        overall_status=overall,
        devices=devices,
        patterns=patterns_index,
        camera_status=camera_status,
        camera_last_seen=camera_last_seen,
    )


@bp.get("/faces-demo")
def faces_demo():
    return render_template("faces_demo.html")


@bp.get("/auth-demo")
def auth_demo():
    return render_template("auth_demo.html")


@bp.get("/audit")
def audit_events():
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


def _camera_preview_response(device_id: int, fps: float) -> Response:
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

    def _load_frame() -> bytes | None:
        # Preferred path: use in-process CameraStreamManager (dev/local).
        if manager is not None:
            return manager.get_frame(device_id)

        # Fallback for production where streams run in a separate worker:
        # read the most recent preview frame from the shared cache directory
        # written by the video worker.
        base = current_app.config.get(
            "PREVIEW_CACHE_DIR", "/var/lib/pentavision/previews"
        )
        try:
            path = Path(str(base)) / f"{device_id}.jpg"
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
    fps = current_app.config.get("PREVIEW_LOW_FPS", 2.0)
    try:
        fps_value = float(fps)
    except (TypeError, ValueError):
        fps_value = 2.0
    return _camera_preview_response(device_id, fps=fps_value)


@bp.get("/cameras/<int:device_id>/preview.mjpg")
def camera_preview(device_id: int):
    fps = current_app.config.get("PREVIEW_HIGH_FPS", 10.0)
    try:
        fps_value = float(fps)
    except (TypeError, ValueError):
        fps_value = 10.0
    return _camera_preview_response(device_id, fps=fps_value)


@bp.get("/cameras/<int:device_id>")
def camera_detail(device_id: int):
    record_engine = get_record_engine()
    if record_engine is None:
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

    return render_template(
        "cameras/session.html",
        device=device,
        pattern=pattern,
        status=status,
        last_seen=last_seen,
    )


@bp.get("/streams/status")
def streams_status():
    manager = get_stream_manager(current_app)
    if manager is None:
        return jsonify({"ok": False, "error": "stream manager not available", "streams": []})

    raw = manager.get_status()
    now_ts = datetime.now(timezone.utc).timestamp()
    streams = []
    for device_id, info in raw.items():
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


@bp.get("/storage")
def storage_settings():
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

    cfg = current_app.config
    s3_bucket = str(cfg.get("S3_BUCKET") or "")
    s3_endpoint = str(cfg.get("S3_ENDPOINT") or "")
    s3_region = str(cfg.get("S3_REGION") or "")
    s3_access_key = str(cfg.get("S3_ACCESS_KEY") or "")
    s3_secret_key = str(cfg.get("S3_SECRET_KEY") or "")

    def _mask(value: str, keep: int = 4) -> str:
        if not value:
            return ""
        if len(value) <= keep:
            return "*" * len(value)
        return "*" * (len(value) - keep) + value[-keep:]

    s3_info = {
        "bucket": s3_bucket,
        "endpoint": s3_endpoint,
        "region": s3_region,
        "access_key_masked": _mask(s3_access_key),
        "secret_key_masked": _mask(s3_secret_key),
    }

    gcs_bucket = str(cfg.get("GCS_BUCKET") or "")
    gcs_info = {
        "bucket": gcs_bucket,
    }

    azure_conn = str(cfg.get("AZURE_BLOB_CONNECTION_STRING") or "")
    azure_container = str(cfg.get("AZURE_BLOB_CONTAINER") or "")
    azure_info = {
        "container": azure_container,
        "connection_string_masked": _mask(azure_conn),
    }

    dropbox_token = str(cfg.get("DROPBOX_ACCESS_TOKEN") or "")
    dropbox_info = {
        "access_token_masked": _mask(dropbox_token),
    }

    webdav_base = str(cfg.get("WEBDAV_BASE_URL") or "")
    webdav_username = str(cfg.get("WEBDAV_USERNAME") or "")
    webdav_password = str(cfg.get("WEBDAV_PASSWORD") or "")
    webdav_info = {
        "base_url": webdav_base,
        "username": webdav_username,
        "password_masked": _mask(webdav_password),
    }

    return render_template(
        "storage.html",
        providers=providers,
        s3=s3_info,
        gcs=gcs_info,
        azure=azure_info,
        dropbox=dropbox_info,
        webdav=webdav_info,
    )


@bp.get("/recordings")
def recordings():
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
