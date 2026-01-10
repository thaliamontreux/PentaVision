import os
import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from dotenv import load_dotenv

from sqlalchemy.orm import Session

from .models import AppConfigSetting

load_dotenv()


def _load_json_config() -> dict[str, object]:
    path = str(os.getenv("PENTAVISION_CONFIG_FILE") or "config.json").strip()
    if not path:
        return {}
    try:
        if not os.path.isabs(path):
            path = os.path.abspath(path)
        if not os.path.isfile(path):
            return {}
        raw = open(path, "r", encoding="utf-8").read()
        obj = json.loads(raw) if raw else {}
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


_JSON_CONFIG: dict[str, object] = _load_json_config()


def _get_source_value(name: str) -> Optional[str]:
    val = os.getenv(name)
    if val is not None:
        return val
    try:
        if name in _JSON_CONFIG and _JSON_CONFIG.get(name) is not None:
            return str(_JSON_CONFIG.get(name))
    except Exception:
        return None
    return None


def _get_float_env(name: str, default: float) -> float:
    value = _get_source_value(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


def _get_int_env(name: str, default: int) -> int:
    value = _get_source_value(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _get_bool_env(name: str, default: bool) -> bool:
    value = _get_source_value(name)
    if value is None:
        return default
    text = value.strip().lower()
    return text in {"1", "true", "yes", "on"}


def load_db_config_overrides(engine) -> dict[str, str]:
    try:
        AppConfigSetting.__table__.create(bind=engine, checkfirst=True)
    except Exception:
        return {}
    try:
        with Session(engine) as session:
            rows = session.query(AppConfigSetting).all()
    except Exception:
        return {}
    out: dict[str, str] = {}
    for row in rows:
        try:
            k = str(getattr(row, "config_key", "") or "").strip()
            if not k:
                continue
            v = getattr(row, "config_value", None)
            out[k] = "" if v is None else str(v)
        except Exception:
            continue
    return out


def set_db_config_value(engine, key: str, value: Optional[str]) -> bool:
    key_norm = str(key or "").strip()
    if not key_norm:
        return False
    try:
        AppConfigSetting.__table__.create(bind=engine, checkfirst=True)
    except Exception:
        return False
    now_dt = datetime.now(timezone.utc)
    try:
        with Session(engine) as session:
            row = (
                session.query(AppConfigSetting)
                .filter(AppConfigSetting.config_key == key_norm)
                .first()
            )
            if value is None:
                if row is not None:
                    session.delete(row)
                    session.commit()
                return True

            if row is None:
                row = AppConfigSetting(config_key=key_norm)
            row.config_value = value
            row.updated_at = now_dt
            session.add(row)
            session.commit()
        return True
    except Exception:
        return False


def apply_db_overrides_to_config(
    config: dict[str, Any],
    overrides: dict[str, str],
) -> dict[str, Any]:
    out = dict(config)
    for k, v in overrides.items():
        if k not in out:
            continue

        cur = out.get(k)
        if isinstance(cur, bool):
            text = str(v or "").strip().lower()
            out[k] = text in {"1", "true", "yes", "on"}
        elif isinstance(cur, int) and not isinstance(cur, bool):
            try:
                out[k] = int(str(v).strip())
            except Exception:
                out[k] = cur
        elif isinstance(cur, float):
            try:
                out[k] = float(str(v).strip())
            except Exception:
                out[k] = cur
        else:
            out[k] = v
    return out


def load_config() -> Dict[str, Any]:
    _i = _get_int_env
    _b = _get_bool_env
    _f = _get_float_env
    _GST_REC = "USE_GSTREAMER_RECORDING"
    return {
        "SECRET_KEY": str(_get_source_value("APP_SECRET_KEY") or "change-me"),
        "USER_DB_URL": str(_get_source_value("USER_DB_URL") or ""),
        "FACE_DB_URL": str(_get_source_value("FACE_DB_URL") or ""),
        "RECORD_DB_URL": str(_get_source_value("RECORD_DB_URL") or ""),
        "PROPERTY_DB_ADMIN_URL": str(_get_source_value("PROPERTY_DB_ADMIN_URL") or ""),
        "PROPERTY_DB_APP_URL_BASE": str(_get_source_value("PROPERTY_DB_APP_URL_BASE") or ""),
        "PROPERTY_DB_NAME_PREFIX": str(_get_source_value("PROPERTY_DB_NAME_PREFIX") or "pv_prop_"),
        "INSTALL_LOCKED": str(_get_source_value("INSTALL_LOCKED") or ""),
        "INSTALL_ACCESS_CODE": str(_get_source_value("INSTALL_ACCESS_CODE") or ""),
        "RECORDING_ENABLED": _b("RECORDING_ENABLED", False),
        "RTMP_ENABLED": _b("RTMP_ENABLED", False),
        "RTMP_LOW_LATENCY": _b("RTMP_LOW_LATENCY", False),
        "DLNA_ENABLED": _b("DLNA_ENABLED", False),
        "DLNA_FRIENDLY_NAME": str(
            _get_source_value("DLNA_FRIENDLY_NAME")
            or "PentaVision DLNA"
        ),
        "MINIDLNA_BIN": str(_get_source_value("MINIDLNA_BIN") or "minidlnad"),
        "GERBERA_BIN": str(_get_source_value("GERBERA_BIN") or "gerbera"),
        "IPTV_ENABLED": _b("IPTV_ENABLED", False),
        "RECORDING_BASE_DIR": str(_get_source_value("RECORDING_BASE_DIR") or ""),
        "STORAGE_TARGETS": str(_get_source_value("STORAGE_TARGETS") or ""),
        "LOCAL_STORAGE_PATH": str(_get_source_value("LOCAL_STORAGE_PATH") or ""),
        "RECORD_SEGMENT_SECONDS": _i("RECORD_SEGMENT_SECONDS", 60),
        "RECORD_FFMPEG_THREADS": _i("RECORD_FFMPEG_THREADS", 2),
        "UPLOAD_QUEUE_RETENTION_DAYS": _i("UPLOAD_QUEUE_RETENTION_DAYS", 7),
        "UPLOAD_QUEUE_MAX_AGE_HOURS": _i("UPLOAD_QUEUE_MAX_AGE_HOURS", 12),
        "DISK_FULL_THRESHOLD_PCT": _i("DISK_FULL_THRESHOLD_PCT", 90),
        "DISK_FULL_RECOVERY_PCT": _i("DISK_FULL_RECOVERY_PCT", 88),
        "DISK_FULL_DELETE_OLDER_THAN_DAYS": _i(
            "DISK_FULL_DELETE_OLDER_THAN_DAYS",
            3,
        ),
        "USE_SHM_INGEST": _b("USE_SHM_INGEST", True),
        "SHM_INGEST_CAMERA_LIMIT_MB": _i(
            "SHM_INGEST_CAMERA_LIMIT_MB",
            256,
        ),
        "SHM_INGEST_GLOBAL_LIMIT_MB": _i(
            "SHM_INGEST_GLOBAL_LIMIT_MB",
            2048,
        ),
        "SHM_INGEST_MIN_FREE_MB": _i(
            "SHM_INGEST_MIN_FREE_MB",
            256,
        ),
        "SHM_INGEST_PROBE_DURATION": _b(
            "SHM_INGEST_PROBE_DURATION",
            False,
        ),
        "SHM_PROCESSING_REQUIRED": _b("SHM_PROCESSING_REQUIRED", True),
        "PREVIEW_LOW_FPS": _f("PREVIEW_LOW_FPS", 2.0),
        "PREVIEW_HIGH_FPS": _f("PREVIEW_HIGH_FPS", 10.0),
        "PREVIEW_MAX_WIDTH": _i("PREVIEW_MAX_WIDTH", 0),
        "PREVIEW_MAX_HEIGHT": _i("PREVIEW_MAX_HEIGHT", 0),
        "PREVIEW_CAPTURE_FPS": _f("PREVIEW_CAPTURE_FPS", 10.0),
        "PREVIEW_CACHE_DIR": str(
            _get_source_value("PREVIEW_CACHE_DIR")
            or "/dev/shm/pentavision/previews"
        ),
        "PREVIEW_HISTORY_SECONDS": _i("PREVIEW_HISTORY_SECONDS", 60),
        "URL_HEALTHCHECK_ENABLED": _b("URL_HEALTHCHECK_ENABLED", True),
        "LOG_SERVER_HOST": str(_get_source_value("LOG_SERVER_HOST") or "127.0.0.1"),
        "LOG_SERVER_PORT": _i("LOG_SERVER_PORT", 8123),
        "STREAMS_ENABLED": _b("STREAMS_ENABLED", True),
        "INGEST_ENABLED": _b("INGEST_ENABLED", False),
        "USE_GSTREAMER_CAPTURE": _b("USE_GSTREAMER_CAPTURE", False),
        "USE_GSTREAMER_RECORDING": _b(
            _GST_REC,
            False,
        ),
        "GST_RTSP_LATENCY_MS": _i("GST_RTSP_LATENCY_MS", 200),
        "STREAM_FFMPEG_DIAGNOSTICS": str(
            _get_source_value("STREAM_FFMPEG_DIAGNOSTICS")
            or "0"
        ),
        "WEBAUTHN_RP_ID": str(_get_source_value("WEBAUTHN_RP_ID") or ""),
        "WEBAUTHN_RP_NAME": str(_get_source_value("WEBAUTHN_RP_NAME") or "PentaVision"),
        "S3_ENDPOINT": str(_get_source_value("S3_ENDPOINT") or ""),
        "S3_REGION": str(_get_source_value("S3_REGION") or ""),
        "S3_BUCKET": str(_get_source_value("S3_BUCKET") or ""),
        "S3_ACCESS_KEY": str(_get_source_value("S3_ACCESS_KEY") or ""),
        "S3_SECRET_KEY": str(_get_source_value("S3_SECRET_KEY") or ""),
        "GCS_BUCKET": str(_get_source_value("GCS_BUCKET") or ""),
        "AZURE_BLOB_CONNECTION_STRING": str(_get_source_value("AZURE_BLOB_CONNECTION_STRING") or ""),
        "AZURE_BLOB_CONTAINER": str(_get_source_value("AZURE_BLOB_CONTAINER") or ""),
        "DROPBOX_ACCESS_TOKEN": str(_get_source_value("DROPBOX_ACCESS_TOKEN") or ""),
        "WEBDAV_BASE_URL": str(_get_source_value("WEBDAV_BASE_URL") or ""),
        "WEBDAV_USERNAME": str(_get_source_value("WEBDAV_USERNAME") or ""),
        "WEBDAV_PASSWORD": str(_get_source_value("WEBDAV_PASSWORD") or ""),
        "FACE_MATCH_THRESHOLD": str(_get_source_value("FACE_MATCH_THRESHOLD") or ""),

        # Diagnostics crawler support (disabled by default).
        # Enable only when you need diagnostics and keep it IP-restricted.
        "DIAGNOSTICS_ENABLED": _b("DIAGNOSTICS_ENABLED", False),
        "DIAGNOSTICS_TOKEN": str(_get_source_value("DIAGNOSTICS_TOKEN") or ""),
        "DIAGNOSTICS_USER_EMAIL": str(_get_source_value("DIAGNOSTICS_USER_EMAIL") or ""),
        "DIAGNOSTICS_GRANT_SYSTEM_ADMIN": _b(
            "DIAGNOSTICS_GRANT_SYSTEM_ADMIN",
            False,
        ),
        "DIAGNOSTICS_LOCAL_ONLY": _b(
            "DIAGNOSTICS_LOCAL_ONLY",
            True,
        ),
        "DIAGNOSTICS_ALLOWED_CIDRS": str(_get_source_value("DIAGNOSTICS_ALLOWED_CIDRS") or ""),

        "BOOTSTRAP_SYSTEM_ADMIN_EMAIL": str(_get_source_value("BOOTSTRAP_SYSTEM_ADMIN_EMAIL") or ""),
    }
