import os
from typing import Dict, Any

from dotenv import load_dotenv


load_dotenv()


def _get_float_env(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


def _get_int_env(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def load_config() -> Dict[str, Any]:
    return {
        "SECRET_KEY": os.getenv("APP_SECRET_KEY", "change-me"),
        "USER_DB_URL": os.getenv("USER_DB_URL", ""),
        "FACE_DB_URL": os.getenv("FACE_DB_URL", ""),
        "RECORD_DB_URL": os.getenv("RECORD_DB_URL", ""),
        "INSTALL_LOCKED": os.getenv("INSTALL_LOCKED", ""),
        "INSTALL_ACCESS_CODE": os.getenv("INSTALL_ACCESS_CODE", ""),
        "RECORDING_ENABLED": os.getenv("RECORDING_ENABLED", "0"),
        "RECORDING_BASE_DIR": os.getenv("RECORDING_BASE_DIR", ""),
        "STORAGE_TARGETS": os.getenv("STORAGE_TARGETS", ""),
        "LOCAL_STORAGE_PATH": os.getenv("LOCAL_STORAGE_PATH", ""),
        "RECORD_SEGMENT_SECONDS": _get_int_env("RECORD_SEGMENT_SECONDS", 60),
        "RECORD_FFMPEG_THREADS": _get_int_env("RECORD_FFMPEG_THREADS", 2),
        "PREVIEW_LOW_FPS": _get_float_env("PREVIEW_LOW_FPS", 2.0),
        "PREVIEW_HIGH_FPS": _get_float_env("PREVIEW_HIGH_FPS", 10.0),
        "PREVIEW_MAX_WIDTH": _get_int_env("PREVIEW_MAX_WIDTH", 0),
        "PREVIEW_MAX_HEIGHT": _get_int_env("PREVIEW_MAX_HEIGHT", 0),
        "PREVIEW_CAPTURE_FPS": _get_float_env("PREVIEW_CAPTURE_FPS", 10.0),
        "STREAM_FFMPEG_DIAGNOSTICS": os.getenv("STREAM_FFMPEG_DIAGNOSTICS", "0"),
        "WEBAUTHN_RP_ID": os.getenv("WEBAUTHN_RP_ID", ""),
        "WEBAUTHN_RP_NAME": os.getenv("WEBAUTHN_RP_NAME", "PentaVision"),
        "S3_ENDPOINT": os.getenv("S3_ENDPOINT", ""),
        "S3_REGION": os.getenv("S3_REGION", ""),
        "S3_BUCKET": os.getenv("S3_BUCKET", ""),
        "S3_ACCESS_KEY": os.getenv("S3_ACCESS_KEY", ""),
        "S3_SECRET_KEY": os.getenv("S3_SECRET_KEY", ""),
        "GCS_BUCKET": os.getenv("GCS_BUCKET", ""),
        "AZURE_BLOB_CONNECTION_STRING": os.getenv(
            "AZURE_BLOB_CONNECTION_STRING",
            "",
        ),
        "AZURE_BLOB_CONTAINER": os.getenv("AZURE_BLOB_CONTAINER", ""),
        "DROPBOX_ACCESS_TOKEN": os.getenv("DROPBOX_ACCESS_TOKEN", ""),
        "WEBDAV_BASE_URL": os.getenv("WEBDAV_BASE_URL", ""),
        "WEBDAV_USERNAME": os.getenv("WEBDAV_USERNAME", ""),
        "WEBDAV_PASSWORD": os.getenv("WEBDAV_PASSWORD", ""),
        "FACE_MATCH_THRESHOLD": os.getenv("FACE_MATCH_THRESHOLD", ""),
    }
