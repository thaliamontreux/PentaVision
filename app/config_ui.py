from __future__ import annotations


CONFIG_SECTIONS: list[dict[str, str]] = [
    {"id": "recording", "label": "Recording"},
    {"id": "upload_queue", "label": "Upload Queue"},
    {"id": "disk_pressure", "label": "Disk Pressure"},
    {"id": "ingest", "label": "Ingest / Memory"},
    {"id": "preview", "label": "Preview"},
    {"id": "streaming", "label": "Streaming"},
    {"id": "integrations", "label": "Integrations"},
    {"id": "diagnostics", "label": "Diagnostics"},
    {"id": "bootstrap", "label": "Bootstrap (Protected)"},
    {"id": "other", "label": "Other"},
]


CONFIG_UI: dict[str, dict[str, object]] = {
    "SECRET_KEY": {
        "section": "bootstrap",
        "label": "App Secret Key",
        "description": "Used to sign session cookies and CSRF tokens. Changing this will log everyone out.",
        "protected": True,
    },
    "USER_DB_URL": {
        "section": "bootstrap",
        "label": "User Database URL",
        "description": "Connection string for the UserDB (accounts, roles, admin settings).",
        "protected": True,
    },
    "FACE_DB_URL": {
        "section": "bootstrap",
        "label": "Face Database URL",
        "description": "Connection string for the FaceDB (embeddings, face recognition data).",
        "protected": True,
    },
    "RECORD_DB_URL": {
        "section": "bootstrap",
        "label": "Recording Database URL",
        "description": "Connection string for the RecordDB (recordings, upload queue).",
        "protected": True,
    },
    "PROPERTY_DB_ADMIN_URL": {
        "section": "bootstrap",
        "label": "Property DB Admin URL",
        "description": "Admin connection string used to create/manage per-property tenant databases.",
        "protected": True,
    },
    "PROPERTY_DB_APP_URL_BASE": {
        "section": "bootstrap",
        "label": "Property DB App URL Base",
        "description": "App connection string base used to connect to per-property tenant databases.",
        "protected": True,
    },
    "PROPERTY_DB_NAME_PREFIX": {
        "section": "bootstrap",
        "label": "Property DB Name Prefix",
        "description": "Prefix used when creating per-property tenant database names.",
    },
    "INSTALL_LOCKED": {
        "section": "bootstrap",
        "label": "Installer Locked",
        "description": "When set, the web installer is locked/disabled.",
    },
    "INSTALL_ACCESS_CODE": {
        "section": "bootstrap",
        "label": "Installer Access Code",
        "description": "Optional installer access code for one-time setup.",
    },
    "RECORDING_ENABLED": {
        "section": "recording",
        "label": "Enable Recording",
        "description": "Turns the recording service on/off. Recording schedules still control when segments are kept.",
    },
    "RECORD_SEGMENT_SECONDS": {
        "section": "recording",
        "label": "Segment Length (Seconds)",
        "description": "Length of each recording segment produced by the recorder.",
        "range": (10, 300, 10),
    },
    "RECORD_FFMPEG_THREADS": {
        "section": "recording",
        "label": "FFmpeg Threads",
        "description": "Thread count for FFmpeg recording/transcode operations.",
        "range": (1, 16, 1),
    },
    "UPLOAD_QUEUE_RETENTION_DAYS": {
        "section": "upload_queue",
        "label": "Upload Queue Retention (Days)",
        "description": "Deletes upload queue rows older than this to prevent RecordDB growth.",
        "range": (1, 30, 1),
    },
    "UPLOAD_QUEUE_MAX_AGE_HOURS": {
        "section": "upload_queue",
        "label": "Max Upload Backlog (Hours)",
        "description": "If the upload queue for a camera exceeds this age, recording pauses until uploads catch up.",
        "range": (1, 48, 1),
    },
    "DISK_FULL_THRESHOLD_PCT": {
        "section": "disk_pressure",
        "label": "Disk Full Threshold (%)",
        "description": "When disk usage reaches this percentage, automatic cleanup begins.",
        "range": (50, 99, 1),
    },
    "DISK_FULL_RECOVERY_PCT": {
        "section": "disk_pressure",
        "label": "Disk Recovery Target (%)",
        "description": "Cleanup stops once disk usage drops to this percentage.",
        "range": (50, 99, 1),
    },
    "DISK_FULL_DELETE_OLDER_THAN_DAYS": {
        "section": "disk_pressure",
        "label": "Delete Older Than (Days)",
        "description": "When disk is full, delete local recordings older than this many days.",
        "range": (1, 14, 1),
    },
    "INGEST_ENABLED": {
        "section": "ingest",
        "label": "Enable Persistent Ingest",
        "description": "Maintains one ingest connection per camera to feed previews and recordings.",
    },
    "USE_SHM_INGEST": {
        "section": "ingest",
        "label": "Use RAM Disk Ingest",
        "description": "Writes ingest buffers into memory (tmpfs) for speed and to avoid disk churn.",
    },
    "SHM_INGEST_CAMERA_LIMIT_MB": {
        "section": "ingest",
        "label": "Per-Camera RAM Limit (MB)",
        "description": "Maximum memory allowed per camera for ingest buffers.",
        "range": (64, 2048, 64),
    },
    "SHM_INGEST_GLOBAL_LIMIT_MB": {
        "section": "ingest",
        "label": "Global RAM Limit (MB)",
        "description": "Maximum total memory allowed for all ingest buffers.",
        "range": (256, 8192, 256),
    },
    "SHM_INGEST_MIN_FREE_MB": {
        "section": "ingest",
        "label": "Minimum Free RAM (MB)",
        "description": "Minimum free tmpfs space required before ingest buffers can grow.",
        "range": (64, 2048, 64),
    },
    "SHM_INGEST_PROBE_DURATION": {
        "section": "ingest",
        "label": "Probe Duration",
        "description": "Use a longer probe duration when opening streams (slower, but can improve compatibility).",
    },
    "SHM_PROCESSING_REQUIRED": {
        "section": "ingest",
        "label": "Require Memory Processing",
        "description": "When enabled, stream/segment processing is required to occur in memory (tmpfs).",
    },
    "PREVIEW_LOW_FPS": {
        "section": "preview",
        "label": "Preview Low FPS",
        "description": "Lower preview FPS used in low-activity or background contexts.",
        "options": ["0.5", "1", "2", "5", "10", "15", "20", "30"],
    },
    "PREVIEW_HIGH_FPS": {
        "section": "preview",
        "label": "Preview High FPS",
        "description": "Higher preview FPS used when actively viewing a feed.",
        "options": ["0.5", "1", "2", "5", "10", "15", "20", "30"],
    },
    "PREVIEW_CAPTURE_FPS": {
        "section": "preview",
        "label": "Preview Capture FPS",
        "description": "Capture rate for preview frame generation.",
        "options": ["0.5", "1", "2", "5", "10", "15", "20", "30"],
    },
    "PREVIEW_MAX_WIDTH": {
        "section": "preview",
        "label": "Preview Max Width",
        "description": "Limit preview width (0 means unlimited).",
        "range": (0, 3840, 160),
    },
    "PREVIEW_MAX_HEIGHT": {
        "section": "preview",
        "label": "Preview Max Height",
        "description": "Limit preview height (0 means unlimited).",
        "range": (0, 2160, 120),
    },
    "PREVIEW_HISTORY_SECONDS": {
        "section": "preview",
        "label": "Preview History (Seconds)",
        "description": "How long preview snapshots are kept for timeline/scrubbing.",
        "range": (10, 600, 10),
    },
    "PREVIEW_CACHE_DIR": {
        "section": "preview",
        "label": "Preview Cache Directory",
        "description": "Filesystem path where preview snapshots are cached.",
    },
    "STREAMS_ENABLED": {
        "section": "streaming",
        "label": "Enable Live Streams",
        "description": "Enables the live streaming subsystem for camera sessions.",
    },
    "USE_GSTREAMER_CAPTURE": {
        "section": "streaming",
        "label": "Use GStreamer for Capture",
        "description": "Prefer GStreamer pipeline for capturing RTSP feeds when possible.",
    },
    "USE_GSTREAMER_RECORDING": {
        "section": "recording",
        "label": "Use GStreamer for Recording",
        "description": "Prefer GStreamer pipeline for recording when possible.",
    },
    "GST_RTSP_LATENCY_MS": {
        "section": "streaming",
        "label": "RTSP Latency (ms)",
        "description": "GStreamer RTSP latency buffer. Higher is smoother; lower is lower-latency.",
        "range": (0, 2000, 50),
    },
    "STREAM_FFMPEG_DIAGNOSTICS": {
        "section": "diagnostics",
        "label": "FFmpeg Stream Diagnostics",
        "description": "Enables extra FFmpeg diagnostics output for troubleshooting.",
    },
    "RTMP_ENABLED": {
        "section": "integrations",
        "label": "Enable RTMP",
        "description": "Enables RTMP output support.",
    },
    "RTMP_LOW_LATENCY": {
        "section": "integrations",
        "label": "RTMP Low Latency",
        "description": "Optimizes RTMP output for lower latency.",
    },
    "DLNA_ENABLED": {
        "section": "integrations",
        "label": "Enable DLNA",
        "description": "Enables DLNA media server support.",
    },
    "DLNA_FRIENDLY_NAME": {
        "section": "integrations",
        "label": "DLNA Friendly Name",
        "description": "Name shown to DLNA clients.",
    },
    "IPTV_ENABLED": {
        "section": "integrations",
        "label": "Enable IPTV",
        "description": "Enables IPTV output support.",
    },
    "URL_HEALTHCHECK_ENABLED": {
        "section": "diagnostics",
        "label": "URL Healthcheck",
        "description": "Periodically checks camera URLs and reports health.",
    },
    "LOG_SERVER_HOST": {
        "section": "diagnostics",
        "label": "Log Server Host",
        "description": "Host for internal log server ingestion.",
    },
    "LOG_SERVER_PORT": {
        "section": "diagnostics",
        "label": "Log Server Port",
        "description": "Port for internal log server ingestion.",
        "range": (8000, 9000, 1),
    },
    "DIAGNOSTICS_ENABLED": {
        "section": "diagnostics",
        "label": "Enable Diagnostics Crawler",
        "description": "Enables diagnostics crawler support (keep IP-restricted).",
    },
    "DIAGNOSTICS_TOKEN": {
        "section": "diagnostics",
        "label": "Diagnostics Token",
        "description": "Optional token required for diagnostics endpoints.",
    },
    "DIAGNOSTICS_USER_EMAIL": {
        "section": "diagnostics",
        "label": "Diagnostics User Email",
        "description": "Optional email used by diagnostics tooling.",
    },
}


def get_config_ui(key: str) -> dict[str, object]:
    meta = CONFIG_UI.get(str(key or ""), {})
    out: dict[str, object] = {
        "section": str(meta.get("section") or "other"),
        "label": str(meta.get("label") or str(key or "")),
        "description": str(meta.get("description") or ""),
        "protected": bool(meta.get("protected") or False),
        "range": meta.get("range"),
        "options": meta.get("options"),
    }
    return out
