"""Constants for the PentaVision integration."""

DOMAIN = "pentavision"

# Configuration
CONF_HOST = "host"
CONF_PORT = "port"
CONF_API_KEY = "api_key"

# Defaults
DEFAULT_PORT = 8473
DEFAULT_NAME = "PentaVision"

# API Endpoints
API_HANDSHAKE_INIT = "/api/auth/handshake/init"
API_HANDSHAKE_COMPLETE = "/api/auth/handshake/complete"
API_SESSION_REVOKE = "/api/auth/session/revoke"
API_CAMERAS = "/api/cameras"
API_CAMERA_INFO = "/api/cameras/{camera_id}"
API_CAMERA_SNAPSHOT = "/api/cameras/{camera_id}/snapshot"
API_CAMERA_STREAM = "/api/cameras/{camera_id}/stream"
API_MJPEG_STREAM = "/stream/mjpeg/{camera_id}"
API_HLS_PLAYLIST = "/stream/hls/{camera_id}/index.m3u8"
API_STATUS = "/api/status"
API_EVENTS = "/api/events"
API_PTZ = "/api/cameras/{camera_id}/ptz"

# Attributes
ATTR_CAMERA_ID = "camera_id"
ATTR_CAMERA_NAME = "camera_name"
ATTR_PROPERTY_ID = "property_id"
ATTR_STREAM_URL = "stream_url"
ATTR_SNAPSHOT_URL = "snapshot_url"
ATTR_PTZ_CAPABLE = "ptz_capable"
ATTR_RECORDING = "recording"
ATTR_MOTION_DETECTED = "motion_detected"

# Services
SERVICE_PTZ_MOVE = "ptz_move"
SERVICE_PTZ_PRESET = "ptz_preset"
SERVICE_SNAPSHOT = "take_snapshot"

# Events
EVENT_MOTION_DETECTED = f"{DOMAIN}_motion_detected"
EVENT_CAMERA_OFFLINE = f"{DOMAIN}_camera_offline"
EVENT_CAMERA_ONLINE = f"{DOMAIN}_camera_online"
