from __future__ import annotations

from datetime import datetime, date
from typing import Optional

from sqlalchemy import Date, DateTime, Integer, LargeBinary, String, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class UserBase(DeclarativeBase):
    """Declarative base for the user/auth database."""


class FaceBase(DeclarativeBase):
    """Declarative base for the facial embeddings database."""


class RecordBase(DeclarativeBase):
    """Declarative base for the recordings/metadata database."""


class AuditBase(DeclarativeBase):
    """Declarative base for the audit logging database.

    In smaller deployments this may share the same physical database as the
    user/auth schema; in larger or more regulated environments it can be
    moved to a dedicated, locked-down database or instance.
    """


class User(UserBase):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    full_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    preferred_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    pronouns: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    date_of_birth: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    primary_phone: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    secondary_phone: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    secondary_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    emergency_contact_name: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )
    emergency_contact_phone: Mapped[Optional[str]] = mapped_column(
        String(32), nullable=True
    )
    sms_alert_number: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    email_alert_address: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )
    primary_address_line1: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )
    primary_address_line2: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )
    primary_city: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    primary_state: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    primary_postal_code: Mapped[Optional[str]] = mapped_column(
        String(32), nullable=True
    )
    primary_country: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True
    )
    timezone: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    mfa_preference: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    session_display_size: Mapped[Optional[str]] = mapped_column(
        String(32), nullable=True
    )
    dashboard_display_size: Mapped[Optional[str]] = mapped_column(
        String(32), nullable=True
    )
    account_status: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    created_by_admin_id: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True, index=True
    )
    modified_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    deactivation_reason: Mapped[Optional[str]] = mapped_column(
        String(512), nullable=True
    )
    disarm_pin_hash: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    failed_pin_attempts: Mapped[int] = mapped_column(Integer, server_default="0")
    pin_locked_until: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_login_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_pin_use_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_pin_use_context: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class StorageSettings(RecordBase):
    __tablename__ = "storage_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    storage_targets: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )
    local_storage_path: Mapped[Optional[str]] = mapped_column(
        String(512), nullable=True
    )
    recording_base_dir: Mapped[Optional[str]] = mapped_column(
        String(512), nullable=True
    )
    s3_bucket: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    s3_endpoint: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    s3_region: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    s3_access_key: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )
    s3_secret_key: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )
    gcs_bucket: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    azure_blob_connection_string: Mapped[Optional[str]] = mapped_column(
        String(1024), nullable=True
    )
    azure_blob_container: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )
    dropbox_access_token: Mapped[Optional[str]] = mapped_column(
        String(512), nullable=True
    )
    webdav_base_url: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    webdav_username: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )
    webdav_password: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class WebAuthnCredential(UserBase):
    __tablename__ = "webauthn_credentials"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, index=True)
    credential_id: Mapped[bytes] = mapped_column(LargeBinary)
    public_key: Mapped[bytes] = mapped_column(LargeBinary)
    sign_count: Mapped[int] = mapped_column(Integer, server_default="0")
    transports: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    nickname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    last_used_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class Property(UserBase):
    __tablename__ = "properties"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    address_line1: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    address_line2: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    city: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    state: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    postal_code: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    country: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    timezone: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class UserProperty(UserBase):
    __tablename__ = "user_properties"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, index=True)
    property_id: Mapped[int] = mapped_column(Integer, index=True)
    residency_status: Mapped[Optional[str]] = mapped_column(
        String(32), nullable=True
    )
    authorized_zones: Mapped[Optional[str]] = mapped_column(
        String(512), nullable=True
    )
    camera_scope: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    access_windows: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    role_overrides: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class Role(UserBase):
    __tablename__ = "roles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    scope: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class Permission(UserBase):
    __tablename__ = "permissions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    description: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class RolePermission(UserBase):
    __tablename__ = "role_permissions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    role_id: Mapped[int] = mapped_column(Integer, index=True)
    permission_id: Mapped[int] = mapped_column(Integer, index=True)


class UserRole(UserBase):
    __tablename__ = "user_roles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, index=True)
    role_id: Mapped[int] = mapped_column(Integer, index=True)
    property_id: Mapped[Optional[int]] = mapped_column(Integer, index=True, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class UserNotificationSettings(UserBase):
    __tablename__ = "user_notification_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, index=True, unique=True)
    intrusion_alerts: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    fire_alerts: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    system_faults: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    camera_motion_events: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    door_window_activity: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    environmental_alerts: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    escalation_level: Mapped[Optional[str]] = mapped_column(
        String(32), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class CameraDevice(RecordBase):
    __tablename__ = "camera_devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    pattern_id: Mapped[Optional[int]] = mapped_column(Integer, index=True, nullable=True)
    ip_address: Mapped[str] = mapped_column(String(255))
    port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    username: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    password: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    admin_lock: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    is_active: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    placement: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    location: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    facing_direction: Mapped[Optional[str]] = mapped_column(String(8), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class FaceEmbedding(FaceBase):
    __tablename__ = "face_embeddings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, index=True)
    embedding: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class FacePrivacySetting(FaceBase):
    __tablename__ = "face_privacy_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, index=True, unique=True)
    is_opted_out: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class Recording(RecordBase):
    __tablename__ = "recordings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, index=True)
    storage_provider: Mapped[str] = mapped_column(String(100))
    storage_key: Mapped[str] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class RecordingData(RecordBase):
    __tablename__ = "recording_data"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    data: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class CameraRecording(RecordBase):
    __tablename__ = "camera_recordings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(Integer, index=True)
    storage_provider: Mapped[str] = mapped_column(String(100))
    storage_key: Mapped[str] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class CameraUrlPattern(RecordBase):
    __tablename__ = "camera_url_patterns"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    manufacturer: Mapped[str] = mapped_column(String(128), index=True)
    model_or_note: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    rtsp_url_pattern: Mapped[str] = mapped_column(String(512))
    source: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    is_active: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class CameraStoragePolicy(RecordBase):
    __tablename__ = "camera_storage_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(Integer, index=True, unique=True)
    storage_targets: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )
    retention_days: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class CameraPropertyLink(RecordBase):
    __tablename__ = "camera_property_links"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(Integer, index=True, unique=True)
    property_id: Mapped[int] = mapped_column(Integer, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class UploadQueueItem(RecordBase):
    __tablename__ = "upload_queue"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(Integer, index=True)
    provider_name: Mapped[str] = mapped_column(String(100))
    key_hint: Mapped[str] = mapped_column(String(255))
    payload: Mapped[bytes] = mapped_column(LargeBinary)
    status: Mapped[str] = mapped_column(String(32), server_default="pending")
    attempts: Mapped[int] = mapped_column(Integer, server_default="0")
    last_error: Mapped[Optional[str]] = mapped_column(
        String(512), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


def create_user_schema(engine) -> None:
    """Create tables for the user DB on the given engine."""

    UserBase.metadata.create_all(engine)


def create_face_schema(engine) -> None:
    """Create tables for the facial embeddings DB on the given engine."""

    FaceBase.metadata.create_all(engine)


def create_record_schema(engine) -> None:
    """Create tables for the recordings/metadata DB on the given engine."""

    RecordBase.metadata.create_all(engine)


class AuditEvent(AuditBase):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    when: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    user_id: Mapped[Optional[int]] = mapped_column(Integer, index=True, nullable=True)
    event_type: Mapped[str] = mapped_column(String(64))
    ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    details: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)


def create_audit_schema(engine) -> None:
    """Create tables for the audit logging DB on the given engine."""

    AuditBase.metadata.create_all(engine)
