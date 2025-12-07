from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Integer, LargeBinary, String, func
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
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    failed_logins: Mapped[int] = mapped_column(Integer, server_default="0")
    locked_until: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    totp_secret: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)


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
    is_active: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
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
