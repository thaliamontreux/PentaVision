from __future__ import annotations

import uuid
from datetime import datetime, date
from typing import Optional

from sqlalchemy import (
    Date,
    DateTime,
    Integer,
    LargeBinary,
    String,
    func,
    inspect,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column


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
    failed_logins: Mapped[int] = mapped_column(Integer, server_default="0")
    locked_until: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    totp_secret: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class LoginFailure(UserBase):
    __tablename__ = "login_failures"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    when: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    username: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    password_enc: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)
    reason: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)


class PropertyScheduleTemplate(UserBase):
    __tablename__ = "property_schedule_templates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    property_id: Mapped[int] = mapped_column(Integer, index=True)
    name: Mapped[str] = mapped_column(String(128), index=True)
    description: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class PropertyScheduleTemplateWindow(UserBase):
    __tablename__ = "property_schedule_template_windows"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    template_id: Mapped[int] = mapped_column(Integer, index=True)
    days_of_week: Mapped[str] = mapped_column(String(32), server_default="0,1,2,3,4,5,6")
    start_time: Mapped[str] = mapped_column(String(8), server_default="00:00")
    end_time: Mapped[str] = mapped_column(String(8), server_default="23:59")
    timezone: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    is_enabled: Mapped[int] = mapped_column(Integer, server_default="1")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class UserPropertyScheduleAssignment(UserBase):
    __tablename__ = "user_property_schedule_assignments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    property_id: Mapped[int] = mapped_column(Integer, index=True)
    user_id: Mapped[int] = mapped_column(Integer, index=True)
    template_id: Mapped[int] = mapped_column(Integer, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class PropertyGroupScheduleAssignment(UserBase):
    __tablename__ = "property_group_schedule_assignments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    property_id: Mapped[int] = mapped_column(Integer, index=True)
    property_group_id: Mapped[int] = mapped_column(Integer, index=True)
    template_id: Mapped[int] = mapped_column(Integer, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class UserPropertyGroupScope(UserBase):
    __tablename__ = "user_property_group_scopes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, index=True)
    property_id: Mapped[int] = mapped_column(Integer, index=True)
    property_group_id: Mapped[int] = mapped_column(Integer, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class UserPropertyRoleOverride(UserBase):
    __tablename__ = "user_property_role_overrides"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, index=True)
    property_id: Mapped[int] = mapped_column(Integer, index=True)
    role_id: Mapped[int] = mapped_column(Integer, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class PropertyZone(UserBase):
    __tablename__ = "property_zones"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    property_id: Mapped[int] = mapped_column(Integer, index=True)
    name: Mapped[str] = mapped_column(String(128), index=True)
    description: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class UserPropertyZoneLink(UserBase):
    __tablename__ = "user_property_zone_links"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, index=True)
    property_id: Mapped[int] = mapped_column(Integer, index=True)
    zone_id: Mapped[int] = mapped_column(Integer, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class UserPropertyAccessWindow(UserBase):
    __tablename__ = "user_property_access_windows"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, index=True)
    property_id: Mapped[int] = mapped_column(Integer, index=True)
    # CSV of day indices (0=Mon .. 6=Sun) to keep things simple with the current
    # migration-lite approach.
    days_of_week: Mapped[str] = mapped_column(String(32), server_default="0,1,2,3,4,5,6")
    start_time: Mapped[str] = mapped_column(String(8), server_default="00:00")
    end_time: Mapped[str] = mapped_column(String(8), server_default="23:59")
    timezone: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    is_enabled: Mapped[int] = mapped_column(Integer, server_default="1")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class PropertyUser(UserBase):
    __tablename__ = "property_users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    property_id: Mapped[int] = mapped_column(Integer, index=True)
    username: Mapped[str] = mapped_column(String(128), index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    pin_hash: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    full_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    is_active: Mapped[int] = mapped_column(Integer, server_default="1")
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
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class PropertyRole(UserBase):
    __tablename__ = "property_roles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    property_id: Mapped[int] = mapped_column(Integer, index=True)
    name: Mapped[str] = mapped_column(String(128), index=True)
    description: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class PropertyGroup(UserBase):
    __tablename__ = "property_groups"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    property_id: Mapped[int] = mapped_column(Integer, index=True)
    name: Mapped[str] = mapped_column(String(128), index=True)
    description: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class PropertyGroupMember(UserBase):
    __tablename__ = "property_group_members"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_id: Mapped[int] = mapped_column(Integer, index=True)
    property_user_id: Mapped[int] = mapped_column(Integer, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class PropertyUserRole(UserBase):
    __tablename__ = "property_user_roles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    property_user_id: Mapped[int] = mapped_column(Integer, index=True)
    role_id: Mapped[int] = mapped_column(Integer, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class CameraStorageScheduleEntry(RecordBase):
    __tablename__ = "camera_storage_schedule_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(Integer, index=True)
    storage_targets: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    retention_days: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    mode: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    days_of_week: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    start_time: Mapped[Optional[str]] = mapped_column(String(8), nullable=True)
    end_time: Mapped[Optional[str]] = mapped_column(String(8), nullable=True)
    is_enabled: Mapped[int] = mapped_column(Integer, server_default="1")
    priority: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class BlocklistDistributionSettings(UserBase):
    __tablename__ = "blocklist_distribution_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    enabled: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    consumer_allow_cidrs: Mapped[Optional[str]] = mapped_column(
        String(2048), nullable=True
    )
    token_enabled: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    token: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    ttl_seconds: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    rate_limit_per_min: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class SiteTheme(UserBase):
    __tablename__ = "site_themes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scope: Mapped[str] = mapped_column(String(16))
    slug: Mapped[str] = mapped_column(String(64))
    name: Mapped[str] = mapped_column(String(128))
    is_system: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    is_readonly: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    theme_json: Mapped[Optional[str]] = mapped_column(String(8192), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class SiteThemeSettings(UserBase):
    __tablename__ = "site_theme_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    main_theme: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    admin_theme: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class CameraRtmpOutput(RecordBase):
    __tablename__ = "camera_rtmp_outputs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(Integer, index=True)
    target_url: Mapped[str] = mapped_column(String(512))
    is_active: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    last_error: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    last_started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class CameraDlnaMedia(RecordBase):
    __tablename__ = "camera_dlna_media"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(Integer, index=True, unique=True)
    is_enabled: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    title: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    last_error: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    last_started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class IpAllowlist(UserBase):
    __tablename__ = "ip_allowlist"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cidr: Mapped[str] = mapped_column(String(64), unique=True)
    description: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class IpBlocklist(UserBase):
    __tablename__ = "ip_blocklist"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cidr: Mapped[str] = mapped_column(String(64), unique=True)
    description: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class CountryAccessPolicy(UserBase):
    __tablename__ = "country_access_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    mode: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    allowed_countries: Mapped[Optional[str]] = mapped_column(
        String(512), nullable=True
    )
    blocked_countries: Mapped[Optional[str]] = mapped_column(
        String(512), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class StorageProviderModule(RecordBase):
    __tablename__ = "storage_provider_modules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider_type: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    display_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    category: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    definition_json: Mapped[Optional[str]] = mapped_column(String(8192), nullable=True)
    template_path: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    wizard_path: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    is_installed: Mapped[int] = mapped_column(Integer, server_default="1")
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class StorageModule(RecordBase):
    __tablename__ = "storage_modules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Unique name used by workers and policies (for example, "gcs:corp-backups").
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    # Human-friendly label shown in the UI (for example, "Corp GCS – Backups").
    label: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    # Provider type key, such as "local_fs", "db", "s3", "gcs", "azure_blob",
    # "dropbox", "webdav", "gdrive", etc.
    provider_type: Mapped[str] = mapped_column(String(64))
    # When disabled, this module is ignored by build_storage_providers and never
    # instantiated by the recording workers.
    is_enabled: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    # Global ordering for primary + failover routing (lower number = higher priority).
    priority: Mapped[int] = mapped_column(Integer, server_default="100")
    # Provider-specific configuration stored as a JSON-encoded object. This keeps
    # the schema flexible so that each provider can define its own fields without
    # requiring additional columns.
    config_json: Mapped[Optional[str]] = mapped_column(String(4096), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class DlnaSettings(RecordBase):
    __tablename__ = "dlna_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    enabled: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    interface_name: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True
    )
    bind_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    network_cidr: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    last_started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_error: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
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
    uid: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
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
    mac_address: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    username: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    password: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    admin_lock: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    is_active: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    placement: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    location: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    facing_direction: Mapped[Optional[str]] = mapped_column(String(8), nullable=True)
    pattern_params: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
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


class StorageModuleHealthCheck(RecordBase):
    __tablename__ = "storage_module_health_checks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    module_id: Mapped[Optional[int]] = mapped_column(Integer, index=True, nullable=True)
    module_name: Mapped[str] = mapped_column(String(160), index=True)
    provider_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    ok: Mapped[int] = mapped_column(Integer, server_default="0")
    message: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class StorageModuleEvent(RecordBase):
    __tablename__ = "storage_module_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    module_id: Mapped[Optional[int]] = mapped_column(Integer, index=True, nullable=True)
    module_name: Mapped[str] = mapped_column(String(160), index=True)
    level: Mapped[str] = mapped_column(String(16), server_default="info")
    event_type: Mapped[str] = mapped_column(String(64), server_default="event")
    message: Mapped[str] = mapped_column(String(1024))
    stream_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class StorageModuleWriteStat(RecordBase):
    __tablename__ = "storage_module_write_stats"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    module_id: Mapped[Optional[int]] = mapped_column(Integer, index=True, nullable=True)
    module_name: Mapped[str] = mapped_column(String(160), index=True)
    device_id: Mapped[Optional[int]] = mapped_column(Integer, index=True, nullable=True)
    storage_key: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    bytes_written: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    ok: Mapped[int] = mapped_column(Integer, server_default="1")
    error: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
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
    use_auth: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    source: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    is_active: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    device_type: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    oui_regex: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    video_encoding: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    default_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    streams_raw: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    channels_raw: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    stream_names_raw: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    channel_names_raw: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    low_res_stream: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    high_res_stream: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    default_username: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    default_password: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    digest_auth_supported: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    manual_url: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)


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


class CameraRecordingSchedule(RecordBase):
    __tablename__ = "camera_recording_schedules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(Integer, index=True, unique=True)
    timezone: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    mode: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    days_of_week: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    start_time: Mapped[Optional[str]] = mapped_column(String(8), nullable=True)
    end_time: Mapped[Optional[str]] = mapped_column(String(8), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class CameraRecordingWindow(RecordBase):
    __tablename__ = "camera_recording_windows"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    schedule_id: Mapped[int] = mapped_column(Integer, index=True)
    day_of_week: Mapped[int] = mapped_column(Integer, index=True)
    start_time: Mapped[str] = mapped_column(String(8))
    end_time: Mapped[str] = mapped_column(String(8))
    mode: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
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


class CameraGroupLink(RecordBase):
    __tablename__ = "camera_group_links"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(Integer, index=True, unique=True)
    property_id: Mapped[int] = mapped_column(Integer, index=True)
    property_group_id: Mapped[int] = mapped_column(Integer, index=True)
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
    try:
        insp = inspect(engine)
        cols = {c.get("name") for c in insp.get_columns("users")}
        if "timezone" not in cols:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE users ADD COLUMN timezone VARCHAR(64)"))
    except Exception:  # noqa: BLE001
        pass

    # Migration-lite: ensure Property has a stable UID for tenant DB naming.
    try:
        insp = inspect(engine)
        cols = {c.get("name") for c in insp.get_columns("properties")}
        if "uid" not in cols:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE properties ADD COLUMN uid VARCHAR(64)"))

        with Session(engine) as db:
            missing = (
                db.query(Property)
                .filter(
                    (Property.uid == None)  # noqa: E711
                )
                .all()
            )
            if missing:
                for prop in missing:
                    prop.uid = uuid.uuid4().hex
                    db.add(prop)
                db.commit()
    except Exception:  # noqa: BLE001
        pass


def create_property_schema(engine) -> None:
    """Create tables for a per-property tenant database on the given engine."""

    for tbl in (
        PropertyUser.__table__,
        PropertyRole.__table__,
        PropertyUserRole.__table__,
        PropertyGroup.__table__,
        PropertyGroupMember.__table__,
        PropertyZone.__table__,
        UserPropertyZoneLink.__table__,
        UserPropertyAccessWindow.__table__,
    ):
        tbl.create(bind=engine, checkfirst=True)

    # Migration-lite: property user PIN support.
    try:
        insp = inspect(engine)
        cols = {c.get("name") for c in insp.get_columns("property_users")}
        alters: list[str] = []
        if "pin_hash" not in cols:
            alters.append("ADD COLUMN pin_hash VARCHAR(255) NULL")
        if "failed_pin_attempts" not in cols:
            alters.append("ADD COLUMN failed_pin_attempts INTEGER NOT NULL DEFAULT 0")
        if "pin_locked_until" not in cols:
            alters.append("ADD COLUMN pin_locked_until DATETIME(6) NULL")
        if "last_login_at" not in cols:
            alters.append("ADD COLUMN last_login_at DATETIME(6) NULL")
        if "last_pin_use_at" not in cols:
            alters.append("ADD COLUMN last_pin_use_at DATETIME(6) NULL")
        if alters:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE property_users " + ", ".join(alters)))
    except Exception:  # noqa: BLE001
        pass


def create_face_schema(engine) -> None:
    """Create tables for the facial embeddings DB on the given engine."""

    FaceBase.metadata.create_all(engine)


def create_record_schema(engine) -> None:
    """Create tables for the recordings/metadata DB on the given engine."""

    RecordBase.metadata.create_all(engine)

    # Migration-lite: add new columns to existing deployments without requiring a full
    # migration framework.
    try:
        insp = inspect(engine)
        cols = {c.get("name") for c in insp.get_columns("storage_modules")}
        if "priority" not in cols:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE storage_modules ADD COLUMN priority INTEGER DEFAULT 100"))
    except Exception:  # noqa: BLE001
        pass


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

