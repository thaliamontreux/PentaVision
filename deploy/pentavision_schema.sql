-- PentaVision schema bootstrap / upgrade
-- Adjust DB names if yours differ from pe_users / pe_faces / pe_records.

/**************************************************************************
 * USER / AUTH / RBAC / PROPERTIES / NOTIFICATIONS / AUDIT  (pe_users)
 **************************************************************************/
USE pe_users;

CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(255) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  full_name VARCHAR(255) NULL,
  preferred_name VARCHAR(255) NULL,
  pronouns VARCHAR(64) NULL,
  date_of_birth DATE NULL,
  primary_phone VARCHAR(32) NULL,
  secondary_phone VARCHAR(32) NULL,
  secondary_email VARCHAR(255) NULL,
  emergency_contact_name VARCHAR(255) NULL,
  emergency_contact_phone VARCHAR(32) NULL,
  sms_alert_number VARCHAR(32) NULL,
  email_alert_address VARCHAR(255) NULL,
  primary_address_line1 VARCHAR(255) NULL,
  primary_address_line2 VARCHAR(255) NULL,
  primary_city VARCHAR(128) NULL,
  primary_state VARCHAR(64) NULL,
  primary_postal_code VARCHAR(32) NULL,
  primary_country VARCHAR(64) NULL,
  timezone VARCHAR(64) NULL,
  mfa_preference VARCHAR(32) NULL,
  session_display_size VARCHAR(32) NULL,
  dashboard_display_size VARCHAR(32) NULL,
  account_status VARCHAR(32) NULL,
  created_by_admin_id INT NULL,
  modified_at DATETIME(6) NULL,
  deactivation_reason VARCHAR(512) NULL,
  disarm_pin_hash VARCHAR(255) NULL,
  failed_pin_attempts INT NOT NULL DEFAULT 0,
  pin_locked_until DATETIME(6) NULL,
  last_login_at DATETIME(6) NULL,
  last_pin_use_at DATETIME(6) NULL,
  last_pin_use_context VARCHAR(255) NULL,
  created_at DATETIME(6) NULL,
  failed_logins INT NOT NULL DEFAULT 0,
  locked_until DATETIME(6) NULL,
  totp_secret VARCHAR(255) NULL,
  UNIQUE KEY ux_users_email (email),
  KEY ix_users_created_by_admin_id (created_by_admin_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS session_display_size VARCHAR(32) NULL AFTER mfa_preference,
  ADD COLUMN IF NOT EXISTS dashboard_display_size VARCHAR(32) NULL AFTER session_display_size;

CREATE TABLE IF NOT EXISTS webauthn_credentials (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  credential_id LONGBLOB NOT NULL,
  public_key LONGBLOB NOT NULL,
  sign_count INT NOT NULL DEFAULT 0,
  transports VARCHAR(255) NULL,
  nickname VARCHAR(255) NULL,
  created_at DATETIME(6) NULL,
  last_used_at DATETIME(6) NULL,
  KEY ix_webauthn_user_id (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS properties (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  address_line1 VARCHAR(255) NULL,
  address_line2 VARCHAR(255) NULL,
  city VARCHAR(128) NULL,
  state VARCHAR(64) NULL,
  postal_code VARCHAR(32) NULL,
  country VARCHAR(64) NULL,
  timezone VARCHAR(64) NULL,
  created_at DATETIME(6) NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS user_properties (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  property_id INT NOT NULL,
  residency_status VARCHAR(32) NULL,
  authorized_zones VARCHAR(512) NULL,
  camera_scope VARCHAR(512) NULL,
  access_windows VARCHAR(512) NULL,
  role_overrides VARCHAR(512) NULL,
  created_at DATETIME(6) NULL,
  KEY ix_user_properties_user_id (user_id),
  KEY ix_user_properties_property_id (property_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS roles (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(128) NOT NULL,
  scope VARCHAR(32) NULL,
  description VARCHAR(512) NULL,
  created_at DATETIME(6) NULL,
  UNIQUE KEY ux_roles_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS permissions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(128) NOT NULL,
  description VARCHAR(512) NULL,
  created_at DATETIME(6) NULL,
  UNIQUE KEY ux_permissions_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS role_permissions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  role_id INT NOT NULL,
  permission_id INT NOT NULL,
  KEY ix_role_permissions_role_id (role_id),
  KEY ix_role_permissions_permission_id (permission_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS user_roles (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  role_id INT NOT NULL,
  property_id INT NULL,
  created_at DATETIME(6) NULL,
  KEY ix_user_roles_user_id (user_id),
  KEY ix_user_roles_role_id (role_id),
  KEY ix_user_roles_property_id (property_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS user_notification_settings (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  intrusion_alerts INT NULL,
  fire_alerts INT NULL,
  system_faults INT NULL,
  camera_motion_events INT NULL,
  door_window_activity INT NULL,
  environmental_alerts INT NULL,
  escalation_level VARCHAR(32) NULL,
  created_at DATETIME(6) NULL,
  UNIQUE KEY ux_user_notification_user_id (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS audit_events (
  id INT AUTO_INCREMENT PRIMARY KEY,
  `when` DATETIME(6) NULL,
  user_id INT NULL,
  event_type VARCHAR(64) NOT NULL,
  ip VARCHAR(64) NULL,
  details VARCHAR(1024) NULL,
  KEY ix_audit_events_user_id (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS blocklist_distribution_settings (
  id INT AUTO_INCREMENT PRIMARY KEY,
  enabled INT NULL,
  consumer_allow_cidrs VARCHAR(2048) NULL,
  token_enabled INT NULL,
  token VARCHAR(255) NULL,
  ttl_seconds INT NULL,
  rate_limit_per_min INT NULL,
  created_at DATETIME(6) NULL,
  updated_at DATETIME(6) NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS ip_allowlist (
  id INT AUTO_INCREMENT PRIMARY KEY,
  cidr VARCHAR(64) NOT NULL,
  description VARCHAR(255) NULL,
  created_at DATETIME(6) NULL,
  UNIQUE KEY ux_ip_allowlist_cidr (cidr)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS ip_blocklist (
  id INT AUTO_INCREMENT PRIMARY KEY,
  cidr VARCHAR(64) NOT NULL,
  description VARCHAR(255) NULL,
  created_at DATETIME(6) NULL,
  UNIQUE KEY ux_ip_blocklist_cidr (cidr)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS country_access_policies (
  id INT AUTO_INCREMENT PRIMARY KEY,
  mode VARCHAR(32) NULL,
  allowed_countries VARCHAR(512) NULL,
  blocked_countries VARCHAR(512) NULL,
  created_at DATETIME(6) NULL,
  updated_at DATETIME(6) NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

/**************************************************************************
 * FACE EMBEDDINGS & PRIVACY (pe_faces)
 **************************************************************************/
USE pe_faces;

CREATE TABLE IF NOT EXISTS face_embeddings (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  embedding LONGBLOB NOT NULL,
  created_at DATETIME(6) NULL,
  KEY ix_face_embeddings_user_id (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS face_privacy_settings (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  is_opted_out INT NULL,
  created_at DATETIME(6) NULL,
  UNIQUE KEY ux_face_privacy_user_id (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

/**************************************************************************
 * CAMERAS / RECORDINGS / STORAGE / QUEUE (pe_records)
 **************************************************************************/
USE pe_records;

CREATE TABLE IF NOT EXISTS camera_devices (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  pattern_id INT NULL,
  ip_address VARCHAR(255) NOT NULL,
  mac_address VARCHAR(32) NULL,
  port INT NULL,
  username VARCHAR(255) NULL,
  password VARCHAR(255) NULL,
  notes VARCHAR(512) NULL,
  admin_lock TINYINT(1) NULL,
  is_active TINYINT(1) NULL,
  placement VARCHAR(16) NULL,
  location VARCHAR(64) NULL,
  facing_direction VARCHAR(8) NULL,
  pattern_params VARCHAR(1024) NULL,
  created_at DATETIME(6) NULL,
  KEY ix_camera_devices_pattern_id (pattern_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- On MySQL 8+ this is safe and idempotent; on older versions, remove IF NOT EXISTS
ALTER TABLE camera_devices
  ADD COLUMN IF NOT EXISTS admin_lock TINYINT(1) NULL DEFAULT 0 AFTER notes,
  ADD COLUMN IF NOT EXISTS mac_address VARCHAR(32) NULL AFTER ip_address,
  ADD COLUMN IF NOT EXISTS placement VARCHAR(16) NULL AFTER is_active,
  ADD COLUMN IF NOT EXISTS location VARCHAR(64) NULL AFTER placement,
  ADD COLUMN IF NOT EXISTS facing_direction VARCHAR(8) NULL AFTER location,
  ADD COLUMN IF NOT EXISTS pattern_params VARCHAR(1024) NULL AFTER facing_direction;

CREATE TABLE IF NOT EXISTS recordings (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  storage_provider VARCHAR(100) NOT NULL,
  storage_key VARCHAR(512) NOT NULL,
  created_at DATETIME(6) NULL,
  KEY ix_recordings_user_id (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS recording_data (
  id INT AUTO_INCREMENT PRIMARY KEY,
  data LONGBLOB NOT NULL,
  created_at DATETIME(6) NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS camera_recordings (
  id INT AUTO_INCREMENT PRIMARY KEY,
  device_id INT NOT NULL,
  storage_provider VARCHAR(100) NOT NULL,
  storage_key VARCHAR(512) NOT NULL,
  created_at DATETIME(6) NULL,
  KEY ix_camera_recordings_device_id (device_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS camera_url_patterns (
  id INT AUTO_INCREMENT PRIMARY KEY,
  manufacturer VARCHAR(128) NOT NULL,
  model_or_note VARCHAR(255) NULL,
  protocol VARCHAR(32) NULL,
  rtsp_url_pattern VARCHAR(512) NOT NULL,
  source VARCHAR(255) NULL,
  is_active INT NULL,
  created_at DATETIME(6) NULL,
  KEY ix_camera_patterns_manufacturer (manufacturer)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- On MySQL 8+ this is safe and idempotent; on older versions, remove IF NOT EXISTS
ALTER TABLE camera_url_patterns
  ADD COLUMN IF NOT EXISTS use_auth INT NULL DEFAULT 1 AFTER rtsp_url_pattern;

ALTER TABLE camera_url_patterns
  ADD COLUMN IF NOT EXISTS device_type VARCHAR(32) NULL,
  ADD COLUMN IF NOT EXISTS oui_regex VARCHAR(512) NULL,
  ADD COLUMN IF NOT EXISTS video_encoding VARCHAR(32) NULL,
  ADD COLUMN IF NOT EXISTS default_port INT NULL,
  ADD COLUMN IF NOT EXISTS streams_raw VARCHAR(255) NULL,
  ADD COLUMN IF NOT EXISTS channels_raw VARCHAR(255) NULL,
  ADD COLUMN IF NOT EXISTS stream_names_raw VARCHAR(255) NULL,
  ADD COLUMN IF NOT EXISTS channel_names_raw VARCHAR(255) NULL,
  ADD COLUMN IF NOT EXISTS low_res_stream VARCHAR(32) NULL,
  ADD COLUMN IF NOT EXISTS high_res_stream VARCHAR(32) NULL,
  ADD COLUMN IF NOT EXISTS default_username VARCHAR(255) NULL,
  ADD COLUMN IF NOT EXISTS default_password VARCHAR(255) NULL,
  ADD COLUMN IF NOT EXISTS digest_auth_supported TINYINT(1) NULL,
  ADD COLUMN IF NOT EXISTS manual_url VARCHAR(1024) NULL;

CREATE TABLE IF NOT EXISTS camera_storage_policies (
  id INT AUTO_INCREMENT PRIMARY KEY,
  device_id INT NOT NULL,
  storage_targets VARCHAR(255) NULL,
  retention_days INT NULL,
  created_at DATETIME(6) NULL,
  UNIQUE KEY ux_camera_storage_device_id (device_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS camera_property_links (
  id INT AUTO_INCREMENT PRIMARY KEY,
  device_id INT NOT NULL,
  property_id INT NOT NULL,
  created_at DATETIME(6) NULL,
  UNIQUE KEY ux_camera_property_device_id (device_id),
  KEY ix_camera_property_property_id (property_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS upload_queue (
  id INT AUTO_INCREMENT PRIMARY KEY,
  device_id INT NOT NULL,
  provider_name VARCHAR(100) NOT NULL,
  key_hint VARCHAR(255) NOT NULL,
  payload LONGBLOB NOT NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'pending',
  attempts INT NOT NULL DEFAULT 0,
  last_error VARCHAR(512) NULL,
  created_at DATETIME(6) NULL,
  KEY ix_upload_queue_device_id (device_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS storage_provider_modules (
  id INT AUTO_INCREMENT PRIMARY KEY,
  provider_type VARCHAR(64) NOT NULL,
  display_name VARCHAR(255) NULL,
  category VARCHAR(128) NULL,
  definition_json VARCHAR(8192) NULL,
  template_path VARCHAR(512) NULL,
  wizard_path VARCHAR(512) NULL,
  is_installed INT NOT NULL DEFAULT 1,
  last_seen_at DATETIME(6) NULL,
  created_at DATETIME(6) NULL,
  updated_at DATETIME(6) NULL,
  UNIQUE KEY ux_storage_provider_modules_provider_type (provider_type),
  KEY ix_storage_provider_modules_provider_type (provider_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS storage_modules (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  label VARCHAR(255) NULL,
  provider_type VARCHAR(64) NOT NULL,
  is_enabled INT NULL,
  priority INT NOT NULL DEFAULT 100,
  config_json VARCHAR(4096) NULL,
  created_at DATETIME(6) NULL,
  updated_at DATETIME(6) NULL,
  UNIQUE KEY ux_storage_modules_name (name),
  KEY ix_storage_modules_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS storage_module_health_checks (
  id INT AUTO_INCREMENT PRIMARY KEY,
  module_id INT NULL,
  module_name VARCHAR(160) NOT NULL,
  provider_type VARCHAR(64) NULL,
  ok INT NOT NULL DEFAULT 0,
  message VARCHAR(512) NULL,
  duration_ms INT NULL,
  created_at DATETIME(6) NULL,
  KEY ix_storage_module_health_checks_module_id (module_id),
  KEY ix_storage_module_health_checks_module_name (module_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS storage_module_events (
  id INT AUTO_INCREMENT PRIMARY KEY,
  module_id INT NULL,
  module_name VARCHAR(160) NOT NULL,
  level VARCHAR(16) NOT NULL DEFAULT 'info',
  event_type VARCHAR(64) NOT NULL DEFAULT 'event',
  message VARCHAR(1024) NOT NULL,
  stream_id VARCHAR(128) NULL,
  created_at DATETIME(6) NULL,
  KEY ix_storage_module_events_module_id (module_id),
  KEY ix_storage_module_events_module_name (module_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS storage_module_write_stats (
  id INT AUTO_INCREMENT PRIMARY KEY,
  module_id INT NULL,
  module_name VARCHAR(160) NOT NULL,
  device_id INT NULL,
  storage_key VARCHAR(512) NULL,
  bytes_written INT NULL,
  ok INT NOT NULL DEFAULT 1,
  error VARCHAR(512) NULL,
  created_at DATETIME(6) NULL,
  KEY ix_storage_module_write_stats_module_id (module_id),
  KEY ix_storage_module_write_stats_module_name (module_name),
  KEY ix_storage_module_write_stats_device_id (device_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS camera_recording_schedules (
  id INT AUTO_INCREMENT PRIMARY KEY,
  device_id INT NOT NULL,
  timezone VARCHAR(64) NULL,
  mode VARCHAR(32) NULL,
  days_of_week VARCHAR(32) NULL,
  start_time VARCHAR(8) NULL,
  end_time VARCHAR(8) NULL,
  created_at DATETIME(6) NULL,
  updated_at DATETIME(6) NULL,
  UNIQUE KEY ux_camera_recording_schedules_device_id (device_id),
  KEY ix_camera_recording_schedules_device_id (device_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS camera_recording_windows (
  id INT AUTO_INCREMENT PRIMARY KEY,
  schedule_id INT NOT NULL,
  day_of_week INT NOT NULL,
  start_time VARCHAR(8) NOT NULL,
  end_time VARCHAR(8) NOT NULL,
  mode VARCHAR(32) NULL,
  created_at DATETIME(6) NULL,
  KEY ix_camera_recording_windows_schedule_id (schedule_id),
  KEY ix_camera_recording_windows_day_of_week (day_of_week)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS dlna_settings (
  id INT AUTO_INCREMENT PRIMARY KEY,
  enabled INT NULL,
  interface_name VARCHAR(64) NULL,
  bind_address VARCHAR(64) NULL,
  network_cidr VARCHAR(64) NULL,
  last_started_at DATETIME(6) NULL,
  last_error VARCHAR(512) NULL,
  created_at DATETIME(6) NULL,
  updated_at DATETIME(6) NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS camera_rtmp_outputs (
  id INT AUTO_INCREMENT PRIMARY KEY,
  device_id INT NOT NULL,
  target_url VARCHAR(512) NOT NULL,
  is_active INT NULL,
  created_at DATETIME(6) NULL,
  last_error VARCHAR(512) NULL,
  last_started_at DATETIME(6) NULL,
  KEY ix_camera_rtmp_outputs_device_id (device_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS camera_dlna_media (
  id INT AUTO_INCREMENT PRIMARY KEY,
  device_id INT NOT NULL,
  is_enabled INT NULL,
  title VARCHAR(255) NULL,
  last_error VARCHAR(512) NULL,
  last_started_at DATETIME(6) NULL,
  created_at DATETIME(6) NULL,
  UNIQUE KEY ux_camera_dlna_media_device_id (device_id),
  KEY ix_camera_dlna_media_device_id (device_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
