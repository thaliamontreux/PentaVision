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
  port INT NULL,
  username VARCHAR(255) NULL,
  password VARCHAR(255) NULL,
  notes VARCHAR(512) NULL,
  admin_lock TINYINT(1) NULL DEFAULT 0,
  is_active TINYINT(1) NULL,
  created_at DATETIME(6) NULL,
  KEY ix_camera_devices_pattern_id (pattern_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- On MySQL 8+ this is safe and idempotent; on older versions, remove IF NOT EXISTS
ALTER TABLE camera_devices
  ADD COLUMN IF NOT EXISTS admin_lock TINYINT(1) NULL DEFAULT 0
  AFTER notes;

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
