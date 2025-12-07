# Application Configuration

This document describes how to configure the PentaVision app using environment
variables (typically stored in a `.env` file loaded by `python-dotenv`). It
covers database URLs, storage providers, streaming, authentication, and
recognition thresholds.

## Loading configuration

On startup, `app/config.py` reads settings from the process environment:

- Place a `.env` file in the project root, or
- Set variables via your process manager (systemd, Docker, etc.).

The `load_config()` helper exposes these settings to the Flask app.

---

## Core settings

- `APP_SECRET_KEY` / `SECRET_KEY`
  - Required. Long, random string used for Flask sessions and CSRF.
  - Example: `openssl rand -hex 32`.
- `INSTALL_LOCKED`
  - When set (e.g. `1`), disables the installer after initial setup.
- `INSTALL_ACCESS_CODE`
  - Optional one-time code required to access the installer.

---

## Database URLs

The app uses three separate databases (see `docs/database-architecture.md`):

- `USER_DB_URL` – SQLAlchemy URL for the user/auth/audit database.
- `FACE_DB_URL` – URL for the facial embeddings database.
- `RECORD_DB_URL` – URL for the recordings/metadata database.

Example (MariaDB via PyMySQL):

```text
USER_DB_URL=mysql+pymysql://user_service:PASS@db-users:3306/users_db
FACE_DB_URL=mysql+pymysql://face_service:PASS@db-faces:3306/faces_db
RECORD_DB_URL=mysql+pymysql://record_service:PASS@db-records:3306/records_db
```

These values are usually set via the web installer.

---

## Recording and storage

- `RECORDING_ENABLED`
  - `1` to enable recording workers, `0` to disable.
- `RECORDING_BASE_DIR`
  - Base directory for local recording segments when using filesystem storage.
- `STORAGE_TARGETS`
  - Comma-separated list of active storage providers.
  - Supported values: `local_fs`, `db`, `s3`, `gcs`, `azure_blob`, `dropbox`, `webdav`.
  - Example: `STORAGE_TARGETS="local_fs,s3"`.
- `LOCAL_STORAGE_PATH`
  - Optional explicit base directory for `local_fs` storage. If unset, the app
    falls back to `RECORDING_BASE_DIR` or `instance/recordings`.

### S3-compatible storage

- `S3_ENDPOINT` – optional custom endpoint (e.g. `https://s3.us-west-002.backblazeb2.com`).
- `S3_REGION` – optional region (e.g. `us-east-1`).
- `S3_BUCKET` – bucket name.
- `S3_ACCESS_KEY` – access key ID.
- `S3_SECRET_KEY` – secret access key.

All of the above must be set for the `s3` provider to be activated by
`build_storage_providers`.

### Google Cloud Storage

- `GCS_BUCKET` – GCS bucket name for the `gcs` provider.

Authentication uses the standard Google ADC mechanism (e.g. service account
JSON via `GOOGLE_APPLICATION_CREDENTIALS`).

### Azure Blob Storage

- `AZURE_BLOB_CONNECTION_STRING` – full connection string for the storage
  account.
- `AZURE_BLOB_CONTAINER` – container name used for recordings.

Both must be non-empty for the `azure_blob` provider to be enabled.

### Dropbox

- `DROPBOX_ACCESS_TOKEN` – OAuth access token used by the Dropbox SDK.

When set and `dropbox` is listed in `STORAGE_TARGETS`, recordings are uploaded
under `/recordings` in the linked account.

### WebDAV / Nextcloud

- `WEBDAV_BASE_URL` – base URL to a WebDAV endpoint (e.g. `https://cloud.example.com/remote.php/dav/files/user`).
- `WEBDAV_USERNAME` – username for HTTP basic auth (optional).
- `WEBDAV_PASSWORD` – password for HTTP basic auth (optional).

When `webdav` is present in `STORAGE_TARGETS` and `WEBDAV_BASE_URL` is set, the
WebDAV provider uploads recordings to that server.

---

## Preview / streaming settings

These control how often preview frames are captured and how large they are:

- `PREVIEW_LOW_FPS` – low-rate preview refresh (default `2.0`).
- `PREVIEW_HIGH_FPS` – high-rate preview refresh (default `10.0`).
- `PREVIEW_MAX_WIDTH` – optional max preview width in pixels (default `0` = no limit).
- `PREVIEW_MAX_HEIGHT` – optional max preview height in pixels (default `0` = no limit).
- `PREVIEW_CAPTURE_FPS` – capture rate for preview frames (default `10.0`).

---

## WebAuthn / passkeys

- `WEBAUTHN_RP_ID` – relying-party ID (usually the domain, e.g. `example.com`).
- `WEBAUTHN_RP_NAME` – human-readable RP name shown in browser dialogs
  (default `PentaVision`).

These values should match the production hostname and branding used for the app.

---

## Face recognition threshold

Face recognition compares embeddings using Euclidean distance. The decision
threshold is controlled by:

- `FACE_MATCH_THRESHOLD`
  - Optional. If unset or invalid, a default of `0.6` is used.
  - Lower values reduce false positives but may increase false negatives.
  - Higher values do the opposite. Tune based on your environment and risk
    tolerance.

The active threshold is exposed in API responses from the recognition endpoints
so operators can see what value is in effect.

---

## Installer-related flags

These are primarily used by the graphical installer flow:

- `INSTALL_LOCKED` – set to `1` once installation is complete to prevent
  re-running the installer.
- `INSTALL_ACCESS_CODE` – optional shared secret required to start the
  installer.

In production, keep these values secret and avoid leaving the installer
accessible after initial configuration.
