# Logging, Monitoring, and Retention

This document explains how PentaVision records security/audit events and how you can monitor and retain those logs.

## Audit log schema

The application defines an `AuditEvent` table (see `app/models.py`) with the following key fields:

- `when` – timestamp of the event (UTC).
- `user_id` – the user associated with the event (if any).
- `event_type` – short code describing the event, e.g. `AUTH_LOGIN_SUCCESS`.
- `ip` – client IP address (best-effort, from `X-Forwarded-For` or `remote_addr`).
- `details` – additional context (JSON string or short message).

By default, audit events are stored in the **user database** (`UserDB`). In higher-security deployments you can host the audit schema on a dedicated MariaDB instance and point a separate engine at it.

The installer (`/install`) ensures that the audit schema is created along with the user schema.

## What is logged today

The `app/logging_utils.py` module exposes a `log_event` helper used by various parts of the app.

Currently, the following events are recorded:

- **Registration**
  - `AUTH_REGISTER_INVALID` – missing email or password.
  - `AUTH_REGISTER_EMAIL_EXISTS` – attempted registration with an existing email.
  - `AUTH_REGISTER_SUCCESS` – successful registration (with user id and email).
- **Login**
  - `AUTH_LOGIN_INVALID` – missing email or password.
  - `AUTH_LOGIN_ERROR` – user DB not configured.
  - `AUTH_LOGIN_FAILURE` – invalid credentials or unknown email.
  - `AUTH_LOGIN_LOCKED` – login attempt against a locked account.
  - `AUTH_LOGIN_LOCKED_SET` – account lockout triggered after repeated failures.
  - `AUTH_LOGIN_SUCCESS` – successful login.
- **Installer** (planned to be wired similarly)
  - `INSTALL_DB_CONFIGURED` – DB URLs saved and schemas initialized.
  - `INSTALL_ADMIN_CREATED` – initial admin account created.

Future features (role changes, video start/stop, storage configuration changes) should also call `log_event` with appropriate `event_type` codes.

## Account lockout & rate limiting

To mitigate brute-force attacks, the `User` model includes:

- `failed_logins` – failed attempts counter.
- `locked_until` – timestamp after which login attempts are allowed again.

The login flow behaves as follows:

- On each bad password, `failed_logins` is incremented.
- After 5 failures, `locked_until` is set to 15 minutes in the future and an
  `AUTH_LOGIN_LOCKED_SET` event is recorded.
- While `locked_until` is in the future, login attempts are rejected with a
  403 status and an `AUTH_LOGIN_LOCKED` event.
- On successful login, `failed_logins` is reset to 0 and `locked_until` is
  cleared, and `AUTH_LOGIN_SUCCESS` is logged.

## Retention and review

Recommended practices:

- **Retention period** – keep audit logs for at least 90 days, or longer if
  required by your compliance regime.
- **Archiving** – periodically export old `audit_events` rows to cold storage
  (e.g. compressed files in an object store) before deletion from the live DB.
- **Access control** – restrict direct DB access to logs to a small set of
  administrators; use read-only DB users for reporting.

## Write-once / tamper-evident storage

For higher-assurance deployments, store exported audit logs in a location that
is append-only or tamper-evident:

- Use an object store (for example S3-compatible storage) with bucket policies
  and object-lock/WORM features enabled so that archived log objects cannot be
  modified or deleted before their retention period expires.
- Alternatively, write logs to an append-only medium (for example, a file
  system with OS-level append-only flags) and restrict write access to a
  dedicated service account.
- Ensure only a small set of privileged operators can modify the storage
  configuration; normal application roles should not be able to delete or
  overwrite archived logs.

A simple approach is to run a scheduled job that:

1. Selects events older than your retention threshold.
2. Writes them to an archive format (CSV/JSON) and uploads to secure storage.
3. Deletes archived rows from the `audit_events` table.

## Integration with external monitoring

You can ship logs to an external system (ELK/OpenSearch, Splunk, cloud
monitoring, etc.) using one of these approaches:

- **DB-based export** – periodically read from `audit_events` and send events
  to your log pipeline.
- **Application logging** – in addition to DB writes, emit JSON lines to a
  structured log (e.g. `stdout`), and configure a log shipper (Filebeat,
  Fluent Bit, etc.) to forward them.

Key signals to monitor:

- Spikes in `AUTH_LOGIN_FAILURE` or `AUTH_LOGIN_LOCKED_SET`.
- Repeated `AUTH_LOGIN_ERROR` (misconfigurations).
- `INSTALL_*` events occurring after initial deployment.
- Abnormal rates of video session start/stop events.
- Storage upload errors or retries for specific providers.

## Fail2ban and web logs

In addition to application-level logging, Apache and the OS-level services
produce logs that Fail2ban can consume.

Ensure Apache access and error logs are enabled and consider a Fail2ban
configuration such as:

```ini
[apache-auth]
enabled  = true
port     = http,https
filter   = apache-auth
logpath  = /var/log/apache2/error.log
maxretry = 5
findtime = 600
bantime  = 900
```

Combined with the in-app audit logs, this provides both **prevention**
(Fail2ban) and **detection**/forensics (audit trail in the database).

## Operational runbooks (examples)

For common incidents, define and follow simple runbooks, for example:

- **DB failure (UserDB/FaceDB/RecordDB)**
  - Check `/health` to confirm which DB is failing.
  - Inspect DB host (disk, CPU, service status).
  - Fail over to a replica or restore from the latest backup if necessary.
  - Verify application connectivity and monitor new `AUTH_LOGIN_ERROR` or
    storage-related events.

- **Storage outage**
  - Identify the affected provider from error logs (`storage`-related events
    in `audit_events`).
  - Switch to an alternate provider in configuration, if available.
  - Queue or temporarily store new recordings locally until the provider is
    healthy.
  - Once resolved, backfill any queued uploads.

- **Recognition issues (false positives/negatives)**
  - Review thresholds and similarity metrics used by the recognition module.
  - Re-enroll affected users with higher-quality images.
  - Inspect logs for recognition-related events to see patterns (lighting,
    camera quality, etc.).
  - If necessary, temporarily disable automatic tagging while investigating.
