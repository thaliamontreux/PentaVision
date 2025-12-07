# Project TODO

## System setup & security

- [x] Provision Ubuntu 24.04 minimal server (see `deploy/install_ubuntu_24.sh` for automated setup steps).
- [x] Install and configure Apache (modules, TLS/SSL, mod_security, mod_evasive, rewrite).
- [x] Install language runtimes (PHP, Python, Node) and common tools (git, curl, vim).
- [x] Configure UFW firewall (allow only HTTP/HTTPS/SSH) and harden Apache defaults.
- [x] Install and secure MariaDB (run `mysql_secure_installation`).
- [x] Install additional dependencies (ffmpeg, python3, python3-pip, python3-opencv, python3-venv, etc.).
- [x] Set up Fail2ban or similar intrusion-prevention tooling.
- [x] Enable services on boot and ensure regular security updates.

## Graphical web installer

- [x] Design installer flow (multi-step wizard: DB setup, admin account, security options).
- [x] Implement installer endpoint (e.g. `/install/installer.php` or equivalent).
- [x] Add forms for each database (UserDB, FaceDB, RecordDB) with host/port/user/password.
- [x] Add form for initial admin account and core configuration.
- [x] Implement strong server-side validation and CSRF protection.
- [x] Test DB connections and create schemas/tables via parameterized queries.
- [x] Write configuration to secure files (outside webroot, least-privilege permissions).
- [x] Implement installer finalization: lock/remove installer after success, disable directory.
- [x] Protect installer with one-time code or session token and enforce HTTPS during setup.

## Database architecture and segmentation

- [x] Design schemas for user accounts/auth, facial embeddings, and recordings/metadata.
- [x] Decide physical deployment: separate MariaDB servers/instances per component.
- [x] Configure private networking/VLANs and TLS/SSL for DB connections.
- [x] Create separate DB users per service with least-privilege grants.
- [x] Ensure no cross-DB joins in SQL; handle cross-component queries in application layer.
- [x] Set up automated, encrypted backups per database with tested restore procedures.

## Authentication, passkeys, and activity logging

- [x] Choose WebAuthn/FIDO2 server library or service for passkey support.
- [x] Implement passkey registration and login flows (primary auth method) via JSON APIs in the auth blueprint and the auth demo page.
- [x] Implement fallback 2FA (TOTP app, SMS/email OTP, or hardware token).
- [x] Implement secure password handling where needed (Argon2id hashing, salts).
- [x] Implement account lockout and rate limiting for repeated failures.
- [x] Define audit log schema for security events and critical actions.
- [x] Log authentication attempts (success/failure), role changes, configuration changes, and video events.
- [x] Store logs in write-once or tamper-evident storage with restricted access.
- [x] Define log retention and review procedures; integrate with log analysis/alerting tools.

## Facial recognition module

- [x] Select facial recognition stack (e.g. `face_recognition` with dlib/OpenCV or equivalent).
- [x] Implement enrollment flow: capture images during registration, compute embeddings, store in FaceDB (faces demo page + `/api/face/enroll`).
- [x] Design FaceDB schema for embeddings and associated user identifiers.
- [x] Implement runtime processing: detect faces in frames, compute embeddings, compare to stored vectors (snapshot and live camera recognition APIs).
- [x] Choose similarity metric and thresholds and tune for accuracy (Euclidean distance with configurable threshold, default 0.6).
- [x] Overlay recognized user names on live video (dashboard camera tiles, per-camera session view, and faces demo).
- [x] Overlay recognized user names on recorded output during playback (recording playback page with per-frame face recognition overlays).
- [x] Implement privacy controls (opt-out of tagging, deletion of biometric data on request) via FaceDB policy table and opt-out/opt-in APIs.
- [x] Ensure FaceDB is isolated, encrypted at rest, and only accessible to recognition service (handled via deployment/DB configuration and documented operational guidance).

## User interface and flow

- [x] Choose UI stack (server-rendered Flask templates with lightweight vanilla JS and custom CSS).
- [x] Design responsive layout for desktop and mobile (dashboard, navigation, modals) via `main.css` media queries and flexible grids.
- [x] Implement login/auth pages (passkeys, 2FA fallback) with clear UX (auth demo page using WebAuthn and TOTP).
- [x] Implement dashboard with "Start Session" and status indicators (dashboard camera tiles with Start session button and live stream health badges).
- [x] Implement camera access (HTML5 `getUserMedia`) and a "Scan Face" flow for enrollment (faces demo page with webcam capture and enrollment/recognition).
- [x] Implement session page with live video, overlays for recognized users, and controls (per-camera session view with face recognition overlay and simple controls).
- [x] Add pages or views for logs/audit review (admin-only audit events page).
- [x] Add storage settings UI to select and configure storage providers (storage overview page with provider details and configuration hints).
- [x] Implement client-side validation for forms (usernames, passwords, DB settings, etc.).
- [x] Address accessibility (keyboard navigation, ARIA labels, contrast) with aria-live regions, landmarks, and grouped camera tiles.

## Storage provider integration

- [x] Design a storage provider interface/abstraction (`StorageProvider` with `upload`, `get_url`, and `delete`).
- [x] Implement S3-compatible provider module (generic S3 provider supporting AWS S3 and custom endpoints such as Backblaze B2, Wasabi, DigitalOcean Spaces, IBM Cloud OS, etc.).
- [x] Implement cloud vendor object stores (Google Cloud Storage, Azure Blob Storage).
- [x] Implement business file-sync provider example (Dropbox) and a pattern that can be extended to Box, OneDrive for Business, and Google Drive Workspace.
- [x] Implement privacy-focused or self-hosted option via a generic WebDAV provider (e.g. Nextcloud or other WebDAV-compatible services).
- [x] Implement provider configuration UI and credential handling via environment variables (securely scoped to the service process, with secrets masked in the UI).
- [x] Ensure uploads are resilient (upload queue with retries) and store returned IDs/keys in RecordDB, with download support via local files, direct DB reads, or provider URLs/signed URLs.
- [x] Allow admins to choose default provider and per-camera/provider overrides via `STORAGE_TARGETS` and per-camera `CameraStoragePolicy.storage_targets`.

## Logging, monitoring, and operations

- [x] Define what to monitor (auth failures, unusual access patterns, storage errors, recognition errors).
- [x] Integrate with log analysis/monitoring stack (e.g. ELK, hosted service) for alerting.
- [x] Configure Fail2ban or similar using log patterns from web/auth services.
- [x] Document operational runbooks for common incidents (DB failure, storage outage, recognition issues).

## Documentation and compliance

- [x] Document installation steps for Ubuntu 24.04 (including web installer usage) (see `docs/ubuntu-setup.md`).
- [x] Document configuration of databases, storage, and security options (see `docs/configuration.md` and `docs/database-architecture.md`).
- [x] Document facial recognition data handling, retention, and deletion procedures (see `docs/facial-recognition.md`).
- [x] Prepare privacy/security notes (GDPR-like considerations for biometrics and logs) (see `docs/privacy-security.md` and `docs/logging-monitoring.md`).
