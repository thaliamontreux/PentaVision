# PentaVision Operator Manual

This manual describes what PentaVision is, how it is deployed, and how to install and operate it on a fresh **Ubuntu Server 24.04 (minimal install)**.

If you are looking for focused deep-dives, also see:

- `docs/configuration.md` (environment variables)
- `docs/database-architecture.md` (3-database layout)
- `docs/auth-passkeys.md` (WebAuthn / passkeys)
- `docs/facial-recognition.md` (face recognition)
- `docs/privacy-security.md` (security posture)
- `docs/logging-monitoring.md` (logging)

---

## 1) What the system is

PentaVision is a server-rendered Flask web application that provides:

- Secure authentication (password + optional TOTP + WebAuthn/passkeys).
- Camera management and video recording/retention.
- Face recognition enrollment and matching.
- Pluggable storage modules for recording upload/retention.
- Administrative security controls (IP allow/block lists, country policies).
- A dedicated blocklist distribution service for appliances like pfSense.
- A dedicated log server endpoint for operational log viewing.

At runtime, the app is a set of **systemd services** + a **reverse proxy**:

- `pentavision-web.service` (main web app, Gunicorn behind Apache)
- `pentavision-video.service` (video worker / recording worker)
- `pentavision-logserver.service` (log server API)
- `pentavision-blocklist.service` (blocklist distribution API)
- `pentavision-autoupdate.timer` / `pentavision-autoupdate.service` (optional auto-update)

---

## 2) Ports and network surface

Default ports used by the deployed services:

- **80/tcp**: Apache reverse proxy (public HTTP). You will typically add TLS/SSL and use **443/tcp**.
- **8000/tcp (localhost only)**: Gunicorn for the main web app (proxied by Apache).
- **8123/tcp**: Log server Gunicorn listener (`pentavision-logserver.service`).
- **7080/tcp**: Blocklist distribution service (`pentavision-blocklist.service`).

Recommended firewall stance:

- Allow: `22/tcp` (SSH), `80/tcp`, `443/tcp`.
- Allow `7080/tcp` **only** if you explicitly need the blocklist service reachable from outside (and restrict by IP allowlisting/token).
- Allow `8123/tcp` only to trusted admin networks.

---

## 3) Database model (what you need)

PentaVision uses **three separate SQL databases** (typically MariaDB/MySQL). This can be three schemas on one server, or separate DB servers.

- **User DB** (default `pe_users`)
  - Users, roles/permissions, audit events
  - IP allow/block lists and country access policies
  - Blocklist distribution settings

- **Face DB** (default `pe_faces`)
  - Face embeddings + privacy settings

- **Record DB** (default `pe_records`)
  - Cameras, recordings metadata
  - Storage module configuration, health checks, write stats
  - Upload queue
  - Recording schedules/windows
  - DLNA/RTMP state

Schema bootstrap SQL:

- `deploy/pentavision_schema.sql`

Notes:

- The application also calls `metadata.create_all()` on startup for the configured DB engines; the SQL file is the authoritative “fresh install / repair” bootstrap.

---

## 4) Installation (Ubuntu 24.04 minimal)

### 4.1 Prerequisites

- Fresh **Ubuntu Server 24.04** (minimal install is fine)
- Internet access (to install packages and clone the repository)
- A user with `sudo`

### 4.2 One-command-ish install

The installer is:

- `deploy/install_ubuntu_24.sh`

Recommended install steps:

```bash
sudo apt update && sudo apt install -y git
git clone https://github.com/thaliamontreux/PentaVision.git
cd PentaVision

# Optional: create a dedicated DB user that the installer will grant privileges to.
# If you omit these, the installer still creates databases and applies schema,
# but will not create the application DB user.
export PENTAVISION_DB_USER=pv_app
export PENTAVISION_DB_PASS='change-this-password'

sudo bash deploy/install_ubuntu_24.sh
```

What the script does:

- Installs system dependencies (Python build deps, ffmpeg, gstreamer, Apache, MariaDB if absent)
- Creates `pentavision` system user
- Clones the repo to `/opt/pentavision/app`
- Creates `/opt/pentavision/venv` and installs `requirements.txt`
- Builds OpenCV (first run) and links it into the venv
- Creates `/opt/pentavision/app/.env` if missing
- Bootstraps local MariaDB DBs (`pe_users`, `pe_faces`, `pe_records`) and applies `deploy/pentavision_schema.sql`
- Installs/enables systemd services and configures Apache proxy to `127.0.0.1:8000`

### 4.3 After install: mandatory configuration

Edit:

- `/opt/pentavision/app/.env`

At minimum set:

- `APP_SECRET_KEY` to a strong value
- `WEBAUTHN_RP_ID` to your production domain

If you created a DB user via `PENTAVISION_DB_USER/PENTAVISION_DB_PASS`, also update DB URLs:

- `USER_DB_URL=mysql+pymysql://pv_app:PASS@localhost/pe_users`
- `FACE_DB_URL=mysql+pymysql://pv_app:PASS@localhost/pe_faces`
- `RECORD_DB_URL=mysql+pymysql://pv_app:PASS@localhost/pe_records`

Then restart services:

```bash
sudo systemctl restart pentavision-web pentavision-video pentavision-logserver pentavision-blocklist
```

### 4.4 Verify install

```bash
sudo systemctl status pentavision-web pentavision-video pentavision-logserver pentavision-blocklist --no-pager

# Main app proxied by Apache
curl -fsS http://127.0.0.1/health

# Blocklist service (if enabled)
curl -fsS http://127.0.0.1:7080/

# Log server
curl -fsS http://127.0.0.1:8123/
```

---

## 5) First-time setup in the UI

- Browse to the server’s URL.
- Use the built-in installer:
  - `/install`

The installer:

- Validates DB connectivity
- Initializes DB schemas (safe to run on empty DBs)
- Seeds the initial System Administrator account

Once finished:

- Set `INSTALL_LOCKED=1` in `.env` (recommended).

---

## 6) Operations

### 6.1 Service management

Common actions:

```bash
sudo systemctl restart pentavision-web
sudo systemctl restart pentavision-video
sudo systemctl restart pentavision-logserver
sudo systemctl restart pentavision-blocklist

sudo journalctl -u pentavision-web -n 200 --no-pager
sudo journalctl -u pentavision-video -n 200 --no-pager
```

### 6.2 Updating the database schema

For local MariaDB installs, you can re-apply the schema:

```bash
sudo bash /opt/pentavision/app/deploy/update_databases.sh
```

### 6.3 Upgrades

If you are using the autoupdate timer, code updates are pulled periodically.
If you upgrade manually:

- `git pull` in `/opt/pentavision/app`
- restart services

---

## 7) Blocklist distribution service (port 7080)

This is a dedicated, read-only publication service intended to feed security appliances.

- Service: `pentavision-blocklist.service`
- Port: `7080`

Operational controls:

- Consumer IP allowlisting (CIDR list)
- Optional token authentication
- Rate limiting

Admin UI:

- Admin -> Blocklist Distribution
- Admin -> Blocklist Integration
- Admin -> Blocklist Audit

---

## 8) Troubleshooting

- If the UI loads but login fails:
  - confirm `APP_SECRET_KEY` is set
  - check DB URLs and DB user grants
  - check `journalctl -u pentavision-web`

- If video worker is failing:
  - check `journalctl -u pentavision-video`
  - confirm ffmpeg/gstreamer installed
  - confirm OpenCV build succeeded (marker: `/opt/pentavision/opencv_build.done`)

- If schema/table errors appear:
  - run `deploy/update_databases.sh`
  - verify DB URLs point to the expected databases

---

## 9) Security checklist (minimum)

- Set a strong `APP_SECRET_KEY`.
- Configure TLS (Apache vhost on 443).
- Restrict access to 7080/8123 with firewall rules and/or IP allowlisting.
- Lock the installer (`INSTALL_LOCKED=1`) after initial setup.
- Back up the 3 databases.
