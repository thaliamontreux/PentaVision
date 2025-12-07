#!/usr/bin/env bash
# Automated installer for PentaVision on Ubuntu 24.04
# - Sets up system packages, Python venv, and services
# - Configures Gunicorn web service and dedicated video worker
# - Optionally configures Apache as a reverse proxy

set -euo pipefail

APP_USER="pentavision"
APP_DIR="/opt/pentavision"
REPO_URL="https://github.com/thaliamontreux/PentaVision.git"  # Git repository URL for application code
PYTHON_BIN="python3"

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root (sudo)." >&2
  exit 1
fi

echo "==> Updating package index and installing system dependencies"
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  ${PYTHON_BIN} ${PYTHON_BIN}-venv ${PYTHON_BIN}-dev \
  build-essential libffi-dev libssl-dev \
  ffmpeg libopencv-dev \
  gstreamer1.0-tools gstreamer1.0-libav \
  gstreamer1.0-plugins-good gstreamer1.0-plugins-bad gstreamer1.0-plugins-ugly \
  default-libmysqlclient-dev \
  apache2 libxml2-dev \
  git cmake python-is-python3

# Only install a local DB server if none is present. This avoids removing an
# existing MariaDB server when running the installer on a machine that already
# has its own MySQL/MariaDB setup.
if ! dpkg -s mariadb-server >/dev/null 2>&1 && ! dpkg -s mysql-server >/dev/null 2>&1; then
  echo "==> No existing MySQL/MariaDB server detected; installing MariaDB server"
  DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server
else
  echo "==> Existing MySQL/MariaDB server detected; skipping DB server install"
fi

if ! id -u "${APP_USER}" >/dev/null 2>&1; then
  echo "==> Creating application user ${APP_USER}"
  adduser --system --group --home "${APP_DIR}" "${APP_USER}"
fi

mkdir -p "${APP_DIR}"
chown "${APP_USER}:${APP_USER}" "${APP_DIR}"

if [[ ! -d "${APP_DIR}/app" ]]; then
  echo "==> Cloning application repository into ${APP_DIR}/app"
  sudo -u "${APP_USER}" git clone "${REPO_URL}" "${APP_DIR}/app"
fi

cd "${APP_DIR}/app"

if [[ ! -d "${APP_DIR}/venv" ]]; then
  echo "==> Creating Python virtual environment"
  sudo -u "${APP_USER}" ${PYTHON_BIN} -m venv "${APP_DIR}/venv"
fi

echo "==> Installing Python dependencies"
sudo -u "${APP_USER}" "${APP_DIR}/venv/bin/pip" install --upgrade pip --break-system-packages
sudo -u "${APP_USER}" "${APP_DIR}/venv/bin/pip" install -r requirements.txt --break-system-packages
sudo -u "${APP_USER}" "${APP_DIR}/venv/bin/pip" install "git+https://github.com/ageitgey/face_recognition_models" --break-system-packages

if [[ ! -f "${APP_DIR}/app/.env" ]]; then
  echo "==> Creating default .env template at ${APP_DIR}/app/.env"
  cat >"${APP_DIR}/app/.env" <<'EOF'
# Core
APP_SECRET_KEY=change-me

# Databases (SQLAlchemy URLs)
USER_DB_URL=mysql+pymysql://user:pass@localhost/pe_users
FACE_DB_URL=mysql+pymysql://user:pass@localhost/pe_faces
RECORD_DB_URL=mysql+pymysql://user:pass@localhost/pe_records

# Recording / storage
RECORDING_ENABLED=1
RECORDING_BASE_DIR=/var/lib/pentavision/recordings
STORAGE_TARGETS=local_fs
LOCAL_STORAGE_PATH=/var/lib/pentavision/storage

# Preview tuning (adjust for load)
PREVIEW_LOW_FPS=1.0
PREVIEW_HIGH_FPS=5.0
PREVIEW_CAPTURE_FPS=5.0
PREVIEW_MAX_WIDTH=640
PREVIEW_MAX_HEIGHT=360

# GStreamer / pipeline tuning
USE_GSTREAMER_CAPTURE=1
USE_GSTREAMER_RECORDING=1
GST_RTSP_LATENCY_MS=200

# WebAuthn
WEBAUTHN_RP_ID=example.com
WEBAUTHN_RP_NAME=PentaVision
EOF
  chown "${APP_USER}:${APP_USER}" "${APP_DIR}/app/.env"
fi

mkdir -p /var/lib/pentavision/recordings /var/lib/pentavision/storage /var/lib/pentavision/previews
chown -R "${APP_USER}:${APP_USER}" /var/lib/pentavision

WRAPPER_SCRIPT="${APP_DIR}/video_worker_wrapper.sh"
echo "==> Writing video worker wrapper script: ${WRAPPER_SCRIPT}"
cat >"${WRAPPER_SCRIPT}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
exec "${APP_DIR}/venv/bin/python" "${APP_DIR}/app/video_worker.py" 2> >(\
  grep -v '\[h264 @' | \
  grep -v 'error while decoding MB' | \
  grep -v 'cabac decode of qscale diff failed' | \
  grep -v 'left block unavailable for requested intra' >&2)
EOF
chown "${APP_USER}:${APP_USER}" "${WRAPPER_SCRIPT}"
chmod +x "${WRAPPER_SCRIPT}"

WEB_UNIT="/etc/systemd/system/pentavision-web.service"
VIDEO_UNIT="/etc/systemd/system/pentavision-video.service"

echo "==> Writing systemd unit for web service: ${WEB_UNIT}"
cat >"${WEB_UNIT}" <<EOF
[Unit]
Description=PentaVision Web (Gunicorn)
After=network.target

[Service]
User=${APP_USER}
Group=${APP_USER}
WorkingDirectory=${APP_DIR}/app
Environment="PATH=${APP_DIR}/venv/bin"
ExecStart=${APP_DIR}/venv/bin/gunicorn "app:create_app()" --bind 127.0.0.1:8000 --workers 4 --threads 4
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

echo "==> Writing systemd unit for video worker: ${VIDEO_UNIT}"
cat >"${VIDEO_UNIT}" <<EOF
[Unit]
Description=PentaVision Video Worker (streams + recordings)
After=network.target mysql.service

[Service]
User=${APP_USER}
Group=${APP_USER}
WorkingDirectory=${APP_DIR}/app
Environment="PATH=${APP_DIR}/venv/bin"
ExecStart=${APP_DIR}/video_worker_wrapper.sh
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable pentavision-web.service pentavision-video.service
systemctl restart pentavision-web.service pentavision-video.service

echo "==> Configuring Apache as reverse proxy to Gunicorn"
a2enmod proxy proxy_http >/dev/null
APACHE_SITE="/etc/apache2/sites-available/pentavision.conf"
cat >"${APACHE_SITE}" <<'EOF'
<VirtualHost *:80>
    ServerName pentavision.local

    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:8000/
    ProxyPassReverse / http://127.0.0.1:8000/

    ErrorLog ${APACHE_LOG_DIR}/pentavision_error.log
    CustomLog ${APACHE_LOG_DIR}/pentavision_access.log combined
</VirtualHost>
EOF

a2ensite pentavision.conf >/dev/null
systemctl reload apache2

echo "==> Installation complete"
echo "- Update ${APP_DIR}/app/.env with real database credentials and secrets."
echo "- Add a proper ServerName / TLS configuration in ${APACHE_SITE} if needed."
echo "- Access the app via http://pentavision.local/ (or your server's IP)."
