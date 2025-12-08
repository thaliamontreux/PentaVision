#!/usr/bin/env bash
set -euo pipefail

# Reconfigure PentaVision systemd services to use the Python virtualenv
# at /opt/pentavision/venv and the app at /opt/pentavision/app.
#
# Usage (on the Ubuntu server as root):
#   cd /opt/pentavision/app
#   bash scripts/setup_pentavision_venv_services.sh

APP_USER="pentavision"
APP_DIR="/opt/pentavision"
APP_SRC_DIR="${APP_DIR}/app"
VENV_DIR="${APP_DIR}/venv"

WEB_UNIT="/etc/systemd/system/pentavision-web.service"
VIDEO_UNIT="/etc/systemd/system/pentavision-video.service"
WRAPPER_SCRIPT="${APP_DIR}/video_worker_wrapper.sh"

if [[ "${EUID}" -ne 0 ]]; then
  echo "This script must be run as root (sudo)." >&2
  exit 1
fi

if [[ ! -d "${APP_SRC_DIR}" ]]; then
  echo "ERROR: App directory ${APP_SRC_DIR} does not exist." >&2
  exit 1
fi

if [[ ! -d "${VENV_DIR}" ]]; then
  echo "ERROR: Virtualenv directory ${VENV_DIR} does not exist." >&2
  echo "Create it first, e.g.:" >&2
  echo "  python3 -m venv ${VENV_DIR}" >&2
  echo "  ${VENV_DIR}/bin/pip install -r ${APP_SRC_DIR}/requirements.txt" >&2
  exit 1
fi

echo "==> Writing video worker wrapper script: ${WRAPPER_SCRIPT}"
cat >"${WRAPPER_SCRIPT}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
exec "${VENV_DIR}/bin/python" "${APP_SRC_DIR}/video_worker.py" 2> >(\
  grep -v '\\[h264 @' | \
  grep -v 'error while decoding MB' | \
  grep -v 'cabac decode of qscale diff failed' | \
  grep -v 'left block unavailable for requested intra' >&2)
EOF
chown "${APP_USER}:${APP_USER}" "${WRAPPER_SCRIPT}"
chmod +x "${WRAPPER_SCRIPT}"

echo "==> Writing systemd unit for web service: ${WEB_UNIT}"
cat >"${WEB_UNIT}" <<EOF
[Unit]
Description=PentaVision Web (Gunicorn)
After=network.target

[Service]
User=${APP_USER}
Group=${APP_USER}
WorkingDirectory=${APP_SRC_DIR}
Environment="PATH=${VENV_DIR}/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=${VENV_DIR}/bin/gunicorn "app:create_app()" --bind 127.0.0.1:8000 --workers 4 --threads 4
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
WorkingDirectory=${APP_SRC_DIR}
Environment="PATH=${VENV_DIR}/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=${WRAPPER_SCRIPT}
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF


echo "==> Reloading systemd and (re)starting services"
systemctl daemon-reload
systemctl enable pentavision-web.service pentavision-video.service >/dev/null 2>&1 || true
systemctl restart pentavision-web.service pentavision-video.service

echo "==> Done. Current status:"
systemctl status pentavision-web.service --no-pager || true
systemctl status pentavision-video.service --no-pager || true
