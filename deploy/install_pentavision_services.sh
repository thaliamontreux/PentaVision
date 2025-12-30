#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-0} -ne 0 ]]; then
  echo "This script must be run as root (sudo)." >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

WEB_SRC="${SCRIPT_DIR}/pentavision-web.service"
WORKER_SRC="${SCRIPT_DIR}/pentavision-video-worker.service"
PLUGINS_SRC="${SCRIPT_DIR}/pentavision-plugins.service"

WEB_DST="/etc/systemd/system/pentavision-web.service"
WORKER_DST="/etc/systemd/system/pentavision-video-worker.service"
PLUGINS_DST="/etc/systemd/system/pentavision-plugins.service"

if [[ ! -f "${WEB_SRC}" ]]; then
  echo "Missing unit file: ${WEB_SRC}" >&2
  exit 1
fi
if [[ ! -f "${WORKER_SRC}" ]]; then
  echo "Missing unit file: ${WORKER_SRC}" >&2
  exit 1
fi

echo "==> Installing systemd unit files"
install -m 0644 "${WEB_SRC}" "${WEB_DST}"
install -m 0644 "${WORKER_SRC}" "${WORKER_DST}"

# Install plugins service if available
if [[ -f "${PLUGINS_SRC}" ]]; then
  echo "==> Installing plugins service"
  install -m 0644 "${PLUGINS_SRC}" "${PLUGINS_DST}"
fi

# Create plugins directory
echo "==> Creating plugins directory"
mkdir -p /opt/pentavision/plugins
chown -R pentavision:pentavision /opt/pentavision/plugins

echo "==> Reloading systemd"
systemctl daemon-reload

# Avoid running duplicate workers if the legacy unit exists.
if systemctl list-unit-files | awk '{print $1}' | grep -qx "pentavision-video.service"; then
  echo "==> Disabling legacy unit pentavision-video.service (replaced by pentavision-video-worker.service)"
  systemctl disable --now pentavision-video.service >/dev/null 2>&1 || true
fi

echo "==> Enabling and starting services"
systemctl enable --now pentavision-web.service
systemctl enable --now pentavision-video-worker.service

# Enable plugins service if installed
if [[ -f "${PLUGINS_DST}" ]]; then
  echo "==> Enabling plugins service"
  systemctl enable --now pentavision-plugins.service
fi

# If Apache is used as a reverse proxy (typical install), restart it so it
# reconnects to the backend in case the bind/port changed.
if systemctl list-unit-files | awk '{print $1}' | grep -qx "apache2.service"; then
  echo "==> Restarting apache2 (if active)"
  systemctl restart apache2 >/dev/null 2>&1 || true
fi

echo "==> Done"
echo "Web:     systemctl status pentavision-web --no-pager"
echo "Worker:  systemctl status pentavision-video-worker --no-pager"
echo "Plugins: systemctl status pentavision-plugins --no-pager"
