#!/usr/bin/env bash
# Install PentaVision plugins to the server
# Run as: sudo bash deploy/install_plugins.sh

set -euo pipefail

if [[ ${EUID:-0} -ne 0 ]]; then
  echo "This script must be run as root (sudo)." >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"
PLUGINS_SRC="${PROJECT_DIR}/plugins"
PLUGINS_DST="/opt/pentavision/plugins"

echo "==> Installing PentaVision plugins"
echo "    Source: ${PLUGINS_SRC}"
echo "    Destination: ${PLUGINS_DST}"

# Create plugins directory if it doesn't exist
mkdir -p "${PLUGINS_DST}"

# Install each plugin
for plugin_dir in "${PLUGINS_SRC}"/*; do
  if [[ -d "${plugin_dir}" ]]; then
    plugin_name=$(basename "${plugin_dir}")
    echo "==> Installing plugin: ${plugin_name}"
    
    # Remove old version if exists
    rm -rf "${PLUGINS_DST}/${plugin_name}"
    
    # Copy plugin
    cp -r "${plugin_dir}" "${PLUGINS_DST}/"
    
    # Set permissions
    chown -R pentavision:pentavision "${PLUGINS_DST}/${plugin_name}"
    chmod -R 755 "${PLUGINS_DST}/${plugin_name}"
    
    echo "    Installed: ${PLUGINS_DST}/${plugin_name}"
  fi
done

# Install plugin dependencies
echo "==> Installing plugin dependencies"
if [[ -f "${PLUGINS_DST}/home-assistant/main.py" ]]; then
  echo "    Installing Home Assistant plugin dependencies..."
  /opt/pentavision/venv/bin/pip install --quiet requests paho-mqtt 2>/dev/null || true
fi

echo "==> Done installing plugins"
echo ""
echo "Installed plugins:"
ls -la "${PLUGINS_DST}/"
echo ""
echo "To restart the plugin service:"
echo "  sudo systemctl restart pentavision-plugins"
