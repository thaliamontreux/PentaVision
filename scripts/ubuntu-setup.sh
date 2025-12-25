#!/usr/bin/env bash
set -euo pipefail

# Ubuntu 24.04 minimal server bootstrap script for PentaVision.
# Run as a sudo-capable user. This script is intentionally conservative and
# focuses on installing and enabling core services; review before use.

if [[ "${EUID}" -ne 0 ]]; then
  echo "Please run this script with sudo or as root." >&2
  exit 1
fi

apt update
apt -y upgrade

# Apache and modules
apt install -y \
  apache2 apache2-utils \
  libapache2-mod-security2 \
  libapache2-mod-evasive \
  libapache2-mod-php php-mysql \
  ufw

systemctl enable --now apache2

a2dissite 000-default.conf || true
systemctl reload apache2 || true

a2dismod autoindex || true

a2enmod rewrite ssl headers || true
systemctl reload apache2 || true

# MariaDB
apt install -y mariadb-server
systemctl enable --now mariadb

echo "**********************************************************************"
echo "MariaDB installed. Now run 'sudo mysql_secure_installation' manually to"
echo "set root password and secure the installation."
echo "**********************************************************************"

# Languages and tools
apt install -y \
  python3 python3-venv python3-pip \
  git curl vim \
  ffmpeg python3-opencv

# Optional: Node.js from Ubuntu repositories
apt install -y nodejs npm || true

# Firewall
ufw allow 22/tcp || true
ufw allow 80/tcp || true
ufw allow 443/tcp || true
ufw --force enable

# Fail2ban
apt install -y fail2ban
systemctl enable --now fail2ban

cat <<'EOF'

Base system setup complete.

Next steps (manual):
  1. Run: sudo mysql_secure_installation
  2. Create separate MariaDB databases and users for users/faces/records.
  3. Clone the PentaVision repo, create a Python venv, and install requirements.
  4. Configure Apache (or another web server) to serve the app via WSGI or proxy.
EOF
