#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "This script must be run as root (sudo)." >&2
  exit 1
fi

read -r -p "Hostname to issue certificate for (e.g. blocklist.pentastarstudios.com): " HOSTNAME
HOSTNAME="${HOSTNAME// /}"
if [[ -z "${HOSTNAME}" ]]; then
  echo "Hostname is required." >&2
  exit 1
fi

read -r -p "Let\u2019s Encrypt account email (for expiry notices): " LE_EMAIL
LE_EMAIL="${LE_EMAIL// /}"
if [[ -z "${LE_EMAIL}" ]]; then
  echo "Email is required." >&2
  exit 1
fi

CLOUDFLARE_INI="/etc/letsencrypt/cloudflare.ini"

if [[ ! -f "${CLOUDFLARE_INI}" ]]; then
  echo "Cloudflare credentials file not found: ${CLOUDFLARE_INI}"
  echo "You need a Cloudflare API token with DNS:Edit permissions for the zone."
  read -r -s -p "Cloudflare API token: " CF_TOKEN
  echo
  if [[ -z "${CF_TOKEN}" ]]; then
    echo "Cloudflare API token is required." >&2
    exit 1
  fi

  cat >"${CLOUDFLARE_INI}" <<EOF
# managed by PentaVision setup script
# https://certbot-dns-cloudflare.readthedocs.io/
dns_cloudflare_api_token = ${CF_TOKEN}
EOF
  chmod 600 "${CLOUDFLARE_INI}"
fi

if ! command -v certbot >/dev/null 2>&1; then
  echo "==> Installing certbot"
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y certbot
fi

if ! python3 -c "import certbot_dns_cloudflare" >/dev/null 2>&1; then
  echo "==> Installing certbot Cloudflare DNS plugin"
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y python3-certbot-dns-cloudflare
fi

if ! command -v apache2ctl >/dev/null 2>&1; then
  echo "==> Installing Apache"
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y apache2
fi

CERT_DIR="/etc/letsencrypt/live/${HOSTNAME}"

echo "==> Requesting/renewing certificate for ${HOSTNAME} via Cloudflare DNS"
certbot certonly \
  --non-interactive \
  --agree-tos \
  --email "${LE_EMAIL}" \
  --dns-cloudflare \
  --dns-cloudflare-credentials "${CLOUDFLARE_INI}" \
  --dns-cloudflare-propagation-seconds 60 \
  -d "${HOSTNAME}"

if [[ ! -d "${CERT_DIR}" ]]; then
  echo "ERROR: Expected cert directory not found: ${CERT_DIR}" >&2
  exit 1
fi

echo "==> Enabling required Apache modules"
a2enmod ssl >/dev/null
 a2enmod proxy proxy_http headers >/dev/null

SITE_NAME="pentavision-blocklist-service"
SITE_CONF="/etc/apache2/sites-available/${SITE_NAME}.conf"

echo "==> Writing Apache site: ${SITE_CONF}"
cat >"${SITE_CONF}" <<EOF
<VirtualHost *:80>
    ServerName ${HOSTNAME}
    Redirect permanent / https://${HOSTNAME}/
</VirtualHost>

<VirtualHost *:443>
    ServerName ${HOSTNAME}

    SSLEngine on
    SSLCertificateFile ${CERT_DIR}/fullchain.pem
    SSLCertificateKeyFile ${CERT_DIR}/privkey.pem

    ProxyPreserveHost On
    RequestHeader set X-Forwarded-Proto "https"
    RequestHeader set X-Forwarded-Port "443"

    ProxyPass / http://127.0.0.1:7080/
    ProxyPassReverse / http://127.0.0.1:7080/

    ErrorLog \${APACHE_LOG_DIR}/pentavision_blocklist_error.log
    CustomLog \${APACHE_LOG_DIR}/pentavision_blocklist_access.log combined
</VirtualHost>
EOF

a2ensite "${SITE_NAME}.conf" >/dev/null

apache2ctl configtest
systemctl reload apache2

echo "==> Done"
echo "Certificate: ${CERT_DIR}"
echo "Apache vhost: ${SITE_CONF}"
echo "Blocklist over TLS: https://${HOSTNAME}/"
