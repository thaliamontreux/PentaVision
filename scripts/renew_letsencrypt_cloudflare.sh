#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "This script must be run as root (sudo)." >&2
  exit 1
fi

CLOUDFLARE_INI="/etc/letsencrypt/cloudflare.ini"

if [[ ! -f "${CLOUDFLARE_INI}" ]]; then
  echo "Cloudflare credentials file not found: ${CLOUDFLARE_INI}"
  echo "You need a Cloudflare API token with DNS:Edit permissions for the zone(s)."
  read -r -s -p "Cloudflare API token: " CF_TOKEN
  echo
  if [[ -z "${CF_TOKEN}" ]]; then
    echo "Cloudflare API token is required." >&2
    exit 1
  fi

  install -d -m 700 "$(dirname "${CLOUDFLARE_INI}")"
  cat >"${CLOUDFLARE_INI}" <<EOF
# managed by PentaVision renewal script
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

echo "==> Renewing certificates (Cloudflare DNS)"
# When certs were originally issued with --dns-cloudflare, renew will reuse
# that authenticator. We still provide credentials path to be explicit.
certbot renew \
  --dns-cloudflare \
  --dns-cloudflare-credentials "${CLOUDFLARE_INI}" \
  --quiet

echo "==> Reloading Apache (if installed)"
if systemctl list-unit-files | grep -q '^apache2\.service'; then
  systemctl reload apache2 || true
fi

echo "==> Renewal complete"
