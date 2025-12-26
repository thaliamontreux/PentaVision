#!/usr/bin/env bash
set -euo pipefail

# PentaVision database schema updater
# This script applies deploy/pentavision_schema.sql to the local MySQL server.
# Adjust MYSQL_USER / MYSQL_HOST / MYSQL_OPTS as needed for your environment.

MYSQL_USER="root"


SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCHEMA_FILE="${SCRIPT_DIR}/pentavision_schema.sql"
RBAC_FILE="${SCRIPT_DIR}/pentavision_rbac_seed.sql"

if [[ ! -f "${SCHEMA_FILE}" ]]; then
  echo "Schema file not found: ${SCHEMA_FILE}" >&2
  exit 1
fi

if [[ ! -f "${RBAC_FILE}" ]]; then
  echo "RBAC seed file not found: ${RBAC_FILE}" >&2
  exit 1
fi

echo "Applying PentaVision schema from ${SCHEMA_FILE}..."

# If root has no password, this will not prompt. If you use another user or
# require a password, export MYSQL_PWD before running or remove -p below.
mysql -u"${MYSQL_USER}" < "${SCHEMA_FILE}"

echo "Seeding RBAC roles/permissions from ${RBAC_FILE}..."
mysql -u"${MYSQL_USER}" < "${RBAC_FILE}"

echo "Schema update complete. You may need to restart the PentaVision service, e.g.:"
echo "  sudo systemctl restart pentavision"
