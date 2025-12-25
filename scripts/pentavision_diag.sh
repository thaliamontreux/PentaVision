#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="/var/log/pentavision"
OUT_FILE="${OUT_DIR}/diagnostics.txt"

mkdir -p "${OUT_DIR}"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

{
  echo "PentaVision diagnostics - ${TIMESTAMP}"
  echo

  echo "== System info =="
  uname -a || true
  echo

  echo "== Uptime =="
  uptime || true
  echo

  echo "== Disk usage =="
  df -h || true
  echo

  echo "== Service status: pentavision-web =="
  systemctl status pentavision-web --no-pager || true
  echo

  echo "== Service status: pentavision-video =="
  systemctl status pentavision-video --no-pager || true
  echo

  echo "== Service status: apache2 =="
  systemctl status apache2 --no-pager || true
  echo

  echo "== Service status: mariadb/mysql =="
  systemctl status mariadb --no-pager 2>/dev/null || systemctl status mysql --no-pager 2>/dev/null || true
  echo

  echo "== Recent logs: pentavision-web (last 200 lines) =="
  journalctl -u pentavision-web -n 200 --no-pager || true
  echo

  echo "== Recent logs: pentavision-video (last 200 lines) =="
  journalctl -u pentavision-video -n 200 --no-pager || true
  echo

  echo "== Apache error log (last 200 lines) =="
  tail -n 200 /var/log/apache2/pentavision_error.log 2>/dev/null || true
  echo

  echo "== Apache access log (last 200 lines) =="
  tail -n 200 /var/log/apache2/pentavision_access.log 2>/dev/null || true
  echo

  echo "== Listening sockets (ports 80 and 8000) =="
  ss -ltnp '( sport = :80 or sport = :8000 )' 2>/dev/null || true
  echo
} >"${OUT_FILE}"

echo "Diagnostics written to ${OUT_FILE}"
