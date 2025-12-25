#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-}"
COOKIE="${COOKIE:-}"
TIMEOUT="${TIMEOUT:-12}"

if [[ -z "${BASE_URL}" ]]; then
  BASE_URL="${PENTAVISION_BASE_URL:-}"
fi

if [[ -z "${BASE_URL}" ]]; then
  echo "usage: $0 https://your-host" >&2
  echo "  optional env: COOKIE='session=...'; TIMEOUT=12" >&2
  exit 2
fi

BASE_URL="${BASE_URL%/}"

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

if ! have_cmd curl; then
  echo "ERROR: curl not found" >&2
  exit 1
fi

print_kv() {
  local k="$1"
  local v="$2"
  printf "%-28s %s\n" "${k}:" "${v}"
}

read_unit() {
  local unit="$1"
  if have_cmd systemctl; then
    systemctl cat "$unit" 2>/dev/null || true
  fi
}

extract_gunicorn_bind() {
  # Return either:
  #   tcp:127.0.0.1:8000
  #   unix:/run/pentavision-web.sock
  local unit_text="$1"
  local bind
  bind=$(echo "$unit_text" | grep -Eo -- "--bind[= ]+[^ ]+" | head -n 1 || true)
  if [[ -z "$bind" ]]; then
    return 0
  fi
  bind=${bind#--bind}
  bind=${bind#=}
  bind=${bind# } 

  if [[ "$bind" == unix:* ]]; then
    echo "unix:${bind#unix:}"
    return 0
  fi

  # gunicorn allows 0.0.0.0:8000, 127.0.0.1:8000, :8000
  if [[ "$bind" == :* ]]; then
    bind="127.0.0.1${bind}"
  fi
  echo "tcp:${bind}"
}

curl_head() {
  local url="$1"
  local cookie="$2"

  if [[ -n "$cookie" ]]; then
    curl -sS -D - -o /dev/null \
      --max-time "$TIMEOUT" \
      -H "Cookie: $cookie" \
      "$url" || true
  else
    curl -sS -D - -o /dev/null \
      --max-time "$TIMEOUT" \
      "$url" || true
  fi
}

curl_head_unix() {
  local sock="$1"
  local url_path="$2"
  local cookie="$3"

  if [[ -n "$cookie" ]]; then
    curl -sS -D - -o /dev/null \
      --max-time "$TIMEOUT" \
      --unix-socket "$sock" \
      -H "Host: ${BASE_URL#https://}" \
      -H "Cookie: $cookie" \
      "http://localhost${url_path}" || true
  else
    curl -sS -D - -o /dev/null \
      --max-time "$TIMEOUT" \
      --unix-socket "$sock" \
      -H "Host: ${BASE_URL#https://}" \
      "http://localhost${url_path}" || true
  fi
}

status_from_headers() {
  echo "$1" | head -n 1 | awk '{print $2}'
}

header_value() {
  local headers="$1"
  local name="$2"
  echo "$headers" | awk -v n="${name}" 'BEGIN{IGNORECASE=1} $0 ~ "^"n":" {sub(/\r/,"",$0); sub("^"n":[ ]*","",$0); print; exit}'
}

print_headers_summary() {
  local label="$1"
  local headers="$2"

  local st
  st=$(status_from_headers "$headers")
  print_kv "$label status" "${st:-?}"
  print_kv "$label server" "$(header_value "$headers" "Server")"
  print_kv "$label via" "$(header_value "$headers" "Via")"
  print_kv "$label set-cookie" "$(header_value "$headers" "Set-Cookie")"
  print_kv "$label location" "$(header_value "$headers" "Location")"
}

TARGET_PATH="/admin/storage"

echo "=== pentavision /admin/storage 403 diagnostic ==="
print_kv "Base URL" "$BASE_URL"
print_kv "Target path" "$TARGET_PATH"
print_kv "Cookie provided" "$([[ -n "$COOKIE" ]] && echo yes || echo no)"
echo

echo "--- Public URL (through Apache/proxy) ---"
PUB_HEADERS=$(curl_head "${BASE_URL}${TARGET_PATH}" "$COOKIE")
print_headers_summary "public" "$PUB_HEADERS"
echo

UNIT_TEXT=$(read_unit "pentavision-web.service")
BIND=""
if [[ -n "$UNIT_TEXT" ]]; then
  BIND=$(extract_gunicorn_bind "$UNIT_TEXT")
fi

if [[ -z "$BIND" ]]; then
  echo "--- Upstream detection ---"
  echo "Could not detect gunicorn bind from systemd unit 'pentavision-web.service'."
  echo "If your unit has a different name, set it here or edit the script." 
  echo
else
  echo "--- Direct upstream (bypass Apache) ---"
  print_kv "Detected bind" "$BIND"

  if [[ "$BIND" == unix:* ]]; then
    SOCK="${BIND#unix:}"
    if [[ ! -S "$SOCK" ]]; then
      print_kv "Socket" "$SOCK (not found)"
    else
      UP_HEADERS=$(curl_head_unix "$SOCK" "$TARGET_PATH" "$COOKIE")
      print_headers_summary "upstream" "$UP_HEADERS"
    fi
  else
    HOSTPORT="${BIND#tcp:}"
    UP_URL="http://${HOSTPORT}${TARGET_PATH}"
    UP_HEADERS=$(curl_head "$UP_URL" "$COOKIE")
    print_headers_summary "upstream" "$UP_HEADERS"
  fi
  echo
fi

echo "--- Interpretation ---"
PUB_STATUS=$(status_from_headers "$PUB_HEADERS")
PUB_SERVER=$(header_value "$PUB_HEADERS" "Server")

if [[ -n "$BIND" ]]; then
  UP_STATUS=$(status_from_headers "${UP_HEADERS:-}")
  UP_SERVER=$(header_value "${UP_HEADERS:-}" "Server")
else
  UP_STATUS=""
  UP_SERVER=""
fi

if [[ -n "$PUB_STATUS" && -n "$UP_STATUS" && "$PUB_STATUS" != "$UP_STATUS" ]]; then
  echo "Public status (${PUB_STATUS}) differs from upstream (${UP_STATUS})."
  echo "That strongly suggests Apache/proxy config is changing behavior (auth, routing, headers, or vhost)."
elif [[ "$PUB_STATUS" == "403" && ( -z "$UP_STATUS" || "$UP_STATUS" == "403" ) ]]; then
  echo "Both public and upstream return 403. This is almost certainly application/RBAC logic, not Apache." 
  echo "Next proof step: verify which user the session cookie maps to and whether that user has the System Administrator role." 
elif [[ "$PUB_STATUS" == "302" || "$PUB_STATUS" == "301" ]]; then
  echo "Public returns redirect. If it redirects to /login unexpectedly, cookies may not be sticking through Apache (SameSite/Secure/Domain/Path)."
else
  echo "Result is inconclusive. Review the headers above (Server/Via/Set-Cookie/Location)."
fi

echo
print_kv "Tip" "If you can, rerun with COOKIE='session=...'(from browser devtools) to test authenticated behavior."
