#!/usr/bin/env bash
set -euo pipefail

export BIND_ADDR="${BIND_ADDR:-127.0.0.1:18080}"
export AKAMANA_DATA_DIR="${AKAMANA_DATA_DIR:-/data}"
export ADDONS_DIR="${ADDONS_DIR:-${AKAMANA_DATA_DIR}/addons}"

mkdir -p \
  "${AKAMANA_DATA_DIR}" \
  "${AKAMANA_DATA_DIR}/addons" \
  "${AKAMANA_DATA_DIR}/certs" \
  "${AKAMANA_DATA_DIR}/exports" \
  "${AKAMANA_DATA_DIR}/logs" \
  "${AKAMANA_DATA_DIR}/backups"

# Harden directory permissions for persisted secrets and config artifacts.
chmod 750 "${AKAMANA_DATA_DIR}" || true
chmod 750 \
  "${AKAMANA_DATA_DIR}/addons" \
  "${AKAMANA_DATA_DIR}/certs" \
  "${AKAMANA_DATA_DIR}/exports" \
  "${AKAMANA_DATA_DIR}/logs" \
  "${AKAMANA_DATA_DIR}/backups" || true

/app/akamana-backend &
BACKEND_PID=$!

cleanup() {
  kill "$BACKEND_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

exec nginx -g 'daemon off;'
