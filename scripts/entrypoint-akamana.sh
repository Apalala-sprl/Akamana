#!/usr/bin/env bash
# entrypoint-akamana.sh — runs the backend and nginx as ONE unit.
#
# Two things the previous version did not do, both seen on s10 on 2026-09-20
# after a `systemctl restart docker`:
#   1. wait for the database. Docker restarts every container at once, so
#      `mariadb` was not resolvable yet when the backend connected — it died
#      with "Temporary failure in name resolution". `depends_on:
#      service_healthy` only orders a `compose up`, not a daemon restart.
#   2. die when either process dies. nginx was `exec`ed after the backend
#      was backgrounded, so a dead backend left a "running" container whose
#      nginx answered 502 forever — `restart: unless-stopped` never fired.
#      Now both run in the background, the first exit ends the container
#      with that exit status, and the restart policy brings it back.
set -euo pipefail

export BIND_ADDR="${BIND_ADDR:-127.0.0.1:18080}"
export AKAMANA_DATA_DIR="${AKAMANA_DATA_DIR:-/data}"
export ADDONS_DIR="${ADDONS_DIR:-${AKAMANA_DATA_DIR}/addons}"

# Overridable so the script can be exercised outside the image.
BACKEND_BIN="${AKAMANA_BACKEND_BIN:-/app/akamana-backend}"
NGINX_BIN="${AKAMANA_NGINX_BIN:-nginx}"
DB_WAIT_SECONDS="${AKAMANA_DB_WAIT_SECONDS:-90}"

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

# ── 1. Wait for the database host to accept TCP connections ─────────────────
# host:port come from DATABASE_URL (mysql://user:pass@host[:port]/db). Bounded:
# past the deadline the backend is started anyway and its own error is the
# diagnosis; the container then exits and the restart policy retries.
wait_for_db() {
  local url="${DATABASE_URL:-}" hostport host port deadline
  [ -n "$url" ] || return 0
  hostport="${url#*@}"; hostport="${hostport%%/*}"; hostport="${hostport%%\?*}"
  host="${hostport%%:*}"; port="${hostport##*:}"
  [ "$port" != "$host" ] || port=3306
  deadline=$((SECONDS + DB_WAIT_SECONDS))
  while ! (exec 3<>"/dev/tcp/${host}/${port}") 2>/dev/null; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      echo "entrypoint: ${host}:${port} still unreachable after ${DB_WAIT_SECONDS}s — starting anyway" >&2
      return 0
    fi
    echo "entrypoint: waiting for ${host}:${port}…" >&2
    sleep 2
  done
  echo "entrypoint: ${host}:${port} reachable" >&2
}
wait_for_db

# ── 2. Run both processes; the first to exit takes the container with it ────
"${BACKEND_BIN}" &
BACKEND_PID=$!
"${NGINX_BIN}" -g 'daemon off;' &
NGINX_PID=$!

stop_both() {
  kill "$BACKEND_PID" "$NGINX_PID" 2>/dev/null || true
}
# docker stop → SIGTERM to this shell: forward it and let the wait below end.
SIGNALLED=0
trap 'SIGNALLED=1; stop_both' INT TERM

# `wait -n` returns when EITHER child exits. Inside `if` so errexit does not
# fire before the status is captured.
if wait -n; then status=0; else status=$?; fi

if [ "$SIGNALLED" = 1 ]; then
  echo "entrypoint: stop requested — shutting both down" >&2
elif kill -0 "$BACKEND_PID" 2>/dev/null; then
  echo "entrypoint: nginx exited (status ${status}) — stopping the backend" >&2
else
  echo "entrypoint: akamana-backend exited (status ${status}) — stopping nginx" >&2
fi
stop_both
wait "$BACKEND_PID" "$NGINX_PID" 2>/dev/null || true
exit "$status"
