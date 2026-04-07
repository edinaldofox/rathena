#!/usr/bin/env bash

set -euo pipefail

DB_HOST="${DB_HOST:-db}"
DB_PORT="${DB_PORT:-3306}"
DB_NAME="${DB_NAME:-ragnarok}"
DB_USER="${DB_USER:-ragnarok}"
DB_PASSWORD="${DB_PASSWORD:-ragnarok}"

wait_for_db() {
    echo "Waiting for database at ${DB_HOST}:${DB_PORT}..."
    until mariadb-admin ping \
        --host="${DB_HOST}" \
        --port="${DB_PORT}" \
        --user="${DB_USER}" \
        --password="${DB_PASSWORD}" \
        --silent; do
        sleep 2
    done
}

shutdown() {
    local exit_code=${1:-0}
    for pid in "${MAP_PID:-}" "${CHAR_PID:-}" "${LOGIN_PID:-}"; do
        if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
            kill "${pid}" 2>/dev/null || true
        fi
    done
    wait || true
    exit "${exit_code}"
}

trap 'shutdown 0' SIGINT SIGTERM

mkdir -p log
wait_for_db

echo "Starting rAthena services..."
./login-server &
LOGIN_PID=$!
./char-server &
CHAR_PID=$!
./map-server &
MAP_PID=$!

set +e
wait -n "${LOGIN_PID}" "${CHAR_PID}" "${MAP_PID}"
EXIT_CODE=$?
set -e

echo "One of the rAthena services stopped."
shutdown "${EXIT_CODE}"
