#!/usr/bin/env bash
# Backend entrypoint: `web` runs migrations + the API, `worker` runs the Celery memory-analysis
# worker, both from this image.
set -euo pipefail

role="${1:-web}"

# Which component this process reports as, derived from the role it was launched with — podman-
# compose does not reliably merge an environment override, so deriving it is what keeps the
# health row honest.
case "${role}" in
    web|worker) export IR_HEALTH_REPORT_ROLE="${IR_HEALTH_REPORT_ROLE:-${role}}" ;;
esac

# --- Vault mode -------------------------------------------------------------
# When IR_VAULT=1, secrets are not in the environment; a Vault Agent sidecar
# renders them (dynamic Postgres creds + KV: Django key, HMAC keys, MinIO creds)
# into a shared file. Wait for it, then source it so the rest of settings.py
# reads them from the environment exactly as before.
if [ "${IR_VAULT:-0}" = "1" ]; then
    secrets_file="${IR_VAULT_SECRETS_FILE:-/vault/secrets/app.env}"
    echo "[entrypoint] Vault mode — waiting for ${secrets_file} (rendered by Vault Agent)"
    for _ in $(seq 1 90); do
        if [ -s "${secrets_file}" ] && grep -q POSTGRES_PASSWORD "${secrets_file}"; then
            break
        fi
        sleep 2
    done
    [ -s "${secrets_file}" ] || { echo "[entrypoint] Vault secrets never rendered" >&2; exit 1; }
    set -a; . "${secrets_file}"; set +a
    echo "[entrypoint] sourced Vault-issued secrets (db user: ${POSTGRES_USER:-?})"
fi

# Waits INDEFINITELY by default — a mesh requirement, not patience: with Connect enforcing,
# Postgres is reachable only through this service's own sidecar, which may still be
# initializing.
wait_for_db() {
    echo "[entrypoint] waiting for postgres at ${POSTGRES_HOST}:${POSTGRES_PORT:-5432} ..."
    tries="${IR_DB_WAIT_TRIES:-0}"
    n=0
    while :; do
        if python -c "
import os,psycopg,sys
try:
    psycopg.connect(host=os.environ['POSTGRES_HOST'],port=os.environ.get('POSTGRES_PORT','5432'),
                    dbname=os.environ['POSTGRES_DB'],user=os.environ['POSTGRES_USER'],
                    password=os.environ['POSTGRES_PASSWORD']).close()
except Exception as e:
    sys.exit(1)
" 2>/dev/null; then
            echo "[entrypoint] postgres is up"; return 0
        fi
        n=$((n + 1))
        [ "${tries}" -gt 0 ] && [ "${n}" -ge "${tries}" ] && {
            echo "[entrypoint] postgres never came up after ${n} attempts" >&2; return 1; }
        # Said periodically, not every cycle: a silent container looks hung, and a line every
        # two seconds buries everything else in the log.
        [ $((n % 15)) -eq 0 ] && \
            echo "[entrypoint] still waiting for postgres (${n} attempts) — is this service's sidecar up?"
        sleep 2
    done
}

# Create the correlation database when absent: CREATE DATABASE cannot run inside a transaction,
# so it goes through a direct autocommit connection.
require_side_db() {  # NAME_VAR  DEFAULT_NAME  HOST_VAR  PORT_VAR
    IR_DB_NAME_VAR="$1" IR_DB_NAME_DEFAULT="$2" IR_DB_HOST_VAR="$3" IR_DB_PORT_VAR="$4" \
    python - <<'PY'
import os
import sys

import psycopg

name = os.environ.get(os.environ["IR_DB_NAME_VAR"], os.environ["IR_DB_NAME_DEFAULT"])
try:
    conn = psycopg.connect(
        dbname=name,
        user=os.environ.get("POSTGRES_USER", "ir_platform"),
        password=os.environ.get("POSTGRES_PASSWORD", ""),
        host=os.environ.get(os.environ["IR_DB_HOST_VAR"], os.environ.get("POSTGRES_HOST", "db")),
        port=os.environ.get(os.environ["IR_DB_PORT_VAR"], os.environ.get("POSTGRES_PORT", "5432")),
        connect_timeout=5,
    )
except Exception as exc:
    print(f"[entrypoint] database '{name}' is not reachable: {exc}", file=sys.stderr)
    print(f"[entrypoint] it is created by hashicorp/db-bootstrap.py — run the data-tier "
          f"stage of deploy.sh before the application tier", file=sys.stderr)
    raise SystemExit(1)
conn.close()
print(f"[entrypoint] database '{name}' present")
PY
}

case "$role" in
    web)
        wait_for_db
        # Migrations are committed, never generated at start-up — regenerating here made the recorded
        # history diverge from the database.
        python manage.py migrate --noinput
        # The derived correlation store is a separate database: create it if absent, then
        # migrate it explicitly. The router keeps `cases` out of it and it out of `default`.
        require_side_db CORRELATION_POSTGRES_DB ir_correlation \
                        CORRELATION_POSTGRES_HOST CORRELATION_POSTGRES_PORT
        python manage.py migrate --database=correlation --noinput
        # Operational log store. Kept out of the evidence database: highest-volume writer in
        # the platform, and explicitly not evidence.
        require_side_db OPSLOG_POSTGRES_DB ir_opslog \
                        OPSLOG_POSTGRES_HOST OPSLOG_POSTGRES_PORT
        python manage.py migrate --database=opslog --noinput
        python manage.py seed_roles
        python manage.py collectstatic --noinput >/dev/null 2>&1 || true
        # Access log to a file the shipper can move; everything else stays on stdout so
        # `podman logs` is still useful while the container is alive.
        mkdir -p "${IR_APP_LOG_DIR:-/logs/app}" 2>/dev/null || true
        exec gunicorn ir_platform.wsgi:application \
            --bind 0.0.0.0:8000 --workers "${GUNICORN_WORKERS:-3}" --timeout 120 \
            --access-logfile "${IR_APP_LOG_DIR:-/logs/app}/backend-access.log" \
            --error-logfile -
        ;;
    worker)
        wait_for_db
        exec celery -A ir_platform worker --loglevel=INFO --concurrency "${CELERY_CONCURRENCY:-2}"
        ;;
    *)
        exec "$@"
        ;;
esac
