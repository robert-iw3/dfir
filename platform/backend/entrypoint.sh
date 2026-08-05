#!/usr/bin/env bash
# Backend entrypoint. `web` runs migrations + the API; `worker` runs the Celery
# memory-analysis worker. Both share this image.
set -euo pipefail

role="${1:-web}"

# Which component this process reports resources as. Derived from the role it was launched
# with rather than passed in through compose: podman-compose does not reliably merge an
# `environment:` block with an `env_file:`, and a variable that silently fails to arrive
# leaves a process reporting nothing while looking correctly configured. This process
# already knows what it is. An explicit value still wins.
#
# Only for the two roles that ARE reporters: any other command through this image — the log
# shipper, a one-off manage.py — would otherwise report itself as the API.
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

# Waits INDEFINITELY by default, and that is a mesh requirement rather than patience.
#
# With Connect enforcing, this service reaches Postgres only through its own sidecar, and that
# sidecar lives in THIS container's network namespace. Exiting here is therefore self-defeating:
# the restart gives the container a NEW namespace, which strands the proxy that was about to
# start serving, so the next attempt fails for the reason the previous exit created. Two
# containers cannot converge that way — each restart breaks the thing it is waiting for.
#
# Waiting instead keeps the namespace stable so the proxy can attach to it. A database that is
# genuinely unreachable is caught by the deployment's own health gate and reported there, with
# the whole stage's context, rather than as a container that quietly exited.
#
# IR_DB_WAIT_TRIES bounds it for anything that needs a definite failure (0 = forever).
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

# Create the correlation database when it does not exist yet. CREATE DATABASE cannot run
# inside a transaction, so it goes through a direct autocommit connection rather than a
# migration.
# A side store must already exist. Creating it here needs the CREATEDB attribute, which the
# app tier deliberately does not hold — hashicorp/db-bootstrap.py owns the one static admin
# credential and creates every database before the application starts. Attempting it here
# died with "permission denied to create database" and took the API down with it, which is
# the security control working; the fix is to stop asking, not to widen the grant.
#
# Checked rather than assumed: a missing database must say so by name, because the migrate
# that follows would otherwise fail with a connection error that names nothing useful.
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
        # Migrations are committed, not generated at start-up. Regenerating them here
        # made the migration history diverge from the database: Django recorded 0001 as
        # applied, then rewrote 0001 to include later model changes, so it believed the new
        # columns existed while the database had never received them. Schema changes ship
        # as migration files reviewed with the code that needs them.
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
        exec gunicorn ir_platform.wsgi:application \
            --bind 0.0.0.0:8000 --workers "${GUNICORN_WORKERS:-3}" --timeout 120
        ;;
    worker)
        wait_for_db
        exec celery -A ir_platform worker --loglevel=INFO --concurrency "${CELERY_CONCURRENCY:-2}"
        ;;
    *)
        exec "$@"
        ;;
esac
