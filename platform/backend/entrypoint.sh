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
export IR_HEALTH_REPORT_ROLE="${IR_HEALTH_REPORT_ROLE:-${role}}"

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
ensure_correlation_db() {
    python - <<'PY'
import os

import psycopg

name = os.environ.get("CORRELATION_POSTGRES_DB", "ir_correlation")
conn = psycopg.connect(
    dbname="postgres",
    user=os.environ.get("POSTGRES_USER", "ir_platform"),
    password=os.environ.get("POSTGRES_PASSWORD", ""),
    host=os.environ.get("CORRELATION_POSTGRES_HOST", os.environ.get("POSTGRES_HOST", "db")),
    port=os.environ.get("CORRELATION_POSTGRES_PORT", os.environ.get("POSTGRES_PORT", "5432")),
    autocommit=True,
)
with conn.cursor() as cur:
    cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (name,))
    if cur.fetchone():
        print(f"[entrypoint] correlation database '{name}' present")
    else:
        cur.execute(f'CREATE DATABASE "{name}"')
        print(f"[entrypoint] created correlation database '{name}'")
conn.close()
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
        ensure_correlation_db
        python manage.py migrate --database=correlation --noinput
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
