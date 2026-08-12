#!/bin/bash
# Keycloak entrypoint. With IR_VAULT=1 the database credential is a Vault lease rendered to
# /vault/secrets/kc-db.env — wait for it, source it, start.
set -euo pipefail

if [ "${IR_VAULT:-0}" = "1" ]; then
    secrets_file="${IR_VAULT_SECRETS_FILE:-/vault/secrets/kc-db.env}"
    echo "[kc-entrypoint] Vault mode — waiting for ${secrets_file}"
    for _ in $(seq 1 90); do
        [ -s "${secrets_file}" ] && grep -q KC_DB_PASSWORD "${secrets_file}" && break
        sleep 2
    done
    [ -s "${secrets_file}" ] || { echo "[kc-entrypoint] credential never rendered" >&2; exit 1; }
    set -a; . "${secrets_file}"; set +a
    echo "[kc-entrypoint] sourced Vault-issued credential (db user: ${KC_DB_USERNAME:-?})"
else
    # No Vault, no credential path to Postgres: fall back to the embedded store so identity
    # still boots. Accounts then do NOT survive a recreate — a degraded mode, said out loud.
    echo "[kc-entrypoint] IR_VAULT!=1 — embedded store; accounts will NOT survive a recreate" >&2
    unset KC_DB KC_DB_URL KC_DB_USERNAME KC_DB_PASSWORD
fi

exec /opt/keycloak/bin/kc.sh "$@"
