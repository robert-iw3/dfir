#!/usr/bin/env bash
# Rotate the application tier's credentials, end to end, and converge the platform on them.
#
#   ./rotate-app-creds.sh          from anywhere on the enclave host
#
# What one run does, in order:
#   1. revokes every database lease (Postgres drops the old dynamic users NOW, not at TTL)
#      and refreshes the agent's bounded secret_id — rotate-app-creds.py, via break-glass root
#   2. restarts the Vault Agent, which authenticates with the fresh secret_id and renders a
#      NEW database credential into /vault/secrets/app.env
#   3. restarts backend and worker so they source that render — the processes read secrets at
#      start, so rotation is not complete until they have been through it
#   4. waits for the API to answer, because a rotation that leaves the platform down has failed
#
# Run it on a schedule shorter than the secret_id TTL (72h by default), and immediately when a
# credential is suspected taken. KV values (custody/audit HMAC, Django key) do not rotate here —
# changing the custody key would orphan every existing seal.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNTIME="${IR_RUNTIME:-podman}"
AGENT=ir-enclave_vault-agent_1
BACKEND=ir-enclave_backend_1
WORKER=ir-enclave_worker_1

say() { printf '[rotate] %s\n' "$*"; }
die() { printf '[rotate] FAIL: %s\n' "$*" >&2; exit 1; }

# Restarting the worker kills whatever it is analyzing — same guard, same override, as
# deploy.sh. A memory pass runs for over an hour; rotation can usually wait for it.
n="$(${RUNTIME} exec "${WORKER}" sh -c 'ps -eo args | grep -c "[a]nalyze_memory_linux"' 2>/dev/null | head -1 || true)"
if [[ "${n:-0}" -gt 0 && "${IR_FORCE_ROTATE:-0}" != "1" ]]; then
    die "a memory analysis is running — re-run when it finishes, or IR_FORCE_ROTATE=1 to rotate anyway"
fi

old="$(${RUNTIME} exec "${AGENT}" sed -n 's/^export POSTGRES_USER=//p' /vault/secrets/app.env 2>/dev/null | head -1)"
[[ -n "${old}" ]] || die "no rendered credential to rotate — is the agent up?"
say "current database user: ${old}"

# The revocation step runs in its own vault-image container: the server mounts the state volume
# read-only (it has no business writing its own unseal material), and the fresh secret_id has to
# be WRITTEN. Joining the internal network resolves `vault` exactly as the services do.
${RUNTIME} run --rm --user root \
    --network ir-enclave_internal \
    -v ir-enclave_vault-state:/vault/state \
    -v ir-enclave_vault-certs:/certs:ro \
    -v "${HERE}/rotate-app-creds.py:/rotate.py:ro,z" \
    -e VAULT_ADDR=https://vault:8200 -e VAULT_CACERT=/certs/vault-ca.crt.pem \
    --entrypoint python3 \
    localhost/vault:2.0.3 /rotate.py

say "restarting the agent for a fresh render"
${RUNTIME} restart "${AGENT}" >/dev/null

new=""
for i in $(seq 1 45); do
    new="$(${RUNTIME} exec "${AGENT}" sed -n 's/^export POSTGRES_USER=//p' /vault/secrets/app.env 2>/dev/null | head -1)"
    [[ -n "${new}" && "${new}" != "${old}" ]] && break
    sleep 2
done
[[ -n "${new}" && "${new}" != "${old}" ]] \
    || die "the agent never rendered a new credential (still ${new:-empty}) — check its logs"
say "new database user: ${new}"

say "restarting the application tier onto the new credential"
${RUNTIME} restart "${BACKEND}" "${WORKER}" >/dev/null

# Their sidecars, AFTER them. A restarted service gets a fresh network namespace, and its proxy
# is still attached to the old one — serving nothing — so without this the backend comes up,
# dials 127.0.0.1:5432, and finds no listener: down on a valid credential, which reads as the
# rotation having broken authentication.
${RUNTIME} restart ir-enclave_backend-sidecar_1 ir-enclave_worker-sidecar_1 >/dev/null 2>&1 \
    || say "WARNING: could not restart the sidecars — the app tier may not reach the database"

for i in $(seq 1 60); do
    if ${RUNTIME} exec "${BACKEND}" python -c \
        "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/api/health/', timeout=4)" >/dev/null 2>&1; then
        say "rotation complete: ${old} -> ${new}, platform healthy"
        exit 0
    fi
    sleep 3
done
die "the API never came back after rotation — the platform is DOWN on the new credential"
