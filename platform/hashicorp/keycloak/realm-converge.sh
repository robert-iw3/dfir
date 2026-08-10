#!/usr/bin/env bash
# ==============================================================================
# Realm converge — makes realm-irplatform.json the enforced configuration on EVERY deploy.
#
# With the identity store on Postgres, `--import-realm` applies only on first start; an
# existing realm is never updated by it. Without this script a changed password policy,
# brute-force threshold or session lifetime would deploy cleanly and change nothing.
# Same principle as Consul's config entries: a bootstrap that never updates an existing
# object is not configuration management.
#
#   realm settings   converged from the file (password policy, brute force, lifetimes, theme)
#   clients          partialImport with OVERWRITE — a changed client definition applies
#   groups           created when missing, otherwise untouched (recreating a group would
#                    orphan every membership, which lives on the user by group id)
#   users            NEVER touched here — provision-demo-users.sh owns users
#
# Runs against the LOCAL Keycloak container only, like provisioning.
# ==============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNTIME="${IR_RUNTIME:-podman}"
KC=ir-enclave_keycloak_1
REALM=irplatform
REALM_FILE="${HERE}/realm-irplatform.json"

[[ -f "${REALM_FILE}" ]] || { echo "[realm-converge] ${REALM_FILE} missing" >&2; exit 1; }
${RUNTIME} inspect "${KC}" >/dev/null 2>&1 \
    || { echo "[realm-converge] ${KC} is not running on THIS host" >&2; exit 1; }

kcadm() {
    ${RUNTIME} exec -i "${KC}" sh -c '
        /opt/keycloak/bin/kcadm.sh config credentials --server http://127.0.0.1:8080 \
            --realm master --user "${KC_BOOTSTRAP_ADMIN_USERNAME:-admin}" \
            --password "${KC_BOOTSTRAP_ADMIN_PASSWORD:-admin}" >/dev/null 2>&1 &&
        /opt/keycloak/bin/kcadm.sh "$@" 2>&1' -- "$@"
}

# The realm must exist before it can be converged; on a fresh database --import-realm is
# still creating it while Keycloak reports listening.
ready=0
for _ in $(seq 1 60); do
    kcadm get "realms/${REALM}" --fields realm 2>/dev/null | grep -q "${REALM}" && { ready=1; break; }
    sleep 2
done
[[ "${ready}" == "1" ]] || { echo "[realm-converge] realm ${REALM} never answered" >&2; exit 1; }

rc=0

# Realm-level settings. Structural members are handled separately below; `id`/`realm` are
# identity, not configuration.
if jq 'del(.clients, .groups, .users, .id, .realm)' "${REALM_FILE}" \
        | kcadm update "realms/${REALM}" -f - >/dev/null; then
    echo "[realm-converge] realm settings converged (password policy, brute force, lifetimes)"
else
    echo "[realm-converge] FAILED to update realm settings" >&2; rc=1
fi

# Clients: OVERWRITE so an edited redirect URI, mapper or secret actually lands.
if jq '{clients: .clients}' "${REALM_FILE}" \
        | kcadm create partialImport -r "${REALM}" -s ifResourceExists=OVERWRITE -f - >/dev/null; then
    echo "[realm-converge] clients converged: $(jq -r '[.clients[].clientId] | join(", ")' "${REALM_FILE}")"
else
    echo "[realm-converge] FAILED to converge clients" >&2; rc=1
fi

# Groups: additive only.
#
# Captured, THEN matched. Piped into `grep -q` the existence check is a race it loses: grep
# exits on the first match, the writer takes SIGPIPE, and under `set -o pipefail` the pipeline
# reports 141 — indistinguishable from "not found". A group that exists is then created again,
# Keycloak refuses the duplicate, and convergence reports a failure that is entirely its own.
while IFS= read -r g; do
    [[ -n "${g}" ]] || continue
    found="$(kcadm get groups -r "${REALM}" -q "search=${g}" --fields name 2>/dev/null)"
    if [[ "$(grep -c "\"${g}\"" <<<"${found}")" -eq 0 ]]; then
        kcadm create groups -r "${REALM}" -s "name=${g}" >/dev/null \
            && echo "[realm-converge] created missing group ${g}" \
            || { echo "[realm-converge] FAILED to create group ${g}" >&2; rc=1; }
    fi
done < <(jq -r '.groups[]?.name' "${REALM_FILE}")

exit "${rc}"
