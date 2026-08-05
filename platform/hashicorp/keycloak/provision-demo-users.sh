#!/usr/bin/env bash
# ==============================================================================
# Demo account provisioning — idempotent, and the ONLY place these users are created.
#
# Not in the realm import: an import never updates an existing realm, so users defined
# there exist exactly once and silently drift ever after. This runs on every deploy:
#
#   absent user   -> created with the initial password from the environment, group
#                    membership, and a FORCED password update at first login. The initial
#                    credential is printed — it is single-use by construction.
#   present user  -> left entirely alone. Their password is theirs.
#
#   provision-demo-users.sh                    ensure all demo accounts exist
#   provision-demo-users.sh --force <user>     delete + recreate ONE account (re-arms the
#                                              forced update; prints the fresh initial
#                                              credential). For lockout/unknown-password
#                                              recovery see admin/kc-userctl.sh.
#
# Initial passwords come from IR_DEMO_<ROLE>_PASSWORD (deploy/.env); defaults hold the
# documented development values. Runs against the LOCAL Keycloak container only.
# ==============================================================================
set -uo pipefail

RUNTIME="${IR_RUNTIME:-podman}"
KC=ir-enclave_keycloak_1
REALM=irplatform

# username : group : env var : default initial password
ACCOUNTS=(
    "default-admin:admin:IR_DEMO_ADMIN_PASSWORD:default-admin-Pw1!"
    "default-analyst:analyst:IR_DEMO_ANALYST_PASSWORD:default-analyst-Pw1!"
    "default-auditor:auditor:IR_DEMO_AUDITOR_PASSWORD:default-auditor-Pw1!"
    "default-reverse-engineer:reverse_engineer:IR_DEMO_RE_PASSWORD:default-re-Pw1!"
)

${RUNTIME} inspect "${KC}" >/dev/null 2>&1 \
    || { echo "[demo-users] ${KC} is not running on THIS host — provisioning is host-local" >&2; exit 1; }

# kcadm inside the container, authenticated with the bootstrap admin it already holds.
kcadm() {
    ${RUNTIME} exec -i "${KC}" sh -c '
        /opt/keycloak/bin/kcadm.sh config credentials --server http://127.0.0.1:8080 \
            --realm master --user "${KC_BOOTSTRAP_ADMIN_USERNAME:-admin}" \
            --password "${KC_BOOTSTRAP_ADMIN_PASSWORD:-admin}" >/dev/null 2>&1 &&
        /opt/keycloak/bin/kcadm.sh "$@" 2>&1' -- "$@"
}

# Provisioning must not race the realm import: an unanswered kcadm reads as "user absent",
# which turns a slow start into duplicate-create attempts. Gate on the realm answering.
ready=0
for _ in $(seq 1 60); do
    kcadm get "realms/${REALM}" --fields realm 2>/dev/null | grep -q "${REALM}" && { ready=1; break; }
    sleep 2
done
[[ "${ready}" == "1" ]] || { echo "[demo-users] realm ${REALM} never answered — nothing provisioned" >&2; exit 1; }

uid_of() { kcadm get users -r "${REALM}" -q "username=$1" -q exact=true --fields id \
    | tr -d ' \n' | sed -n 's/.*"id":"\([^"]*\)".*/\1/p'; }

gid_of() { kcadm get groups -r "${REALM}" -q "search=$1" --fields id,name \
    | python3 -c "import json,sys; gs=json.load(sys.stdin); print(next((g['id'] for g in gs if g['name']=='$1'), ''))" 2>/dev/null; }

FORCE_USER=""
[[ "${1:-}" == "--force" ]] && FORCE_USER="${2:?--force needs a username}"

rc=0
for row in "${ACCOUNTS[@]}"; do
    IFS=: read -r user group var default <<<"${row}"
    pw="${!var:-${default}}"

    uid="$(uid_of "${user}")"
    if [[ -n "${uid}" && "${FORCE_USER}" == "${user}" ]]; then
        kcadm delete "users/${uid}" -r "${REALM}" >/dev/null
        uid=""
    fi
    if [[ -n "${uid}" ]]; then
        [[ -z "${FORCE_USER}" ]] && echo "[demo-users] ${user}: present — untouched"
        continue
    fi
    [[ -n "${FORCE_USER}" && "${FORCE_USER}" != "${user}" ]] && continue

    out="$(kcadm create users -r "${REALM}" \
        -s "username=${user}" -s enabled=true -s email="${user}@ir-platform.local" \
        -s emailVerified=true -s firstName="${user%%-*}" -s lastName="${user#*-}")"
    uid="$(uid_of "${user}")"
    if [[ -z "${uid}" ]]; then
        echo "[demo-users] FAILED to create ${user}: ${out}" >&2; rc=1; continue
    fi

    # --temporary IS the enforcement: Keycloak refuses any session until the password is
    # replaced by the user. Set after creation so the required action cannot be lost to a
    # partially-applied create.
    kcadm set-password -r "${REALM}" --userid "${uid}" \
        --new-password "${pw}" --temporary >/dev/null

    gid="$(gid_of "${group}")"
    if [[ -n "${gid}" ]]; then
        kcadm update "users/${uid}/groups/${gid}" -r "${REALM}" -n >/dev/null
    else
        echo "[demo-users] WARN: group '${group}' not found — ${user} has no role" >&2; rc=1
    fi

    echo "[demo-users] ${user}: provisioned — initial password: ${pw}  (single-use; a new password is demanded at first login)"
done
exit "${rc}"
