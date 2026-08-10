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
#   present user  -> password left alone (it is theirs); group membership reconciled, so
#                    a right defined after the account was created still reaches it.
#
#   provision-demo-users.sh                    ensure all demo accounts exist
#   provision-demo-users.sh --force <user>     delete + recreate ONE account (re-arms the
#                                              forced update; prints the fresh initial
#                                              credential). For lockout/unknown-password
#                                              recovery see admin/kc-userctl.sh.
#   provision-demo-users.sh --ephemeral <uat-name> <role[+right...]>
#                                              create a THROWAWAY test account. Tests use
#                                              these instead of the demo accounts, because a
#                                              test that rotates or recreates an account a
#                                              person is signed into invalidates their
#                                              session mid-flight. Names must start `uat-`.
#   provision-demo-users.sh --delete <uat-name>
#                                              remove one. Refuses anything not `uat-`.
#
# Initial passwords come from IR_DEMO_<ROLE>_PASSWORD (deploy/.env); defaults hold the
# documented development values. Runs against the LOCAL Keycloak container only.
# ==============================================================================
set -uo pipefail

RUNTIME="${IR_RUNTIME:-podman}"
KC=ir-enclave_keycloak_1
REALM=irplatform

# username : groups (+-joined) : env var : default initial password
#
# The first group is the ROLE; any that follow are rights that compose with it. The analyst
# carries `export` and the auditor deliberately does not: an auditor sees everything, which is
# a separate question from being allowed to carry it out, and the pair is what makes the
# distinction testable in both directions rather than asserted in a docstring.
ACCOUNTS=(
    "default-admin:admin:IR_DEMO_ADMIN_PASSWORD:default-admin-Pw1!"
    "default-analyst:analyst+export:IR_DEMO_ANALYST_PASSWORD:default-analyst-Pw1!"
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

# Throwaway test accounts. The `uat-` prefix is a hard gate in BOTH directions: a test cannot
# create an account a person might mistake for real, and --delete cannot reach a real one.
if [[ "${1:-}" == "--ephemeral" || "${1:-}" == "--delete" ]]; then
    user="${2:?${1} needs a username}"
    [[ "${user}" == uat-* ]] || { echo "[demo-users] ${1} only handles uat-* accounts, not '${user}'" >&2; exit 1; }
    uid="$(uid_of "${user}")"
    if [[ "${1}" == "--delete" ]]; then
        [[ -n "${uid}" ]] && kcadm delete "users/${uid}" -r "${REALM}" >/dev/null
        echo "[demo-users] ${user}: removed"
        exit 0
    fi
    groups="${3:?--ephemeral needs a role}"
    [[ -n "${uid}" ]] && kcadm delete "users/${uid}" -r "${REALM}" >/dev/null
    pw="Uat-$(head -c9 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c12)-Pw1!"
    kcadm create users -r "${REALM}" \
        -s "username=${user}" -s enabled=true -s email="${user}@ir-platform.local" \
        -s emailVerified=true -s firstName=uat -s lastName="${user#uat-}" >/dev/null
    uid="$(uid_of "${user}")"
    [[ -n "${uid}" ]] || { echo "[demo-users] FAILED to create ${user}" >&2; exit 1; }
    # --temporary keeps the forced first-login change in the flow a test walks — that
    # enforcement is part of what the tests exist to exercise.
    kcadm set-password -r "${REALM}" --userid "${uid}" --new-password "${pw}" --temporary >/dev/null
    IFS='+' read -ra MEMBERSHIPS <<<"${groups}"
    for g in "${MEMBERSHIPS[@]}"; do
        gid="$(gid_of "${g}")"
        [[ -n "${gid}" ]] && kcadm update "users/${uid}/groups/${gid}" -r "${REALM}" -n >/dev/null \
            || echo "[demo-users] WARN: group '${g}' not found — ${user} is missing it" >&2
    done
    echo "EPHEMERAL_PASSWORD=${pw}"
    exit 0
fi

rc=0

# Groups are realm-converge.sh's to create, and it runs first in the deploy. Asserted rather
# than duplicated: two scripts creating the same groups is two places to keep correct, but a
# missing group here means a membership assignment that fails with a warning and a right that
# silently cannot be held — so the dependency is stated where it would break.
for g in admin analyst auditor reverse_engineer export; do
    [[ -n "$(gid_of "${g}")" ]] || {
        echo "[demo-users] group '${g}' does not exist — run realm-converge.sh first" >&2
        rc=1
    }
done

for row in "${ACCOUNTS[@]}"; do
    IFS=: read -r user groups var default <<<"${row}"
    pw="${!var:-${default}}"
    # NOT `GROUPS`: bash owns that name and it is read-only — the assignment fails
    # silently and the loop iterates the invoking user's Unix group IDs instead.
    IFS='+' read -ra MEMBERSHIPS <<<"${groups}"

    uid="$(uid_of "${user}")"
    # Membership is reconciled on EVERY run, including for accounts left otherwise untouched.
    # A password is the user's and stays theirs; a right is the platform's, and one that only
    # reaches accounts created after it was defined is a right that does not apply to anyone
    # already working the incident.
    if [[ -n "${uid}" && -z "${FORCE_USER}" ]]; then
        for g in "${MEMBERSHIPS[@]}"; do
            gid="$(gid_of "${g}")"
            [[ -n "${gid}" ]] && kcadm update "users/${uid}/groups/${gid}" -r "${REALM}" -n >/dev/null 2>&1
        done
    fi
    if [[ -n "${uid}" && "${FORCE_USER}" == "${user}" ]]; then
        kcadm delete "users/${uid}" -r "${REALM}" >/dev/null
        uid=""
    fi
    if [[ -n "${uid}" ]]; then
        [[ -z "${FORCE_USER}" ]] && echo "[demo-users] ${user}: present — password untouched, groups reconciled (${groups//+/, })"
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

    for g in "${MEMBERSHIPS[@]}"; do
        gid="$(gid_of "${g}")"
        if [[ -n "${gid}" ]]; then
            kcadm update "users/${uid}/groups/${gid}" -r "${REALM}" -n >/dev/null
        else
            echo "[demo-users] WARN: group '${g}' not found — ${user} is missing it" >&2; rc=1
        fi
    done

    echo "[demo-users] ${user}: provisioned (${groups//+/, }) — initial password: ${pw}  (single-use; a new password is demanded at first login)"
done
exit "${rc}"
