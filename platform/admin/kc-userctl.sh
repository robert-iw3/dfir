#!/usr/bin/env bash
# ==============================================================================
# Account recovery for the platform realm — lockouts and forgotten passwords.
#
#   ./kc-userctl.sh status <username>     lockout state, enabled flag, pending actions
#   ./kc-userctl.sh unlock <username>     clear the brute-force lockout counter
#   ./kc-userctl.sh reset  <username>     set a TEMPORARY password (printed); the user
#                                         must replace it at next login. Also unlocks.
#   ./kc-userctl.sh reset  <username> --password '<value>'   use a chosen value instead
#
# HOST-BOUND BY CONSTRUCTION: this works through `podman exec` into the local Keycloak
# container. There is no network path, no listener and no API — on any machine that is not
# running Keycloak it can do nothing.
#
# A reset here never hands out a working session: the printed password admits exactly one
# login, which Keycloak refuses to complete until it is replaced.
# ==============================================================================
set -uo pipefail

RUNTIME="${IR_RUNTIME:-podman}"
KC=ir-enclave_keycloak_1
REALM=irplatform

c_grn=$'\e[1;32m'; c_ylw=$'\e[1;33m'; c_red=$'\e[1;31m'; c_off=$'\e[0m'
ok()   { printf '  %s✔%s %s\n' "${c_grn}" "${c_off}" "$*"; }
warn() { printf '  %s!%s %s\n' "${c_ylw}" "${c_off}" "$*"; }
die()  { printf '  %s✘%s %s\n' "${c_red}" "${c_off}" "$*" >&2; exit 1; }

ACTION="${1:-}"; USER="${2:-}"
[[ -n "${ACTION}" && -n "${USER}" ]] || { sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }

${RUNTIME} inspect "${KC}" >/dev/null 2>&1 \
    || die "Keycloak is not running on THIS host — account recovery is deliberately host-local"

kcadm() {
    ${RUNTIME} exec -i "${KC}" sh -c '
        /opt/keycloak/bin/kcadm.sh config credentials --server http://127.0.0.1:8080 \
            --realm master --user "${KC_BOOTSTRAP_ADMIN_USERNAME:-admin}" \
            --password "${KC_BOOTSTRAP_ADMIN_PASSWORD:-admin}" >/dev/null 2>&1 &&
        /opt/keycloak/bin/kcadm.sh "$@" 2>&1' -- "$@"
}

UID_="$(kcadm get users -r "${REALM}" -q "username=${USER}" -q exact=true --fields id \
    | tr -d ' \n' | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')"
[[ -n "${UID_}" ]] || die "no user '${USER}' in realm ${REALM}"

case "${ACTION}" in
status)
    kcadm get "users/${UID_}" -r "${REALM}" --fields username,enabled,requiredActions
    echo "  brute-force:"
    kcadm get "attack-detection/brute-force/users/${UID_}" -r "${REALM}"
    ;;
unlock)
    kcadm delete "attack-detection/brute-force/users/${UID_}" -r "${REALM}" >/dev/null
    kcadm update "users/${UID_}" -r "${REALM}" -s enabled=true >/dev/null
    ok "${USER}: lockout cleared and account enabled"
    ;;
reset)
    PW=""
    [[ "${3:-}" == "--password" ]] && PW="${4:?--password needs a value}"
    if [[ -z "${PW}" ]]; then
        # Generated to satisfy the realm policy: length 15+, upper, lower, digit, special.
        PW="Rst!$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 14)a1"
    fi
    kcadm delete "attack-detection/brute-force/users/${UID_}" -r "${REALM}" >/dev/null 2>&1
    kcadm update "users/${UID_}" -r "${REALM}" -s enabled=true >/dev/null
    out="$(kcadm set-password -r "${REALM}" --userid "${UID_}" --new-password "${PW}" --temporary)"
    if grep -qi "error" <<<"${out}"; then
        die "reset refused (policy?): ${out}"
    fi
    ok "${USER}: temporary password set — ${PW}"
    warn "single-use: Keycloak demands a replacement at the next login"
    ;;
*)
    die "unknown action '${ACTION}' (status|unlock|reset)"
    ;;
esac
