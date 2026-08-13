#!/usr/bin/env bash
# ==============================================================================
# Account recovery for the platform realm — lockouts and forgotten passwords.
#
#   ./kc-userctl.sh status <username>     lockout state, enabled flag, pending actions
#   ./kc-userctl.sh unlock <username>     clear the brute-force lockout counter
#   ./kc-userctl.sh reset  <username>     set a TEMPORARY password (printed); the user
#                                         must replace it at next login. Also unlocks.
#   ./kc-userctl.sh reset  <username> --password '<value>'   use a chosen value instead
#   ./kc-userctl.sh grant  <username> <group> [--ttl 4h]   temporary group membership
#   ./kc-userctl.sh revoke <username> <group>              remove it now
#   ./kc-userctl.sh expire                                 drop every lapsed grant
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
# `expire` sweeps every account, so it is the one action that takes no username.
[[ -n "${ACTION}" ]] || { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
[[ -n "${USER}" || "${ACTION}" == "expire" ]] \
    || { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }

${RUNTIME} inspect "${KC}" >/dev/null 2>&1 \
    || die "Keycloak is not running on THIS host — account recovery is deliberately host-local"

kcadm() {
    ${RUNTIME} exec -i "${KC}" sh -c '
        /opt/keycloak/bin/kcadm.sh config credentials --server http://127.0.0.1:8080 \
            --realm master --user "${KC_BOOTSTRAP_ADMIN_USERNAME:-admin}" \
            --password "${KC_BOOTSTRAP_ADMIN_PASSWORD:-admin}" >/dev/null 2>&1 &&
        /opt/keycloak/bin/kcadm.sh "$@" 2>&1' -- "$@"
}

UID_=""
if [[ -n "${USER}" ]]; then
    UID_="$(kcadm get users -r "${REALM}" -q "username=${USER}" -q exact=true --fields id \
        | tr -d ' \n' | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')"
    [[ -n "${UID_}" ]] || die "no user '${USER}' in realm ${REALM}"
fi

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
grant)
    GROUP="${3:?grant needs a group}"
    TTL="4h"
    [[ "${4:-}" == "--ttl" ]] && TTL="${5:?--ttl needs a value}"
    case "${TTL}" in
        *h) SECS=$(( ${TTL%h} * 3600 )) ;;
        *m) SECS=$(( ${TTL%m} * 60 )) ;;
        *)  die "--ttl takes 4h or 30m" ;;
    esac
    GID="$(kcadm get groups -r "${REALM}" -q "search=${GROUP}" --fields id,name \
        | tr -d ' \n' | sed -n "s/.*{\"id\":\"\([^\"]*\)\",\"name\":\"${GROUP}\".*/\1/p")"
    [[ -n "${GID}" ]] || die "no group '${GROUP}' in realm ${REALM}"
    EXP="$(date -u -d "+${SECS} seconds" '+%Y-%m-%dT%H:%M:%SZ')"
    kcadm update "users/${UID_}/groups/${GID}" -r "${REALM}" -n >/dev/null \
        || die "could not add ${USER} to ${GROUP}"
    # The expiry rides on the USER as an attribute: Keycloak has no per-membership TTL, so
    # `expire` is what enforces it and this is the only record of when it lapses.
    kcadm update "users/${UID_}" -r "${REALM}" \
        -s "attributes.jit_${GROUP}=${EXP}" >/dev/null
    ok "${USER}: ${GROUP} granted until ${EXP}"
    warn "run 'kc-userctl.sh expire' on a schedule — the grant does not lapse by itself"
    ;;
revoke)
    GROUP="${3:?revoke needs a group}"
    GID="$(kcadm get groups -r "${REALM}" -q "search=${GROUP}" --fields id,name \
        | tr -d ' \n' | sed -n "s/.*{\"id\":\"\([^\"]*\)\",\"name\":\"${GROUP}\".*/\1/p")"
    [[ -n "${GID}" ]] || die "no group '${GROUP}' in realm ${REALM}"
    kcadm delete "users/${UID_}/groups/${GID}" -r "${REALM}" >/dev/null 2>&1
    kcadm update "users/${UID_}" -r "${REALM}" -s "attributes.jit_${GROUP}=" >/dev/null 2>&1
    ok "${USER}: ${GROUP} revoked"
    ;;
expire)
    NOW="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    DROPPED=0
    while read -r uid uname; do
        [[ -n "${uid}" ]] || continue
        while read -r gname exp; do
            [[ -n "${gname}" && -n "${exp}" ]] || continue
            [[ "${exp}" > "${NOW}" ]] && continue
            gid="$(kcadm get groups -r "${REALM}" -q "search=${gname}" --fields id,name \
                | tr -d ' \n' | sed -n "s/.*{\"id\":\"\([^\"]*\)\",\"name\":\"${gname}\".*/\1/p")"
            [[ -n "${gid}" ]] || continue
            kcadm delete "users/${uid}/groups/${gid}" -r "${REALM}" >/dev/null 2>&1
            kcadm update "users/${uid}" -r "${REALM}" -s "attributes.jit_${gname}=" >/dev/null 2>&1
            ok "${uname}: ${gname} expired at ${exp}"
            DROPPED=$((DROPPED + 1))
        done < <(kcadm get "users/${uid}" -r "${REALM}" --fields attributes \
                 | tr -d ' \n' | grep -o '"jit_[^"]*":\["[^"]*"\]' \
                 | sed 's/"jit_\([^"]*\)":\["\([^"]*\)"\]/\1 \2/')
    done < <(kcadm get users -r "${REALM}" --fields id,username \
             | tr -d ' \n' | grep -o '"id":"[^"]*","username":"[^"]*"' \
             | sed 's/"id":"\([^"]*\)","username":"\([^"]*\)"/\1 \2/')
    ok "expired ${DROPPED} grant(s)"
    ;;
*)
    die "unknown action '${ACTION}' (status|unlock|reset|grant|revoke|expire)"
    ;;
esac
