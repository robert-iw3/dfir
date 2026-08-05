#!/usr/bin/env bash
# ==============================================================================
# IDENTITY STORE — separation, dynamic credentials, persistence, converge, mesh.
#
# Every assertion ATTEMPTS THE VIOLATION with a credential proven to work elsewhere, or
# proves the property by exercising it. Reading a config value proves the file, not the
# property. Connections are forced over TCP (-h 127.0.0.1): the local socket authenticates
# by trust, which would make every credential claim vacuous.
#
# The persistence section is DESTRUCTIVE-ADJACENT (removes the Keycloak container and
# redeploys the enclave through deploy.sh) and therefore runs LAST, gated on everything
# before it. It removes only a namespace SHARER — the sidecar owns the namespace — so the
# removal cannot deadlock the runtime.
# ==============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"

# The deployment's own values — including the data-tier admin credential the privilege
# checks authenticate with.
set -a
. "${PLATFORM}/deploy/.env"
[[ -f "${PLATFORM}/deploy/.env.db" ]] && . "${PLATFORM}/deploy/.env.db"
set +a

. "${HERE}/lib/report.sh"
report_begin 46 keycloak_db "Identity store — separated, leased, persistent" \
    "The identity store is a separate database the application is refused the CONNECTION to; both sides run on Vault leases with no static secret in any environment; accounts survive a Keycloak recreate through the deploy path; the realm file is enforced on existing realms; the database hop rides the mesh."
RUNTIME="${IR_RUNTIME:-podman}"
DB=ir-enclave_db_1
BE=ir-enclave_backend_1
WK=ir-enclave_worker_1
KC=ir-enclave_keycloak_1
CONSUL=ir-enclave_consul_1
SEC="${PLATFORM}/hashicorp/consul/secrets"
REALM_FILE="${PLATFORM}/hashicorp/keycloak/realm-irplatform.json"
EVIDENCE_DB="${POSTGRES_DB:-ir_platform}"
CORR_DB="${CORRELATION_POSTGRES_DB:-ir_correlation}"

# TCP, never the local socket: socket connections are trusted, and a "successful" login
# that never checked the password proves nothing about the credential.
pgq() { # user pw db sql
    ${RUNTIME} exec -e PGPASSWORD="$2" "${DB}" \
        psql -h 127.0.0.1 -U "$1" -d "$3" -tAc "$4" 2>&1
}
adminq() { pgq ir_platform "${POSTGRES_PASSWORD:-ir_platform}" "$1" "$2"; }

kcadm() {
    ${RUNTIME} exec -i "${KC}" sh -c '
        /opt/keycloak/bin/kcadm.sh config credentials --server http://127.0.0.1:8080 \
            --realm master --user "${KC_BOOTSTRAP_ADMIN_USERNAME:-admin}" \
            --password "${KC_BOOTSTRAP_ADMIN_PASSWORD:-admin}" >/dev/null 2>&1 &&
        /opt/keycloak/bin/kcadm.sh "$@" 2>&1' -- "$@"
}

say "Preconditions"
for c in "${DB}" "${BE}" "${KC}" ir-enclave_vault-agent_1 ir-enclave_kc-vault-agent_1; do
    [[ "$(${RUNTIME} inspect "$c" --format '{{.State.Status}}' 2>/dev/null)" == "running" ]] \
        && ok "$c running" || { bad "$c not running"; report_finish; exit 1; }
done
# The static admin credential must itself work, or half the checks below prove nothing.
grep -q '^1$' <<<"$(adminq postgres 'SELECT 1')" \
    && ok "static admin credential opens the maintenance database (control for admin checks)" \
    || { bad "static admin credential is broken — aborting before asserting anything with it"; report_finish; exit 1; }

say "The application's LIVE credential — what it sources, not what compose says"
# The file the entrypoint sources is the credential in use; the container's configured
# environment is asserted to be EMPTY of secrets further down.
APP_USER="$(${RUNTIME} exec "${BE}" sh -c 'grep "^export POSTGRES_USER=" /vault/secrets/app.env | cut -d= -f2' 2>/dev/null)"
APP_PW="$(${RUNTIME} exec "${BE}" sh -c 'grep "^export POSTGRES_PASSWORD=" /vault/secrets/app.env | cut -d= -f2' 2>/dev/null)"
[[ -n "${APP_USER}" && -n "${APP_PW}" ]] \
    && ok "read the application's rendered credential (${APP_USER})" \
    || bad "could not read the application's rendered credential from ${BE}"
[[ "${APP_USER}" == v-* ]] \
    && ok "the credential is Vault-issued (username shape ${APP_USER%%-*}-…)" \
    || bad "the application's credential does not look Vault-issued (${APP_USER})"

CTRL="$(pgq "${APP_USER}" "${APP_PW}" "${EVIDENCE_DB}" 'SELECT 1')"
grep -q '^1$' <<<"${CTRL}" \
    && ok "control: that credential DOES open the evidence database over TCP" \
    || bad "control failed — the credential does not work anywhere (${CTRL:0:80})"

say "The application is refused the identity store"
DENIED="$(pgq "${APP_USER}" "${APP_PW}" keycloak 'SELECT 1')"
if grep -qiE "permission denied for database|not permitted|no pg_hba" <<<"${DENIED}"; then
    ok "the application's credential is REFUSED the connection to the keycloak database"
elif grep -q '^1$' <<<"${DENIED}"; then
    bad "the application CONNECTED to the identity store — password hashes are reachable"
else
    bad "unexpected result connecting as the application (${DENIED:0:100})"
fi

# The privilege itself, so every FUTURE table in that database is unreachable by default
# rather than protected by a grant list somebody maintains.
HAS="$(adminq postgres "SELECT has_database_privilege('ir_app','keycloak','CONNECT')" | tr -d ' ')"
[[ "${HAS}" == "f" ]] \
    && ok "ir_app holds no CONNECT privilege on keycloak" \
    || bad "ir_app still holds CONNECT on the identity store (${HAS})"

say "The reciprocal — the identity role reaches no evidence"
for db in "${EVIDENCE_DB}" "${CORR_DB}"; do
    R="$(adminq postgres "SELECT has_database_privilege('kc_app','${db}','CONNECT')" | tr -d ' ')"
    [[ "${R}" == "f" ]] \
        && ok "kc_app holds no CONNECT on ${db}" \
        || bad "kc_app can reach ${db} (${R}) — separation is one-way only"
done

say "Ownership and schema"
OWNER="$(adminq postgres "SELECT pg_catalog.pg_get_userbyid(datdba) FROM pg_database WHERE datname='keycloak'" | tr -d ' ')"
[[ "${OWNER}" == "kc_app" ]] \
    && ok "the keycloak database is owned by kc_app, not by the application's role" \
    || bad "unexpected owner for the keycloak database (${OWNER})"
PUBCREATE="$(adminq keycloak "SELECT has_schema_privilege('public','public','CREATE')" | tr -d ' ')"
[[ "${PUBCREATE}" == "f" ]] \
    && ok "PUBLIC cannot create objects in the identity store's schema" \
    || bad "PUBLIC can still create in the keycloak schema (${PUBCREATE})"

say "No superuser, no static secret, in the app tier"
# The container's CONFIGURED environment — what any process in it can read — must hold no
# database secret. The credential exists only in the Vault-rendered file.
for c in "${BE}" "${WK}"; do
    ENVPW="$(${RUNTIME} exec "$c" printenv POSTGRES_PASSWORD 2>/dev/null || true)"
    [[ -z "${ENVPW}" ]] \
        && ok "$c carries no POSTGRES_PASSWORD in its environment" \
        || bad "$c still carries the static database password in its environment"
done
# What is ACTUALLY connected: every application connection is a Vault-issued user, and none
# of them is a superuser. The count control keeps an empty result from passing vacuously.
NCONN="$(adminq postgres "SELECT count(*) FROM pg_stat_activity WHERE datname IN ('${EVIDENCE_DB}','${CORR_DB}')" | tr -d ' ')"
[[ "${NCONN:-0}" -gt 0 ]] \
    && ok "control: the application holds ${NCONN} live connection(s) to assert against" \
    || bad "no live application connections — the assertions below would pass on an idle lie"
# APPLICATION connections, which is what D-007 is about: "the app tier holds no static
# superuser". The static admin still exists and is still a superuser by design — it is the
# credential broker's identity, kept in deploy/.env.db and loaded only by the data tier — so
# Vault itself holds a live connection as it in order to mint and revoke. Counting that as an
# application connection tests a wider population than the decision covers.
#
# The exclusion is narrow and then asserted in the other direction below, so it cannot become
# somewhere a rogue superuser hides.
NBAD="$(adminq postgres "SELECT count(*) FROM pg_stat_activity a JOIN pg_roles r ON r.rolname=a.usename \
    WHERE a.datname IN ('${EVIDENCE_DB}','${CORR_DB}') AND a.application_name <> 'vault' \
      AND (r.rolsuper OR a.usename NOT LIKE 'v-%')" | tr -d ' ')"
[[ "${NBAD}" == "0" ]] \
    && ok "every live application connection is a Vault-issued non-superuser" \
    || bad "${NBAD} live connection(s) are superuser or non-Vault — grants cannot separate a superuser"

# The other direction: whatever was excluded must BE the broker. Any connection that is not a
# Vault-issued user has to be the static admin arriving over loopback as Vault — a superuser
# session from anywhere else is the thing this decision exists to prevent, and excluding it by
# application_name alone would let it pass unexamined.
NBROKER="$(adminq postgres "SELECT count(*) FROM pg_stat_activity a \
    WHERE a.datname IN ('${EVIDENCE_DB}','${CORR_DB}') AND a.usename NOT LIKE 'v-%' \
      AND NOT (a.application_name = 'vault' AND a.usename = '${POSTGRES_USER:-ir_platform}')" | tr -d ' ')"
[[ "${NBROKER}" == "0" ]] \
    && ok "the only non-Vault-issued session is the credential broker's own (static admin, as vault)" \
    || bad "${NBROKER} session(s) authenticate outside both the Vault-issued users and the broker"

say "Keycloak's credential — a lease, not a static secret wearing a dynamic name"
KC_USER="$(${RUNTIME} exec "${KC}" sh -c 'grep "^export KC_DB_USERNAME=" /vault/secrets/kc-db.env | cut -d= -f2' 2>/dev/null)"
[[ "${KC_USER}" == v-* ]] \
    && ok "Keycloak's rendered credential is Vault-issued (${KC_USER%%.*})" \
    || bad "Keycloak's credential does not look Vault-issued (${KC_USER:-unreadable})"
EXPIRES="$(adminq postgres "SELECT rolvaliduntil IS NOT NULL FROM pg_roles WHERE rolname='${KC_USER}'" | tr -d ' ')"
[[ "${EXPIRES}" == "t" ]] \
    && ok "that user EXPIRES (VALID UNTIL set) — it is a lease" \
    || bad "no expiry on ${KC_USER} — a credential that never expires is static (${EXPIRES})"
MEMBER="$(adminq postgres "SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON m.roleid=r.oid \
    JOIN pg_roles u ON m.member=u.oid WHERE r.rolname='kc_app' AND u.rolname='${KC_USER}'" | tr -d ' ')"
[[ "${MEMBER}" == "1" ]] \
    && ok "the leased user acts as kc_app — objects survive rotation" \
    || bad "${KC_USER} is not a member of kc_app"
KCCONN="$(adminq postgres "SELECT count(*) FROM pg_stat_activity WHERE datname='keycloak' AND usename='${KC_USER}'" | tr -d ' ')"
[[ "${KCCONN:-0}" -gt 0 ]] \
    && ok "Keycloak is CONNECTED to its store with that lease (${KCCONN} connection(s))" \
    || bad "no live Keycloak connection under the leased user — is it running on the embedded store?"

# The credential the PROCESS holds, not the one on disk. Keycloak reads it once and pools
# connections, so a rotation without a restart leaves it authenticating as a user Vault has
# revoked — the pool dies with `role … does not exist` and the login page fails for a reason
# that names nothing. Comparing the file to itself would pass while that is true.
KC_PROC="$(${RUNTIME} exec "${KC}" sh -c "tr '\0' '\n' < /proc/1/environ | sed -n 's/^KC_DB_USERNAME=//p'" 2>/dev/null)"
[[ -n "${KC_PROC}" && "${KC_PROC}" == "${KC_USER}" ]] \
    && ok "the running process holds the CURRENT credential — no superseded user in its pool" \
    || bad "Keycloak is running on ${KC_PROC:-unknown} while Vault has issued ${KC_USER}"
STALE="$(adminq postgres "SELECT count(*) FROM pg_roles WHERE rolname LIKE 'v-approle-keycloak%' AND rolname <> '${KC_USER}'" | tr -d ' ')"
info "superseded keycloak roles still present in the cluster: ${STALE:-?}"
# Static absence — both halves are needed; either alone passes while the other is false.
ENVKC="$(${RUNTIME} exec "${KC}" printenv KC_DB_PASSWORD 2>/dev/null || true)"
[[ -z "${ENVKC}" ]] \
    && ok "no KC_DB_PASSWORD in Keycloak's configured environment" \
    || bad "KC_DB_PASSWORD sits in Keycloak's environment — a static secret"
if grep -rq "KC_DB_PASSWORD" "${PLATFORM}/deploy/enclave/docker-compose.yml" "${PLATFORM}/deploy/.env" 2>/dev/null; then
    bad "KC_DB_PASSWORD appears in compose or .env — a static secret in the tree"
else
    ok "no KC_DB_PASSWORD in compose or .env"
fi

say "The database hop rides the mesh"
consul_check() { # src dst
    ${RUNTIME} exec \
        -e CONSUL_HTTP_ADDR=https://127.0.0.1:8501 \
        -e CONSUL_CACERT=/consul/tls/consul-ca.pem \
        -e CONSUL_HTTP_TOKEN="$(cat "${SEC}/tokens/management.token" 2>/dev/null)" \
        "${CONSUL}" consul intention check "$1" "$2" 2>&1
}
grep -q "Allowed" <<<"$(consul_check ir-keycloak ir-postgres)" \
    && ok "intention permits ir-keycloak -> ir-postgres" \
    || bad "the mesh does not permit Keycloak's database connection"
grep -q "Denied" <<<"$(consul_check ir-frontend ir-postgres)" \
    && ok "control: a pair with no business (ir-frontend -> ir-postgres) is Denied" \
    || bad "the control pair is not denied — default-deny is not holding"

say "Realm converge — the file governs an EXISTING realm"
FILE_FF="$(jq -r '.failureFactor' "${REALM_FILE}")"
kcadm update realms/irplatform -s failureFactor=99 >/dev/null \
    || bad "could not perturb the live realm — converge cannot be proven"
bash "${PLATFORM}/hashicorp/keycloak/realm-converge.sh" >/dev/null 2>&1
LIVE_FF="$(kcadm get realms/irplatform --fields failureFactor | tr -dc '0-9')"
[[ "${LIVE_FF}" == "${FILE_FF}" ]] \
    && ok "a drifted brute-force threshold (99) was converged back to the file's value (${FILE_FF})" \
    || bad "converge did not enforce the file: live=${LIVE_FF:-?}, file=${FILE_FF}"

say "Persistence — the defect that started this (destructive, runs last)"
if [[ "${FAILED}" != "0" ]]; then
    bad "earlier assertions failed — skipping the destructive persistence proof"
else
    PROBE=uat-persist-probe
    PW1='Uat-persist-Pw1!aaaaaa'
    # A throwaway account, so no analyst credential is touched. The FULL profile matters:
    # a user without one carries a pending profile-verification action, and a direct grant
    # then fails "Account is not fully set up" — which reads exactly like data loss.
    kcadm create users -r irplatform -s "username=${PROBE}" -s enabled=true \
        -s firstName=UAT -s lastName=Probe \
        -s "email=${PROBE}@uat.invalid" -s emailVerified=true >/dev/null
    UID_="$(kcadm get users -r irplatform -q "username=${PROBE}" -q exact=true --fields id \
        | tr -d ' \n' | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')"
    [[ -n "${UID_}" ]] && ok "probe account created" || bad "could not create the probe account"
    kcadm set-password -r irplatform --userid "${UID_}" --new-password "${PW1}" >/dev/null

    login_as() { # user pw -> 0 if a token is issued
        ${RUNTIME} exec "${KC}" /opt/keycloak/bin/kcadm.sh config credentials \
            --server http://127.0.0.1:8080 --realm irplatform \
            --user "$1" --password "$2" --client admin-cli >/dev/null 2>&1
    }
    login_as "${PROBE}" "${PW1}" \
        && ok "control: the probe credential authenticates BEFORE the recreate" \
        || bad "probe credential does not authenticate — persistence cannot be proven"

    # Remove the SHARER only (the sidecar owns the namespace), then restore through the
    # deploy path — the thing that must bring identity back with its data.
    ${RUNTIME} rm -f "${KC}" >/dev/null 2>&1
    ok "Keycloak container removed"
    if bash "${PLATFORM}/deploy/deploy.sh" enclave >/dev/null 2>&1; then
        ok "enclave redeployed through deploy.sh"
    else
        bad "deploy.sh enclave failed after the removal — see its output"
    fi
    # The deploy's gate is "listening", not "settled": the late-stage sidecar sweep can
    # bounce the database path under a just-started Keycloak, which restarts once more. A
    # login refused by a server that is not serving yet says nothing about persistence —
    # gate on the realm answering through the full auth path, then assert.
    ready=0
    for _ in $(seq 1 45); do
        kcadm get realms/irplatform --fields realm 2>/dev/null | grep -q irplatform && { ready=1; break; }
        sleep 4
    done
    [[ "${ready}" == "1" ]] || bad "the realm never answered after the redeploy"
    login_as "${PROBE}" "${PW1}" \
        && ok "the credential set BEFORE the recreate authenticates AFTER it — accounts persist" \
        || bad "the probe credential is GONE after a recreate — the identity store did not persist"
    login_as "${PROBE}" 'Wrong-password-1!aaaa' \
        && bad "a wrong password authenticated — the login check is not real" \
        || ok "control: a wrong password is still refused"

    # Leave nothing behind.
    UID2="$(kcadm get users -r irplatform -q "username=${PROBE}" -q exact=true --fields id \
        | tr -d ' \n' | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')"
    [[ -n "${UID2}" ]] && kcadm delete "users/${UID2}" -r irplatform >/dev/null
fi

say "Result"
if [[ "${FAILED}" == "0" ]]; then
    ok "identity is separated by privilege, leased by Vault, and survives a recreate"
else
    bad "identity store guarantees do NOT hold — see failures above"
fi
report_finish
exit "${FAILED}"
