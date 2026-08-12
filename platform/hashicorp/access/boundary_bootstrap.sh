#!/bin/sh
# Provision Boundary for the analyst path — one target, the enclave SSO gate. Runs on every
# deployment inside the boundary container, RECONCILING rather than creating: names are unique, so
# a partial run converges instead of duplicating.
set -eu

OUT="${1:-/boundary-state/boundary-ids.env}"
# Over TLS to the controller's own API listener, and pinned to its certificate. Loopback is not a
# reason to skip verification: the recovery key travels on this connection, and `-tls-insecure`
# here would be a habit that later gets copied to a call that crosses the link.
export BOUNDARY_ADDR="${BOUNDARY_ADDR:-https://127.0.0.1:9200}"
export BOUNDARY_CACERT="${BOUNDARY_CACERT:-/boundary/certs/boundary.crt}"
TARGET_HOST="${IR_ENCLAVE_INGRESS_HOST:-traefik}"
TARGET_PORT="${IR_ENCLAVE_INGRESS_PORT:-443}"
ANALYST_LOGIN="${BOUNDARY_ANALYST_LOGIN:-analyst}"
ANALYST_PASSWORD="${BOUNDARY_ANALYST_PASSWORD:?BOUNDARY_ANALYST_PASSWORD is required}"

# Runs in full every time: an early exit on a marker file means a correction here never reaches a
# deployment that already has one.

echo "[boundary] waiting for the controller to answer"
for i in $(seq 1 90); do
    wget -q -O- "http://127.0.0.1:9203/health" >/dev/null 2>&1 && break
    [ "$i" = 90 ] && { echo "[boundary] controller never became healthy" >&2; exit 1; }
    sleep 2
done

RECOVERY="$(mktemp)"
cat > "${RECOVERY}" <<EOF
kms "aead" {
  purpose   = "recovery"
  aead_type = "aes-gcm"
  key       = "${BOUNDARY_RECOVERY_KEY}"
  key_id    = "global_recovery"
}
EOF
trap 'rm -f "${RECOVERY}"' EXIT

b() { boundary "$@" -recovery-config "${RECOVERY}" -format json; }
# The boundary image carries no jq or python. An item's own id is the first "id" in its output.
jget() { grep -o '"id": *"[^"]*"' | head -1 | cut -d'"' -f4; }

# Create, or return what already exists under that name — a partial run leaves resources with no
# marker, and unique names make the retry converge.
ensure() {  # ensure <kind> <scope-flag> <scope-id> <name> <create-args...>
    _kind="$1"; _sflag="$2"; _sid="$3"; _name="$4"; shift 4
    # Asked for by NAME through Boundary's own filter, rather than matching id and name out of a
    # list by line proximity — field order in the response is not guaranteed, and a near-miss
    # returns an empty id that reads as "created" while nothing was found.
    _found="$(b "${_kind}" list "${_sflag}" "${_sid}" \
        -filter "\"/item/name\"==\"${_name}\"" 2>/dev/null | jget)"
    if [ -n "${_found}" ]; then printf '%s' "${_found}"; return 0; fi
    b "${_kind}" create "$@" | jget
}

# Association steps with the failure REPORTED: blanket `|| true` for idempotency also swallowed
# the real failures, leaving the next error describing a symptom.
must() {  # must <description> <boundary-args...>
    _what="$1"; shift
    if ! _out="$(b "$@" 2>&1)"; then
        echo "[boundary] ${_what} failed:" >&2
        printf '%s\n' "${_out}" | tail -4 | sed 's/^/[boundary]   /' >&2
        return 1
    fi
}

echo "[boundary] scopes"
ORG="$(ensure scopes -scope-id global ir-platform \
        -scope-id global -name ir-platform -description "IR platform")"
PROJ="$(ensure scopes -scope-id "${ORG}" enclave-access \
        -scope-id "${ORG}" -name enclave-access -description "Brokered access into the enclave")"

echo "[boundary] host catalog + host (${TARGET_HOST})"
HC="$(ensure host-catalogs -scope-id "${PROJ}" enclave static -scope-id "${PROJ}" -name enclave)"
# By name: the ingress container is recreated on every deployment.
H="$(ensure hosts -host-catalog-id "${HC}" ingress static -host-catalog-id "${HC}" -name ingress \
      -address "${TARGET_HOST}")"
HS="$(ensure host-sets -host-catalog-id "${HC}" ingress static -host-catalog-id "${HC}" -name ingress)"
must "attaching the host to its set" host-sets set-hosts -id "${HS}" -host "${H}"

echo "[boundary] target — the SSO gate on :${TARGET_PORT}"
# The allow-list. Everything else in the enclave has no target and therefore no route.
T="$(ensure targets -scope-id "${PROJ}" sso-gate tcp -scope-id "${PROJ}" -name sso-gate \
      -description "Traefik + oauth2-proxy — the only thing an analyst may reach" \
      -default-port "${TARGET_PORT}")"
must "attaching the host set to the target" targets set-host-sources -id "${T}" -host-source "${HS}"

echo "[boundary] auth method + analyst principal"
AM="$(ensure auth-methods -scope-id "${ORG}" analysts password -scope-id "${ORG}" -name analysts)"
b auth-methods change-state oidc -id "${AM}" -state active-public >/dev/null 2>&1 || true
# Accounts have no name, so they are matched on login name — the field that is actually unique
# here. A plain create fails on every re-run once the account exists, which would leave the user
# with no account and every session unattributable.
ACCT="$(b accounts list -auth-method-id "${AM}" \
        -filter "\"/item/attributes/login_name\"==\"${ANALYST_LOGIN}\"" 2>/dev/null | jget)"
[ -n "${ACCT}" ] || ACCT="$(b accounts create password -auth-method-id "${AM}" \
         -login-name "${ANALYST_LOGIN}" -password "env://ANALYST_PW" | jget)"
U="$(ensure users -scope-id "${ORG}" "${ANALYST_LOGIN}" -scope-id "${ORG}" -name "${ANALYST_LOGIN}")"
[ -n "${ACCT}" ] || { echo "[boundary] no account for ${ANALYST_LOGIN} — sessions cannot be attributed" >&2; exit 1; }
# Without this the token belongs to an account with no user, so no role applies to it and every
# grant below is inert. It authenticates and is then refused at authorize-session.
must "binding the ${ANALYST_LOGIN} account to its user" users set-accounts -id "${U}" -account "${ACCT}"

# One principal PER BROKER SESSION beside the base analyst: a shared principal makes sessions
# indistinguishable in the access record and turns any principal-scoped cancel into a fleet-wide
# one.
SESSIONS_N="${BOUNDARY_SESSION_PRINCIPALS:-8}"
export SESS_PW="${ANALYST_PASSWORD}"
SESSION_USERS=""
i=1
while [ "${i}" -le "${SESSIONS_N}" ]; do
    SLOGIN="${ANALYST_LOGIN}-s${i}"
    SACCT="$(b accounts list -auth-method-id "${AM}" \
            -filter "\"/item/attributes/login_name\"==\"${SLOGIN}\"" 2>/dev/null | jget)"
    [ -n "${SACCT}" ] || SACCT="$(b accounts create password -auth-method-id "${AM}" \
             -login-name "${SLOGIN}" -password "env://SESS_PW" | jget)"
    SU="$(ensure users -scope-id "${ORG}" "${SLOGIN}" -scope-id "${ORG}" -name "${SLOGIN}")"
    [ -n "${SACCT}" ] || { echo "[boundary] no account for ${SLOGIN}" >&2; exit 1; }
    must "binding ${SLOGIN} to its user" users set-accounts -id "${SU}" -account "${SACCT}"
    SESSION_USERS="${SESSION_USERS} ${SU}"
    i=$((i + 1))
done

echo "[boundary] role — authorize-session on that target and nothing else"
R="$(ensure roles -scope-id "${PROJ}" analyst-session -scope-id "${PROJ}" -name analyst-session)"
# set-principals REPLACES the set, so every principal goes in one call: the base analyst and
# each session principal.
_principals="-principal ${U}"
for _su in ${SESSION_USERS}; do _principals="${_principals} -principal ${_su}"; done
# shellcheck disable=SC2086
must "adding the analyst principals to the role" roles set-principals -id "${R}" ${_principals}
# Scoped to the one target: an id-less `type=target;actions=authorize-session` grant would
# authorize every target ever created in the project.
must "granting ${ANALYST_LOGIN} a session on the target" \
    roles set-grant-scopes -id "${R}" -grant-scope-id "${PROJ}"
# `list,read:self,cancel:self`: list results are filtered to what the principal can read, so it
# sees only its own sessions — which is how a restarted broker finds and cancels the session its
# predecessor abandoned, instead of leaving it "active" in the access record until expiry.
must "granting ${ANALYST_LOGIN} a session on the target" \
    roles set-grants -id "${R}" \
        -grant "ids=${T};actions=authorize-session" \
        -grant "ids=*;type=session;actions=list,read:self,cancel:self"

# The chain is VERIFIED, not assumed: six links stand between an authenticated analyst and a
# session, and a missing one produces an unexplained 403.
if ! b roles read -id "${R}" | grep -q "ids=${T};actions=authorize-session"; then
    echo "[boundary] the authorize-session grant is not on role ${R} after writing it" >&2
    echo "[boundary] the analyst would authenticate and then be refused with 403" >&2
    exit 1
fi

echo "[boundary] session-auditor principal — the platform's read-only view of brokered sessions"
# The account the platform authenticates as to SHOW who is connected: list and read sessions,
# nothing else — not authorize, not cancel, not read a target.
SA_LOGIN="${BOUNDARY_SESSION_AUDITOR_LOGIN:-session-auditor}"
export SA_PW="${BOUNDARY_SESSION_AUDITOR_PASSWORD:-${ANALYST_PASSWORD}}"
SA_ACCT="$(b accounts list -auth-method-id "${AM}" \
        -filter "\"/item/attributes/login_name\"==\"${SA_LOGIN}\"" 2>/dev/null | jget)"
[ -n "${SA_ACCT}" ] || SA_ACCT="$(b accounts create password \
        -auth-method-id "${AM}" -login-name "${SA_LOGIN}" -password "env://SA_PW" | jget)"
SA_USER="$(ensure users -scope-id "${ORG}" "${SA_LOGIN}" -scope-id "${ORG}" -name "${SA_LOGIN}")"
must "binding the ${SA_LOGIN} account to its user" \
    users set-accounts -id "${SA_USER}" -account "${SA_ACCT}"
# No -grant-scope-id on create: this Boundary rejects the flag there and the whole create
# fails, leaving no role — so the grant below has no id to attach to and the sessions page
# lists nothing instead of erroring. A new role is scoped to "this" already, which is this
# project, so nothing further is needed.
SA_ROLE="$(ensure roles -scope-id "${PROJ}" session-auditor -scope-id "${PROJ}" \
        -name session-auditor)"
must "adding ${SA_LOGIN} to the auditor role" roles set-principals -id "${SA_ROLE}" -principal "${SA_USER}"
# `list,read`, not `read:self`: the point is seeing OTHER principals' sessions. Still read-only:
# no authorize-session, no cancel, no target read.
must "granting ${SA_LOGIN} read-only session visibility" \
    roles set-grants -id "${SA_ROLE}" \
        -grant "ids=*;type=session;actions=list,read"
# Verified, because a grant that fails to apply leaves the page permanently empty — which reads
# as "nobody is connected", the most dangerous wrong answer an access-audit page can give.
if ! b roles read -id "${SA_ROLE}" | grep -q 'type=session'; then
    echo "[boundary] the session-auditor grant did not apply — the sessions page would show nothing" >&2
    exit 1
fi
# Users are ORG resources; a user grant on a project role is inert, and the page can only print
# `u_...` ids. A second role at the org resolves identities — list,read on users and nothing
# else, so an auditor can NAME who acted without gaining any reach.
SA_ORG_ROLE="$(ensure roles -scope-id "${ORG}" session-auditor -scope-id "${ORG}" \
        -name session-auditor)"
must "adding ${SA_LOGIN} to the org auditor role" \
    roles set-principals -id "${SA_ORG_ROLE}" -principal "${SA_USER}"
must "granting ${SA_LOGIN} identity resolution at the org" \
    roles set-grants -id "${SA_ORG_ROLE}" -grant "ids=*;type=user;actions=list,read"
if ! b roles read -id "${SA_ORG_ROLE}" | grep -q 'type=user'; then
    echo "[boundary] the org user grant did not apply — sessions would show ids instead of names" >&2
    exit 1
fi

mkdir -p "$(dirname "${OUT}")"
umask 077
cat > "${OUT}" <<EOF
BOUNDARY_ORG_ID=${ORG}
BOUNDARY_PROJECT_ID=${PROJ}
BOUNDARY_TARGET_ID=${T}
BOUNDARY_AUTH_METHOD_ID=${AM}
BOUNDARY_ANALYST_USER_ID=${U}
BOUNDARY_SESSION_USER_IDS="$(echo ${SESSION_USERS})"
BOUNDARY_SESSION_AUDITOR_LOGIN=${SA_LOGIN}
EOF
echo "[boundary] provisioned — target ${T} -> ${TARGET_HOST}:${TARGET_PORT}"
