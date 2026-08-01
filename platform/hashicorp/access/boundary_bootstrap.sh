#!/bin/sh
# Provision Boundary for the analyst path: one target, the enclave SSO gate.
#
# Run on every deployment by deploy.sh, inside the boundary container, and RECONCILING rather
# than merely idempotent: each step is find-or-create or set-, so a re-run converges on this
# state instead of duplicating it or skipping it. That matters because a second scope or a second
# target would silently split the allow-list in two, and because a correction made here has to
# reach a deployment that was already provisioned by an earlier version.
#
# Provisioning uses the recovery KMS, not an admin account: it authenticates with the key in the
# config, so the deployment never invents an admin password and then has to keep it. Nothing
# except this script should use that path.
#
#   org / project scope   Boundary's unit of isolation. One project holds this platform's access,
#                         so a second platform on the same controller cannot see its targets.
#   static host catalog   The enclave ingress, by NAME. Resolved at connect time, so a recreated
#                         container does not need re-provisioning.
#   target (tcp :443)     The allow-list. One target, one port; a service with no target has no
#                         route, enforced per session and per principal.
#   password auth method  How the session client authenticates, so sessions are attributable.
#   role                  Grants that principal authorize-session on that target and nothing else.
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

# Runs in full every time. An early exit on the marker file would mean a correction to what is
# provisioned here never reaches a deployment that already has one — the resources stay as the
# first run left them and the fix appears to do nothing. Every step below is find-or-create or
# set-, so a re-run converges rather than duplicating.

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

# Create, or return what already exists under that name.
#
# A partial run leaves resources behind with no marker file, and these names are unique, so a
# plain create fails on every retry with "second resource with the same field value". A retried
# deployment has to converge rather than deadlock.
#
# POSIX only — the image's shell is ash, which has no arrays.
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

# Association steps, with the failure REPORTED.
#
# These were `|| true` for idempotency — re-adding an existing member is an error — and that is
# how a broken association became invisible. A user with no account, or a role with no principal,
# authenticates perfectly well and is then refused at authorize-session with a bare 403, which
# says nothing about which of the two it was. `set-` is idempotent by construction, so nothing has
# to be swallowed to make a re-run safe.
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

echo "[boundary] role — authorize-session on that target and nothing else"
R="$(ensure roles -scope-id "${PROJ}" analyst-session -scope-id "${PROJ}" -name analyst-session)"
must "adding ${ANALYST_LOGIN} to the role" roles set-principals -id "${R}" -principal "${U}"
# Scoped to the one target. A grant of `type=target;actions=authorize-session` without an id
# would authorize every target that ever gets created in this project.
#
# set-grants, not add-grants: re-running must converge on exactly these grants rather than
# accumulate, and a role created by an earlier run with the wrong scope has to be corrected.
#
# `ids=`, not `id=`: the singular form is deprecated and a grant using it is accepted at write
# time but does not authorize, which surfaces only as a 403 on authorize-session.
#
# `ids=*;type=session`, not a bare `type=session`: a grant naming only a type permits `create` and
# `list` and REJECTS per-resource actions outright. And set-grants is ATOMIC — one unparseable
# grant discards the whole call, so a malformed second grant leaves the role with no grants at
# all, including the target grant that was written correctly.
must "granting ${ANALYST_LOGIN} a session on the target" \
    roles set-grant-scopes -id "${R}" -grant-scope-id "${PROJ}"
# `list,read:self,cancel:self`: list results are filtered to what the principal can read, so it
# sees only its own sessions — which is how a restarted broker finds and cancels the session its
# predecessor abandoned, instead of leaving it "active" in the access record until expiry.
must "granting ${ANALYST_LOGIN} a session on the target" \
    roles set-grants -id "${R}" \
        -grant "ids=${T};actions=authorize-session" \
        -grant "ids=*;type=session;actions=list,read:self,cancel:self"

# The chain is verified rather than assumed. Six links stand between an authenticated analyst and
# a session — account, user, role, principals, grant scopes, grant — and a missing one produces
# the same bare 403 as any other. Checking the grant landed turns that into a failure here, next
# to the call that was supposed to write it.
if ! b roles read -id "${R}" | grep -q "ids=${T};actions=authorize-session"; then
    echo "[boundary] the authorize-session grant is not on role ${R} after writing it" >&2
    echo "[boundary] the analyst would authenticate and then be refused with 403" >&2
    exit 1
fi

echo "[boundary] session-auditor principal — the platform's read-only view of brokered sessions"
# The account the platform authenticates as to SHOW who is connected. It can list and read
# sessions and nothing else: not authorize one, not cancel one, not read a target. Watching
# sessions in the UI must not become a way to acquire one, and the recovery key — which would
# make this trivial — is exactly the credential that must never leave this tier.
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
BOUNDARY_SESSION_AUDITOR_LOGIN=${SA_LOGIN}
EOF
echo "[boundary] provisioned — target ${T} -> ${TARGET_HOST}:${TARGET_PORT}"
