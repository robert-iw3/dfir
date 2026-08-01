#!/bin/sh
# Dump the authorization chain behind the analyst's session, one link per line.
#
# Run inside the controller container:  boundary_authz.sh
#
#   account -> user -> role -> role's principals -> role's grant scopes -> grant on the target
set -eu

: "${BOUNDARY_RECOVERY_KEY:?BOUNDARY_RECOVERY_KEY is required}"
export BOUNDARY_ADDR="${BOUNDARY_ADDR:-https://127.0.0.1:9200}"
export BOUNDARY_CACERT="${BOUNDARY_CACERT:-/boundary/certs/boundary.crt}"
ANALYST_LOGIN="${BOUNDARY_ANALYST_LOGIN:-analyst}"

RECOVERY="$(mktemp)"
trap 'rm -f "${RECOVERY}"' EXIT
cat > "${RECOVERY}" <<EOF
kms "aead" {
  purpose   = "recovery"
  aead_type = "aes-gcm"
  key       = "${BOUNDARY_RECOVERY_KEY}"
  key_id    = "global_recovery"
}
EOF

b() { boundary "$@" -recovery-config "${RECOVERY}" -format json 2>&1; }
# Ids carry a type prefix, which is what makes them safe to pull from a raw response without jq.
idof() { grep -o "\"id\":\"$1[^\"]*\"" | cut -d'"' -f4; }

ORG="$(b scopes list -scope-id global -filter '"/item/name"=="ir-platform"' | idof o_ | head -1)"
[ -n "${ORG}" ] || { echo "org scope ir-platform: MISSING"; exit 1; }
echo "org scope        ${ORG}"

PROJ="$(b scopes list -scope-id "${ORG}" -filter '"/item/name"=="enclave-access"' | idof p_ | head -1)"
[ -n "${PROJ}" ] || { echo "project scope enclave-access: MISSING"; exit 1; }
echo "project scope    ${PROJ}"

T="$(b targets list -scope-id "${PROJ}" -filter '"/item/name"=="sso-gate"' | idof ttcp_ | head -1)"
echo "target sso-gate  ${T:-MISSING}"

U="$(b users list -scope-id "${ORG}" -filter "\"/item/name\"==\"${ANALYST_LOGIN}\"" | idof u_ | head -1)"
echo "user ${ANALYST_LOGIN}     ${U:-MISSING}"
if [ -n "${U}" ]; then
    # An account here is what ties the authenticated token to this user. With none, the token is
    # anonymous as far as grants are concerned and every role below is inert.
    accts="$(b users read -id "${U}" | grep -o '"account_ids":\[[^]]*\]' || true)"
    echo "  accounts       ${accts:-NONE — the token would carry no user}"
fi

R="$(b roles list -scope-id "${PROJ}" -filter '"/item/name"=="analyst-session"' | idof r_ | head -1)"
echo "role             ${R:-MISSING}"
if [ -n "${R}" ]; then
    role="$(b roles read -id "${R}")"
    echo "  principals     $(printf '%s' "${role}" | grep -o '"principal_ids":\[[^]]*\]' || echo 'NONE')"
    echo "  grant scopes   $(printf '%s' "${role}" | grep -o '"grant_scope_ids":\[[^]]*\]' || echo 'NONE')"
    # `ids=` is the authorizing form. A grant written `id=` is accepted and does nothing.
    echo "  grants         $(printf '%s' "${role}" | grep -o '"grant_strings":\[[^]]*\]' || echo 'NONE')"
fi
