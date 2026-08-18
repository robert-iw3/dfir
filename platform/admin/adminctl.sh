#!/usr/bin/env bash
# Administrative access, opened on demand and closed when the task is done.
#
# An admin logs into the host that owns a tier and opens a forwarder for that tier only.
# Nothing here runs as part of a normal deployment: management interfaces are reachable
# while an admin is working and unreachable the rest of the time, which is a much smaller
# window than leaving consoles published.
#
#   ./adminctl.sh up enclave          # MinIO, Keycloak, Consul, Postgres, Vault, Boundary
#   ./adminctl.sh up dmz              # receiver, headscale
#   ./adminctl.sh up enclave --ttl 30m
#   ./adminctl.sh status
#   ./adminctl.sh down enclave|dmz|all
#   ./adminctl.sh creds               # this deployment's generated credentials, from Vault
#   ./adminctl.sh unseal              # Vault seals on every restart; this opens it
#
# Two forwarders exist rather than one because each joins only its own tier's network:
# the DMZ forwarder has no route to an enclave service and the enclave forwarder has no
# route into the DMZ. That isolation is the network membership, not this script.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY="$(cd "${HERE}/../deploy" && pwd)"
RUNTIME="${IR_RUNTIME:-podman}"
COMPOSE="${IR_COMPOSE:-podman-compose}"

# Management bind address. Loopback by default: on a single host that is the admin's own
# machine, and in a split deployment this is set to the interface on the management VLAN.
MGMT_BIND="${IR_MGMT_BIND:-127.0.0.1}"

c_red=$'\e[1;31m'; c_grn=$'\e[1;32m'; c_ylw=$'\e[1;33m'; c_cyn=$'\e[1;36m'; c_off=$'\e[0m'
say()  { printf '%s==> %s%s\n' "$c_cyn" "$1" "$c_off"; }
ok()   { printf '    %s✔%s %s\n' "$c_grn" "$c_off" "$1"; }
warn() { printf '    %s!%s %s\n' "$c_ylw" "$c_off" "$1"; }
die()  { printf '    %s✘%s %s\n' "$c_red" "$c_off" "$1" >&2; exit 1; }

# Ends at the first non-comment line rather than a fixed line number, so extending the header
# above cannot start printing code as usage.
usage() { sed -n '2,/^[^#]/{/^[^#]/d;p;}' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

[[ $# -ge 1 ]] || usage 1
ACTION="$1"; shift || true

TIER="${1:-all}"; [[ $# -gt 0 ]] && shift || true
TTL=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ttl) TTL="$2"; shift 2 ;;
        *) die "unknown option: $1" ;;
    esac
done

# Accepts 45, 30m, 2h.
ttl_seconds() {
    local v="$1"
    case "$v" in
        *h) echo $(( ${v%h} * 3600 )) ;;
        *m) echo $(( ${v%m} * 60 )) ;;
        *s) echo "${v%s}" ;;
        "") echo "" ;;
        *)  echo "$v" ;;
    esac
}

proj_of() { [[ "$1" == "dmz" ]] && echo "ir-dmz" || echo "ir-enclave"; }

# Targets per tier: listen_port=container:port. Resolved to the container's address ON THE
# NETWORK THE FORWARDER JOINS, which does two things: it works on `ir-edge`, where DNS is
# deliberately disabled as an anti-exfil control, and it makes the reachable network an
# explicit part of each target rather than whatever a name happens to resolve to.
targets_dmz=(
    "18090=ir-dmz_receiver_1:8090:ir-edge"      # evidence receiver health/queue
    "18081=ir-dmz_headscale_1:8080:ir-edge"     # headscale control
    # No CoreDNS entry: its Corefile runs no metrics listener, and adding one to a
    # deliberately minimal resolver to populate a panel is not worth the surface.
)
targets_enclave=(
    "19001=ir-enclave_minio_1:9001:ir-enclave_internal"     # MinIO console
    "18080=ir-enclave_keycloak_1:8080:ir-enclave_internal"  # Keycloak admin console
    "18501=ir-enclave_consul_1:8501:ir-enclave_internal"   # Consul UI (HTTPS, private CA)
    "15432=ir-enclave_db_1:5432:ir-enclave_internal"        # PostgreSQL (both stores)
    # Vault's UI and API. Absent until now, which left the root token as the only human way in
    # — sign in as platform-admin (deploy/.env) against the ir-admin policy instead.
    "18200=ir-enclave_vault_1:8200:ir-enclave_internal"     # Vault UI + API
    # The session farm and its controller: "the analyst cannot connect" is the failure this
    # platform produces most, and answering it meant exec'ing into the broker to read a log.
    "19200=ir-enclave_boundary_1:9200:ir-enclave_internal"  # Boundary API
)

# Address of a container on one specific network. Empty when it is not on that network —
# which is the isolation check, not just a lookup.
ip_on_network() {
    ${RUNTIME} inspect "$1" \
        --format "{{with index .NetworkSettings.Networks \"$2\"}}{{.IPAddress}}{{end}}" \
        2>/dev/null || true
}

resolve_targets() {
    local tier="$1" spec listen rest cname port net ip out=()
    local -n table="targets_${tier}"
    for spec in "${table[@]}"; do
        listen="${spec%%=*}"; rest="${spec#*=}"
        cname="${rest%%:*}"; rest="${rest#*:}"
        port="${rest%%:*}"; net="${rest##*:}"
        ip="$(ip_on_network "${cname}" "${net}")"
        if [[ -z "${ip}" ]]; then
            warn "skipping ${cname}:${port} — not running on ${net}"
            continue
        fi
        out+=("${listen}=${ip}:${port}")
    done
    (IFS=,; echo "${out[*]}")
}

compose_admin() {
    local tier="$1"; shift
    env -C "${DEPLOY}/${tier}" \
        IR_MGMT_BIND="${MGMT_BIND}" ADMIN_TTL="$(ttl_seconds "${TTL}")" \
        ADMIN_TARGETS="${ADMIN_TARGETS:-}" \
        ${COMPOSE} -p "$(proj_of "$tier")" --env-file ../.env \
        -f docker-compose.admin.yml "$@"
}

up_tier() {
    local tier="$1"
    [[ -f "${DEPLOY}/${tier}/docker-compose.admin.yml" ]] \
        || die "no admin compose for tier '${tier}'"

    say "Admin access · ${tier}"
    [[ "${MGMT_BIND}" == "0.0.0.0" ]] && \
        warn "IR_MGMT_BIND is 0.0.0.0 — reachable from every interface, including the analyst side"

    ADMIN_TARGETS="$(resolve_targets "$tier")"
    [[ -n "${ADMIN_TARGETS}" ]] || die "no ${tier} targets are running — nothing to forward"
    export ADMIN_TARGETS

    compose_admin "$tier" up -d >/dev/null 2>&1 || die "failed to start the ${tier} forwarder"
    sleep 2

    local name="$(proj_of "$tier")_adminfwd_1"
    [[ $(${RUNTIME} ps --format '{{.Names}}' | grep -cx "${name}") -gt 0 ]] \
        || die "${name} did not stay up — check: ${RUNTIME} logs ${name}"

    ok "${tier} forwarder up, bound to ${MGMT_BIND}"
    [[ -n "${TTL}" ]] && ok "closes automatically after ${TTL}"
    ${RUNTIME} port "${name}" 2>/dev/null | sed 's/^/    /' || true
    echo
    warn "close it when the task is done:  $0 down ${tier}"
}

down_tier() {
    local tier="$1"
    local name="$(proj_of "$tier")_adminfwd_1"
    if [[ $(${RUNTIME} ps -a --format '{{.Names}}' | grep -cx "${name}") -gt 0 ]]; then
        ${RUNTIME} rm -f "${name}" >/dev/null 2>&1 || true
        ok "${tier} admin access closed"
    else
        ok "${tier} admin access was not open"
    fi
}

status() {
    say "Admin access"
    local any=0
    for tier in dmz enclave; do
        local name="$(proj_of "$tier")_adminfwd_1"
        if [[ $(${RUNTIME} ps --format '{{.Names}}' | grep -cx "${name}") -gt 0 ]]; then
            any=1
            printf '    %sOPEN%s   %-8s %s\n' "$c_ylw" "$c_off" "$tier" \
                "$(${RUNTIME} port "${name}" 2>/dev/null | tr '\n' ' ')"
        else
            printf '    closed %s\n' "$tier"
        fi
    done
    [[ "$any" -eq 1 ]] && warn "an open forwarder is a live path to management interfaces"
    return 0
}

VAULT_C=ir-enclave_vault_1
vault_exec() { ${RUNTIME} exec -e VAULT_ADDR=https://127.0.0.1:8200 \
    -e VAULT_CACERT=/certs/vault-ca.crt.pem "$@" ; }

# The credentials THIS deployment generated, read from Vault with the admin's own login. The
# copy in deploy/.env is only on the host that ran the deploy, so an admin working anywhere else
# had no way to obtain the credential a service is refusing.
creds() {
    ${RUNTIME} inspect "${VAULT_C}" >/dev/null 2>&1 \
        || die "Vault is not running on this host — the setup credentials live in the enclave"
    set -a; . "${DEPLOY}/.env" 2>/dev/null || true; set +a
    local user="${IR_PLATFORM_ADMIN_USER:-platform-admin}" pw="${IR_PLATFORM_ADMIN_PASSWORD:-}" token
    [[ -n "${pw}" ]] \
        || die "IR_PLATFORM_ADMIN_PASSWORD is unset — run deploy.sh enclave to provision the admin"
    say "Setup credentials · ir/setup (as ${user})"
    # `|| true` because a failing login under `set -e` + pipefail aborts the assignment with
    # Vault's own status and no message at all — the die below is what explains it.
    local login_err
    login_err="$(vault_exec -e AP="${pw}" "${VAULT_C}" sh -c \
        "vault login -method=userpass -token-only username='${user}' password=\"\$AP\"" 2>&1 || true)"
    token="$(printf '%s' "${login_err}" | tr -dc '[:print:]' | tail -1)"
    if [[ "${token}" == *"denied"* || "${token}" == *rror* || -z "${token}" ]]; then
        warn "$(printf '%s' "${login_err}" | tail -3)"
        die "${user} could not log in to Vault — deploy.sh enclave provisions this account"
    fi
    vault_exec -e VT="${token}" "${VAULT_C}" sh -c 'VAULT_TOKEN=$VT vault kv get ir/setup' \
        || die "could not read ir/setup — deploy.sh enclave is what writes it"
    warn "live credentials were just printed to this terminal"
}

# Vault seals on every restart by design, and a sealed Vault answers health checks while serving
# nothing. The unseal lives in the codebase; this is the admin's handle on it.
unseal() {
    ${RUNTIME} inspect "${VAULT_C}" >/dev/null 2>&1 || die "Vault is not running on this host"
    say "Vault · unseal"
    bash "${HERE}/../hashicorp/vault/vault-unseal.sh" || die "unseal failed — see the output above"
    vault_exec "${VAULT_C}" sh -c 'vault status -format=json' 2>/dev/null \
        | grep -q '"sealed": *false' \
        && ok "Vault is unsealed and serving" \
        || die "Vault is still sealed"
}

case "${ACTION}" in
    up)
        [[ "${TIER}" == "all" ]] && die "name a tier: up dmz|enclave (both at once is not the point)"
        up_tier "${TIER}" ;;
    down)
        if [[ "${TIER}" == "all" ]]; then down_tier dmz; down_tier enclave
        else down_tier "${TIER}"; fi ;;
    status) status ;;
    creds) creds ;;
    unseal) unseal ;;
    -h|--help|help) usage 0 ;;
    *) usage 1 ;;
esac
