#!/usr/bin/env bash
# ==============================================================================
# MULTI-HOST MESH UAT — run ON EVERY ENCLAVE HOST of a multi-host deployment.
#
# A mesh spanning hosts cannot be proven from one of them. Each host owns two claims nobody
# else can make for it:
#   LOCAL  — my services' sidecars are published on my interface, TLS-gated, and sound
#   REMOTE — every peer service advertised to me (IR_MESH_ADDR_*) answers TLS from HERE,
#            which is the only vantage that exercises the actual wire, the routing between
#            hosts, and the firewall allows (NETWORKING.md §5a) at once
#
# Run it on each enclave host; each host's report section is its own view, and together they
# prove the mesh. On a single-host deployment there is nothing here to validate and it says so.
#
# What it does NOT do: reshape the deployment. The host is already in the multi-host shape
# (IR_MESH_MULTIHOST=1 in deploy/.env) or this test does not apply.
# ==============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"
RUNTIME="${IR_RUNTIME:-podman}"

# The deployment's own configuration decides whether this test applies.
set -a; . "${PLATFORM}/deploy/.env"; set +a

if [[ "${IR_MESH_MULTIHOST:-0}" != "1" ]]; then
    echo "uat_mesh_multihost: this deployment is single-host (IR_MESH_MULTIHOST unset) — nothing to validate."
    echo "Run this on each enclave host of a multi-host deployment."
    exit 0
fi

. "${HERE}/lib/report.sh"
report_begin 36 mesh_multihost "Service mesh — this host's view of the multi-host deployment" \
    "This host publishes its sidecars TLS-gated at distinct ports, and every peer service advertised to it answers TLS from here — the vantage that exercises the wire, the routing and the firewall allows together."

declare -A PORTS=([db]="${IR_MESH_PORT_DB:-21001}" [minio]="${IR_MESH_PORT_MINIO:-21002}"
                  [vault]="${IR_MESH_PORT_VAULT:-21003}" [backend]="${IR_MESH_PORT_BACKEND:-21004}"
                  [worker]="${IR_MESH_PORT_WORKER:-21005}" [frontend]="${IR_MESH_PORT_FRONTEND:-21006}"
                  [puller]="${IR_MESH_PORT_PULLER:-21007}")

# Which mesh services live on THIS host: the ones whose containers exist here.
local_svcs=(); remote=()
for svc in db minio vault backend worker frontend puller; do
    if ${RUNTIME} inspect "ir-enclave_${svc}_1" --format '{{.Id}}' >/dev/null 2>&1; then
        local_svcs+=("${svc}")
    fi
done

# TLS probe: an uncertified client must get a TLS answer and no session — Connect mTLS gating
# at the edge. Connection refused means the path is dead; a completed session means anyone on
# the segment is a peer.
tls_gated() { # host port -> 0 answered+gated / 1 refused / 2 open session
    local out
    out="$(echo | timeout 5 openssl s_client -connect "$1:$2" 2>&1)"
    grep -q "Connection refused" <<<"${out}" && return 1
    grep -qE "Verification: OK.*Session-ID: [0-9A-F]" <<<"${out}" && return 2
    grep -qE "SSL handshake|CONNECTED" <<<"${out}" && return 0
    return 1
}

# ============================================================ 1. this host's publishes
say "This host's services are published and TLS-gated"
[[ ${#local_svcs[@]} -gt 0 ]] \
    && ok "mesh services on this host: ${local_svcs[*]}" \
    || bad "no mesh services on this host — is the enclave deployed here?"

for svc in "${local_svcs[@]}"; do
    p="${PORTS[$svc]}"
    m="$(${RUNTIME} port "ir-enclave_${svc}_1" 21000/tcp 2>/dev/null | head -1)"
    [[ "${m}" == *":${p}" ]] \
        && ok "${svc}: host :${p} -> namespace :21000 published (${m})" \
        || bad "${svc}: expected host :${p}, got '${m:-no mapping}' — remote proxies have nothing to dial"

    tls_gated 127.0.0.1 "${p}"; rc=$?
    case "${rc}" in
        0) ok  "${svc}: :${p} answers TLS and refuses an uncertified client" ;;
        2) bad "${svc}: an uncertified client completed a session on :${p} — mTLS is not gating" ;;
        *) bad "${svc}: :${p} gave no TLS answer — the published path is dead" ;;
    esac
done

# ============================================================ 2. sidecars sound
say "Each local sidecar shares its service's live namespace"
for svc in "${local_svcs[@]}"; do
    p_svc="$(${RUNTIME} inspect -f '{{.State.Pid}}' "ir-enclave_${svc}_1" 2>/dev/null)"
    p_prx="$(${RUNTIME} inspect -f '{{.State.Pid}}' "ir-enclave_${svc}-sidecar_1" 2>/dev/null)"
    ns_svc="$(readlink "/proc/${p_svc:-0}/ns/net" 2>/dev/null)"
    ns_prx="$(readlink "/proc/${p_prx:-0}/ns/net" 2>/dev/null)"
    [[ -n "${ns_svc}" && "${ns_svc}" == "${ns_prx}" ]] \
        && ok "${svc}-sidecar shares its service's namespace" \
        || bad "${svc}-sidecar is orphaned — it serves a namespace its service no longer uses"
done

# ============================================================ 3. peers, from here
say "Peer services advertised to this host answer from this host"
# IR_MESH_ADDR_<SERVICE> for a service NOT running here names a peer host. Probing it from
# here is the point of running this test on every host: it is the dial local proxies make.
declare -A KEY=([IR_POSTGRES]=db [IR_MINIO]=minio [IR_VAULT]=vault [IR_BACKEND]=backend
                [IR_WORKER]=worker [IR_FRONTEND]=frontend [IR_PULLER]=puller)
found=0
for k in "${!KEY[@]}"; do
    svc="${KEY[$k]}"; var="IR_MESH_ADDR_${k}"; addr="${!var:-}"
    [[ -n "${addr}" ]] || continue
    # Local services are covered by section 1; a peer is one that is advertised but not here.
    printf '%s\n' "${local_svcs[@]}" | grep -qx "${svc}" && continue
    found=1
    p="${PORTS[$svc]}"
    tls_gated "${addr}" "${p}"; rc=$?
    case "${rc}" in
        0) ok  "peer ${svc}: answers TLS from this host — wire, routing and firewall all pass" ;;
        2) bad "peer ${svc}: an uncertified client completed a session — mTLS is not gating on the peer" ;;
        *) bad "peer ${svc}: no answer from this host — check the peer's publish and the firewall allow (NETWORKING.md §5a)" ;;
    esac
done
[[ "${found}" == "1" ]] \
    || info "no peer services advertised to this host (every IR_MESH_ADDR_* names a local service)"

say "Result"
if [[ "${FAILED}" == "0" ]]; then
    ok "this host's view of the mesh holds — combine with the same run on every other enclave host"
else
    bad "this host's view of the mesh does NOT hold — see failures above"
fi
report_finish
exit "${FAILED}"
