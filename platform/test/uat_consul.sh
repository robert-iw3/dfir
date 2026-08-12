#!/usr/bin/env bash
# ==============================================================================
# CONSUL UAT — service authorization is explicit, default-deny, and enforced.
#
# A layer independent of network reachability. The enclave's internal network lets every service
# address every other; that is a property of the segment, not a policy.
#
# What passing proves:
#   1. Consul runs in the enclave with Connect enabled and a leader elected
#   2. its CONTROL plane is hardened — TLS with the enclave CA, gossip encrypted, cleartext
#      ports closed, ACLs default-deny
#   3. the intentions in server.hcl are loaded and evaluate correctly
#   4. they are ENFORCED ON THE WIRE — a denied pair cannot connect, an allowed pair can
#   5. a compromised service cannot rewrite the policy that governs it
#
# Asserted against the RUNNING enclave.
# ==============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"
RUNTIME="${IR_RUNTIME:-podman}"
SEC="${PLATFORM}/hashicorp/consul/secrets"

. "${HERE}/lib/report.sh"
report_begin 35 consul "Service mesh — default-deny authorization, on a hardened control plane" \
    "Which service may reach which is stated explicitly, denied by default, and enforced on the wire — and the policy itself is protected by TLS and ACLs, so the services it governs cannot read or rewrite it."

CONSUL=ir-enclave_consul_1
MGMT="$(cat "${SEC}/tokens/management.token" 2>/dev/null)"

running() { [[ "$(${RUNTIME} inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" == "true" ]]; }

# Authenticated, over TLS, from inside the control plane.
ccli() {
    ${RUNTIME} exec \
        -e CONSUL_HTTP_ADDR=https://127.0.0.1:8501 \
        -e CONSUL_CACERT=/consul/tls/consul-ca.pem \
        -e CONSUL_HTTP_TOKEN="${MGMT}" \
        "${CONSUL}" consul "$@" 2>/dev/null
}

# An operator-grade probe: network peer of Consul, holding the CA. Throwaway container, so
# nothing is installed into a running service to run the test.
probe() { # curl-args...
    ${RUNTIME} run --rm --network ir-enclave_internal \
        -v "${SEC}/consul-ca.pem:/ca.pem:ro,z" \
        localhost/ir-workstation:latest curl -sS --max-time 8 "$@" 2>&1
}
code() { probe -o /dev/null -w '%{http_code}' "$@"; }

# ============================================================ 1. up, in the enclave
say "Consul is running in the enclave with Connect enabled"
if ! running "${CONSUL}"; then
    bad "Consul (${CONSUL}) is not running — service authorization is not being enforced"
    report_finish; exit 1
fi
ok "Consul is running in the enclave"
nets="$(${RUNTIME} inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' "${CONSUL}" 2>/dev/null)"
[[ "${nets// /}" == "ir-enclave_internal" ]] \
    && ok "on the internal network only — the mesh control plane is exposed to no other tier" \
    || bad "Consul is attached beyond the internal network: ${nets}"

[[ -n "${MGMT}" ]] \
    && ok "management token present on the deploy host (gen-consul-secrets.sh ran)" \
    || bad "no management token at ${SEC}/tokens — the control plane was never bootstrapped"

leader=""
for i in $(seq 1 30); do
    leader="$(ccli operator raft list-peers | grep -c leader)"
    [[ "${leader:-0}" -ge 1 ]] && break
    sleep 2
done
[[ "${leader:-0}" -ge 1 ]] \
    && ok "a leader is elected — the catalog and mesh are serving" \
    || bad "Consul never elected a leader — no intention can be evaluated"

# ============================================================ 2. control-plane TLS
say "The control plane is TLS-only, with the enclave's own CA"
# Cleartext HTTP and gRPC are disabled in server.hcl. Tested from the frontend — the most
# exposed service — because reachability is what matters, not configuration.
for pp in "8500 cleartext HTTP API" "8502 cleartext gRPC (xDS)"; do
    set -- ${pp}; port="$1"; shift; label="$*"
    if ${RUNTIME} exec ir-enclave_frontend_1 sh -c "nc -z -w3 consul ${port}" >/dev/null 2>&1; then
        bad "consul:${port} (${label}) is OPEN — a second, unauthenticated path to the same API"
    else
        ok "consul:${port} (${label}) is closed"
    fi
done

c="$(code --cacert /ca.pem https://consul:8501/v1/status/leader)"
[[ "${c}" == "200" ]] \
    && ok "HTTPS on 8501 serves and its certificate chains to the enclave CA (HTTP ${c})" \
    || bad "HTTPS on 8501 did not answer with the enclave CA (got '${c}')"

# Without the CA the handshake must fail: proof the certificate is privately rooted rather than
# merely present.
if probe https://consul:8501/v1/status/leader >/dev/null 2>&1; then
    bad "an untrusting client completed the TLS handshake — the certificate is publicly rooted"
else
    ok "a client without the enclave CA cannot complete the handshake"
fi

# ============================================================ 3. gossip encryption
say "Gossip traffic is encrypted"
kr="$(ccli keyring -list)"
if grep -qi 'gossip\|WAN\|LAN' <<<"${kr}" && ! grep -qi 'disabled\|not available' <<<"${kr}"; then
    ok "the gossip keyring is loaded — membership and health traffic is encrypted"
else
    bad "no gossip keyring — membership traffic is readable and forgeable on the segment: ${kr:-no answer}"
fi

# ============================================================ 4. ACLs, default-deny
say "The API is default-deny and the policy is not writable by the services it governs"
c="$(code --cacert /ca.pem https://consul:8501/v1/acl/tokens)"
[[ "${c}" == "403" ]] \
    && ok "an untokened request for the ACL store is refused (HTTP ${c})" \
    || bad "the ACL store answered an untokened request (HTTP ${c}) — ACLs are not enforcing"

c="$(code --cacert /ca.pem https://consul:8501/v1/config/service-intentions/ir-postgres)"
[[ "${c}" == "403" ]] \
    && ok "an untokened request to READ the intentions is refused (HTTP ${c})" \
    || bad "the intentions were readable without a token (HTTP ${c})"

# The compromised-service case. A 403 alone would not prove much — it is also what an invalid
# token returns — so the SAME token is first shown to work for what it is entitled to.
FTOK="$(cat "${SEC}/tokens/ir-frontend.token" 2>/dev/null)"
c="$(code --cacert /ca.pem -H "X-Consul-Token: ${FTOK}" https://consul:8501/v1/catalog/services)"
[[ "${c}" == "200" ]] \
    && ok "the frontend's own token is valid and reads the catalog (HTTP ${c})" \
    || bad "the frontend's token could not read the catalog (HTTP ${c}) — later denials prove nothing"

c="$(code --cacert /ca.pem -X DELETE -H "X-Consul-Token: ${FTOK}" \
        https://consul:8501/v1/config/service-intentions/ir-postgres)"
[[ "${c}" == "403" ]] \
    && ok "that same token CANNOT delete the intention denying it Postgres (HTTP ${c})" \
    || bad "a service token deleted or was permitted to delete its own governing intention (HTTP ${c})"

# ============================================================ 5. intentions loaded
say "Bootstrapped intentions are loaded"
INT="$(ccli config list -kind service-intentions)"
for svc in ir-postgres ir-minio ir-redis ir-backend; do
    grep -qx "${svc}" <<<"${INT}" \
        && ok "intentions present for ${svc}" \
        || bad "no intentions for ${svc} — it would fall through to whatever the default is"
done

# ============================================================ 6. the policy itself
# Consul's own evaluation — the same check a sidecar makes on a live connection.
authz() { ccli intention check "$1" "$2"; }

say "The pairs the platform needs are allowed"
# ir-vault → ir-postgres is on this list because it once was NOT: the live intentions predated
# the file that allowed it, every listed pair passed, and credential issuing was the one denied
# path — invisible until Vault next had to mint or revoke.
for pair in "ir-backend ir-postgres" "ir-worker ir-postgres" \
            "ir-backend ir-minio" "ir-worker ir-minio" \
            "ir-frontend ir-backend" "ir-puller ir-postgres" \
            "ir-puller ir-minio" "ir-puller ir-backend" "ir-vault ir-postgres" \
            "ir-backend ir-redis" "ir-worker ir-redis"; do
    set -- ${pair}
    r="$(authz "$1" "$2")"
    [[ "${r}" == *Allowed* ]] && ok "$1 → $2: ALLOWED" \
                             || bad "$1 → $2 must be allowed; Consul says ${r:-no answer}"
done

say "Everything else is denied — lateral movement is refused by rule"
# Each is a real post-compromise move: the frontend is the most exposed service and has network
# reach to both stores; the receiver is in the DMZ and must never touch enclave state; an
# unknown service is what a dropped binary registers as.
for pair in "ir-frontend ir-postgres" "ir-frontend ir-minio" \
            "ir-receiver ir-postgres" "unknown-svc ir-minio" \
            "ir-frontend ir-redis" "ir-puller ir-redis"; do
    set -- ${pair}
    r="$(authz "$1" "$2")"
    [[ "${r}" == *Denied* ]] && ok "$1 → $2: DENIED" \
                            || bad "$1 → $2 must be denied; Consul says ${r:-no answer}"
done

# ============================================================ 7. enforcement, not evaluation
say "The policy is ENFORCED on the wire, not merely evaluated"
# Everything above proves Consul answers the authorization question correctly. It does not prove
# anything stops the connection, and those are different claims.
n_svcs="$(ccli catalog services | grep -c .)"
[[ "${n_svcs:-0}" -gt 1 ]] \
    && ok "platform services are registered in the catalog (${n_svcs} entries)" \
    || bad "only Consul itself is registered — no service is in the mesh, so no intention applies"

for pair in "ir-enclave_frontend_1 db 5432 ir-frontend ir-postgres" \
            "ir-enclave_frontend_1 minio 9000 ir-frontend ir-minio" \
            "ir-enclave_frontend_1 redis 6379 ir-frontend ir-redis"; do
    set -- ${pair}
    c="$1" host="$2" port="$3" src="$4" dst="$5"
    if ${RUNTIME} exec "${c}" sh -c "nc -z -w3 ${host} ${port}" >/dev/null 2>&1; then
        bad "${src} → ${dst}: Consul DENIES it, but the connection to ${host}:${port} SUCCEEDS"
    else
        ok "${src} → ${dst}: the connection to ${host}:${port} is actually refused"
    fi
done

# The allowed direction, through the proxy: without this, everything above is also satisfied by
# a mesh that simply blocks all traffic.
if ${RUNTIME} exec ir-enclave_backend_1 sh -c \
    'python3 -c "import socket;socket.create_connection((\"127.0.0.1\",5432),timeout=4)"' \
    >/dev/null 2>&1; then
    ok "ir-backend → ir-postgres: the allowed upstream carries traffic through its sidecar"
else
    bad "ir-backend cannot reach Postgres through its own sidecar — the mesh is blocking, not authorizing"
fi

if ${RUNTIME} exec ir-enclave_backend_1 sh -c \
    'python3 -c "import socket;socket.create_connection((\"127.0.0.1\",6379),timeout=4)"' \
    >/dev/null 2>&1; then
    ok "ir-backend → ir-redis: the queue upstream carries traffic through its sidecar"
else
    bad "ir-backend cannot reach Redis through its own sidecar — task dispatch is broken"
fi

# The worker's leg, proven by the queue answering — celery only responds to `inspect ping` if
# the worker process holds a live broker connection, so this is dispatch through the mesh. The
# output is CAPTURED and then matched, never piped into `grep -q`.
WORKER_PONG=0
for _ in $(seq 1 10); do
    ping_out="$(${RUNTIME} exec ir-enclave_worker_1 \
                sh -c 'celery -A ir_platform inspect ping -t 5' 2>/dev/null || true)"
    case "${ping_out}" in *pong*) WORKER_PONG=1; break ;; esac
    sleep 3
done
if [[ "${WORKER_PONG}" == "1" ]]; then
    ok "ir-worker → ir-redis: the celery worker answers over the queue through the mesh"
else
    bad "the celery worker does not answer over the queue after 30s — its broker connection is broken"
fi

# Vault's leg, proven by MINTING a credential — not by the platform being up, which only shows
# an already-issued lease still works. Minting forces Vault to dial Postgres through the mesh
# right now, so a denied ir-vault → ir-postgres fails here and nowhere else.
minted="$(${RUNTIME} exec ir-enclave_vault-agent_1 sh -c '
    export VAULT_ADDR=https://vault:8200 VAULT_CACERT=/vault/state/vault-ca.crt.pem
    export VAULT_TOKEN="$(vault write -field=token auth/approle/login \
        role_id="$(cat /vault/state/role_id)" secret_id="$(cat /vault/state/secret_id)")"
    vault read -field=username database/creds/ir-platform' 2>/dev/null || true)"
[[ "${minted}" == v-approle-* ]] \
    && ok "ir-vault → ir-postgres: minted a live credential through the mesh (${minted})" \
    || bad "Vault could NOT mint a credential — its path to Postgres is broken even if the platform looks healthy"

# Every sidecar authenticated. A proxy that cannot get a token exits and restarts forever, which
# looks like an intention failure from every other angle.
say "Every sidecar authenticated to the hardened control plane"
for s in db minio redis vault backend worker frontend puller; do
    cn="ir-enclave_${s}-sidecar_1"
    rs="$(${RUNTIME} inspect -f '{{.RestartCount}}' "${cn}" 2>/dev/null)"
    if running "${cn}" && [[ "${rs:-0}" -lt 3 ]]; then
        ok "${s}-sidecar is up and stable (${rs:-0} restarts)"
    else
        bad "${s}-sidecar is not running or is restart-looping (${rs:-?}) — check its token and CA"
    fi
    # Namespace-inode identity, because addresses can no longer tell: with static addressing an
    # orphaned proxy has bound the exact address the recreated service now holds — same number,
    # dead namespace, serving nothing while every listener probe passes. Inode via /proc, not
    # podman's SandboxKey, which is empty for restarted containers.
    p_svc="$(${RUNTIME} inspect -f '{{.State.Pid}}' "ir-enclave_${s}_1" 2>/dev/null)"
    p_prx="$(${RUNTIME} inspect -f '{{.State.Pid}}' "${cn}" 2>/dev/null)"
    ns_svc="$(readlink "/proc/${p_svc:-0}/ns/net" 2>/dev/null)"
    ns_prx="$(readlink "/proc/${p_prx:-0}/ns/net" 2>/dev/null)"
    [[ -n "${ns_svc}" && "${ns_svc}" == "${ns_prx}" ]] \
        && ok "${s}-sidecar shares its service's live network namespace (${ns_svc})" \
        || bad "${s}-sidecar is orphaned — it serves a namespace its service no longer uses"
done

say "Result"
if [[ "${FAILED}" == "0" ]]; then
    ok "mesh authorization holds: explicit allow-list, default-deny, enforced on the wire, on a TLS control plane the services cannot rewrite"
else
    bad "mesh authorization does NOT hold — see failures above"
fi
report_finish
exit "${FAILED}"
