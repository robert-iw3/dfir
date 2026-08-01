#!/usr/bin/env bash
# Give Consul the identity behind each secret gen-consul-secrets.sh generated. Run once Consul
# has a leader; idempotent, every deployment re-runs it.
#
# -service-identity expands to service:write on the service and its sidecar-proxy, plus read on
# the catalog. It grants no operator rights and nothing on service-intentions — so a compromised
# proxy can re-register itself but cannot edit the policy governing it.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SEC="${IR_CONSUL_SECRET_DIR:-${HERE}/secrets}"
RUNTIME="${IR_RUNTIME:-podman}"
CONSUL_C="${CONSUL_CONTAINER:-ir-enclave_consul_1}"
DC="${IR_CONSUL_DATACENTER:-dc1}"
NODE="${IR_CONSUL_NODE:-ir-consul}"

MESH_SERVICES=(ir-postgres ir-minio ir-backend ir-worker ir-puller ir-vault ir-frontend)

say() { printf '    %s\n' "$*"; }

[[ -f "${SEC}/tokens/management.token" ]] \
    || { say "no management token — run gen-consul-secrets.sh first"; exit 1; }
MGMT="$(cat "${SEC}/tokens/management.token")"

# Over TLS on loopback, which the agent certificate covers (SAN IP:127.0.0.1).
with_token() { # token  args...
    local tok="$1"; shift
    ${RUNTIME} exec \
        -e CONSUL_HTTP_ADDR=https://127.0.0.1:8501 \
        -e CONSUL_CACERT=/consul/tls/consul-ca.pem \
        -e CONSUL_HTTP_TOKEN="${tok}" \
        "${CONSUL_C}" consul "$@"
}
cc() { with_token "${MGMT}" "$@"; }

# `token read -self` is the only lookup keyed by the secret rather than the accessor.
ensure() { # label  secret  identity-flag...
    local label="$1" secret="$2"; shift 2
    if with_token "${secret}" acl token read -self >/dev/null 2>&1; then
        say "token for ${label} already present"; return 0
    fi
    if cc acl token create -secret="${secret}" -description="ir-platform ${label}" "$@" \
        >/dev/null 2>&1; then
        say "created token for ${label}"
    else
        say "FAILED to create token for ${label} — its proxy will not authenticate"
        return 1
    fi
}

rc=0

# Without a node identity the server cannot complete anti-entropy under a deny default, and
# drops out of its own catalog.
AGENT_TOK="$(cat "${SEC}/tokens/agent.token")"
ensure "the agent (${NODE})" "${AGENT_TOK}" -node-identity="${NODE}:${DC}" || rc=1

# The config file covers restarts; this covers first boot, where the agent read a token that did
# not exist yet.
cc acl set-agent-token agent "${AGENT_TOK}" >/dev/null 2>&1 \
    || say "could not set the agent token live — it applies on the next restart"

for svc in "${MESH_SERVICES[@]}"; do
    ensure "${svc}" "$(cat "${SEC}/tokens/${svc}.token")" -service-identity="${svc}:${DC}" || rc=1
done

# The health page reads the mesh; it must not be able to change it. `intentions = "read"` is
# what lets it show WHICH pairs are authorized — the policy is the interesting half, and a
# catalog without it only shows what is registered, not what is allowed.
UI_TOK="$(cat "${SEC}/tokens/ui-readonly.token" 2>/dev/null || true)"
if [[ -n "${UI_TOK}" ]]; then
    # exec -i: the policy arrives on stdin, and `cc` does not forward it.
    printf 'service_prefix "" { policy = "read" intentions = "read" }\nnode_prefix    "" { policy = "read" }\n' \
      | ${RUNTIME} exec -i \
            -e CONSUL_HTTP_ADDR=https://127.0.0.1:8501 \
            -e CONSUL_CACERT=/consul/tls/consul-ca.pem \
            -e CONSUL_HTTP_TOKEN="${MGMT}" \
            "${CONSUL_C}" consul acl policy create -name ir-ui-readonly -rules - \
        >/dev/null 2>&1 || true
    ensure "the health page (read-only)" "${UI_TOK}" -policy-name=ir-ui-readonly || rc=1
fi

# The anonymous token is left with no policy. Under default_policy = "deny" that absence IS the
# control that refuses untokened requests.
say "anonymous token carries no policy — untokened requests are denied"

# The mesh policy, converged on EVERY run. A config_entries.bootstrap block applies only when
# the entry does not already exist, so an edited intention never reaches a cluster whose data
# volume predates the edit — the file and the enforced policy silently diverge. `config write`
# is idempotent and makes the files in config-entries/ the single source of truth.
for f in "${HERE}/config-entries/"*.hcl; do
    [[ -f "${f}" ]] || continue
    n="$(basename "${f}")"
    if ${RUNTIME} exec -i \
        -e CONSUL_HTTP_ADDR=https://127.0.0.1:8501 \
        -e CONSUL_CACERT=/consul/tls/consul-ca.pem \
        -e CONSUL_HTTP_TOKEN="${MGMT}" \
        "${CONSUL_C}" sh -c "cat > /tmp/ce-${n} && consul config write /tmp/ce-${n}" \
        < "${f}" >/dev/null 2>&1; then
        say "config entry ${n} converged"
    else
        say "FAILED to write config entry ${n} — the enforced policy may not match the file"
        rc=1
    fi
done

[[ "${rc}" == "0" ]] && say "ACL bootstrap complete" || say "ACL bootstrap INCOMPLETE"
exit "${rc}"
