#!/usr/bin/env bash
# Register the enclave's services and their sidecars with Consul, at deploy time.
#
#   register-mesh.sh            (run from deploy.sh, on the enclave host)
#
# At deploy time and not in a config file: a Connect registration carries the ADDRESS other
# proxies dial, and that address is assigned by the environment — by the container runtime on one
# host, by the site's addressing plan across several.
#
# Single host and multi-host from one definition:
#   IR_MESH_ADDR_<SERVICE>   advertised address for that service; set these in a multi-host
#                            deployment. The sidecar is always co-located with its service, so
#                            this is what remote proxies dial.
#   (unset)                  the container's address on the enclave network.
#
# A registration declares where the real service listens (loopback, inside its own namespace),
# the proxy in front of it, and for a consumer the local ports that tunnel to named upstreams —
# so the application connects to 127.0.0.1 and never names the destination on the wire. The
# intentions in server.hcl decide which of those tunnels carry traffic.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SEC="${IR_CONSUL_SECRET_DIR:-${HERE}/secrets}"
RUNTIME="${IR_RUNTIME:-podman}"
CONSUL_C="${CONSUL_CONTAINER:-ir-enclave_consul_1}"

say() { printf '    %s\n' "$*"; }

# Configuration, never discovery: IR_MESH_ADDR_<SERVICE> (multi-host, the routable host
# address) over IR_IP_<SVC> (single-host, the static container address from deploy/.env). A
# discovered address is stale the moment the runtime recreates a container, so inspect remains
# only as a last resort for a service someone runs without either value set.
addr_of() { # container  service-key
    local container="$1" key="$2" var configured svc
    var="IR_MESH_ADDR_$(printf '%s' "${key}" | tr '[:lower:]-' '[:upper:]_')"
    configured="${!var:-}"
    if [[ -n "${configured}" ]]; then printf '%s' "${configured}"; return 0; fi

    svc="${container#ir-enclave_}"; svc="${svc%_1}"
    var="IR_IP_$(printf '%s' "${svc}" | tr '[:lower:]-' '[:upper:]_')"
    configured="${!var:-}"
    if [[ -n "${configured}" ]]; then
        # Registered only if the container exists: the address is fixed, but a service that is
        # not running yet must still be SKIPped so this stage's report stays truthful.
        ${RUNTIME} inspect "${container}" --format '{{.Id}}' >/dev/null 2>&1 \
            && printf '%s' "${configured}"
        return 0
    fi

    # `|| true` because a not-yet-created container is NORMAL here: this runs at each stage and
    # the consumers do not exist during the first.
    ${RUNTIME} inspect "${container}" \
        --format '{{(index .NetworkSettings.Networks "ir-enclave_internal").IPAddress}}' \
        2>/dev/null || true
}

# Through Consul's own CLI, not its HTTP API: the image ships busybox wget, which cannot send a
# PUT with a body, so the API route registered nothing and every sidecar failed to find its
# service.
#
# Each service registers with ITS OWN token, not the management one. The agent persists whatever
# token it was given for that service's anti-entropy, so the management credential would end up
# stored against seven services that each need service:write on one name.
register() { # name json
    local name="$1" json="$2" tok="${SEC}/tokens/$1.token"
    [[ -r "${tok}" ]] || { say "no token for ${name} — run gen-consul-secrets.sh"; return 1; }
    printf '%s' "${json}" | ${RUNTIME} exec -i \
        -e CONSUL_HTTP_ADDR=https://127.0.0.1:8501 \
        -e CONSUL_CACERT=/consul/tls/consul-ca.pem \
        -e CONSUL_HTTP_TOKEN="$(cat "${tok}")" \
        "${CONSUL_C}" \
        sh -c "cat > /tmp/svc-${name}.json && consul services register /tmp/svc-${name}.json" >/dev/null
}

# An upstream entry: the consumer reaches `destination` by connecting to 127.0.0.1:local_port.
ups() { # destination local_port
    printf '{"destination_name":"%s","local_bind_port":%s}' "$1" "$2"
}

# service <consul-name> <container> <port> [upstream-json,...]
service() {
    local name="$1" container="$2" port="$3" upstreams="${4:-}"
    local ip; ip="$(addr_of "${container}" "${name}")"
    if [[ -z "${ip}" ]]; then
        say "SKIP ${name} — no IR_MESH_ADDR override and ${container} is not on ir-enclave_internal"
        return 0
    fi

    # The sidecar's ADVERTISED port and its BOUND port separate on multiple hosts. The catalog
    # must carry the host's published port (IR_MESH_PORT_<SVC>, mapped by the multihost overlay)
    # at the routable address; Envoy meanwhile can only bind inside its own namespace, so the
    # proxy config pins the bind to 0.0.0.0:21000 and the host's port mapping joins the two.
    # On one host both are 21000 at the container address and the bind override is harmless.
    local svc mvar pvar sport=21000 bind=""
    svc="${container#ir-enclave_}"; svc="${svc%_1}"
    mvar="IR_MESH_ADDR_$(printf '%s' "${name}" | tr '[:lower:]-' '[:upper:]_')"
    pvar="IR_MESH_PORT_$(printf '%s' "${svc}"  | tr '[:lower:]-' '[:upper:]_')"
    if [[ -n "${!mvar:-}" ]]; then
        sport="${!pvar:-21000}"
        bind='"config": { "bind_address": "0.0.0.0", "bind_port": 21000 },'
    fi

    if register "${name}" "$(cat <<JSON
{
  "service": {
    "name": "${name}",
    "id": "${name}",
    "address": "${ip}",
    "port": ${port},
    "connect": {
      "sidecar_service": {
        "port": ${sport},
        "proxy": { ${bind} "upstreams": [${upstreams}] }
      }
    }
  }
}
JSON
)"; then
        say "registered ${name} at ${ip}:${port} (proxy :${sport})$( [[ -n "${upstreams}" ]] && printf ' (+upstreams)' )"
    else
        say "FAILED to register ${name} — its sidecar will not find a service to front"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Destinations. Both bind loopback inside their own namespace, so the only listener the enclave
# network can reach is the sidecar — which refuses anything the intentions deny.
service ir-postgres ir-enclave_db_1     5432
service ir-minio    ir-enclave_minio_1  9000

# Consumers reach each destination on 127.0.0.1 at the same port number the service normally
# uses, so only the host changes in application configuration.
DATA_UPSTREAMS="$(ups ir-postgres 5432),$(ups ir-minio 9000)"
service ir-backend ir-enclave_backend_1 8000 "${DATA_UPSTREAMS}"
service ir-worker  ir-enclave_worker_1  9999 "${DATA_UPSTREAMS}"
service ir-puller  ir-enclave_puller_1  9998 "${DATA_UPSTREAMS}"

# Vault's database secrets engine dials Postgres to mint and revoke the dynamic users. Without a
# sidecar, credential issuing would be the one path bypassing the mesh.
service ir-vault ir-enclave_vault_1 8200 "$(ups ir-postgres 5432)"

# The frontend reaches only the backend: the most exposed service in the enclave, and the one
# whose compromise the intentions are most concerned with.
service ir-frontend ir-enclave_frontend_1 8080 "$(ups ir-backend 8000)"

say "mesh registration complete"
