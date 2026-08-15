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
        # A configured address is DECLARED, so it is registered whether or not the container
        # exists yet. Requiring the container first deadlocks any service whose sidecar owns
        # the namespace — the sidecar cannot start without a registration, and the service
        # cannot be created without the sidecar's namespace. A populated catalog hides that;
        # an empty one (after a purge, or a first deploy) cannot.
        printf '%s' "${configured}"
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
# service. Each service registers with ITS OWN token, not the management one.
register() { # label json [token-name]
    # The token is scoped to the service NAME; the label may be an instance id. Defaulting
    # the token to the label would send ir-worker-2 looking for ir-worker-2.token, which
    # does not exist and must not: one name, one token, N instances.
    local name="$1" json="$2" tok="${SEC}/tokens/${3:-$1}.token"
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
# Register one INSTANCE of a service: same name as its siblings, distinct id. Intentions
# and ACL tokens are scoped to the name, so every instance inherits both unchanged — which
# is what makes "add another worker" a zero-policy operation.
service_instance() {
    local name="$1" id="$2" container="$3" port="$4" upstreams="${5:-}"
    local ip; ip="$(addr_of "${container}" "${name}")"
    if [[ -z "${ip}" ]]; then
        say "SKIP ${id} — no IR_MESH_ADDR override and ${container} is not on ir-enclave_internal"
        return 0
    fi

    # The sidecar's ADVERTISED port and its BOUND port separate on multiple hosts. The catalog must
    # carry the host's published port (IR_MESH_PORT_<SVC>, mapped by the multihost overlay) at the
    # routable address; Envoy meanwhile can only bind inside its own namespace, so the proxy config
    # pins the bind to 0.0.0.0:21000 and the host's port mapping joins the two.
    local svc mvar pvar sport=21000 bind=""
    svc="${container#ir-enclave_}"; svc="${svc%_1}"
    mvar="IR_MESH_ADDR_$(printf '%s' "${name}" | tr '[:lower:]-' '[:upper:]_')"
    pvar="IR_MESH_PORT_$(printf '%s' "${svc}"  | tr '[:lower:]-' '[:upper:]_')"
    if [[ -n "${!mvar:-}" ]]; then
        sport="${!pvar:-21000}"
        bind='"config": { "bind_address": "0.0.0.0", "bind_port": 21000 },'
    fi

    if register "${id}" "$(cat <<JSON
{
  "service": {
    "name": "${name}",
    "id": "${id}",
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
)" "${name}"; then
        say "registered ${id} at ${ip}:${port} (proxy :${sport})$( [[ -n "${upstreams}" ]] && printf ' (+upstreams)' )"
    else
        say "FAILED to register ${id} — its sidecar will not find a service to front"
        return 1
    fi
}

# The single-instance form every existing call uses: same value for name and id.
service() { # name container port upstreams
    service_instance "$1" "$1" "$2" "$3" "${4:-}"
}

# ---------------------------------------------------------------------------
# Destinations. Both bind loopback inside their own namespace, so the only listener the enclave
# network can reach is the sidecar — which refuses anything the intentions deny.
service ir-postgres ir-enclave_db_1     5432
service ir-minio    ir-enclave_minio_1  9000
service ir-redis    ir-enclave_redis_1  6379

# Consumers reach each destination on 127.0.0.1 at the same port number the service normally
# uses, so only the host changes in application configuration.
DATA_UPSTREAMS="$(ups ir-postgres 5432),$(ups ir-minio 9000)"
# The queue's two ends additionally get the ir-redis upstream; the puller has no task traffic.
APP_UPSTREAMS="${DATA_UPSTREAMS},$(ups ir-redis 6379)"
service ir-backend ir-enclave_backend_1 8000 "${APP_UPSTREAMS}"
service ir-worker  ir-enclave_worker_1  9999 "${APP_UPSTREAMS}"
# Worker replicas: same NAME, distinct IDs, so the worker intentions cover every one of
# them with no policy change. The count comes from the same setting the overlay is
# generated from, so registration and containers can never disagree about how many exist.
for _n in $(seq 2 "${IR_WORKER_REPLICAS:-1}"); do
    service_instance ir-worker "ir-worker-${_n}" "ir-enclave_worker-${_n}_1" 9999 "${APP_UPSTREAMS}"
done
service ir-puller  ir-enclave_puller_1  9998 "${DATA_UPSTREAMS}"

# Vault's database secrets engine dials Postgres to mint and revoke the dynamic users. Without a
# sidecar, credential issuing would be the one path bypassing the mesh.
service ir-vault ir-enclave_vault_1 8200 "$(ups ir-postgres 5432)"

# The identity store rides the mesh to Postgres like every other consumer. Only its database
# connection: OIDC traffic still reaches `keycloak` by name, so it keeps its own namespace.
service ir-keycloak ir-enclave_keycloak_1 8080 "$(ups ir-postgres 5432)"

# The log shipper reaches the object store, where the ir-logs bucket lives, and the database,
# where its Component Health self-report lands.
service ir-log-shipper ir-enclave_log-shipper_1 9997 "${DATA_UPSTREAMS}"

# The SSO gate reaches only the queue, where its sessions live. It is deliberately NOT given
# the data tier: the gate authenticates users and holds no case data.
service ir-oauth2-proxy ir-enclave_oauth2-proxy_1 4180 "$(ups ir-redis 6379)"

# The frontend reaches only the backend: the most exposed service in the enclave, and the one
# whose compromise the intentions are most concerned with.
service ir-frontend ir-enclave_frontend_1 8080 "$(ups ir-backend 8000)"

say "mesh registration complete"
