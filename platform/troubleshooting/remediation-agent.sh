#!/usr/bin/env bash
# Runs the repairs an admin asks for in the UI.
#
# Deployed as its own container by `deploy.sh agent` — network none, pid host, the runtime
# socket mounted. Also runs directly on a host that has the socket:
#
#   ./remediation-agent.sh            poll forever
#   ./remediation-agent.sh --once     drain what is queued and exit
#
# WHY THIS IS A SEPARATE EXECUTOR. Every repair below drives podman or the deployment scripts.
# Doing that from the backend would mean mounting the container runtime's socket into a
# request-serving web service — a container-escape path that would defeat the tier separation
# the whole platform is built on. So the backend records a REQUEST, and this agent — holding
# the socket, reachable by nothing — decides what that request means.
#
# THE TRUST BOUNDARY IS THE ACTION NAME. Nothing else crosses it: no command, no arguments, no
# paths. The case statement below is the complete set of things that can happen, and it lives
# here rather than in the database, so a forged or tampered row can only ask for one of them.
# An unknown name is rejected and recorded, not guessed at.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"
RUNTIME="${IR_RUNTIME:-podman}"
BE="${IR_BACKEND_CONTAINER:-ir-enclave_backend_1}"
INTERVAL="${IR_REMEDIATION_INTERVAL:-10}"
# The container's own hostname is a random id; the deploy passes the enclave host's name so
# the audit row says where a repair ran.
AGENT_HOST="${IR_AGENT_HOST:-$(hostname)}"
ONCE=0
[[ "${1:-}" == "--once" ]] && ONCE=1

log() { printf '[remediation] %s\n' "$*"; }

# As a service this waits on missing prerequisites instead of exiting — a crash-looping
# restart policy is noise, and the config may simply not be written yet. --once is a test
# invocation, which wants the hard failure.
while :; do
    set -a; . "${PLATFORM}/deploy/.env" 2>/dev/null; set +a
    TOKEN="${IR_BROKER_TOKEN:-}"
    [[ -n "${TOKEN}" ]] && break
    [[ "${ONCE}" == "1" ]] && { echo "IR_BROKER_TOKEN is required to claim work" >&2; exit 1; }
    log "IR_BROKER_TOKEN not present in deploy/.env yet — waiting"
    sleep 30
done
until ${RUNTIME} info >/dev/null 2>&1; do
    [[ "${ONCE}" == "1" ]] && { echo "cannot reach the container runtime" >&2; exit 1; }
    log "container runtime not reachable — waiting"
    sleep 10
done

# The API is not published outside the enclave, so it is reached the way everything else
# reaches it — from inside the backend's own container.
api() { # method path [json]
    ${RUNTIME} exec -i "${BE}" python -c "
import json, sys, urllib.request as u, urllib.error as e
body = sys.stdin.read() or None
req = u.Request('http://127.0.0.1:8000$2', method='$1',
                data=body.encode() if body else None,
                headers={'Authorization':'Token ${TOKEN}','Content-Type':'application/json'})
try:
    print(u.urlopen(req, timeout=15).read().decode())
except e.HTTPError as ex:
    print('{\"error\": %d}' % ex.code)
" <<<"${3:-}" 2>/dev/null
}

# ---------------------------------------------------------------------------
# THE ALLOW-LIST. Adding a case here is adding a privileged command to the platform; each one
# below corresponds to a failure this deployment hit, diagnosed, and now repairs by name.
run_action() { # action -> output on stdout, exit code is the result
    case "$1" in
        mesh-reattach)
            # Recreates any proxy no longer in its service's namespace. deploy.sh owns the
            # logic; calling it here keeps one implementation of "attach the mesh".
            bash "${PLATFORM}/deploy/deploy.sh" enclave 2>&1 | tail -40
            ;;
        vault-unseal)
            ${RUNTIME} exec --user root "${BE%backend_1}vault_1" sh /opt/vault-unseal.sh 2>&1
            ;;
        rotate-app-credentials)
            bash "${PLATFORM}/hashicorp/vault/rotate-app-creds.sh" 2>&1 | tail -40
            ;;
        consul-converge-policy)
            bash "${PLATFORM}/hashicorp/consul/consul-acl-bootstrap.sh" 2>&1 | tail -40
            ;;
        restart-worker)
            # The service first, then its proxy: restarting a service gives it a fresh network
            # namespace, which strands a proxy that had joined the old one.
            ${RUNTIME} restart ir-enclave_worker_1 2>&1 \
                && ${RUNTIME} restart ir-enclave_worker-sidecar_1 2>&1
            ;;
        reap-boundary-workers)
            ${RUNTIME} exec ir-enclave_boundary_1 sh /boundary/workers.sh ir-egress 2>&1
            ;;
        *)
            echo "unknown action: $1"
            return 127
            ;;
    esac
}

claim_and_run() { # id action
    local id="$1" action="$2" out rc claim
    log "claiming ${id}: ${action}"
    # A refused claim (another agent won the race, or the row is no longer queued) is a skip,
    # not a failure — running the repair anyway is exactly what the guard exists to prevent.
    claim="$(api PATCH "/api/admin/remediation/${id}/" \
        "{\"status\":\"running\",\"agent_host\":\"${AGENT_HOST}\"}")"
    if ! grep -q '"status": *"running"' <<<"${claim}"; then
        log "${id}: claim refused (${claim}) — skipping"
        return 0
    fi

    out="$(run_action "${action}" 2>&1)"; rc=$?
    local status="succeeded"
    [[ ${rc} -eq 127 ]] && status="rejected"
    [[ ${rc} -ne 0 && ${rc} -ne 127 ]] && status="failed"

    # Truncated and JSON-encoded through python: operator output contains quotes and newlines,
    # and hand-built JSON would break on the first one — losing the result of a repair that ran.
    ${RUNTIME} exec -i "${BE}" python -c "
import json, sys, urllib.request as u
payload = json.dumps({'status': '${status}', 'exit_code': ${rc},
                      'output': sys.stdin.read()[-8000:]})
u.urlopen(u.Request('http://127.0.0.1:8000/api/admin/remediation/${id}/', method='PATCH',
    data=payload.encode(),
    headers={'Authorization':'Token ${TOKEN}','Content-Type':'application/json'}), timeout=15)
" <<<"${out}" >/dev/null 2>&1
    log "${id}: ${status} (exit ${rc})"
}

log "polling every ${INTERVAL}s (actions: $(grep -oE '^        [a-z-]+\)' "$0" | tr -d ' )' | tr '\n' ' '))"
while :; do
    # The queue endpoint, not the admin history view — the admin view refuses the service
    # token, and a refusal parsed as "no work" is an agent that polls forever doing nothing.
    queued="$(api GET "/api/admin/remediation/queue/")"
    while IFS=$'\t' read -r id action; do
        [[ -n "${id}" ]] || continue
        claim_and_run "${id}" "${action}"
    done < <(printf '%s' "${queued}" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
if not isinstance(d, dict) or 'requests' not in d:
    print(f'unexpected queue response: {d}', file=sys.stderr)
    sys.exit(0)
for r in d['requests']:
    print(f\"{r['id']}\t{r['action']}\")")
    [[ "${ONCE}" == "1" ]] && break
    sleep "${INTERVAL}"
done
