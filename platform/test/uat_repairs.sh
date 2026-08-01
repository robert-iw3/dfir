#!/usr/bin/env bash
# ==============================================================================
# ENCLAVE REPAIRS UAT — the request/execute split, asserted end to end.
#
# The security model under test: the web tier RECORDS a repair request and executes nothing;
# the deployed agent container claims it, matches the ACTION NAME against its own allow-list,
# runs its own command through the runtime socket, and reports back with a service credential
# an admin does not hold.
#
#   1. THE TWO LISTS AGREE. The UI's catalogue and the agent's case-statement are deliberately
#      separate; drift between them is a request that sits queued forever, or a privileged
#      command nothing can invoke.
#   2. THE EXECUTOR IS ISOLATED. No network, no published ports, host pids for the namespace
#      checks, and the runtime socket as its only authority.
#   3. ONLY AN ADMIN CAN ASK, AND ONLY FOR A NAMED REPAIR. Unknown actions are refused at the
#      API; non-admin roles are refused outright.
#   4. THE LOOP CLOSES — against the DEPLOYED agent, not a copy run by this test. A queued
#      request is claimed, executed, and lands `succeeded` with output, exit code and host.
#   5. THE REPAIR REPAIRS. The policy-converge action leaves Consul holding the intentions the
#      files declare — verified against Consul, not against the agent's exit code.
#   6. AN OUTCOME CANNOT BE REWRITTEN. A second claim on a finished row is refused — the
#      history is an audit record, not a note.
# ==============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"

. "${HERE}/lib/report.sh"
report_begin 45 repairs "Enclave repairs — admin-requested, agent-executed" \
    "A repair is requested in the web tier and executed only by the isolated agent's own allow-list; the outcome is recorded once and cannot be forged or replayed."
RUNTIME="${IR_RUNTIME:-podman}"
BE=ir-enclave_backend_1
AGENT=ir-agent_remediation-agent_1

set -a; . "${PLATFORM}/deploy/.env" 2>/dev/null || true; set +a

# ============================================================ 1. the two lists agree
say "The catalogue and the allow-list"
catalog="$(${RUNTIME} exec "${BE}" python -c \
    'from cases.remediation import CATALOG; print("\n".join(sorted(CATALOG)))' 2>/dev/null)"
allowlist="$(grep -oE '^        [a-z-]+\)' "${PLATFORM}/troubleshooting/remediation-agent.sh" \
    | tr -d ' )' | sort)"
if [[ -n "${catalog}" && "${catalog}" == "${allowlist}" ]]; then
    ok "the UI catalogue and the agent allow-list name the same $(wc -l <<<"${catalog}") repairs"
else
    bad "catalogue and allow-list have drifted"
    info "catalogue:  $(tr '\n' ' ' <<<"${catalog}")"
    info "allow-list: $(tr '\n' ' ' <<<"${allowlist}")"
fi

# ============================================================ 2. the executor is isolated
say "The deployed agent and its posture"
[[ "$(${RUNTIME} inspect -f '{{.State.Running}}' "${AGENT}" 2>/dev/null)" == "true" ]] \
    && ok "the agent container is running (deployed by deploy.sh agent)" \
    || { bad "no running agent container — deploy.sh agent has not run"; report_finish; exit 1; }

netmode="$(${RUNTIME} inspect -f '{{.HostConfig.NetworkMode}}' "${AGENT}" 2>/dev/null)"
[[ "${netmode}" == "none" ]] \
    && ok "network_mode is none — the executor has no address and accepts nothing" \
    || bad "the agent has a network (${netmode}) — its only path should be the socket"

ports="$(${RUNTIME} inspect -f '{{.HostConfig.PortBindings}}' "${AGENT}" 2>/dev/null)"
[[ "${ports}" == "map[]" || -z "${ports}" ]] \
    && ok "no published ports" \
    || bad "the agent publishes ports: ${ports}"

pidmode="$(${RUNTIME} inspect -f '{{.HostConfig.PidMode}}' "${AGENT}" 2>/dev/null)"
[[ "${pidmode}" == "host" ]] \
    && ok "pid: host — the deploy scripts' /proc namespace checks see host pids" \
    || bad "pid mode is '${pidmode}' — mesh namespace checks would read the wrong /proc"

${RUNTIME} inspect -f '{{range .Mounts}}{{.Destination}}{{"\n"}}{{end}}' "${AGENT}" 2>/dev/null \
    | grep -q '^/run/podman/podman.sock$' \
    && ok "the runtime socket is mounted — the agent's one authority" \
    || bad "no runtime socket in the agent — it cannot execute anything"

# ============================================================ 3. who can ask, and for what
say "Requesting a repair"
# Tokens minted inside the backend: an admin's, and a deliberately role-less principal for the
# refusal case.
read -r ADMIN_TOK NOROLE_TOK <<<"$(${RUNTIME} exec -w /app "${BE}" python -c '
import django, os
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ir_platform.settings")
django.setup()
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
a = Token.objects.get_or_create(user=User.objects.filter(is_superuser=True).first())[0].key
u = User.objects.get_or_create(username="uat-norole", defaults={"is_active": True})[0]
n = Token.objects.get_or_create(user=u)[0].key
print(a, n)' 2>/dev/null)"
[[ -n "${ADMIN_TOK:-}" ]] || { bad "could not mint API tokens"; report_finish; exit 1; }

req() { # token method path [json] -> body + last line HTTP code
    ${RUNTIME} exec -i "${BE}" python -c "
import sys, urllib.request as u, urllib.error as e
body = sys.stdin.read() or None
r = u.Request('http://127.0.0.1:8000$3', method='$2',
              data=body.encode() if body else None,
              headers={'Authorization':'Token $1','Content-Type':'application/json'})
try:
    resp = u.urlopen(r, timeout=30); print(resp.read().decode()); print(resp.status)
except e.HTTPError as ex:
    print(ex.read().decode()); print(ex.status)
" <<<"${4:-}" 2>/dev/null
}

out="$(req "${NOROLE_TOK}" POST /api/admin/remediation/ '{"action":"consul-converge-policy","reason":"uat"}')"
[[ "$(tail -1 <<<"${out}")" == "403" ]] \
    && ok "a principal without the admin role cannot request a repair (403)" \
    || bad "a role-less request was not refused: $(tail -1 <<<"${out}")"

out="$(req "${ADMIN_TOK}" POST /api/admin/remediation/ '{"action":"rm -rf /","reason":"uat"}')"
[[ "$(tail -1 <<<"${out}")" == "400" ]] \
    && ok "an unknown action is refused at the API (400)" \
    || bad "an unnamed action was accepted: $(tail -1 <<<"${out}")"

# The queue endpoint answers the service credential with the shape the agent parses. Checked
# before queueing real work — the live agent claims within its poll interval, so asserting a
# specific row here would race it.
out="$(req "${IR_BROKER_TOKEN}" GET /api/admin/remediation/queue/)"
[[ "$(tail -1 <<<"${out}")" == "200" ]] && grep -q '"requests"' <<<"${out}" \
    && ok "the queue endpoint answers the service credential with a requests list" \
    || bad "the queue endpoint refused the service credential: $(tail -1 <<<"${out}")"

out="$(req "${ADMIN_TOK}" POST /api/admin/remediation/ '{"action":"consul-converge-policy","reason":"UAT repairs loop"}')"
RID="$(grep -o '"id": *[0-9]*' <<<"${out}" | head -1 | grep -o '[0-9]*')"
if [[ "$(tail -1 <<<"${out}")" == "201" && -n "${RID}" ]]; then
    ok "admin queued consul-converge-policy (request ${RID})"
else
    bad "queueing the repair failed: ${out}"
    report_finish; exit 1
fi

# ============================================================ 4. the loop closes
say "The deployed agent claims and executes"
# No agent is run here — the one the deploy started must do the work, or the feature does not
# exist outside this test.
state=""
for _ in $(seq 1 60); do
    row="$(req "${ADMIN_TOK}" GET /api/admin/remediation/ | head -1)"
    state="$(python3 -c "
import json, sys
d = json.loads(sys.stdin.read())
m = [r for r in d.get('requests', []) if r['id'] == ${RID}]
print(m[0]['status'] if m else '')" <<<"${row}" 2>/dev/null)"
    [[ "${state}" == "succeeded" || "${state}" == "failed" || "${state}" == "rejected" ]] && break
    sleep 3
done
[[ "${state}" == "succeeded" ]] \
    && ok "request ${RID} landed succeeded — claimed and executed by the deployed agent" \
    || { bad "request ${RID} is '${state:-unknown}' after 180s"; \
         info "$(${RUNTIME} logs --tail 6 "${AGENT}" 2>&1)"; }

[[ "$(${RUNTIME} logs "${AGENT}" 2>&1 | grep -c "claiming ${RID}: consul-converge-policy")" -gt 0 ]] \
    && ok "the agent's own log records the claim" \
    || bad "the agent log never mentions request ${RID}"

detail="$(req "${ADMIN_TOK}" GET "/api/admin/remediation/?status=succeeded" | head -1)"
python3 -c "
import json, sys
d = json.loads(sys.stdin.read())
m = [r for r in d.get('requests', []) if r['id'] == ${RID}]
r = m[0] if m else {}
assert r.get('agent_host') == '$(hostname)', r.get('agent_host')
assert (r.get('output') or '').strip(), 'no output'
assert r.get('exit_code') == 0, r.get('exit_code')
" <<<"${detail}" 2>/dev/null \
    && ok "the record carries the executing host ($(hostname)), the output, and exit 0" \
    || bad "the finished request is missing host, output or a zero exit"

# ============================================================ 5. the repair repairs
say "The repair restored the policy"
# Asserted against Consul with the read-only token the UI uses — the agent's exit code says
# the script ran; this says the mesh now holds what config-entries/ declares.
CONSUL_TOK="$(cat "${PLATFORM}/hashicorp/consul/secrets/tokens/ui-readonly.token" 2>/dev/null)"
declared="$(ls "${PLATFORM}/hashicorp/consul/config-entries/" | grep -c '^ir-')"
held="$(${RUNTIME} exec -e CONSUL_HTTP_TOKEN="${CONSUL_TOK}" ir-enclave_consul_1 \
    consul config list -kind service-intentions \
    -http-addr https://127.0.0.1:8501 -ca-file /consul/tls/consul-ca.pem 2>/dev/null | grep -c .)"
if [[ -n "${held}" && "${held}" -ge "${declared}" ]]; then
    ok "Consul holds ${held} intention set(s) for ${declared} declared — the policy converged"
else
    bad "Consul holds ${held:-0} intention set(s), files declare ${declared}"
fi

# ============================================================ 6. the outcome is final
say "The outcome cannot be rewritten"
out="$(req "${IR_BROKER_TOKEN}" PATCH "/api/admin/remediation/${RID}/" '{"status":"running","agent_host":"impostor"}')"
[[ "$(tail -1 <<<"${out}")" == "409" ]] \
    && ok "a second claim on the finished request is refused (409)" \
    || bad "the finished request could be re-claimed: $(tail -1 <<<"${out}")"

out="$(req "${ADMIN_TOK}" PATCH "/api/admin/remediation/${RID}/" '{"status":"succeeded","output":"forged"}')"
code="$(tail -1 <<<"${out}")"
# IsService admits admins for ops, so the write is refused by the transition guard, not RBAC.
[[ "${code}" == "409" || "${code}" == "403" ]] \
    && ok "an outcome cannot be rewritten after the fact (${code})" \
    || bad "the recorded outcome was overwritten: ${code}"

# Asking for a privileged action is an auditable event whether or not it ever runs.
audit="$(${RUNTIME} exec -w /app "${BE}" python -c "
import django, os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ir_platform.settings')
django.setup()
from cases.models import AuditLog
print(AuditLog.objects.filter(action='remediation.request', object_id='${RID}').count())" 2>/dev/null)"
[[ "${audit}" == "1" ]] \
    && ok "the request is in the audit ledger" \
    || bad "no audit entry for request ${RID}"

# ============================================================ summary
say "Result"
if [[ "${FAILED}" == "0" ]]; then
    ok "enclave repairs hold: named requests, an isolated executor, recorded outcomes, and a repair that actually repairs"
else
    bad "enclave repairs do NOT hold — see failures above"
fi
report_finish
exit "${FAILED}"
