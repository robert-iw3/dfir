#!/usr/bin/env bash
# Horizontal memory-analysis workers: one queue, N consumers, an enterprise surge.
#
# The scenario this proves is the one scale exists for: a SIEM flags dozens of hosts and
# memory arrives from all of them at once. The platform must task every worker in parallel
# — and it must stay a platform while doing it: each capture analyzed exactly once, each
# analysis attributed to the worker that ran it, every replica inside the mesh with the
# same intentions as the primary, and no replica able to evict another's staging.
#
# 5 workers is the crawl proof on one host. The logic is what scales: 50 is stamped by the
# same generator, and past the single host it is analysis hosts under Nomad, not more IPs.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"
. "${HERE}/lib/report.sh"
report_begin 21 workers "N memory-analysis workers drain one surge in parallel" \
    "With five workers consuming the one analysis queue, a 25-endpoint surge is analyzed with real overlap across at least three distinct workers, every capture exactly once, each analysis attributed to the worker that ran it, and every replica registered in the mesh under the ir-worker name with its own sidecar."

num() { local v="${1//[^0-9]/}"; printf '%s' "${v:-0}"; }
RUNTIME="${IR_RUNTIME:-podman}"
BE=ir-enclave_backend_1

set -a; . "${PLATFORM}/deploy/.env" 2>/dev/null || true; set +a
REPLICAS="${IR_WORKER_REPLICAS:-1}"

if [[ "${REPLICAS}" -lt 2 ]]; then
    # A single-worker deployment has nothing to validate here — the same shape as the
    # multihost suite on a single host. Exit 2 so the runner records a skip, not a failure.
    echo "uat_workers: this deployment runs one worker (IR_WORKER_REPLICAS=${REPLICAS}) — deploy with IR_WORKER_REPLICAS=5 to validate parallel analysis." >&2
    exit 2
fi
say "1/4  The worker fleet is real — containers, mesh identities, isolation"
# Settling window, not a single snapshot: run immediately after a deploy returns, the
# runtime is still reconciling and one `podman ps` can transiently miss a container that
# is in fact fine — which failed this suite against a healthy fleet.
UP=0
for _ in $(seq 1 12); do
    UP=1
    for n in $(seq 2 "${REPLICAS}"); do
        ${RUNTIME} ps --format '{{.Names}}' 2>/dev/null | grep -qx "ir-enclave_worker-${n}_1" || UP=0
    done
    [[ "${UP}" == "1" ]] && break
    sleep 5
done
[[ "${UP}" == "1" ]] \
    && ok "worker + $((REPLICAS - 1)) replicas running (worker-2..worker-${REPLICAS})" \
    || { bad "not every declared replica is running after 60s"; report_finish; exit 1; }

# The same authenticated read the consul suite uses: management token, TLS, from inside
# the control plane.
SEC="${PLATFORM}/hashicorp/consul/secrets"
MGMT="$(cat "${SEC}/tokens/management.token" 2>/dev/null)"
INSTANCES="$(${RUNTIME} exec \
    -e CONSUL_HTTP_ADDR=https://127.0.0.1:8501 \
    -e CONSUL_CACERT=/consul/tls/consul-ca.pem \
    -e CONSUL_HTTP_TOKEN="${MGMT}" \
    ir-enclave_consul_1 sh -c \
    'curl -s --cacert /consul/tls/consul-ca.pem -H "X-Consul-Token: ${CONSUL_HTTP_TOKEN}" \
     https://127.0.0.1:8501/v1/catalog/service/ir-worker' 2>/dev/null \
  | python3 -c "import json,sys
try:
    rows = json.load(sys.stdin)
    print(len(rows), ','.join(sorted(r['ServiceID'] for r in rows)))
except Exception:
    print(0, '-')" 2>/dev/null)"
read -r N_INST INST_IDS <<<"${INSTANCES}"
[[ "$(num "${N_INST:-}")" -ge "${REPLICAS}" ]] \
    && ok "the mesh carries ${N_INST} instances under ONE service name (${INST_IDS}) — intentions cover all of them unchanged" \
    || bad "consul lists ${N_INST:-0} ir-worker instance(s), expected ${REPLICAS} (${INST_IDS:-none})"

SIDECARS=0
for n in $(seq 2 "${REPLICAS}"); do
    ${RUNTIME} ps --format '{{.Names}}' | grep -qx "ir-enclave_worker-${n}-sidecar_1" && SIDECARS=$((SIDECARS + 1))
done
[[ "${SIDECARS}" -eq $((REPLICAS - 1)) ]] \
    && ok "every replica has its own Envoy sidecar in its own namespace" \
    || bad "only ${SIDECARS}/$((REPLICAS - 1)) replica sidecars are running"

SCRATCH=0
for n in $(seq 2 "${REPLICAS}"); do
    ${RUNTIME} volume exists "ir-enclave_worker-${n}-scratch" 2>/dev/null && SCRATCH=$((SCRATCH + 1))
done
[[ "${SCRATCH}" -eq $((REPLICAS - 1)) ]] \
    && ok "every replica stages on its OWN scratch volume — no replica can evict another's capture" \
    || bad "only ${SCRATCH}/$((REPLICAS - 1)) replica scratch volumes exist"

say "2/4  The surge — a fleet's memory arrives at once"
CORPUS_PREFIX=INC-CORPUS
CORPUS_COUNT=25
SCEN="$(mktemp -d)"
trap 'rm -rf "${SCEN}"' EXIT
. "${HERE}/lib/corpus_pipeline.sh"
corpus_preconditions || { report_finish; exit 1; }
python3 "${HERE}/corpus/scenarios.py" "${SCEN}" >/dev/null \
    && ok "25 endpoint scenarios generated — the flagged fleet" \
    || { bad "scenario generation failed"; report_finish; exit 1; }
corpus_reset
corpus_receiver_addr
corpus_collect_and_ship "${SCEN}"
[[ "$(num "${SHIPPED:-}")" -ge "${CORPUS_COUNT}" ]] \
    && ok "${SHIPPED} endpoints collected and shipped in one burst" \
    || bad "only ${SHIPPED:-0} bundles were accepted"
corpus_await_ingest
corpus_await_analysis
corpus_assert_analysis_ran

say "3/4  The proof — parallel, distributed, exactly once"
# The pipeline round arrives one bundle at a time (the puller's interval), and a 0.9-second
# analysis finishes before the next bundle lands — so that round proves distribution and
# exactly-once, never overlap. The SURGE is dispatched through the platform's own
# re-analysis endpoint: every capture queued in one burst, the way an XDR-flagged fleet's
# memory hits the queue, and the overlap is measured on that round alone.
BURST="$(${RUNTIME} exec -i "${BE}" python manage.py shell -c "
import urllib.request
from django.contrib.auth.models import User
from django.utils import timezone
from rest_framework.authtoken.models import Token
from cases.models import MemoryCapture
tok = Token.objects.get_or_create(user=User.objects.filter(is_superuser=True).first())[0].key
mark = timezone.now().isoformat()
caps = list(MemoryCapture.objects.filter(
    run__investigation__incident_id__startswith='INC-CORPUS').exclude(retention_status='purged'))
n = 0
for c in caps:
    r = urllib.request.Request(f'http://127.0.0.1:8000/api/captures/{c.id}/reanalyze/',
                               method='POST', data=b'{}',
                               headers={'Authorization': 'Token ' + tok,
                                        'Content-Type': 'application/json'})
    try:
        urllib.request.urlopen(r, timeout=30)
        n += 1
    except Exception:
        pass
print(mark, n)" 2>/dev/null | tail -1)"
read -r BURST_MARK BURST_N <<<"${BURST}"
[[ "$(num "${BURST_N:-}")" -ge 10 ]] \
    && ok "${BURST_N} re-analyses dispatched in ONE burst through the platform's own endpoint" \
    || bad "only ${BURST_N:-0} re-analyses could be dispatched"

# Wait for the burst round to drain.
for _ in $(seq 1 60); do
    LEFT="$(${RUNTIME} exec -i "${BE}" python manage.py shell -c "
from cases.models import MemoryAnalysisRun
print(MemoryAnalysisRun.objects.filter(created_at__gte='${BURST_MARK}',
                                       status__in=('queued','running')).count())" 2>/dev/null | tail -1)"
    [[ "$(num "${LEFT:-1}")" -eq 0 ]] && break
    sleep 5
done

PROOF="$(${RUNTIME} exec -i "${BE}" python manage.py shell -c "
from cases.models import MemoryAnalysisRun
runs = list(MemoryAnalysisRun.objects.filter(
    capture__run__investigation__incident_id__startswith='INC-CORPUS',
    created_at__gte='${BURST_MARK}',
    status='completed'))

workers = sorted({(r.summary or {}).get('analysis_worker', '?') for r in runs})

# Exactly once: no capture may carry two completed analyses from this pass.
per_cap = {}
for r in runs:
    per_cap[r.capture_id] = per_cap.get(r.capture_id, 0) + 1
doubled = [c for c, n in per_cap.items() if n > 1]

# True overlap: the maximum number of analyses in flight at one instant, from the
# recorded start/finish stamps — the sweep-line over the platform's own rows.
events = []
for r in runs:
    if r.started_at and r.finished_at:
        events.append((r.started_at, 1)); events.append((r.finished_at, -1))
peak = cur = 0
for _, delta in sorted(events, key=lambda e: (e[0], -e[1])):
    cur += delta; peak = max(peak, cur)

print(len(runs), len(workers), '|'.join(workers), len(doubled), peak)" 2>/dev/null | tail -1)"
read -r N_RUNS N_WORKERS WORKER_LIST N_DOUBLED PEAK <<<"${PROOF}"

[[ "$(num "${N_RUNS:-}")" -ge "$(num "${BURST_N:-}")" ]] \
    && ok "${N_RUNS} analyses completed for the burst" \
    || bad "only ${N_RUNS:-0} of ${BURST_N} burst analyses completed"
[[ "$(num "${N_WORKERS:-}")" -ge 3 ]] \
    && ok "the load was carried by ${N_WORKERS} distinct workers (${WORKER_LIST}) — one queue, many hands" \
    || bad "only ${N_WORKERS:-0} worker(s) analyzed anything (${WORKER_LIST:-none}) — replicas are idle passengers"
[[ "$(num "${N_DOUBLED:-}")" -eq 0 ]] \
    && ok "every capture was analyzed EXACTLY once — N consumers did not double-draw from the queue" \
    || bad "${N_DOUBLED} capture(s) were analyzed more than once"
[[ "$(num "${PEAK:-}")" -ge 3 ]] \
    && ok "true parallelism: ${PEAK} analyses were in flight at one instant, by the platform's own timestamps" \
    || bad "peak concurrency was ${PEAK:-0} — the fleet analyzed one at a time"

say "4/4  The fleet is observable and attributable"
HEALTH="$(${RUNTIME} exec -i "${BE}" python manage.py shell -c "
from datetime import timedelta
from django.utils import timezone
from cases.models import ComponentHealth
# Rows are keyed 'role (container)' and containers change ids across recreates, so old
# rows linger. Only ROLES seen in the last 20 minutes say who is reporting NOW.
fresh = timezone.now() - timedelta(minutes=20)
roles = sorted({c.component.split(' ')[0] for c in ComponentHealth.objects.all()
                if c.updated_at >= fresh
                and (c.component == 'worker' or c.component.startswith('worker'))})
print(len(roles), ','.join(roles))" 2>/dev/null | tail -1)"
read -r N_HEALTH HEALTH_LIST <<<"${HEALTH}"
[[ "$(num "${N_HEALTH:-}")" -ge "${REPLICAS}" ]] \
    && ok "every worker reports under its OWN role (${HEALTH_LIST}) — a sick replica is findable" \
    || bad "only ${N_HEALTH:-0} distinct worker role(s) reporting of ${REPLICAS} (${HEALTH_LIST:-none})"

ATTR="$(${RUNTIME} exec -i "${BE}" python manage.py shell -c "
from cases.models import MemoryAnalysisRun
runs = MemoryAnalysisRun.objects.filter(
    capture__run__investigation__incident_id__startswith='INC-CORPUS',
    created_at__gte='${BURST_MARK}', status='completed')
missing = sum(1 for r in runs if not (r.summary or {}).get('analysis_worker'))
print(missing)" 2>/dev/null | tail -1)"
[[ "$(num "${ATTR:-}")" -eq 0 ]] \
    && ok "every analysis names the worker that performed it — reproducibility material, like the engine version" \
    || bad "${ATTR} analysis(es) have no worker attribution"

report_finish
exit "${FAILED}"
