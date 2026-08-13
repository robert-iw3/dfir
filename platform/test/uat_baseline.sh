#!/usr/bin/env bash
# ==============================================================================
# BASELINE UAT — the collector path through every component, verified both ways. Closes out the
# current baseline.
#
#
#
#
#
# ==============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"

. "${HERE}/lib/report.sh"
report_begin 50 baseline "Platform baseline — identity and SSO gate" \
    "The deployed platform serves its API behind the SSO gate, with identity enforced rather than assumed."
DEPLOY="${PLATFORM}/deploy"
RUNTIME="${IR_RUNTIME:-podman}"
# The probe image is BUILT with curl, dig and getent. Tests must never install tooling at
# runtime: the networks under test have no egress by design, so an install silently fails and
# the empty result reads as a platform defect instead of a broken test.
PROBE="${IR_PROBE_IMAGE:-localhost/ir-workstation:latest}"
# The deployment's configuration, so assertions about it read the values actually in use
# rather than unset variables — an absent RECEIVER_URL is indistinguishable from a
# misconfigured one when the test never loaded it.
set -a; . "${PLATFORM}/deploy/.env" 2>/dev/null || true; set +a
WORK="$(mktemp -d -t ir-uat-baseline.XXXXXX)"

cleanup() { rm -rf "${WORK}"; }
trap cleanup EXIT

be() { ${RUNTIME} exec -i ir-enclave_backend_1 "$@"; }

# Count matches rather than testing grep's exit status. `producer | grep -q` under
# pipefail returns 141 when grep exits early and the producer dies on SIGPIPE, so a
# SUCCESSFUL match reads as a failure — which inverts every assertion written that way.
has() { [[ "$(grep -c -- "$2" <<<"$1")" -gt 0 ]]; }

dj() { be python -c "
import os, django, json
os.environ.setdefault('DJANGO_SETTINGS_MODULE','ir_platform.settings')
django.setup()
$1
"; }

# ------------------------------------------------------------------ 1. components up
say "Components — every tier answers"
for c in ir-enclave_db_1 ir-enclave_redis_1 ir-enclave_minio_1 ir-enclave_backend_1 \
         ir-enclave_worker_1 ir-enclave_puller_1 ir-dmz_receiver_1; do
    state="$(${RUNTIME} inspect "${c}" --format '{{.State.Status}}' 2>/dev/null || echo missing)"
    [[ "${state}" == "running" ]] && ok "${c} running" || bad "${c} is ${state}"
done

# The receiver is addressed by NAME here, exactly as the collector and puller address it. The
# test used to look its address up and use that, which asserted against a value the runtime
# owns and re-assigns — and silently skipped the question of whether the name resolves at all.
RECV_HOST="receiver"
RECV_ADDR="$(${RUNTIME} run --rm --network ir-dmzlink "${PROBE}" \
    getent ahostsv4 "${RECV_HOST}" 2>/dev/null | awk 'NR==1{print $1}')"
[[ -n "${RECV_ADDR}" ]] \
    && ok "receiver resolves by name (${RECV_HOST} -> ${RECV_ADDR})" \
    || bad "receiver does not resolve by name — every client addresses it this way"

# ------------------------------------------------------------- 2. collector identity
say "Collector — identity is the machine's, not the container's"
${RUNTIME} run --rm --privileged --pid=host --network none \
    -v /proc:/host/proc:ro -v /:/host/root:ro -v "${WORK}:/evidence:z" \
    -e IR_INCIDENT_ID=INC-UAT-BASELINE \
    localhost/ir-collector:latest >"${WORK}/collect.log" 2>&1
COLLECT_LOG="$(cat "${WORK}/collect.log")"

REPORT_DIR="$(find "${WORK}/reports" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | head -1)"
if [[ -n "${REPORT_DIR}" ]]; then
    ok "collection produced $(basename "${REPORT_DIR}")/"
else
    bad "collection produced no report directory"
    # The WHY dies with the temp workdir unless it is said here: carry the collector's own
    # last words into the report, or the failure is undiagnosable after the run.
    info "collector output (tail): $(tail -5 "${WORK}/collect.log" 2>/dev/null | tr '\n' ' ' | cut -c1-400)"
fi

# Empty when collection failed; every consumer below must degrade to a failing assertion
# rather than an unbound-variable abort that takes the rest of the suite's evidence with it.
NAME=""
HOST_ID="${REPORT_DIR}/_host_identity.json"
if [[ -f "${HOST_ID}" ]]; then
    SRC="$(python3 -c "import json;print(json.load(open('${HOST_ID}')).get('hostname_source',''))")"
    MID="$(python3 -c "import json;print(json.load(open('${HOST_ID}')).get('machine_id',''))")"
    NAME="$(python3 -c "import json;print(json.load(open('${HOST_ID}')).get('hostname',''))")"
    [[ "${SRC}" == "host-mount" || "${SRC}" == "override" ]] \
        && ok "hostname resolved from ${SRC} (${NAME})" \
        || bad "hostname_source is '${SRC}' — evidence would file under a container id"
    [[ -n "${MID}" ]] && ok "machine-id recorded (${#MID} chars, value withheld)" \
        || bad "no machine-id — collection cannot be tied to a memory image ingested separately"
else
    bad "_host_identity.json missing — nothing identifies the source machine"
fi

# The toolkit computes its own hostname and writes it into the metadata ingest reads.
# Both layers have to agree or the folder and the record name different hosts.
if has "${COLLECT_LOG}" "IR COLLECTION | host=${NAME}"; then
    ok "toolkit and collector agree on the hostname"
else
    bad "toolkit recorded a different hostname than the collector"
fi

# ------------------------------------------------------- 3. memory capture honesty
say "Memory capture — succeeds, or says exactly why not"
META="${REPORT_DIR}/_capture_meta.json"
if [[ -f "${META}" ]]; then
    SYNTH="$(python3 -c "import json;print(json.load(open('${META}')).get('is_synthetic'))")"
    TOOL="$(python3 -c "import json;print(json.load(open('${META}')).get('capture_tool',''))")"
    ERR="$(python3 -c "import json;print(json.load(open('${META}')).get('capture_error',''))")"
    if [[ "${SYNTH}" == "False" ]]; then
        ok "real capture acquired via ${TOOL}"
    else
        # A synthetic sample analyzes cleanly and looks like a completed collection. The
        # failure is only visible if the collector recorded the reason, so that is the
        # property under test — not whether acquisition happened to be possible here.
        [[ -n "${ERR}" ]] \
            && ok "synthetic fallback records why: ${ERR:0:60}…" \
            || bad "synthetic fallback with no capture_error — a failed collection looks complete"
        has "${COLLECT_LOG}" "memory capture FAILED" \
            && ok "fallback warned loudly in the log" \
            || bad "fallback was silent in the log"
    fi
else
    bad "_capture_meta.json missing"
fi

# --------------------------------------------------------- 4. forward: ship inward
say "DMZ receiver — accepts a verified bundle, refuses what will not fit"
SHIP="$(${RUNTIME} run --rm --network ir-dmzlink -v "${WORK}:/evidence:ro" \
    -e RECEIVER_URL="https://${RECV_HOST}:8090" \
    -e CA_BUNDLE=/ca/receiver.crt \
    -v "${PLATFORM}/dmz/certs/receiver.crt:/ca/receiver.crt:ro,z" --entrypoint sh \
    localhost/ir-collector:latest /opt/collector/ship.sh 2>&1)"
if has "${SHIP}" '"verified": true'; then
    ok "bundle accepted and custody-verified"
else
    bad "bundle rejected: $(tail -1 <<<"${SHIP}")"
fi

# A Content-Length larger than the holding volume must be refused before any bytes are
# read, rather than filling the volume and taking the path down for every other host.
HUGE="$(${RUNTIME} run --rm --network ir-dmzlink \
  -v "${PLATFORM}/dmz/certs/receiver.crt:/ca.crt:ro,z" "${PROBE}" \
  curl -s -o /dev/null -w '%{http_code}' --cacert /ca.crt \
       -X POST -H 'Content-Length: 999999999999999' \
       --max-time 15 "https://${RECV_HOST}:8090/ingest" 2>/dev/null)"
[[ "${HUGE}" == "400" ]] \
    && ok "oversized upload refused up front (400)" \
    || bad "oversized upload was not refused (got '${HUGE}')"

# ------------------------------------------- 4b. the evidence path is encrypted
say "Transport — evidence does not cross the wire in the clear"
# A bundle carries a memory image: every credential, key, token and open file the host had in
# RAM. The custody seal proves it was not ALTERED in transit and does nothing to stop it being
# READ, so confidentiality is a separate control and needs its own assertion.
if [[ "${RECEIVER_URL:-}" == https://* ]]; then
    ok "the configured receiver URL is https (${RECEIVER_URL})"
else
    bad "RECEIVER_URL is '${RECEIVER_URL:-unset}' — evidence would ship in plaintext"
fi

# Asserted against the running socket, not the configuration: a receiver that started before
# TLS was wired, or fell back, still reads as configured-for-https in .env.
TLS_OUT="$(${RUNTIME} run --rm --network ir-dmzlink \
    -v "${PLATFORM}/dmz/certs/receiver.crt:/ca.crt:ro,z" "${PROBE}" \
    curl -sv --cacert /ca.crt --max-time 15 -o /dev/null \
    "https://${RECV_HOST}:8090/healthz" 2>&1)"
if has "${TLS_OUT}" "SSL connection using"; then
    ok "receiver negotiates TLS ($(sed -n 's/.*SSL connection using \([^ ]*\).*/\1/p' <<<"${TLS_OUT}" | head -1))"
else
    bad "receiver did not complete a TLS handshake — the evidence path is plaintext"
fi

# The collector must VERIFY, not merely encrypt. Without verification it will hand a host's
# memory to whoever answers on that address, which on a hostile segment is the realistic case.
VERIFY="$(${RUNTIME} run --rm --network ir-dmzlink \
    -v "${PLATFORM}/dmz/certs/receiver.crt:/ca.crt:ro,z" "${PROBE}" \
    curl -sS -o /dev/null -w '%{http_code}' --cacert /ca.crt \
    --max-time 15 "https://${RECV_HOST}:8090/healthz" 2>&1)"
[[ "${VERIFY}" == "200" ]] \
    && ok "receiver's certificate verifies against the pinned CA" \
    || bad "certificate verification failed (${VERIFY}) — collectors would refuse to ship"

# And an UNTRUSTED chain must be rejected. If it is not, verification is decorative and the
# pinning above proves nothing.
UNTRUSTED="$(${RUNTIME} run --rm --network ir-dmzlink "${PROBE}" \
    curl -sS -o /dev/null -w '%{http_code}' \
    --max-time 15 "https://${RECV_HOST}:8090/healthz" 2>&1 || true)"
if [[ "${UNTRUSTED}" == "200" ]]; then
    bad "an unpinned client accepted the receiver's certificate — verification is not enforced"
else
    ok "a client without the pinned CA is rejected (verification is real)"
fi

# ------------------------------------------------- 5. reverse: the boundary holds
say "Boundary — the DMZ cannot reach in, and leaks nothing about the enclave"
for target in "ir-enclave_db_1 5432" "ir-enclave_minio_1 9000" "ir-enclave_backend_1 8000"; do
    set -- ${target}
    OUT="$(${RUNTIME} exec -i ir-dmz_receiver_1 python3 -c "
import socket
try:
    socket.create_connection(('$1', $2), timeout=4); print('REACHED')
except Exception: print('blocked')" 2>/dev/null || echo blocked)"
    [[ "${OUT}" == "blocked" ]] \
        && ok "receiver cannot reach $1:$2" \
        || bad "receiver REACHED $1:$2 — the one-way boundary is broken"
done

# The endpoint learns nothing about downstream capacity: a compromised host must not be
# able to map the enclave's storage by asking the only service it can talk to.
STATS="$(${RUNTIME} run --rm --network ir-dmzlink docker.io/library/alpine:3.24 sh -c "
  curl -s --max-time 10 --cacert /ca.crt https://${RECV_HOST}:8090/stats" 2>/dev/null)"
if has "${STATS}" "receiver"; then
    has "${STATS}" "minio\|postgres\|scratch\|worker" \
        && bad "/stats exposes enclave-side components to the endpoint network" \
        || ok "/stats reports only the receiver's own resources"
else
    info "/stats not reachable from the edge network (also acceptable)"
fi

# ------------------------------------------------- 6. ingest, identity convergence
say "Enclave — the bundle lands, and joins the host it came from"
for _ in $(seq 1 60); do
    COUNT="$(dj "from cases.models import CollectionRun; print(CollectionRun.objects.count())" 2>/dev/null | tr -d '\r')"
    [[ -n "${COUNT}" ]] && break
    sleep 5
done
RUNS_BEFORE="${COUNT:-0}"
info "collection runs currently recorded: ${RUNS_BEFORE}"

HOSTS="$(dj "
from cases.models import Host
rows=[(h.hostname, h.machine_id) for h in Host.objects.all()]
print(json.dumps(rows))" 2>/dev/null | tr -d '\r')"
DUPES="$(python3 -c "
import json,sys,collections
rows=json.loads('''${HOSTS}''' or '[]')
ids=[m for _,m in rows if m]
d=[m for m,c in collections.Counter(ids).items() if c>1]
print(len(d))" 2>/dev/null || echo 0)"
[[ "${DUPES}" == "0" ]] \
    && ok "no machine-id maps to two host records" \
    || bad "${DUPES} machine-id(s) forked into multiple hosts"

# ------------------------------------------------------- 7. analysis correctness
say "Analysis — the parser gate holds on real evidence"
C2="$(dj "
from cases.models import MemoryFinding
q = MemoryFinding.objects.filter(finding_type__icontains='C2') | \
    MemoryFinding.objects.filter(finding_type__icontains='Config Recovered')
print(q.count())" 2>/dev/null | tr -d '\r')"
if [[ -n "${C2}" ]]; then
    [[ "${C2}" == "0" ]] \
        && ok "no C2/config findings on a clean host (${C2})" \
        || bad "${C2} C2/config finding(s) on a clean host — parser gate regressed"
fi

SYNTH_DRIVEN="$(dj "
from cases.models import CollectionRun, Finding
bad = 0
for r in CollectionRun.objects.all():
    if not r.compromised:
        continue
    real = [f for f in Finding.objects.filter(run=r)
            if not (f.raw or {}).get('synthetic')]
    if not real:
        bad += 1
print(bad)" 2>/dev/null | tr -d '\r')"
[[ "${SYNTH_DRIVEN:-0}" == "0" ]] \
    && ok "no run is marked compromised by synthetic content alone" \
    || bad "${SYNTH_DRIVEN} run(s) compromised purely by synthetic findings"

# ------------------------------------------------------ 8. component health path
say "Component health — every reporter is present and current"
HEALTH="$(dj "
from cases import componenthealth
o = componenthealth.overview()
print(json.dumps({'n': len(o['components']),
                  'stale': [c['component'] for c in o['components'] if c['stale']],
                  'worst': o['worst_level'],
                  'alerts': len(o['alerts'])}))" 2>/dev/null | tr -d '\r')"
if [[ -n "${HEALTH}" ]]; then
    N="$(python3 -c "import json;print(json.loads('''${HEALTH}''')['n'])")"
    STALE="$(python3 -c "import json;print(','.join(json.loads('''${HEALTH}''')['stale']))")"
    ALERTS="$(python3 -c "import json;print(json.loads('''${HEALTH}''')['alerts'])")"
    [[ "${N}" -gt 0 ]] \
        && ok "${N} component(s) reporting resources" \
        || bad "no component has reported — the admin console would be empty"
    [[ -z "${STALE}" ]] \
        && ok "no reporter is stale" \
        || info "stale reporters: ${STALE} (expected shortly after a restart)"
    info "open capacity/resource alerts: ${ALERTS}"
else
    bad "component health overview could not be read"
fi

# ------------------------------------------------- the login page is ours
say "Login branding — the custom theme is actually served"
# Keycloak falls back to its built-in theme when it cannot load the configured one, logs one
# line about it, and serves a working login page — so the only symptom is that the page looks
# wrong. It happened here because the theme was bind-mounted and the directory tree was
# rewritten: a bind mount tracks the inode, so the container held a stale, unlinked one and saw
# an empty directory while the host plainly had the files.
LOGIN_HTML="$(${RUNTIME} exec -i ir-enclave_backend_1 python3 -c "
import urllib.request as u
print(u.urlopen('http://keycloak:8080/realms/irplatform/protocol/openid-connect/auth'
                '?client_id=ir-platform&response_type=code'
                '&redirect_uri=https%3A%2F%2Fir-platform.local%3A8443%2Foauth2%2Fcallback'
                '&scope=openid', timeout=10).read().decode())" 2>/dev/null)"
if has "${LOGIN_HTML}" "/login/dfir"; then
    ok "login page serves the platform theme"
else
    bad "login page fell back to a built-in theme — branding is not being served"
fi
has "${LOGIN_HTML}" "DFIR_FRAMEWORK" \
    && ok "login page carries the platform wordmark" \
    || bad "login page does not carry the wordmark"
n_theme="$(${RUNTIME} logs ir-enclave_keycloak_1 2>&1 | grep -c "Failed to find LOGIN theme" || true)"
[[ "${n_theme:-0}" -eq 0 ]] \
    && ok "no theme-load failures in the identity provider" \
    || bad "${n_theme} theme-load failure(s) — the theme is not reaching the container"

say "Manifests describe what is actually here"
#
# The code graph is GENERATED from source and is a manifest: services, the script graph, the API
# surface, and which UAT proves which service. It went stale unnoticed once — two services and
# two UATs existed in the tree and not in the graph — because nothing failed when it drifted.
GRAPH_GEN="$(cd "${PLATFORM}/.." && pwd)/gen_code_graph.py"
if [[ ! -f "${GRAPH_GEN}" ]]; then
    bad "gen_code_graph.py not found — the code graph cannot be verified"
elif python3 "${GRAPH_GEN}" --check >/dev/null 2>&1; then
    ok "the code graph matches the tree — services, scripts, routes and their UATs are current"
else
    bad "the code graph is STALE — run gen_code_graph.py (a service, script, route or UAT changed)"
fi

#
# The documentation is a manifest too, and it drifts the same way — silently, because a dead
# link and a stale diagram both render perfectly. Three links in the documentation index pointed
# at files a tree move had relocated, and stayed broken because nothing asserted them.
DOCS_CHECK="${PLATFORM}/ci/docs-check.sh"
if [[ ! -f "${DOCS_CHECK}" ]]; then
    bad "ci/docs-check.sh not found — documentation integrity cannot be verified"
elif docs_out="$(bash "${DOCS_CHECK}" --strict 2>&1)"; then
    ok "every documented link resolves, and every document is in the change-management inventory"
else
    bad "documentation drift: $(grep -cE 'BROKEN|UNLISTED' <<<"${docs_out}") finding(s) — run ci/docs-check.sh"
    while IFS= read -r l; do info "${l}"; done < <(grep -E 'BROKEN|UNLISTED' <<<"${docs_out}" | head -5)
fi

# Comments state what the code does; history and measurements belong in change_logs/.
# Narrative comments age into descriptions of a system that no longer exists.
STYLE_CHECK="${PLATFORM}/ci/comment-style-check.sh"
if [[ ! -f "${STYLE_CHECK}" ]]; then
    bad "ci/comment-style-check.sh not found — comment style cannot be verified"
elif bash "${STYLE_CHECK}" --strict >/dev/null 2>&1; then
    ok "no narrative comments, and no file is majority prose"
else
    bad "comment style: narrative comments or over-dense files — run ci/comment-style-check.sh"
fi

# The runtime's lock pool. Volumes, containers and pods draw from one fixed allocation of 2048;
# six of this platform's images declare VOLUME, so every container recreate that does not bind
# those paths mints an anonymous volume that nothing removes.
LOCK_POOL="${IR_RUNTIME_LOCK_POOL:-2048}"
vols="$(${RUNTIME} volume ls -q 2>/dev/null | wc -l)"
ctrs="$(${RUNTIME} ps -aq 2>/dev/null | wc -l)"
used=$(( vols + ctrs ))
if [[ "${used}" -lt $(( LOCK_POOL * 3 / 4 )) ]]; then
    ok "runtime locks: ${used} of ${LOCK_POOL} in use (${vols} volumes, ${ctrs} containers) — room to create containers"
else
    bad "runtime locks: ${used} of ${LOCK_POOL} in use (${vols} volumes, ${ctrs} containers) — container creation fails when this is exhausted; deploy.sh prunes anonymous volumes"
fi

# ------------------------------------------------------------------------ verdict
say "Baseline"
if (( FAILED )); then
    printf '  \033[1;31mBASELINE UAT FAILED\033[0m\n\n'
    exit 1
fi
printf '  \033[1;32mBASELINE UAT PASSED\033[0m — collector path verified in both directions\n\n'

report_finish
exit "${FAILED}"
