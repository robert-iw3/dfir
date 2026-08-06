# Shared corpus machinery: real collector runs -> seal -> ship -> receiver -> puller ->
# ingest -> analysis. Sourced by the corpus UATs, which differ only in the dataset they
# generate and the claims they then make about it.
#
#     . "${HERE}/lib/corpus_pipeline.sh"
#     CORPUS_PREFIX=INC-CORPUS-L CORPUS_COUNT=22 CORPUS_MANIFEST=/tmp/manifest.json
#     corpus_preconditions                      # services + a collector built from current source
#     corpus_reset                              # scoped destructive reset, AFTER preconditions
#     corpus_receiver_addr                      # -> RECV_ADDR
#     corpus_collect_and_ship "${SCEN}"         # -> SHIPPED
#     corpus_await_ingest                       # -> INGESTED
#     corpus_await_analysis                     # -> TERMINAL, NCOMP
#     corpus_assert_analysis_ran
#     corpus_correlate
#     corpus_checks <<'PYEOF' ... PYEOF         # an assertion block, run in the backend
#
# Every wait is on a condition the pipeline itself publishes, never a fixed sleep. Output is
# captured and then matched rather than piped into `grep -q`: a matcher that closes the pipe
# early kills the writer, and under `set -o pipefail` that failure is indistinguishable from
# the assertion being false.

RUNTIME="${IR_RUNTIME:-podman}"
BE=ir-enclave_backend_1
be() { ${RUNTIME} exec -i "${BE}" "$@"; }

# Set by the calling UAT before any block runs; passed to Python as ENVIRONMENT.
CORPUS_PREFIX="${CORPUS_PREFIX:-}"
CORPUS_COUNT="${CORPUS_COUNT:-}"
CORPUS_MANIFEST="${CORPUS_MANIFEST:-}"

# What every block opens with. Single-quoted, so this shell expands none of it.
_CORPUS_PRELUDE='
import json, os, django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ir_platform.settings"); django.setup()
PREFIX = os.environ["CORPUS_PREFIX"]
COUNT = int(os.environ.get("CORPUS_COUNT") or 0)


def manifest():
    with open(os.environ["CORPUS_MANIFEST"]) as fh:
        return json.load(fh)


def chk(cond, label):
    print(("PASSCHK " if cond else "FAILCHK ") + label)


def note(label):
    print("INFOCHK " + label)
'

# Run a Python block inside the backend. The caller supplies it on stdin as a QUOTED
# heredoc and every value reaches it through the environment, so this shell expands nothing
# inside it — including its comments.
#
# An unquoted heredoc expands backticks, and a backtick in a Python comment is a command the
# test then runs: `/usr/bin/pkexec`, written as an aside about a packaged SUID binary, was
# executed and raised a polkit authentication prompt in the middle of a run.
be_py() {
    { printf '%s\n' "${_CORPUS_PRELUDE}"; cat; } \
        | ${RUNTIME} exec -i \
            -e CORPUS_PREFIX="${CORPUS_PREFIX}" \
            -e CORPUS_COUNT="${CORPUS_COUNT}" \
            -e CORPUS_MANIFEST="${CORPUS_MANIFEST}" \
            "${BE}" python3 -
}

# One assertion block: PASSCHK / FAILCHK / INFOCHK lines become report rows.
corpus_checks() {
    local out line
    out="$(be_py 2>/dev/null)"
    while IFS= read -r line; do
        case "${line}" in
            PASSCHK*) ok "${line#PASSCHK }" ;;
            FAILCHK*) bad "${line#FAILCHK }" ;;
            INFOCHK*) info "${line#INFOCHK }" ;;
        esac
    done <<< "${out}"
}

# A block whose single line of output the caller wants back.
corpus_value() { be_py 2>/dev/null | tail -1; }

corpus_preconditions() {
    say "Preconditions"
    local missing=() svc
    # Load-bearing every one: without the receiver the ships go nowhere, without the worker
    # nothing is analyzed. A missing service ABORTS rather than being recorded, because the
    # alternative is a twenty-minute run reporting one fact many times over.
    for svc in ir-dmz_receiver_1 ir-enclave_puller_1 ir-enclave_backend_1 ir-enclave_worker_1; do
        if [[ "$(${RUNTIME} inspect "$svc" --format '{{.State.Status}}' 2>/dev/null)" == "running" ]]; then
            ok "$svc running"
        else
            bad "$svc not running"; missing+=("$svc")
        fi
    done
    if [[ "${#missing[@]}" -gt 0 ]]; then
        bad "aborting: ${missing[*]} absent — deploy the tier(s) first (deploy.sh dmz / deploy.sh enclave)"
        report_finish
        exit 1
    fi

    # Rebuilt when its source is NEWER, not merely when it is absent. Built-only-when-absent
    # is what left the analysis worker running pre-migration code, and here it is worse: the
    # corpus would collect with a stale collector while the deep-collection assertion greps
    # current source and passes. A green corpus proving nothing about the code under test is
    # the one outcome this suite must not produce.
    local built
    if ! ${RUNTIME} image exists ir-collector:latest 2>/dev/null; then
        built=""
    else
        built="$(${RUNTIME} image inspect ir-collector:latest --format '{{.Created}}' 2>/dev/null)"
        built="$(date -d "${built}" +%s 2>/dev/null)" || built=""
    fi
    if [[ -z "${built}" ]] || [[ -n "$(find "${PLATFORM}/collector" -type f \
            -not -path '*/__pycache__/*' -newermt "@${built}" -print -quit 2>/dev/null)" ]]; then
        bash "${PLATFORM}/collector/build.sh" >/dev/null 2>&1 \
            && ok "collector image rebuilt from current source" \
            || { bad "collector image failed to build"; report_finish; exit 1; }
    else
        ok "collector image current with collector/"
    fi

    # The collector must run the FULL forensics collection, not the inline snapshot.
    # Asserted on the source because the difference is invisible in a passing corpus: without
    # it, four of nine artifacts planted for a low-sophistication intrusion never come back,
    # and a corpus that happens not to plant them stays green while the gap is open.
    local deep
    deep="$(grep -c -- '--deep' "${PLATFORM}/collector/collect.sh" | tail -1)"
    [[ "${deep:-0}" -ge 1 ]] \
        && ok "the collector runs the full forensics collection (--deep)" \
        || bad "collect.sh no longer passes the deep flag — SUID, authorized_keys, shell-init persistence and running-binary hashes will not be collected"
}

# Scoped destructive reset so a re-run is deterministic. Call only AFTER preconditions: this
# is the one destructive step, and reaching it without a receiver empties the corpus and then
# cannot refill it, leaving the deployment emptier than it was found.
corpus_reset() {
    be_py >/dev/null 2>&1 <<'PYEOF'
from cases.models import Investigation, CollectionRun, Host
from correlation.models import CorrelationRun
invs = list(Investigation.objects.filter(incident_id__startswith=PREFIX))
host_ids = set(CollectionRun.objects.filter(investigation__in=invs).values_list("host_id", flat=True))
for inv in invs:
    CorrelationRun.objects.filter(investigation_id=inv.id).delete()
CollectionRun.objects.filter(investigation__in=invs).delete()
Investigation.objects.filter(id__in=[i.id for i in invs]).delete()
Host.objects.filter(id__in=host_ids, runs__isnull=True).delete()
PYEOF
    ok "prior ${CORPUS_PREFIX} data reset (real evidence untouched)"
}

corpus_receiver_addr() {
    RECV_ADDR="$(${RUNTIME} inspect ir-dmz_receiver_1 \
        --format '{{(index .NetworkSettings.Networks "ir-edge").IPAddress}}' 2>/dev/null)"
    # Used, never recorded: these reports are kept, and a live address of a running
    # deployment is not something to write into one.
    [[ -n "${RECV_ADDR}" ]] && ok "receiver holds an address on the edge network" \
                            || bad "receiver has no edge address"
}

# One real collector run per scenario file, sealed, then shipped to the DMZ receiver over
# pinned TLS. IR_MACHINE_ID is the collector's own identity override, resolved before any
# hunt runs: every endpoint shares one container image, and without a distinct id the enclave
# merges the whole corpus into a single host.
corpus_collect_and_ship() {  # <scenario-dir>
    local scen="$1" f host incident mid evid code
    SHIPPED=0
    for f in "${scen}"/*.json; do
        host="$(basename "${f}" .json)"
        [[ "${host}" == "manifest" ]] && continue
        incident="$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['incident_id'])" "${f}")"
        mid="$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['machine_id'])" "${f}")"
        evid="$(mktemp -d)"
        if ! ${RUNTIME} run --rm --hostname "${host}" \
            -e IR_HOSTNAME="${host}" \
            -e IR_MACHINE_ID="${mid}" \
            -e IR_INCIDENT_ID="${incident}" \
            -e IR_CUSTODY_HMAC_KEY="${IR_CUSTODY_HMAC_KEY:-}" \
            -e IR_SCENARIO_FILE=/scenario.json \
            -e IR_SAMPLE_BYTES=8388608 \
            -v "${f}:/scenario.json:ro,z" \
            -v "${evid}:/evidence:z" \
            ir-collector:latest >/dev/null 2>&1; then
            bad "${host}: collector run failed"; rm -rf "${evid}"; continue
        fi
        [[ -f "${evid}/reports/${host}/_custody_platform.json" ]] \
            || { bad "${host}: no custody seal"; rm -rf "${evid}"; continue; }
        tar czf "${evid}/bundle.tar.gz" -C "${evid}/reports" "${host}"
        code=$(${RUNTIME} run --rm --network ir-edge \
            -v "${evid}/bundle.tar.gz:/b.tar.gz:ro,z" \
            -v "${PLATFORM}/dmz/certs/receiver.crt:/r.crt:ro,z" \
            localhost/ir-workstation:latest \
            curl -s -o /dev/null -w '%{http_code}' --cacert /r.crt \
                 --resolve "receiver:8090:${RECV_ADDR}" \
                 -X POST -T /b.tar.gz "https://receiver:8090/ingest" 2>/dev/null)
        rm -rf "${evid}"
        if [[ "${code}" == "202" ]]; then
            SHIPPED=$((SHIPPED + 1))
        else
            bad "${host}: receiver answered ${code:-nothing}"
        fi
    done
    [[ "${SHIPPED}" == "${CORPUS_COUNT}" ]] \
        && ok "all ${CORPUS_COUNT} bundles collected, sealed and accepted by the receiver" \
        || bad "only ${SHIPPED}/${CORPUS_COUNT} bundles were accepted"
}

corpus_await_ingest() {
    local _
    INGESTED=0
    for _ in $(seq 1 60); do
        INGESTED="$(corpus_value <<'PYEOF'
from cases.models import CollectionRun
print(CollectionRun.objects.filter(investigation__incident_id__startswith=PREFIX).count())
PYEOF
)"
        [[ "${INGESTED:-0}" -ge "${CORPUS_COUNT}" ]] && break
        sleep 10
    done
    [[ "${INGESTED:-0}" -ge "${CORPUS_COUNT}" ]] \
        && ok "${CORPUS_COUNT} ${CORPUS_PREFIX} runs ingested through receiver -> puller -> ingest" \
        || bad "only ${INGESTED:-0}/${CORPUS_COUNT} ${CORPUS_PREFIX} runs arrived"

    corpus_checks <<'PYEOF'
from cases.models import CollectionRun
runs = CollectionRun.objects.filter(
    investigation__incident_id__startswith=PREFIX).select_related("host")
hosts = {r.host.hostname: r.host.machine_id for r in runs}
chk(len(hosts) == COUNT and len(set(hosts.values())) == COUNT,
    f"{len(hosts)} distinct hosts with {len(set(hosts.values()))} distinct machine ids — "
    f"no endpoint merged into another")
PYEOF
}

# Compromise is set by the investigation engine AFTER a capture's analysis flips to
# 'completed' — adjudication runs later in the same worker task — so waiting on analysis
# status alone reads compromise mid-flight. Quiesced means every capture terminal AND the
# compromised count no longer moving.
corpus_await_analysis() {
    local stable=0 prev=-1 _
    TERMINAL=0; NCOMP=0
    for _ in $(seq 1 150); do
        read -r TERMINAL NCOMP <<<"$(corpus_value <<'PYEOF'
from cases.models import MemoryCapture, CollectionRun
caps = MemoryCapture.objects.filter(run__investigation__incident_id__startswith=PREFIX)
term = sum(1 for c in caps if c.analyses.filter(status__in=("completed", "failed")).exists())
comp = CollectionRun.objects.filter(
    investigation__incident_id__startswith=PREFIX, compromised=True).count()
print(term, comp)
PYEOF
)"
        if [[ "${TERMINAL:-0}" -ge 1 && "${NCOMP:-0}" == "${prev}" ]]; then
            stable=$((stable + 1)); [[ "${stable}" -ge 2 ]] && break
        else
            stable=0
        fi
        prev="${NCOMP:-0}"; sleep 10
    done
    [[ "${TERMINAL:-0}" -ge 1 ]] \
        && ok "captures terminal and compromise settled (${TERMINAL} analyzed, ${NCOMP} compromised)" \
        || info "no capture reached a terminal state within the wait — classification may read hosts mid-flight"
}

# "Terminal" counts failed analyses, so the settle gate above is quiet when every analysis
# failed. Assert the outcome: an analysis that failed, or completed without adjudicating,
# produces the same downstream picture as a campaign with nothing to find — no verdicts, no
# compromise, no links — and the failure then reads as a correlation defect layers from its
# cause. The recorded error is printed because it names the real one.
corpus_assert_analysis_ran() {
    corpus_checks <<'PYEOF'
from cases.models import MemoryAnalysisRun
qs = MemoryAnalysisRun.objects.filter(
    capture__run__investigation__incident_id__startswith=PREFIX)
failed = [r for r in qs if r.status == "failed"]
chk(not failed,
    (f"{len(failed)}/{qs.count()} analyses FAILED: {failed[0].error or '?'}"[:400]
     if failed else f"every analysis completed ({qs.count()})"))

ran = [r for r in qs if ((r.summary or {}).get("adjudication") or {}).get("ran")]
if qs.exists() and len(ran) == qs.count():
    chk(True, f"every analysis was adjudicated by the investigation engine ({len(ran)})")
else:
    stalled = [r for r in qs if not ((r.summary or {}).get("adjudication") or {}).get("ran")]
    why = ((stalled[0].summary or {}).get("adjudication") or {}).get("reason") if stalled else None
    hosts = sorted(r.capture.run.host.hostname for r in stalled)[:6]
    chk(False, f"only {len(ran)}/{qs.count()} analyses adjudicated — {hosts} — {why or 'no reason recorded'}"[:400])
PYEOF
}

# Correlation on demand, so the assertions that follow read a run this test produced rather
# than whatever a previous one left behind.
corpus_correlate() {
    local out
    out="$(corpus_value <<'PYEOF'
from cases.models import Investigation
from correlation.engine import correlate_investigation
n = 0
for inv in Investigation.objects.filter(incident_id__startswith=PREFIX):
    correlate_investigation(inv.id, inv.name)
    n += 1
print(f"RUNS {n}")
PYEOF
)"
    [[ "${out}" == RUNS* && "${out}" != "RUNS 0" ]] \
        && ok "correlation ran for ${CORPUS_PREFIX} (${out#RUNS } investigation(s))" \
        || bad "correlation did not run for ${CORPUS_PREFIX} (${out:-no output})"
}
