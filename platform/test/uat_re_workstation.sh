#!/usr/bin/env bash
# UAT — reverse-engineering workstation containment.
#
# Carved regions are live malware opened in an interactive tool, which makes this the most
# hazardous surface in the platform. The threat direction is the opposite of the analyst
# workstation: that tier is hardened to stop evidence getting OUT, this one to stop malware
# getting ANYWHERE.
#
# Every assertion below is a boundary that MUST hold. One that starts passing traffic is a
# regression in the segmentation model, not a convenience — so failures here are failures
# of the security design, not of a test.
#
#   ./uat_re_workstation.sh --host <HOST>      # a host with carved regions
#   ./uat_re_workstation.sh                    # discovers a host that has regions
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"

. "${HERE}/lib/report.sh"
report_begin 70 re_workstation "Reverse engineering — contained analysis of carved regions" \
    "Carved regions from a compromised host open in a disassembler that has no network namespace at all."
RUNTIME="${IR_RUNTIME:-podman}"
BE="${IR_BACKEND_CONTAINER:-ir-enclave_backend_1}"
TOOL="${IR_RE_TOOL:-binja}"
HOSTNAME_ARG=""


# Not a failure: the probe still runs against a fallback address, but a probe aimed at an address
# nothing listens on proves less, so say so rather than let it read as a clean pass.
warn() { printf '  \033[1;33mWARN\033[0m %s\n' "$*"; }
note() { printf '  \033[1;33mNOTE\033[0m %s\n' "$*"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host) HOSTNAME_ARG="$2"; shift 2 ;;
        --tool) TOOL="$2"; shift 2 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

say "0/6  Session under test"

# Discover a host that actually has carved regions, so the test runs against real malware
# rather than an empty directory that would pass every boundary trivially.
if [[ -z "${HOSTNAME_ARG}" ]]; then
    HOSTNAME_ARG=$(${RUNTIME} exec -w /app -e PYTHONPATH=/app "${BE}" python -c "
import os, django
os.environ.setdefault('DJANGO_SETTINGS_MODULE','ir_platform.settings'); django.setup()
from cases.models import Host
from cases import storage
for h in Host.objects.all():
    if storage.list_carved_regions(h.hostname):
        print(h.hostname); break
" 2>/dev/null | tail -1)
fi
# A pristine stack has no carved regions, so the suite seeds its own through the same
# command replay uses. The boundary under test is the session's, not the regions' origin.
if [[ -z "${HOSTNAME_ARG}" ]]; then
    SEED_HOST="uat-re-seed"
    ${RUNTIME} exec -w /app "${BE}" sh -c "
python manage.py shell -c \"
from cases.models import Host
Host.objects.get_or_create(hostname='${SEED_HOST}',
                           defaults={'machine_id': 'uat-re-seed-machine', 'platform': 'linux'})\"
mkdir -p /tmp/uat-re-seed
head -c 65536 /dev/urandom > /tmp/uat-re-seed/region_0x400000.bin
head -c 32768 /dev/urandom > /tmp/uat-re-seed/region_0x7f0000.bin
python manage.py seed_carved_regions --host '${SEED_HOST}' --source /tmp/uat-re-seed
rm -rf /tmp/uat-re-seed" >/dev/null 2>&1 \
        && HOSTNAME_ARG="${SEED_HOST}"
fi
[[ -n "${HOSTNAME_ARG}" ]] || { echo "no carved regions and seeding failed — cannot exercise the RE boundary" >&2; exit 2; }
ok "host: ${HOSTNAME_ARG}"

case "${TOOL}" in
    binja)
        IMAGE="${IR_RE_IMAGE:-ir-re-workstation:latest}"
        DOCKERFILE="Dockerfile"
        TOOL_NAME="Binary Ninja"
        TOOL_BIN="/binja/binaryninja"
        TOOL_HOME="/home/binja" ;;
    ghidra)
        IMAGE="${IR_RE_GHIDRA_IMAGE:-ir-re-ghidra:latest}"
        DOCKERFILE="Dockerfile.ghidra"
        TOOL_NAME="Ghidra"
        TOOL_BIN="/ghidra/ghidraRun"
        TOOL_HOME="/home/ghidra" ;;
    *) echo "unknown tool: ${TOOL} (expected binja or ghidra)" >&2; exit 2 ;;
esac

SESSION="/tmp/uat-re-${HOSTNAME_ARG}"
rm -rf "${SESSION}"

${RUNTIME} image exists "${IMAGE}" 2>/dev/null || {
    note "building ${IMAGE} (network is used at BUILD time only)"
    ${RUNTIME} build -t "${IMAGE}" "${PLATFORM}/re-workstation" >/dev/null 2>&1 \
        || { echo "RE image failed to build" >&2; exit 1; }
}

say "1/6  Regions staged by the mediator, not fetched by the session"
if "${PLATFORM}/re-workstation/stage_regions.sh" --host "${HOSTNAME_ARG}" --out "${SESSION}" >/dev/null 2>&1; then
    COUNT=$(find "${SESSION}" -name '*.bin' 2>/dev/null | wc -l)
    [[ "${COUNT}" -gt 0 ]] && ok "${COUNT} region(s) staged" || bad "mediator staged nothing"
else
    bad "mediator failed to stage regions"
fi

# One host per session: a session must never hold two investigations' malware.
STAGED_HOST=$(cat "${SESSION}/.host" 2>/dev/null)
[[ "${STAGED_HOST}" == "${HOSTNAME_ARG}" ]] \
    && ok "session is scoped to exactly one host (${STAGED_HOST})" \
    || bad "session host marker is wrong: ${STAGED_HOST:-none}"

OTHER=$(${RUNTIME} exec -w /app -e PYTHONPATH=/app "${BE}" python -c "
import os, django
os.environ.setdefault('DJANGO_SETTINGS_MODULE','ir_platform.settings'); django.setup()
from cases.models import Host
print(next((h.hostname for h in Host.objects.all() if h.hostname != '${HOSTNAME_ARG}'), ''))
" 2>/dev/null | tail -1)
if [[ -n "${OTHER}" ]]; then
    if "${PLATFORM}/re-workstation/stage_regions.sh" --host "${OTHER}" --out "${SESSION}" >/dev/null 2>&1; then
        bad "mediator mixed a second host (${OTHER}) into one session"
    else
        ok "mediator refuses to mix a second host into the same session"
    fi
fi

# The session runs the same way launch.sh runs it, minus the GUI. Assertions below count matches
# with `grep -c` rather than testing `grep -q`.
SETTINGS_MOUNT=""
[[ "${TOOL}" == "binja" ]] && SETTINGS_MOUNT="-v ${PLATFORM}/re-workstation/binja-settings.json:/home/binja/.binaryninja/settings.json:ro,z"
re_run() { ${RUNTIME} run --rm --network none --cap-drop ALL \
    --security-opt no-new-privileges \
    -v "${SESSION}:/regions:ro,z" \
    ${SETTINGS_MOUNT} \
    --entrypoint sh "${IMAGE}" -c "$1" 2>&1; }

say "2/6  The session has no network at all"
# Addressed by IP, not by name, and deliberately so. The session runs with no network at all, so
# a hostname would fail to RESOLVE and the connection would fail for that reason — the test
# would pass identically against a fully reachable enclave.
addr_of() {  # addr_of <container> <network>
    ${RUNTIME} inspect "$1" \
        --format "{{(index .NetworkSettings.Networks \"$2\").IPAddress}}" 2>/dev/null | tr -d '[:space:]'
}
MINIO_ADDR="$(addr_of ir-enclave_minio_1 ir-enclave_internal)"
RECV_ADDR="$(addr_of ir-dmz_receiver_1 ir-dmzlink)"
[[ -n "${MINIO_ADDR}" ]] || warn "object store address unknown — bring the enclave up for a meaningful probe"
[[ -n "${RECV_ADDR}"  ]] || warn "receiver address unknown — bring the DMZ up for a meaningful probe"
for probe in \
    "1.1.1.1:53|the internet" \
    "${MINIO_ADDR:-10.89.1.3}:9000|the enclave object store" \
    "${RECV_ADDR:-10.89.0.3}:8090|the DMZ receiver"
do
    target="${probe%%|*}"; desc="${probe##*|}"
    host="${target%%:*}"; port="${target##*:}"
    if [[ $(re_run "timeout 4 python3 -c \"import socket;socket.create_connection(('${host}',${port}),timeout=3)\"" \
        | grep -ciE "refused|unreachable|timed out|failure|error|Traceback") -gt 0 ]]; then
        ok "cannot reach ${desc}"
    else
        bad "REACHED ${desc} — the session is not contained"
    fi
done

if [[ $(re_run 'python3 -c "import socket;print(socket.gethostbyname(\"minio\"))"' \
    | grep -ciE "error|failure|Traceback") -gt 0 ]]; then
    ok "cannot resolve internal names (no DNS)"
else
    bad "resolved an internal name — the session has a resolver"
fi

say "3/6  Regions are readable but never writable"
if [[ $(re_run 'ls /regions/*.bin >/dev/null 2>&1 && echo READABLE' | grep -cE READABLE) -gt 0 ]]; then
    ok "carved regions are readable"
else
    bad "regions are not readable — the session cannot do its job"
fi
if [[ $(re_run 'touch /regions/_tamper 2>&1' | grep -ciE "read-only|permission denied") -gt 0 ]]; then
    ok "regions are read-only (analysis cannot alter evidence)"
else
    bad "the session could write into the region mount"
fi
if [[ $(re_run 'rm -f /regions/*.bin 2>&1' | grep -ciE "read-only|permission denied") -gt 0 ]]; then
    ok "regions cannot be deleted from the session"
else
    bad "the session could delete regions"
fi

if [[ "${TOOL}" != "binja" ]]; then
    note "no pinned preferences file for ${TOOL_NAME} — nothing to assert here"
elif [[ $(re_run 'touch /home/binja/.binaryninja/settings.json 2>&1' \
    | grep -ciE "read-only|permission denied") -gt 0 ]]; then
    ok "the session cannot rewrite its own security settings"
else
    bad "the session could edit settings.json — a sample could re-enable update checks"
fi

say "4/6  The session holds no credentials"
LEAKS=$(re_run 'env | grep -iE "secret|password|token|access_key|aws_" | head -5')
if [[ -z "${LEAKS}" ]]; then
    ok "no credentials in the session environment"
else
    bad "credentials present in the environment: $(printf '%s' "${LEAKS}" | head -1 | cut -d= -f1)"
fi
if [[ $(re_run "test -f /root/.aws/credentials -o -f ${TOOL_HOME}/.aws/credentials && echo FOUND" | grep -cE FOUND) -gt 0 ]]; then
    bad "object-store credentials are present on disk"
else
    ok "no object-store credentials on disk"
fi

say "5/6  The session runs without privilege"
CAPS=$(re_run 'grep CapEff /proc/self/status | awk "{print \$2}"')
if [[ "${CAPS}" =~ ^0+$ ]]; then
    ok "all capabilities dropped (CapEff=${CAPS})"
else
    bad "capabilities retained: ${CAPS}"
fi
if [[ $(re_run 'grep NoNewPrivs /proc/self/status' | grep -cE "NoNewPrivs:.*1") -gt 0 ]]; then
    ok "no-new-privileges is set"
else
    bad "no-new-privileges is not set"
fi

say "6/6  ${TOOL_NAME} is present and needs no network"
if [[ $(re_run "test -x ${TOOL_BIN} && echo PRESENT" | grep -cE PRESENT) -gt 0 ]]; then
    ok "${TOOL_NAME} launcher present in the image"
else
    bad "${TOOL_NAME} is missing from the image (expected ${TOOL_BIN})"
fi
if [[ "${TOOL}" == "binja" ]]; then
    if [[ $(re_run 'test -f /home/binja/.binaryninja/settings.json && grep -q "updates.activeContent" /home/binja/.binaryninja/settings.json && echo PINNED' | grep -cE PINNED) -gt 0 ]]; then
        ok "update checks pinned off (defense in depth — the session has no route anyway)"
    else
        note "update settings not pinned; harmless while the session has no network"
    fi
else
    # A headless JDK cannot open a GUI at any display setting and reports itself as running in a
    # "headless environment", which reads as a broken X socket and sends you to the host.
    if [[ $(re_run 'ls "${JAVA_HOME}/lib/libawt_xawt.so" >/dev/null 2>&1 && echo GUI' | grep -cE GUI) -gt 0 ]]; then
        ok "JDK can open a GUI (not the headless package)"
    else
        bad "image has a HEADLESS JDK — ${TOOL_NAME}'s GUI cannot start"
    fi
fi

say "Worksets — which regions a session is for"
# The unit a session is granted. A host's whole carved bucket is the wrong one: parallel
# analysis carves faster than anyone examines, and a disassembler opened on hundreds of
# regions is a crash rather than a workflow.

api() {  # api <METHOD> <path> [json]
    ${RUNTIME} exec -i -w /app "${BE}" python - "$1" "$2" "${3:-}" <<'API' 2>/dev/null
import json, os, sys, urllib.error, urllib.request
import django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ir_platform.settings")
django.setup()
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token

method, path, body = sys.argv[1], sys.argv[2], sys.argv[3]
tok = Token.objects.get_or_create(user=User.objects.filter(is_superuser=True).first())[0].key
req = urllib.request.Request("http://127.0.0.1:8000/api" + path, method=method,
                             data=body.encode() if body else None,
                             headers={"Authorization": "Token " + tok,
                                      "Content-Type": "application/json"})
try:
    resp = urllib.request.urlopen(req, timeout=60)
    print(resp.getcode(), resp.read().decode().replace(chr(10), " "))
except urllib.error.HTTPError as e:
    print(e.code, e.read().decode().replace(chr(10), " ")[:2000])
except Exception as e:                                        # noqa: BLE001
    print(0, e)
API
}
rj() { python3 -c "import json,sys;d=json.loads(sys.argv[1].split(' ',1)[1]);print($2)" "$1" 2>/dev/null; }

PROP="$(api GET "/worksets/propose/?host=${HOSTNAME_ARG}&limit=4")"
PROP_CODE="${PROP%% *}"
PROP_INV="$(rj "${PROP}" "d['investigation']")"
PROP_N="$(rj "${PROP}" "len(d['proposed'])")"
PROP_WHY="$(rj "${PROP}" "sum(1 for p in d['proposed'] if p['why'])")"
if [[ "${PROP_CODE}" == "200" && "${PROP_N:-0}" -gt 0 ]]; then
    ok "the platform proposes a ranked shortlist for ${HOSTNAME_ARG} (${PROP_N} of $(rj "${PROP}" "d['considered']") considered, case ${PROP_INV})"
else
    bad "no proposal for ${HOSTNAME_ARG} — ${PROP:0:160}"
fi
# Ranking that cannot say why is a number nobody can question.
[[ "${PROP_WHY:-0}" == "${PROP_N:-0}" && "${PROP_N:-0}" -gt 0 ]] \
    && ok "every proposed region carries the reasons it ranked (${PROP_WHY}/${PROP_N})" \
    || bad "${PROP_WHY:-0} of ${PROP_N:-0} proposed regions explain their rank"

# A hostname outlives an incident. A proposal spanning two cases is one a workset can never
# accept, so it names one and lists the rest instead of folding them together.
PROP_ONE="$(rj "${PROP}" "len({p['region']['investigation_id'] for p in d['proposed']})")"
[[ "${PROP_ONE:-0}" == "1" ]] \
    && ok "the proposal is ONE case ($(rj "${PROP}" "d['investigation']")), with $(rj "${PROP}" "len(d['other_investigations'])") other(s) named rather than mixed in" \
    || bad "the proposal spans ${PROP_ONE:-?} investigations — a workset would refuse it"

IDS="$(rj "${PROP}" "json.dumps([p['region']['id'] for p in d['proposed']])")"
WS_CREATE="$(api POST "/worksets/" "{\"region_ids\": ${IDS}, \"note\": \"uat\"}")"
WS_SLUG="$(rj "${WS_CREATE}" "d.get('slug','')")"
WS_N="$(rj "${WS_CREATE}" "d.get('region_count',0)")"
if [[ "${WS_CREATE%% *}" == "201" && -n "${WS_SLUG}" ]]; then
    ok "workset ${WS_SLUG} assembled — ${WS_N} region(s), named and bounded"
else
    bad "the workset was refused: ${WS_CREATE:0:200}"
fi

OVER="$(api POST "/worksets/" "{\"region_ids\": $(python3 -c 'import json;print(json.dumps(list(range(1,60))))')}")"
[[ "${OVER%% *}" == "400" ]] \
    && ok "a workset beyond the cap is refused — the bound is the feature, not a limit to raise" \
    || bad "a 59-region workset was accepted (${OVER%% *}) — nothing stops a session being flooded"

# The wall: one investigation per session. Assembled from two, it must refuse.
MIXED="$(${RUNTIME} exec -i "${BE}" python manage.py shell -c "
import json
from cases.models import CarvedRegion
seen, out = {}, []
for r in CarvedRegion.objects.select_related('analysis__capture__run').all()[:400]:
    inv = r.analysis.capture.run.investigation_id
    if inv not in seen:
        seen[inv] = r.id
print(json.dumps(sorted(seen.values())[:2]))" 2>/dev/null | tail -1)"
if [[ "$(python3 -c "import json,sys;print(len(json.loads(sys.argv[1])))" "${MIXED}" 2>/dev/null)" == "2" ]]; then
    CROSS="$(api POST "/worksets/" "{\"region_ids\": ${MIXED}}")"
    [[ "${CROSS%% *}" == "400" ]] \
        && ok "regions from two investigations are refused — a session sees one case's malware, ever" \
        || bad "a workset spanning two investigations was accepted (${CROSS%% *})"
else
    info "only one investigation holds carved regions here — the cross-case refusal is unmeasured"
fi

MINT="$(api POST "/worksets/${WS_SLUG}/stage-command/" '{"tool": "binja"}')"
MINT_STEPS="$(rj "${MINT}" "len(d.get('steps',[]))")"
MINT_KIT="$(rj "${MINT}" "d.get('kit','')")"
[[ "${MINT%% *}" == "200" && "${MINT_STEPS:-0}" -ge 2 && -n "${MINT_KIT}" ]] \
    && ok "the platform mints a procedure (${MINT_STEPS} steps) and a kit to run it — it never reaches into the workstation itself" \
    || bad "no runnable session was minted: ${MINT:0:200}"

AUDITED="$(${RUNTIME} exec -i "${BE}" python manage.py shell -c "
from cases.models import AuditLog
print(AuditLog.objects.filter(action='workset.stage-command', object_id='${WS_SLUG}').count())" 2>/dev/null | tail -1)"
[[ "${AUDITED:-0}" -ge 1 ]] \
    && ok "minting is audited — the platform records that a session was intended, though it runs beyond its sight" \
    || bad "minting a stage command left no audit record"

# Staging: exactly this workset's regions, and one file per region. A short count is the
# collision that flattening object keys used to cause, silently.
WS_DIR="/tmp/uat-ws-${WS_SLUG}"
rm -rf "${WS_DIR}"
"${PLATFORM}/re-workstation/stage_regions.sh" --workset "${WS_SLUG}" --out "${WS_DIR}" >/dev/null 2>&1
STAGED="$(find "${WS_DIR}" -maxdepth 1 -name '*.bin' 2>/dev/null | wc -l)"
[[ "${STAGED}" == "${WS_N}" && "${STAGED}" -gt 0 ]] \
    && ok "staging pulled exactly the workset's ${STAGED} region(s) — one file each, none collapsed onto another" \
    || bad "staged ${STAGED} file(s) for a ${WS_N}-region workset"

# Staging is the session starting, and the platform has to learn that. Left unreported, a
# workset stays "assembled" forever and nothing can say which sessions are open.
WS_STATE="$(${RUNTIME} exec -i "${BE}" python manage.py shell -c "
from cases.models import ReWorkset
w = ReWorkset.objects.filter(slug='${WS_SLUG}').first()
print((w.state if w else 'gone'), ('at' if w and w.staged_at else 'no-time'))" 2>/dev/null | tail -1)"
read -r WS_STATE_V WS_STATE_T <<<"${WS_STATE}"
[[ "${WS_STATE_V}" == "staged" && "${WS_STATE_T}" == "at" ]] \
    && ok "the workset reports itself STAGED once the mediator pulled it — an open session is visible to the platform" \
    || bad "after staging the workset reads '${WS_STATE_V:-no answer}' (${WS_STATE_T:-}) — the platform cannot see that a session started"

BUCKET_TOTAL="$(${RUNTIME} exec -i "${BE}" python manage.py shell -c "
from cases import storage
print(len(storage.list_carved_regions('${HOSTNAME_ARG}')))" 2>/dev/null | tail -1)"
if [[ "${BUCKET_TOTAL:-0}" -gt "${STAGED:-0}" ]]; then
    ok "the session holds ${STAGED} of the host's ${BUCKET_TOTAL} carved regions — the curated set, not the bucket"
else
    info "this host's bucket holds ${BUCKET_TOTAL:-?} region(s); the curation is not visible at that size"
fi
MANIFEST_WS="$(python3 -c "import json;print(json.load(open('${WS_DIR}/_regions.json')).get('workset',''))" 2>/dev/null)"
[[ "${MANIFEST_WS}" == "${WS_SLUG}" ]] \
    && ok "the staged manifest names the workset it came from — provenance without a path back to the store" \
    || bad "the manifest does not name its workset (${MANIFEST_WS:-none})"

# A determination made during a session belongs to that session, and has to reach the
# record — RE work that stays in the RE tool never becomes part of the investigation.
# Recorded through the API the reverse engineer actually uses, so the PLATFORM decides which
# session it belongs to. Computing that here would only prove the test agrees with itself.
DET_REGION="$(${RUNTIME} exec -i "${BE}" python manage.py shell -c "
from django.utils import timezone
from cases.models import ReWorkset
ws = ReWorkset.objects.get(slug='${WS_SLUG}')
ws.state, ws.staged_at = ReWorkset.STAGED, timezone.now()
ws.save(update_fields=['state', 'staged_at', 'updated_at'])
print(ws.members.select_related('region').first().region_id)" 2>/dev/null | tail -1)"
DET_POST="$(api POST "/regions/${DET_REGION}/analyze/" '{"verdict": "inconclusive", "confidence": "low", "statement": "uat: recorded during a staged session to prove the determination reaches the case record", "notes": "uat"}')"
# The response is asserted too: the row is written before it is serialized, so a broken
# response leaves a determination in the database and a 500 in the analyst's face.
[[ "${DET_POST%% *}" == "201" ]] \
    && ok "recording a determination answers 201 — the write and the reply both succeed" \
    || bad "recording a determination answered ${DET_POST%% *} — the row may exist but the analyst saw an error: ${DET_POST:0:160}"
DET="$(${RUNTIME} exec -i "${BE}" python manage.py shell -c "
import json
from cases import record
from cases.models import RegionAnalysis, ReWorkset
det = RegionAnalysis.objects.filter(region_id=${DET_REGION}).order_by('-id').first()
ws = ReWorkset.objects.get(slug='${WS_SLUG}')
entries = record.case_record(ws.investigation)
reached = sum(1 for e in entries if e.get('type') == 'region_analysis'
              and str(e.get('id')) == str(det.id))
print(json.dumps({'workset': det.workset.slug if det and det.workset else '',
                  'in_record': reached}))
RegionAnalysis.objects.filter(id=det.id).delete()" 2>/dev/null | tail -1)"
DET_WS="$(rj "0 ${DET}" "d.get('workset','')")"
DET_REC="$(rj "0 ${DET}" "d.get('in_record',0)")"
[[ "${DET_WS}" == "${WS_SLUG}" ]] \
    && ok "a determination recorded during the session names it (${DET_WS}) — the platform can say what came out of a session, not only what is known about a region" \
    || bad "the determination did not name its session (${DET_WS:-none}) — results are not attributable to a workset"
[[ "${DET_REC:-0}" -ge 1 ]] \
    && ok "that determination is in the investigation record — reverse-engineering work reaches the case, not a silo" \
    || bad "the determination never reached the investigation record"

# Two sessions at once: separate directories, neither touching the other.
WS2="$(api POST "/worksets/" "{\"region_ids\": ${IDS}}")"
WS2_SLUG="$(rj "${WS2}" "d.get('slug','')")"
WS2_DIR="/tmp/uat-ws2-${WS2_SLUG}"
rm -rf "${WS2_DIR}"
"${PLATFORM}/re-workstation/stage_regions.sh" --workset "${WS2_SLUG}" --out "${WS2_DIR}" >/dev/null 2>&1
STAGED2="$(find "${WS2_DIR}" -maxdepth 1 -name '*.bin' 2>/dev/null | wc -l)"
STILL="$(find "${WS_DIR}" -maxdepth 1 -name '*.bin' 2>/dev/null | wc -l)"
[[ -n "${WS2_SLUG}" && "${STAGED2}" == "${STAGED}" && "${STILL}" == "${STAGED}" ]] \
    && ok "a second workset of the same host stages concurrently (${WS2_SLUG}) without disturbing the first" \
    || bad "concurrent worksets interfered: second staged ${STAGED2}, first now holds ${STILL}"

# The same region in two worksets is a reference, never a copy.
SHARED="$(${RUNTIME} exec -i "${BE}" python manage.py shell -c "
from cases.models import ReWorksetRegion
a = set(ReWorksetRegion.objects.filter(workset__slug='${WS_SLUG}').values_list('region_id', flat=True))
b = set(ReWorksetRegion.objects.filter(workset__slug='${WS2_SLUG}').values_list('region_id', flat=True))
print(len(a & b), len(a), len(b))" 2>/dev/null | tail -1)"
read -r SH_BOTH SH_A SH_B <<<"${SHARED}"
[[ "${SH_BOTH:-0}" -gt 0 && "${SH_A:-0}" == "${SH_B:-0}" ]] \
    && ok "a region belongs to both worksets by reference (${SH_BOTH} shared) — the platform can say which sessions examined it" \
    || bad "the two worksets share no region (${SHARED:-no answer}) — membership was copied, not referenced"

# The compartment reaches the bytes, not only the findings. Memory findings from a capture
# were scoped while the regions carved out of that same capture were not, so a restricted
# case's malware was listable by anyone holding the RE role. Asserted both ways in one run:
# a count of zero proves nothing unless the same query returns rows for someone entitled.
LEAK="$(${RUNTIME} exec -i "${BE}" python manage.py shell -c "
import json
from django.contrib.auth.models import Group, User
from rest_framework.authtoken.models import Token
from cases.models import CarvedRegion, Investigation
from cases.rbac import scope_by_investigation

PATH = 'analysis__capture__run__investigation_id'
inv_id = ${PROP_INV:-0}
inv = Investigation.objects.filter(id=inv_id).first()
if not inv:
    print(json.dumps({'error': 'no investigation'}))
else:
    was = inv.compartment
    inv.compartment = Investigation.RESTRICTED
    inv.save(update_fields=['compartment'])
    outsider, _ = User.objects.get_or_create(username='uat-re-outsider')
    grp, _ = Group.objects.get_or_create(name='reverse_engineer')
    outsider.groups.add(grp)
    admin = User.objects.filter(is_superuser=True).first()
    base = CarvedRegion.objects.filter(**{PATH: inv_id})
    out = {
        'total': base.count(),
        'outsider': scope_by_investigation(base, outsider, PATH).count(),
        'admin': scope_by_investigation(base, admin, PATH).count(),
    }
    inv.compartment = was
    inv.save(update_fields=['compartment'])
    User.objects.filter(username='uat-re-outsider').delete()
    print(json.dumps(out))" 2>/dev/null | tail -1)"
LEAK_TOTAL="$(rj "0 ${LEAK}" "d.get('total',-1)")"
LEAK_OUT="$(rj "0 ${LEAK}" "d.get('outsider',-1)")"
LEAK_ADMIN="$(rj "0 ${LEAK}" "d.get('admin',-1)")"
if [[ "${LEAK_TOTAL:-0}" -gt 0 && "${LEAK_OUT}" == "0" && "${LEAK_ADMIN}" == "${LEAK_TOTAL}" ]]; then
    ok "a restricted case's carved regions are invisible to a non-member (0 of ${LEAK_TOTAL}) and whole to someone entitled (${LEAK_ADMIN}) — the compartment reaches the bytes"
elif [[ "${LEAK_TOTAL:-0}" -le 0 ]]; then
    bad "the compartment check is unmeasured — that case holds no carved regions to hide"
else
    bad "carved regions leak past the compartment: non-member sees ${LEAK_OUT} of ${LEAK_TOTAL} (entitled sees ${LEAK_ADMIN})"
fi

say "The session kit, end to end — download it, run it, and the malware is gone afterwards"
# The whole path an analyst takes, exercised as they would: fetch the archive the UI hands
# over, unpack it, run its script. Asserted on the ARTIFACT rather than on the API that
# produced it — a kit that cannot be run is not a handover.
KIT_DIR="$(mktemp -d)"
KIT_HTTP="$(${RUNTIME} exec -i "${BE}" sh -c "
python - <<'KIT' > /tmp/uat-kit.tar.gz 2>/tmp/uat-kit.err; echo \$?
import os, sys, urllib.request
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ir_platform.settings')
django.setup()
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
tok = Token.objects.get_or_create(user=User.objects.filter(is_superuser=True).first())[0].key
req = urllib.request.Request('http://127.0.0.1:8000/api/worksets/${WS_SLUG}/kit/?tool=binja',
                             headers={'Authorization': 'Token ' + tok})
sys.stdout.buffer.write(urllib.request.urlopen(req, timeout=60).read())
KIT
" 2>/dev/null | tail -1)"
${RUNTIME} cp "${BE}:/tmp/uat-kit.tar.gz" "${KIT_DIR}/kit.tar.gz" 2>/dev/null
KIT_BYTES="$(stat -c %s "${KIT_DIR}/kit.tar.gz" 2>/dev/null || echo 0)"
[[ "${KIT_HTTP}" == "0" && "${KIT_BYTES}" -gt 500 ]] \
    && ok "the UI hands over a session kit (${KIT_BYTES} bytes)" \
    || { bad "no session kit could be downloaded (rc=${KIT_HTTP}, ${KIT_BYTES} bytes)"; }

tar -xzf "${KIT_DIR}/kit.tar.gz" -C "${KIT_DIR}" 2>/dev/null
KIT_ROOT="${KIT_DIR}/re-session-${WS_SLUG}"
MISSING=""
for f in run.sh stage_regions.sh launch.sh README.txt; do
    [[ -f "${KIT_ROOT}/${f}" ]] || MISSING="${MISSING} ${f}"
done
[[ -z "${MISSING}" && -x "${KIT_ROOT}/run.sh" ]] \
    && ok "the kit is self-contained and runnable — run.sh, the mediator, the launcher and a README" \
    || bad "the kit is incomplete:${MISSING:-（run.sh not executable）}"

# The reason it can cross a browser at all: it carries no evidence.
CARRIED="$(find "${KIT_ROOT}" -name '*.bin' 2>/dev/null | wc -l)"
[[ "${CARRIED}" -eq 0 ]] \
    && ok "no carved region travels in the kit — malware reaches the workstation through the mediator, never through a browser" \
    || bad "${CARRIED} carved region(s) are inside the kit — evidence crossed the browser"

KIT_WHO="$(grep -c "For     : " "${KIT_ROOT}/README.txt" 2>/dev/null)"
[[ "${KIT_WHO}" -ge 1 ]] \
    && ok "the kit names who it was issued to — found later, it says whose session it was for" \
    || bad "the kit does not name its requester"

# Run it as the analyst would, then cut the session short. run.sh ends by opening the
# disassembler and waiting, so a bounded run is the session being interrupted — which is the
# case the wipe has to survive, not the tidy one.
# --stage-only, because run.sh otherwise ends in `podman run` and waits for a person to
# close the disassembler. Run in full here it blocked the suite for hours with no failure
# and no report. Kept once to prove staging, then run again to prove the wipe.
( cd "${KIT_ROOT}" && IR_KEEP_SESSION=1 timeout 300 ./run.sh --stage-only \
    </dev/null >"${KIT_DIR}/run.out" 2>&1 ) || true
RUN_RC=$?
STAGED_IN_RUN="$(grep -c "region(s) staged" "${KIT_DIR}/run.out" 2>/dev/null)"
[[ "${STAGED_IN_RUN}" -ge 1 ]] \
    && ok "run.sh staged this workset's regions on its own — one command, no lookups" \
    || bad "run.sh did not stage anything (rc=${RUN_RC}): $(tail -3 "${KIT_DIR}/run.out" 2>/dev/null | tr '\n' ' ')"

STAGED_KEPT="$(find "${KIT_ROOT}" -maxdepth 2 -name '*.bin' 2>/dev/null | wc -l)"
[[ "${STAGED_KEPT}" -gt 0 ]] \
    && ok "IR_KEEP_SESSION=1 keeps the staged regions (${STAGED_KEPT}) — deliberate, and the only way they persist" \
    || bad "the kit staged nothing to keep"
( cd "${KIT_ROOT}" && timeout 300 ./run.sh --stage-only </dev/null >>"${KIT_DIR}/run.out" 2>&1 ) || true
WIPED="$(find "${KIT_ROOT}" -maxdepth 2 -name '*.bin' 2>/dev/null | wc -l)"
[[ "${WIPED}" -eq 0 ]] \
    && ok "the staged malware is gone when the session ends — nothing accumulates on the host" \
    || bad "${WIPED} staged region(s) survived the session — unencrypted malware left on disk"

# Integrity: bytes that do not match what was carved must stop the session, not reach a tool.
TAMPER="$(${RUNTIME} exec -i "${BE}" python manage.py shell -c "
from cases.models import ReWorkset
ws = ReWorkset.objects.get(slug='${WS_SLUG}')
m = ws.members.select_related('region').first()
was = m.region.sha256
m.region.sha256 = '0' * 64
m.region.save(update_fields=['sha256'])
print(was)" 2>/dev/null | tail -1)"
( cd "${KIT_ROOT}" && timeout 300 ./stage_regions.sh --workset "${WS_SLUG}" \
    --out "./verify-${WS_SLUG}" >"${KIT_DIR}/tamper.out" 2>&1 )
REFUSED="$(grep -c "REFUSED" "${KIT_DIR}/tamper.out" 2>/dev/null)"
${RUNTIME} exec -i "${BE}" python manage.py shell -c "
from cases.models import ReWorkset
ws = ReWorkset.objects.get(slug='${WS_SLUG}')
m = ws.members.select_related('region').first()
m.region.sha256 = '${TAMPER}'
m.region.save(update_fields=['sha256'])" >/dev/null 2>&1
[[ "${REFUSED}" -ge 1 ]] \
    && ok "staging REFUSES bytes that do not match the hash recorded at carve time — a hash never checked is not integrity" \
    || bad "staging accepted bytes whose hash did not match what was carved"

rm -rf "${KIT_DIR}"

rm -rf "${WS_DIR}" "${WS2_DIR}"
${RUNTIME} exec -i "${BE}" python manage.py shell -c "
from cases.models import ReWorkset
ReWorkset.objects.filter(slug__in=['${WS_SLUG}', '${WS2_SLUG}']).delete()" >/dev/null 2>&1

rm -rf "${SESSION}"

echo
if [[ "${FAILED}" -eq 0 ]]; then
    printf '\033[1;32m  RE WORKSTATION CONTAINMENT HOLDS\033[0m\n'
    printf '  Malware is analyzed with no network, no credentials, and no writable evidence.\n'
else
    printf '\033[1;31m  RE WORKSTATION CONTAINMENT FAILED\033[0m — a boundary opened up (see above)\n'
fi
report_finish
exit "${FAILED}"
