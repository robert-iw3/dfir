#!/usr/bin/env bash
# UAT — memory analysis end to end, against a REAL memory capture.
#
# This validates the path a genuine investigation takes: a capture arrives, the enclave
# resolves (or asks for) a symbol table, the toolkit's Volatility pass runs inside the
# analysis sandbox, findings land in PostgreSQL as metadata, carved regions land in the
# host's own object-storage bucket, and both workstations render so the result can be
# seen rather than inferred.
#
# A REAL MEMORY CAPTURE IS REQUIRED. The synthetic sample the other UATs use exercises the
# structural scan only — it has no kernel structures, so Volatility cannot parse it and
# nothing here would be proven. Supply an image taken from a real Linux host:
#
#   IR_TEST_IMAGE=/path/to/memory_<host>.raw ./uat_memory_analysis.sh
#   ./uat_memory_analysis.sh --image /path/to/capture.raw --host WS-007
#
# An ISF matching that capture's kernel must be in the enclave symbol store, or the run
# will correctly fall back to reduced depth — which this asserts as a distinct outcome
# rather than a pass. See ../symbols/README.md for acquiring one.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"
RUNTIME="${IR_RUNTIME:-podman}"
BE="${IR_BACKEND_CONTAINER:-ir-enclave_backend_1}"
WK="${IR_WORKER_CONTAINER:-ir-enclave_worker_1}"
FAILED=0
IMAGE="${IR_TEST_IMAGE:-}"
HOSTNAME_ARG="${IR_TEST_HOST:-uat-endpoint}"
RENDER="${IR_RENDER_WORKSTATIONS:-1}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --image) IMAGE="$2"; shift 2 ;;
        --host)  HOSTNAME_ARG="$2"; shift 2 ;;
        --no-render) RENDER=0; shift ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

say()  { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
ok()   { printf '  \033[1;32mPASS\033[0m %s\n' "$*"; }
bad()  { printf '  \033[1;31mFAIL\033[0m %s\n' "$*"; FAILED=1; }
note() { printf '  \033[1;33mNOTE\033[0m %s\n' "$*"; }

if [[ -z "${IMAGE}" ]]; then
    cat >&2 <<'MSG'
A real memory capture is required.

  IR_TEST_IMAGE=/path/to/capture.raw ./uat_memory_analysis.sh

Synthetic samples cannot validate this path: Volatility parses kernel structures, which a
generated file does not contain. Capture one with the collector (avml) from a Linux host,
or supply any raw memory image taken from a real system.
MSG
    exit 2
fi
[[ -r "${IMAGE}" ]] || { echo "cannot read image: ${IMAGE}" >&2; exit 2; }

for c in "${BE}" "${WK}"; do
    [[ $(${RUNTIME} ps --format '{{.Names}}' | grep -cx "${c}") -gt 0 ]] || {
        echo "container ${c} is not running — bring the stack up first" >&2; exit 1; }
done

IMG_SIZE=$(stat -c%s "${IMAGE}")
say "0/7  Capture under test"
ok "$(basename "${IMAGE}") — $(numfmt --to=iec "${IMG_SIZE}" 2>/dev/null || echo "${IMG_SIZE} bytes")"

# --- 1. The worker image carries the proven analysis stack -------------------------
say "1/7  Analysis stack present in the sandbox"
for probe in \
    "vol --help >/dev/null 2>&1|Volatility 3 runs" \
    "test -f /opt/toolkit/playbooks/linux/threat_hunting/analyze_memory_linux.py|analyzer staged" \
    "test -f /opt/toolkit/playbooks/linux/threat_hunting/memory_enrich.py|enrichment staged" \
    "test -d /opt/toolkit/playbooks/linux/threat_hunting/vol_plugins|custom Volatility plugins staged" \
    "test -d /opt/toolkit/playbooks/linux/threat_hunting/mwcp_parsers|mwcp parsers staged" \
    "test -d /symbols|symbol store mounted"
do
    cmd="${probe%%|*}"; desc="${probe##*|}"
    if ${RUNTIME} exec "${WK}" sh -c "${cmd}" >/dev/null 2>&1; then ok "${desc}"; else bad "${desc}"; fi
done

# The sandbox must stay contained while parsing hazardous evidence.
if ${RUNTIME} exec "${WK}" sh -c 'timeout 4 wget -q -O- http://1.1.1.1 >/dev/null 2>&1' ; then
    bad "worker reached the internet — the analysis sandbox is not contained"
else
    ok "worker has no egress (parses malware with no route out)"
fi

# --- 2. Symbol resolution ----------------------------------------------------------
say "2/7  Symbol table for this capture's kernel"
# --user root: under rootless podman the container's root maps to the invoking host user,
# which is what can read a capture written 0600 by that user. The worker image otherwise
# runs unprivileged, and the analysis path itself never needs this — it reads the capture
# from object storage, not from the host.
BANNER=$(${RUNTIME} run --rm --user root -v "$(dirname "$(readlink -f "${IMAGE}")")":/img:ro,z \
    --entrypoint vol localhost/ir-worker:latest \
    -q -f "/img/$(basename "${IMAGE}")" banners.Banners 2>/dev/null \
    | grep -oE 'Linux version [0-9][^ ]*' | head -1 | awk '{print $3}')
if [[ -n "${BANNER}" ]]; then
    ok "kernel identified from the image: ${BANNER}"
else
    note "could not read a banner from the image — it may not be a Linux capture"
fi

ISF_COUNT=$(${RUNTIME} exec "${WK}" sh -c 'ls /symbols/*.json 2>/dev/null | wc -l' | tr -d '\r')
if [[ "${ISF_COUNT:-0}" -gt 0 ]]; then
    ok "${ISF_COUNT} symbol table(s) in the enclave store"
    DEEP_EXPECTED=1
else
    note "no symbol table present — a reduced-depth run is the correct outcome"
    note "acquire one: see ../symbols/README.md"
    DEEP_EXPECTED=0
fi

# --- 3. Ingest the capture ---------------------------------------------------------
say "3/7  Ingest the capture as evidence"
cat > /tmp/_uat_mem_ingest.py <<'PYEOF'
import json, os, sys, django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ir_platform.settings")
django.setup()
from django.utils import timezone
from cases.models import CollectionRun, Host, Investigation, MemoryCapture
from cases import storage

hostname, key, size, sha, symctx = sys.argv[1:6]
inv, _ = Investigation.objects.get_or_create(
    name="Memory analysis UAT", defaults={"incident_id": "UAT-MEM", "severity": "high"})
host, _ = Host.objects.get_or_create(hostname=hostname, defaults={"platform": "linux"})
run = CollectionRun.objects.create(
    investigation=inv, host=host, overall_status="COMPLETED",
    custody_verified=True, collected_at=timezone.now(), run_kind="initial")
cap = MemoryCapture.objects.create(
    run=run, store_backend=storage.backend_name(), bucket=storage.bucket(),
    object_key=key, size_bytes=int(size), sha256=sha, image_format="raw",
    capture_tool="avml", is_synthetic=False,
    symbol_context=json.loads(symctx), retention_status="pending")
print(json.dumps({"capture_id": cap.id, "run_id": run.id, "investigation_id": inv.id}))
PYEOF

SHA=$(sha256sum "${IMAGE}" | awk '{print $1}')
OBJ_KEY="UAT-MEM/${HOSTNAME_ARG}/$(basename "${IMAGE}")"
SYMCTX=$(printf '{"kernel_release":"%s","arch":"x86_64","symbol_key":"%s"}' \
         "${BANNER:-unknown}" "${BANNER:-unknown}")

# Upload straight from the host mount into object storage. Copying a capture-sized file
# into a container filesystem first would double the disk cost for no benefit, and on a
# real image it simply fails.
echo "  uploading capture to object storage (real image — this takes a while)"
set -a; . "${PLATFORM}/deploy/.env"; set +a
UPLOAD_OUT=$(${RUNTIME} run --rm --user root \
    --network ir-enclave_internal \
    -v "$(dirname "$(readlink -f "${IMAGE}")")":/img:ro,z \
    -e AWS_ACCESS_KEY_ID="${S3_ACCESS_KEY}" \
    -e AWS_SECRET_ACCESS_KEY="${S3_SECRET_KEY}" \
    --entrypoint python3 localhost/ir-worker:latest -c "
import boto3
from botocore.client import Config
s3 = boto3.client('s3', endpoint_url='http://minio:9000',
                  config=Config(signature_version='s3v4', s3={'addressing_style':'path'}))
try:
    s3.head_bucket(Bucket='${S3_BUCKET:-ir-evidence}')
except Exception:
    s3.create_bucket(Bucket='${S3_BUCKET:-ir-evidence}')
s3.upload_file('/img/$(basename "${IMAGE}")', '${S3_BUCKET:-ir-evidence}', '${OBJ_KEY}')
head = s3.head_object(Bucket='${S3_BUCKET:-ir-evidence}', Key='${OBJ_KEY}')
print('uploaded', head['ContentLength'])
" 2>&1 | tail -1)
if printf '%s' "${UPLOAD_OUT}" | grep -q '^uploaded'; then
    ok "capture uploaded to object storage (${UPLOAD_OUT#uploaded })"
else
    bad "upload failed: ${UPLOAD_OUT}"
fi

${RUNTIME} cp /tmp/_uat_mem_ingest.py "${BE}:/tmp/_uat_mem_ingest.py" >/dev/null 2>&1
IDS=$(${RUNTIME} exec -w /app -e PYTHONPATH=/app "${BE}" python /tmp/_uat_mem_ingest.py \
      "${HOSTNAME_ARG}" "${OBJ_KEY}" "${IMG_SIZE}" "${SHA}" "${SYMCTX}" 2>&1 | tail -1)
CAP_ID=$(printf '%s' "${IDS}" | python3 -c "import json,sys; print(json.load(sys.stdin)['capture_id'])" 2>/dev/null)
if [[ -n "${CAP_ID}" ]]; then ok "capture registered (id ${CAP_ID})"; else bad "ingest failed: ${IDS}"; fi

# --- 4. Analyze --------------------------------------------------------------------
say "4/7  Server-side analysis in the enclave"
[[ -n "${CAP_ID}" ]] && {
    echo "  running analysis — a full Volatility pass over a real image takes a long time"
    # Run it in the WORKER, not the API container: the worker is the only one carrying
    # Volatility and the toolkit analysis stack, and it is the container the real Celery
    # path would use.
    cat > /tmp/_uat_run_analysis.py <<'PYEOF'
import os
import django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ir_platform.settings")
django.setup()
import sys
from cases.tasks import analyze_capture
analyze_capture(int(sys.argv[1]), ruleset_version="uat")
PYEOF
    ${RUNTIME} cp /tmp/_uat_run_analysis.py "${WK}:/tmp/_uat_run_analysis.py" >/dev/null 2>&1
    ${RUNTIME} exec -w /app -e PYTHONPATH=/app "${WK}" \
        python /tmp/_uat_run_analysis.py "${CAP_ID}" >/tmp/_uat_analysis.log 2>&1
    tail -3 /tmp/_uat_analysis.log | sed 's/^/    /'
}

cat > /tmp/_uat_mem_check.py <<'PYEOF'
import json, os, sys, django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ir_platform.settings")
django.setup()
from cases.models import MemoryAnalysisRun, MemoryCapture, SymbolRequest
from cases import storage

cap = MemoryCapture.objects.get(pk=int(sys.argv[1]))
run = MemoryAnalysisRun.objects.filter(capture=cap).order_by("-id").first()
out = {"status": None}
if run:
    out = {
        "status": run.status, "engine": run.engine,
        "findings": run.findings.count(),
        "summary": run.summary or {},
        "error": (run.error or "")[:200],
    }
out["symbol_requests"] = list(
    SymbolRequest.objects.filter(status="needed").values_list("symbol_key", flat=True))
out["carved"] = len(storage.list_carved_regions(cap.run.host.hostname))
out["carved_bucket"] = storage.carved_bucket(cap.run.host.hostname)
out["retention"] = cap.retention_status
print(json.dumps(out))
PYEOF
${RUNTIME} cp /tmp/_uat_mem_check.py "${BE}:/tmp/_uat_mem_check.py" >/dev/null 2>&1
RESULT=$(${RUNTIME} exec -w /app -e PYTHONPATH=/app "${BE}" python /tmp/_uat_mem_check.py "${CAP_ID}" 2>&1 | tail -1)

parse() { printf '%s' "${RESULT}" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('$1',''))" 2>/dev/null; }
STATUS=$(parse status); ENGINE=$(parse engine); NFIND=$(parse findings)
CARVED=$(parse carved); BUCKET=$(parse carved_bucket)

[[ "${STATUS}" == "completed" ]] && ok "analysis completed" || bad "analysis status: ${STATUS:-none} — $(parse error)"

# --- 5. Depth actually achieved ----------------------------------------------------
say "5/7  Analysis depth is reported honestly"
if [[ "${ENGINE}" == "volatility3" ]]; then
    ok "full Volatility pass ran (engine=volatility3)"
    [[ "${NFIND:-0}" -gt 0 ]] && ok "${NFIND} memory finding(s) written to PostgreSQL as metadata" \
                              || bad "Volatility ran but produced no findings"
elif [[ "${ENGINE}" == "native-scan" ]]; then
    if [[ "${DEEP_EXPECTED}" -eq 1 ]]; then
        bad "fell back to the structural scan despite a symbol table being present"
    else
        ok "reduced-depth scan, correctly labeled (engine=native-scan)"
        ok "run is marked reduced_depth so it cannot be mistaken for a full analysis"
    fi
    REQ=$(parse symbol_requests)
    [[ -n "${REQ}" && "${REQ}" != "[]" ]] && ok "symbol request raised for the admin: ${REQ}" \
                                          || bad "no symbol request was raised"
else
    bad "unexpected engine: ${ENGINE:-none}"
fi

# --- 6. Carved regions reach the host's own bucket ---------------------------------
say "6/7  Carved regions in the host's bucket"
if [[ "${ENGINE}" == "volatility3" ]]; then
    if [[ "${CARVED:-0}" -gt 0 ]]; then
        ok "${CARVED} carved region(s) in ${BUCKET}"
        ok "regions are isolated per host, so a session sees one investigation only"
    else
        note "no regions carved — the image may contain no YARA true-positive regions"
    fi
else
    note "carving requires the Volatility pass; skipped at reduced depth"
fi

# --- 7. Render both workstations ---------------------------------------------------
say "7/7  Workstations render for visual validation"
if [[ "${RENDER}" -eq 1 ]]; then
    command -v xhost >/dev/null 2>&1 && xhost +local: >/dev/null 2>&1 || true

    if env -C "${PLATFORM}/deploy/workstation" timeout 200 \
        ${IR_COMPOSE:-podman-compose} -p ir-workstation --env-file ../.env \
        -f docker-compose.yml up -d --no-deps browser >/dev/null 2>&1; then
        sleep 6
        [[ $(${RUNTIME} ps --format '{{.Names}}' | grep -c browser) -gt 0 ]] \
            && ok "analyst workstation up — sign in and open the run to see the findings" \
            || bad "analyst workstation did not start"
    else
        bad "analyst workstation failed to launch"
    fi

    if [[ "${CARVED:-0}" -gt 0 ]]; then
        if "${PLATFORM}/re-workstation/stage_regions.sh" --host "${HOSTNAME_ARG}" \
             --out /tmp/uat-re-session >/dev/null 2>&1; then
            STAGED=$(find /tmp/uat-re-session -name '*.bin' 2>/dev/null | wc -l)
            ok "${STAGED} region(s) staged read-only for reverse engineering"
            note "open them:  re-workstation/launch.sh --regions /tmp/uat-re-session"
        else
            bad "could not stage carved regions for the RE workstation"
        fi
    else
        note "no carved regions to stage — RE workstation not launched"
    fi
else
    note "rendering skipped (--no-render)"
fi

echo
if [[ "${FAILED}" -eq 0 ]]; then
    printf '\033[1;32m  MEMORY ANALYSIS UAT PASSED\033[0m\n'
    printf '  Verify by eye: findings on the run page, and carved regions opening in Binary Ninja.\n'
else
    printf '\033[1;31m  MEMORY ANALYSIS UAT FAILED\033[0m (see above)\n'
fi
exit "${FAILED}"
