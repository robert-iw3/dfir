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
[[ -n "${HOSTNAME_ARG}" ]] || { echo "no host has carved regions — run the memory analysis UAT first" >&2; exit 2; }
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
