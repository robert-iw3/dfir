#!/usr/bin/env bash
# Build the collector image from a STAGED minimal context.
#
# The full ir_toolkit repo is large (Windows binaries, mwcp lib, vol3 wheels). The
# collector only needs the Linux collection subtree + the memory tools, so we stage
# just those into a temp context and build from it — keeping the image lean and the
# build fast, and making explicit exactly what the collector bundles.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# The toolkit tree (playbooks/, tools/) — located, not assumed. It sat beside platform/ in the
# public repository and sits under toolkit/ in the development tree, so the parent is checked
# first and the search widens from there. Zero or multiple matches fail LOUDLY: staging the
# wrong tree produces an image that builds and analyzes with the wrong code.
find_toolkit_root() {
    local base cand hits
    for base in "${HERE}/../.." "${HERE}/../../.."; do
        [[ -d "${base}" ]] || continue
        cand="$(cd "${base}" && pwd)"
        [[ -d "${cand}/playbooks/linux" && -d "${cand}/tools" ]] && { printf '%s' "${cand}"; return 0; }
        hits="$(find "${cand}" -maxdepth 3 -type d -path '*/playbooks/linux' \
                -not -path '*/node_modules/*' -not -path '*/archive/*' 2>/dev/null)"
        if [[ "$(grep -c . <<<"${hits}")" == "1" ]]; then
            printf '%s' "$(cd "$(dirname "$(dirname "${hits}")")" && pwd)"; return 0
        fi
        [[ -n "${hits}" ]] && { echo "[build] ambiguous toolkit trees under ${cand}:" >&2
                                printf '%s\n' "${hits}" >&2; return 1; }
    done
    echo "[build] cannot locate the toolkit tree (playbooks/linux + tools) from ${HERE}" >&2
    return 1
}

TOOLKIT_ROOT="$(find_toolkit_root)" || exit 1
IMAGE="${IR_COLLECTOR_IMAGE:-ir-collector:latest}"
RUNTIME="${IR_RUNTIME:-podman}"

# Every input resolved BEFORE anything is staged, so a tree move is reported in seconds
# with the full list rather than part-way through a build, one file at a time.
. "${HERE}/../ci/build-inputs.sh"
require file "${TOOLKIT_ROOT}/Invoke-IRCollection-Linux.sh" "collection orchestrator"
require dir  "${TOOLKIT_ROOT}/playbooks/linux"              "collection playbooks"
require dir  "${TOOLKIT_ROOT}/playbooks/reporting"          "finding schema + reporting"
require file "${HERE}/../shared/custody.py"                 "custody seal (platform contract)"
for f in collect.sh ship.sh make_sample.py symbol_requisites.py preflight.py scenario_inject.py; do
    require file "${HERE}/${f}" "collector runtime"
done
require_report
build_inputs_check_only && { echo "[build] collector inputs resolve"; exit 0; }

CTX="$(mktemp -d)"
trap 'rm -rf "${CTX}"' EXIT
mkdir -p "${CTX}/toolkit"

echo "[build] staging minimal toolkit subtree from ${TOOLKIT_ROOT}"
# The Linux collection orchestrator + the playbooks it invokes.
cp "${TOOLKIT_ROOT}/Invoke-IRCollection-Linux.sh" "${CTX}/toolkit/"
mkdir -p "${CTX}/toolkit/playbooks"
cp -r "${TOOLKIT_ROOT}/playbooks/linux"     "${CTX}/toolkit/playbooks/"
cp -r "${TOOLKIT_ROOT}/playbooks/reporting" "${CTX}/toolkit/playbooks/"
cp -r "${TOOLKIT_ROOT}/playbooks/lib"       "${CTX}/toolkit/playbooks/" 2>/dev/null || true

# Memory + analysis tools (avml required; yara rules optional).
mkdir -p "${CTX}/toolkit/tools"
cp "${TOOLKIT_ROOT}/tools/avml" "${CTX}/toolkit/tools/" 2>/dev/null || echo "[build] WARN: tools/avml not found"
[[ -d "${TOOLKIT_ROOT}/tools/yara_rules" ]] && cp -r "${TOOLKIT_ROOT}/tools/yara_rules" "${CTX}/toolkit/tools/" || true

# Drop compiled caches to keep the context small.
find "${CTX}/toolkit" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true

# Collector runtime files.
# Every file the Dockerfile COPYs must be staged here. They are listed together so the two
# cannot drift: a missing one fails the build with podman reporting the wrong filename.
cp "${HERE}/collect.sh" "${HERE}/ship.sh" "${HERE}/make_sample.py" \
   "${HERE}/symbol_requisites.py" "${HERE}/preflight.py" "${HERE}/scenario_inject.py" "${CTX}/"
# From the PLATFORM tree, not the toolkit's: custody sealing is the platform's contract with
# the receiver, and both ends must load the identical module. Resolved relative to this
# script so it holds wherever the toolkit tree sits.
cp "${HERE}/../shared/custody.py" "${CTX}/custody.py"
cp "${HERE}/Dockerfile" "${CTX}/Dockerfile"

echo "[build] context size: $(du -sh "${CTX}" | awk '{print $1}')"
echo "[build] building ${IMAGE} with ${RUNTIME}"
"${RUNTIME}" build -t "${IMAGE}" "${CTX}"
echo "[build] done: ${IMAGE}"
