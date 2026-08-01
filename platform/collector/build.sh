#!/usr/bin/env bash
# Build the collector image from a STAGED minimal context.
#
# The full ir_toolkit repo is large (Windows binaries, mwcp lib, vol3 wheels). The
# collector only needs the Linux collection subtree + the memory tools, so we stage
# just those into a temp context and build from it — keeping the image lean and the
# build fast, and making explicit exactly what the collector bundles.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLKIT_ROOT="$(cd "${HERE}/../.." && pwd)"     # ir_toolkit/
IMAGE="${IR_COLLECTOR_IMAGE:-ir-collector:latest}"
RUNTIME="${IR_RUNTIME:-podman}"

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
   "${HERE}/symbol_requisites.py" "${HERE}/preflight.py" "${CTX}/"
cp "${TOOLKIT_ROOT}/platform/shared/custody.py" "${CTX}/custody.py"
cp "${HERE}/Dockerfile" "${CTX}/Dockerfile"

echo "[build] context size: $(du -sh "${CTX}" | awk '{print $1}')"
echo "[build] building ${IMAGE} with ${RUNTIME}"
"${RUNTIME}" build -t "${IMAGE}" "${CTX}"
echo "[build] done: ${IMAGE}"
