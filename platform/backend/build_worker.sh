#!/usr/bin/env bash
# Build the analysis worker image from a STAGED context.
#
# The worker needs two trees that live apart: the Django application here, and the
# toolkit's memory-analysis code plus its Volatility wheels and YARA rules from the
# repository root. A build context cannot reach above itself, so the pieces are staged
# into a temporary directory — the same approach the collector uses, and it makes the
# image's contents explicit rather than implicit in a broad context.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLKIT_ROOT="$(cd "${HERE}/../.." && pwd)"     # ir_toolkit/
IMAGE="${IR_WORKER_IMAGE:-ir-worker:latest}"
RUNTIME="${IR_RUNTIME:-podman}"

CTX="$(mktemp -d)"
trap 'rm -rf "${CTX}"' EXIT

echo "[build] staging backend application"
# Everything the API image gets, since the worker runs the same Django code.
tar -C "${HERE}" --exclude='__pycache__' --exclude='*.pyc' -cf - . | tar -C "${CTX}" -xf -

echo "[build] staging Volatility wheels"
cp -r "${TOOLKIT_ROOT}/tools/vol3_wheels" "${CTX}/vol3_wheels"

# The resource statistics every component reports. Single source in platform/shared/;
# staged here because a build context cannot reach above itself.
cp "${HERE}/../shared/sysstats.py" "${CTX}/sysstats.py"

echo "[build] staging the analysis subtree"
mkdir -p "${CTX}/toolkit/playbooks/linux" "${CTX}/toolkit/tools"
# The analyzer, its enrichment pass, the custom Volatility plugins and the mwcp parsers.
cp -r "${TOOLKIT_ROOT}/playbooks/linux/threat_hunting" "${CTX}/toolkit/playbooks/linux/"
# The investigation engine — what turns findings into verdicts. The correlator weighs
# independent signals landing on one PID, the chain builder reconstructs lineage, and the
# verdict ladder decides. The platform runs this rather than judging for itself, so a
# verdict shown in the UI is the same verdict the toolkit reaches offline.
cp -r "${TOOLKIT_ROOT}/playbooks/linux/investigation" "${CTX}/toolkit/playbooks/linux/"
# It is imported as `playbooks.linux.investigation`, so the intermediate directories have
# to be packages; the toolkit tree relies on the repository root being on sys.path.
touch "${CTX}/toolkit/playbooks/__init__.py" "${CTX}/toolkit/playbooks/linux/__init__.py"
cp -r "${TOOLKIT_ROOT}/tools/yara_rules" "${CTX}/toolkit/tools/" 2>/dev/null || \
    echo "[build]   note: no yara_rules staged — YARA and the mwcp pass will be skipped"

# Windows collection, binaries and the RE tooling are deliberately absent: the worker
# analyzes Linux captures and should carry nothing it does not run.
find "${CTX}/toolkit" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true

echo "[build] building ${IMAGE}"
${RUNTIME} build -t "${IMAGE}" -f "${CTX}/Dockerfile.worker" "${CTX}"

echo "[build] done: ${IMAGE}"
${RUNTIME} run --rm --entrypoint sh "${IMAGE}" -c \
    'echo "  volatility: $(vol --help >/dev/null 2>&1 && echo ok || echo MISSING)"
     echo "  analyzer:   $(test -f /opt/toolkit/playbooks/linux/threat_hunting/analyze_memory_linux.py && echo ok || echo MISSING)"
     echo "  enricher:   $(test -f /opt/toolkit/playbooks/linux/threat_hunting/memory_enrich.py && echo ok || echo MISSING)"
     echo "  vol plugins: $(test -d /opt/toolkit/playbooks/linux/threat_hunting/vol_plugins && echo ok || echo MISSING)"
     echo "  mwcp:       $(test -d /opt/toolkit/playbooks/linux/threat_hunting/mwcp_parsers && echo ok || echo MISSING)"
     echo "  yara rules: $(test -d /opt/toolkit/tools/yara_rules && echo ok || echo absent)"
     echo "  investigation: $(PYTHONPATH=/opt/toolkit python3 -c "from playbooks.linux.investigation import live_runner" 2>/dev/null && echo ok || echo MISSING)"'
