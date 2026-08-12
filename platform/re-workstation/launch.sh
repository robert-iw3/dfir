#!/usr/bin/env bash
# Launch a reverse-engineering session over one host's carved regions, with NO network namespace —
# Binary Ninja Free and Ghidra both need no license or call-home.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNTIME="${IR_RUNTIME:-podman}"
NAME="ir-re-session"
REGIONS=""

# Either tool runs in a session with no route out; which one an analyst prefers is a preference,
# so IR_RE_TOOL selects and `--tool` overrides per session.
TOOL_ARG=""
TOOL_EXPORTED="${IR_RE_TOOL:-}"
ENV_FILE="${IR_ENV_FILE:-${HERE}/../deploy/.env}"
if [[ -f "${ENV_FILE}" ]]; then
    set -a
    # shellcheck source=/dev/null
    . "${ENV_FILE}"
    set +a
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --regions) REGIONS="$2"; shift 2 ;;
        --host) REGIONS="${HERE}/session-$2"; shift 2 ;;
        --tool) TOOL_ARG="$2"; shift 2 ;;
        binja|ghidra) TOOL_ARG="$1"; shift ;;
        *) echo "unknown option: $1" >&2
           echo "usage: launch.sh --host <HOST> [--tool binja|ghidra]" >&2; exit 2 ;;
    esac
done
[[ -n "${REGIONS}" && -d "${REGIONS}" ]] || {
    echo "stage regions first:  ./stage_regions.sh --host <HOST>" >&2; exit 2; }

TOOL="${TOOL_ARG:-${TOOL_EXPORTED:-${IR_RE_TOOL:-binja}}}"

case "${TOOL}" in
    binja)  IMAGE="${IR_RE_IMAGE:-ir-re-workstation:latest}";        DOCKERFILE="Dockerfile" ;;
    ghidra) IMAGE="${IR_RE_GHIDRA_IMAGE:-ir-re-ghidra:latest}";      DOCKERFILE="Dockerfile.ghidra" ;;
    *) echo "unknown tool: ${TOOL} (expected binja or ghidra)" >&2; exit 2 ;;
esac

${RUNTIME} image exists "${IMAGE}" 2>/dev/null || {
    echo "[re] building ${IMAGE} (needs network — build only, never at session time)"
    ${RUNTIME} build -t "${IMAGE}" -f "${HERE}/${DOCKERFILE}" "${HERE}"; }

command -v xhost >/dev/null 2>&1 && xhost +local: >/dev/null 2>&1 || true
ZSUF=""
if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled 2>/dev/null; then ZSUF=":Z"; fi

${RUNTIME} rm -f "${NAME}" >/dev/null 2>&1 || true

# Refuse an empty session rather than opening a disassembler over nothing. A session with no
# regions looks identical to a broken one — the tool starts, the file list is empty, and
# there is no way to tell "nothing was carved" from "the mount did not arrive".
mapfile -t REGION_FILES < <(find "${REGIONS}" -maxdepth 1 -name '*.bin' | sort)
if (( ${#REGION_FILES[@]} == 0 )); then
    echo "[re] ${REGIONS} holds no regions." >&2
    echo "[re] stage them first:  ./stage_regions.sh --host <HOST>" >&2
    echo "[re] if staging reported 0, the analysis carved none — check the YARA pass." >&2
    exit 2
fi

echo "[re] session for host $(cat "${REGIONS}/.host" 2>/dev/null || echo unknown)"
echo "[re] tool: ${TOOL}"
echo "[re] regions: ${#REGION_FILES[@]} (read-only, no network)"

# Ghidra diverges here: it cannot open a file from a read-only mount, so a region is imported into
# a project directory on a tmpfs first — no analysis state from live malware survives the
# container.

# The X socket alone is not enough on Wayland: Xwayland issues an auth COOKIE, so the cookie is
# passed in and XAUTHORITY points at it.
X11_ARGS=()
if [[ -n "${DISPLAY:-}" ]]; then
    X11_ARGS+=(-v /tmp/.X11-unix:/tmp/.X11-unix -e "DISPLAY=${DISPLAY}")
    if [[ -n "${XAUTHORITY:-}" && -r "${XAUTHORITY}" ]]; then
        X11_ARGS+=(-v "${XAUTHORITY}:/tmp/.Xauthority:ro${ZSUF}" -e "XAUTHORITY=/tmp/.Xauthority")
    fi
else
    # Said once, here, rather than left to a Java stack trace inside the container.
    echo "[re] DISPLAY is unset — the tool has no window to open." >&2
    echo "[re] Run this from a desktop session, or export DISPLAY first." >&2
fi

if [[ "${TOOL}" == "ghidra" ]]; then
    exec ${RUNTIME} run --rm -it --name "${NAME}" \
        --network none \
        --userns=keep-id:uid=1001,gid=1001 \
        --cap-drop ALL --security-opt no-new-privileges \
        --memory "${IR_RE_MEMORY:-4g}" \
        --mount "type=tmpfs,dst=/session,tmpfs-size=${IR_RE_PROJECT_SIZE:-4g},tmpfs-mode=1777,nosuid,nodev" \
        "${X11_ARGS[@]}" \
        -v "${REGIONS}:/regions:ro${ZSUF}" \
        -e "IR_GHIDRA_PROCESSOR=${IR_GHIDRA_PROCESSOR:-x86:LE:64:default}" \
        -e "IR_GHIDRA_ANALYSIS=${IR_GHIDRA_ANALYSIS:-1}" \
        "${IMAGE}"
fi

# Open the regions on start. They are the entire reason the session exists, and leaving the
# analyst to find them through a file dialog inside a container makes an empty start screen
# the first thing they see.
MOUNTED_REGIONS=()
for f in "${REGION_FILES[@]}"; do MOUNTED_REGIONS+=("/regions/$(basename "${f}")"); done

# Preferences come from the host read-only, carrying the pins that keep update checks and
# telemetry off; the session opens with them already set.
SETTINGS="${HERE}/binja-settings.json"
if [[ ! -f "${SETTINGS}" ]]; then
    cat > "${SETTINGS}" <<'JSON'
{
  "network.enableExternalResources": false,
  "updates.showAllVersions": false,
  "analysis.suppressInformationalWarnings": true,
  "corePlugins.enable": false,
  "python.autoLoadPluginModules": false,
  "python.autoLoadUserPluginModules": false
}
JSON
    echo "[re] created ${SETTINGS} — Binary Ninja preferences persist here"
fi

# The X socket is owned by the host user and connecting needs write permission on it; under
# rootless podman the host user maps to container root, which has it.
exec ${RUNTIME} run --rm -it --name "${NAME}" \
    --network none \
    --userns=keep-id:uid=1001,gid=1001 \
    --cap-drop ALL --security-opt no-new-privileges \
    -v /tmp/.X11-unix:/tmp/.X11-unix \
    -v "${REGIONS}:/regions:ro${ZSUF}" \
    -v "${SETTINGS}:/home/binja/.binaryninja/settings.json:ro${ZSUF}" \
    -e "DISPLAY=${DISPLAY:-:0}" \
    "${IMAGE}" ./binaryninja "${MOUNTED_REGIONS[@]}"
