#!/usr/bin/env bash
# Launch a reverse-engineering session over one host's carved regions.
#
# The session has NO network namespace. Binary Ninja Free needs no license, activation or
# call-home, so nothing here requires a route — and a container opening live malware
# should not have one. The display arrives over a mounted X11 socket, the regions over a
# read-only mount, and the container is destroyed on exit.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNTIME="${IR_RUNTIME:-podman}"
NAME="ir-re-session"
REGIONS=""

# Binary Ninja and Ghidra are both free of licensing, activation and call-home, so either can
# run in a session with no route out. Which one an analyst reads a disassembly faster in is a
# preference, and forcing the other on them costs accuracy on the work that matters. The
# containment is identical whichever is chosen; only the tool differs.
#
# The choice is a deployment decision, so it lives in deploy/.env with the rest of them — an
# installation standardises on one tool and every session gets it without anyone remembering a
# flag. Precedence runs narrowest-first: a --tool argument beats an exported variable, which
# beats the deployment default.
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

# Ghidra diverges from here. It cannot open a file from a read-only mount the way Binary Ninja
# does: a region has to be imported into a project first, and a project is a directory Ghidra
# writes to. Its launcher also resolves and then SAVES the JDK path under the user's home, and
# treats being unable to write there as "no JDK found" — it falls back to prompting, which in a
# container has no TTY and aborts every import with an error about the prompt rather than about
# Java.
#
# So both the project and the home directory live on one writable tmpfs, and the mode is set
# explicitly: podman copies the image directory's permissions onto a tmpfs without its
# ownership, so mounting over /home/ghidra yields a root-owned 0700 directory the session user
# cannot write to. Everything ephemeral in one mount also means the analysis database built
# from live malware dies with the container, which is the lifetime the Binary Ninja path gets
# by mounting only settings.json.

# ---- X11 for the session window ------------------------------------------
# The socket alone is not enough on a Wayland desktop. Xwayland issues an auth COOKIE, and
# without it the connection is refused and the tool reports itself as running "in a headless
# environment" — which reads as a broken image rather than a missing credential.
#
# The cookie is passed instead of opening the display with `xhost +local:`. Loosening host
# access for every local client, to run a session that opens live malware, is the wrong trade;
# this grants exactly this container a display and changes nothing on the host.
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

# Preferences come from the host, read-only.
#
# This file carries the pins that keep update checks and telemetry off. The session opens
# live malware, so it does not get write access to its own security settings — a sample
# able to edit them could re-enable call-home for every session that follows.
#
# Edit this file on the host to change a preference. Choices made inside the session apply
# for that session and are discarded with it, which is the correct lifetime for anything a
# malware-analysis container touched.
#
# Only settings.json is mounted, not the whole profile directory: recent-file lists and
# analysis databases from a malware session are not things to carry into the next one.
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

# The X server's socket is owned by the host user, and connecting to a Unix socket needs
# write permission on it. Under rootless podman the host user maps to container root, so
# the unprivileged account this image runs as falls into "other" and is refused — Binary
# Ninja starts and immediately dies with "could not connect to display".
#
# Mapping the host user onto that account fixes it without running the session as root,
# which matters more here than anywhere else in the platform: this is the process that
# opens live malware.
exec ${RUNTIME} run --rm -it --name "${NAME}" \
    --network none \
    --userns=keep-id:uid=1001,gid=1001 \
    --cap-drop ALL --security-opt no-new-privileges \
    -v /tmp/.X11-unix:/tmp/.X11-unix \
    -v "${REGIONS}:/regions:ro${ZSUF}" \
    -v "${SETTINGS}:/home/binja/.binaryninja/settings.json:ro${ZSUF}" \
    -e "DISPLAY=${DISPLAY:-:0}" \
    "${IMAGE}" ./binaryninja "${MOUNTED_REGIONS[@]}"
