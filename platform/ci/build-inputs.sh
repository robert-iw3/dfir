#!/usr/bin/env bash
# ==============================================================================
# Build-input resolution — sourced by the image build scripts.
#
# Two kinds of path, and conflating them is what breaks a build after a tree move:
#
#   IN-TREE   files that travel WITH the platform (shared/custody.py, shared/sysstats.py).
#             Resolved relative to the calling script, so the tree can sit anywhere as long
#             as its internal shape holds. Never located by search: two candidates would be
#             indistinguishable and the wrong one ships silently.
#
#   FOREIGN   trees whose position is a property of the HOST, not of the platform — the
#             toolkit, the Vault config. Located by search, and 0-or-many matches fail
#             LOUDLY rather than guessing.
#
# `require` collects every missing input and reports them TOGETHER before staging starts.
# A build that dies on its first missing file hides the other four, and each rediscovery
# costs another multi-minute build.
#
#   . "${HERE}/../ci/build-inputs.sh"
#   require file "${HERE}/../shared/custody.py"   "custody sealing (platform contract)"
#   require dir  "${TOOLKIT_ROOT}/playbooks/linux" "collection playbooks"
#   require_report        # exits 1 listing everything absent
# ==============================================================================

_MISSING=()

require() {  # <file|dir> <path> <what it is for>
    local kind="$1" path="$2" purpose="${3:-}"
    case "${kind}" in
        file) [[ -f "${path}" ]] && return 0 ;;
        dir)  [[ -d "${path}" ]] && return 0 ;;
        *)    echo "[build] require: unknown kind '${kind}'" >&2; return 2 ;;
    esac
    _MISSING+=("${path}${purpose:+  — ${purpose}}")
    return 0
}

require_report() {
    (( ${#_MISSING[@]} == 0 )) && return 0
    echo "[build] cannot build: ${#_MISSING[@]} input(s) do not resolve" >&2
    printf '  missing: %s\n' "${_MISSING[@]}" >&2
    echo "[build] in-tree inputs resolve from the build script's own location; a tree move" >&2
    echo "[build] that changes internal shape must update the script, not the search." >&2
    exit 1
}

# Check-only mode: verify inputs and exit without building. Wired into CI so a path that
# stopped resolving is caught in seconds instead of part-way through an image build.
build_inputs_check_only() { [[ "${IR_BUILD_CHECK_ONLY:-0}" == "1" ]]; }
