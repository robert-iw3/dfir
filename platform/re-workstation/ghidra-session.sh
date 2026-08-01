#!/usr/bin/env bash
# Import this session's carved regions into a throwaway Ghidra project, then open it.
#
# Binary Ninja takes files as arguments and shows them immediately. Ghidra does not: its GUI
# opens a project manager, and a file only becomes analysable once it has been imported into a
# project. Handing the analyst an empty project manager and a read-only /regions mount they
# have to import from by hand is a worse start than the empty file list the Binary Ninja path
# was written to avoid, so the import happens here first and the GUI opens on the result.
#
# A carved region is raw memory: no header, no entry point, nothing a loader can recognize.
# Ghidra therefore needs to be told the processor and the address the bytes came from, and the
# carve filename carries the address — `pid<PID>_<name>_0x<vm_start>.bin`. Importing at that
# base is what makes pointers inside the region resolve to each other instead of to offsets
# from zero, which is the difference between a readable disassembly and a puzzle.
set -uo pipefail

REGIONS="${IR_REGIONS_DIR:-/regions}"

# Everything Ghidra writes goes on the session tmpfs, including its home directory.
#
# Its launcher resolves the JDK and then saves the path under $HOME, and treats a home it
# cannot write to as "no JDK found" — it falls back to prompting for a path, which in a
# container has no TTY and aborts the import with an error about the prompt rather than about
# Java. The image's own /home/ghidra is not usable for this: a tmpfs mounted over it inherits
# the directory's mode without its ownership and lands root-owned.
SESSION_DIR="${IR_SESSION_DIR:-/session}"
export HOME="${SESSION_DIR}/home"
mkdir -p "${HOME}" 2>/dev/null || {
    echo "[ghidra] ${SESSION_DIR} is not writable — mount it as tmpfs with mode 1777." >&2
    exit 1; }
PROJECT_DIR="${IR_GHIDRA_PROJECT_DIR:-${SESSION_DIR}/project}"
PROJECT_NAME="${IR_GHIDRA_PROJECT_NAME:-session}"
# Carved regions come from Linux x86-64 hosts, which is what this platform collects. Override
# for a capture from anything else; Ghidra's language IDs are listed by `analyzeHeadless` with
# an unknown -processor value.
PROCESSOR="${IR_GHIDRA_PROCESSOR:-x86:LE:64:default}"
# Auto-analysis is on: a region that has been imported but not analyzed shows bytes rather
# than code, and running it by hand is the first thing an analyst would do anyway. Regions are
# capped at carve time so this stays short; set IR_GHIDRA_ANALYSIS=0 to skip it.
ANALYSIS="${IR_GHIDRA_ANALYSIS:-1}"
TIMEOUT_PER_FILE="${IR_GHIDRA_ANALYSIS_TIMEOUT:-180}"

HEADLESS=/ghidra/support/analyzeHeadless

mapfile -t REGION_FILES < <(find "${REGIONS}" -maxdepth 1 -name '*.bin' -type f | sort)
if (( ${#REGION_FILES[@]} == 0 )); then
    echo "[ghidra] ${REGIONS} holds no regions — nothing to import." >&2
    echo "[ghidra] stage them first:  ./stage_regions.sh --host <HOST>" >&2
    exit 2
fi

mkdir -p "${PROJECT_DIR}" || {
    echo "[ghidra] ${PROJECT_DIR} is not writable. Ghidra must own its project directory;" >&2
    echo "[ghidra] mount it as tmpfs rather than pointing it at the read-only regions." >&2
    exit 1; }

echo "[ghidra] importing ${#REGION_FILES[@]} region(s) at their carved base addresses"

imported=0
failed=0
for f in "${REGION_FILES[@]}"; do
    base="$(basename "${f}")"
    # The trailing _0x<hex> in the carve name is the region's virtual start. Absent — a region
    # named some other way — import at 0 and say so, because a silently wrong base address
    # produces a disassembly that looks fine and is wrong.
    addr="$(sed -n 's/.*_0x\([0-9a-fA-F]\{1,16\}\)\.bin$/\1/p' <<<"${base}")"
    if [[ -n "${addr}" ]]; then
        base_addr="0x${addr}"
    else
        base_addr="0x0"
        echo "[ghidra]   ${base}: no address in the filename — importing at 0x0" >&2
    fi

    args=("${PROJECT_DIR}" "${PROJECT_NAME}"
          -import "${f}"
          -processor "${PROCESSOR}"
          -loader BinaryLoader
          -loader-baseAddr "${base_addr}"
          -scriptlog /dev/null)
    if [[ "${ANALYSIS}" == "1" ]]; then
        args+=(-analysisTimeoutPerFile "${TIMEOUT_PER_FILE}")
    else
        args+=(-noanalysis)
    fi

    # One invocation per region: -loader-baseAddr applies to every file in a single run, and
    # each region has its own address.
    if out="$("${HEADLESS}" "${args[@]}" 2>&1)"; then
        echo "[ghidra]   ${base} @ ${base_addr}"
        imported=$((imported + 1))
    else
        # Import failure per region, not for the session: nine readable regions beat refusing
        # to open because the tenth would not load.
        echo "[ghidra]   FAILED ${base} @ ${base_addr}" >&2
        sed -n 's/^/[ghidra]     /p' <<<"$(tail -5 <<<"${out}")" >&2
        failed=$((failed + 1))
    fi
done

echo "[ghidra] imported ${imported}, failed ${failed}"
if (( imported == 0 )); then
    echo "[ghidra] nothing imported — refusing to open an empty project." >&2
    echo "[ghidra] if every region failed on the processor, set IR_GHIDRA_PROCESSOR." >&2
    exit 1
fi

PROJECT_FILE="${PROJECT_DIR}/${PROJECT_NAME}.gpr"
[[ -f "${PROJECT_FILE}" ]] || {
    echo "[ghidra] ${PROJECT_FILE} was not created despite ${imported} import(s)." >&2
    exit 1; }

echo "[ghidra] opening ${PROJECT_FILE}"
# MAXMEM is Ghidra's own JVM ceiling. It is set below the container's memory limit rather than
# at it, so the JVM reports being out of heap instead of the kernel killing the process — an
# OOM kill mid-analysis looks like a crashed tool with no explanation.
exec /ghidra/support/launch.sh fg jre Ghidra "${IR_GHIDRA_MAXMEM:-3G}" "" \
    ghidra.GhidraRun "${PROJECT_FILE}"
