#!/usr/bin/env bash
# ==============================================================================
# IR Platform collection container entrypoint (Linux).
#
# Runs the PROVEN ir_toolkit Linux collection (read-only, offline), captures
# volatile memory, then seals the whole evidence folder with a chain-of-custody
# manifest. Output lands in a mounted /evidence volume; the store-and-forward
# broker verifies the seal and ships it to the platform. The container never
# contacts the platform itself (air-gap preserved on the endpoint).
#
# Memory capture: avml needs host kernel memory access (root + CAP_SYS_RAWIO or
# /proc/kcore). When that is not reachable (e.g. a rootless container), we fall
# back to a clearly-labelled bounded SYNTHETIC sample so the end-to-end pipeline
# is still exercised — the sample is flagged is_synthetic=true and is never
# presented as a real RAM image.
# ==============================================================================
set -uo pipefail

TOOLKIT=/opt/toolkit
EVIDENCE="${IR_EVIDENCE_DIR:-/evidence}"
INCIDENT_ID="${IR_INCIDENT_ID:-INC-$(date +%Y%m%d-%H%M%S)}"
# The hostname of the machine under investigation, not of this container.
#
# `hostname` inside a container returns the container id, and every artifact, finding,
# capture and verdict is keyed to this value. Getting it wrong files a host's evidence under
# a name that exists for the lifetime of one container and matches nothing on the next
# collection, so a host can never be correlated with itself.
#
# The host filesystem and /proc are already mounted for collection, so the real name is
# available; an explicit override wins for cases where the mounts are absent.
# Assigns HOST_S and HOSTNAME_SRC directly rather than echoing the name: a caller writing
# HOST_S="$(resolve_hostname)" runs the function in a subshell, and any variable it set there
# is discarded when that subshell exits, leaving the source recorded as unknown.
#
# HOSTNAME_SRC is "override", "host-mount", or "container-fallback". A consumer cannot tell
# those apart from the name itself, and they are not equally trustworthy — the fallback is
# this container's id, which must never overwrite a name resolved properly on an earlier
# collection.
HOST_S=""
HOSTNAME_SRC="unknown"
resolve_hostname() {
    if [ -n "${IR_HOSTNAME:-}" ]; then
        HOST_S="${IR_HOSTNAME}"; HOSTNAME_SRC="override"; return
    fi
    # /etc/hostname on the mounted host filesystem is read first and is the only reliable
    # source here. /proc/sys/kernel/hostname reflects the *reading process's* UTS namespace,
    # not the mounted filesystem, so a bind-mounted /host/proc still answers with this
    # container's name — it looks like the host's and is not.
    for src in /host/root/etc/hostname /host/etc/hostname; do
        if [ -r "${src}" ]; then
            name="$(head -n1 "${src}" 2>/dev/null | tr -d '[:space:]')"
            if [ -n "${name}" ]; then
                HOST_S="${name%%.*}"; HOSTNAME_SRC="host-mount"; return
            fi
        fi
    done
    # No host mounts: say so rather than silently filing evidence under a container id.
    echo "[collector] WARN: host filesystem not mounted — falling back to this container's" >&2
    echo "[collector]       name. Results will not tie to the host they came from. Mount" >&2
    echo "[collector]       /proc and / read-only, or set IR_HOSTNAME." >&2
    HOST_S="$(hostname -s 2>/dev/null || hostname)"
    HOSTNAME_SRC="container-fallback"
}
# A hostname is a label, not an identity: it gets renamed, reused across environments, and
# duplicated. Evidence from one machine has to converge on one host record even when the name
# changes between collections, so record what actually identifies the machine.
#
# machine-id is generated once at install and survives reboots and renames — it is what ties
# this collection to a memory image analyzed hours later by a different worker. boot-id
# changes every boot, which is what distinguishes two collections of the same machine either
# side of a restart. Both are read from the mounted host filesystem for the same reason the
# hostname is: this container has its own.
resolve_machine_id() {
    if [ -n "${IR_MACHINE_ID:-}" ]; then
        echo "${IR_MACHINE_ID}"; return
    fi
    for src in /host/root/etc/machine-id /host/root/var/lib/dbus/machine-id \
               /host/etc/machine-id; do
        if [ -r "${src}" ]; then
            id="$(head -n1 "${src}" 2>/dev/null | tr -cd '[:alnum:]')"
            [ -n "${id}" ] && { echo "${id}"; return; }
        fi
    done
    echo ""
}

resolve_boot_id() {
    for src in /host/proc/sys/kernel/random/boot_id /proc/sys/kernel/random/boot_id; do
        if [ -r "${src}" ]; then
            id="$(head -n1 "${src}" 2>/dev/null | tr -cd '[:alnum:]-')"
            [ -n "${id}" ] && { echo "${id}"; return; }
        fi
    done
    echo ""
}

resolve_hostname          # sets HOST_S and HOSTNAME_SRC
MACHINE_ID="$(resolve_machine_id)"
BOOT_ID="$(resolve_boot_id)"
# The toolkit computes its own hostname and writes it into _status.json and the manifest —
# which is what the platform ingests. Without this it records the container id while the
# folder around it says otherwise.
export IR_HOSTNAME="${HOST_S}"
OUT_DIR="${EVIDENCE}/reports/${HOST_S}"

echo "[collector] host=${HOST_S} incident=${INCIDENT_ID} out=${OUT_DIR}"
if [ -z "${MACHINE_ID}" ]; then
    echo "[collector] WARN: no machine-id readable — this collection can only be tied to its" >&2
    echo "[collector]       host by name, which does not survive a rename and will not join" >&2
    echo "[collector]       a memory image ingested separately." >&2
else
    echo "[collector] machine-id=${MACHINE_ID} boot-id=${BOOT_ID:-unknown}"
fi
mkdir -p "${OUT_DIR}"

# Written by the collector rather than the toolkit: identity is a property of the machine
# being collected from, not of the collection, and the toolkit runs offline against images
# where these do not apply.
cat > "${OUT_DIR}/_host_identity.json" <<EOF
{"hostname": "${HOST_S}", "hostname_source": "${HOSTNAME_SRC}",
 "machine_id": "${MACHINE_ID}", "boot_id": "${BOOT_ID}"}
EOF

# --- 1. Prove the analysis tools are present in the image ---------------------
echo "[collector] staged tools:"
for t in "${TOOLKIT}/tools/avml" "$(command -v yara)" "$(command -v python3)"; do
    if [[ -n "$t" && -e "$t" ]]; then echo "  OK  $t"; else echo "  MISSING $t"; fi
done
python3 -c "import sys; print('  python', sys.version.split()[0])"

# --- 2. Run the proven toolkit collection (degrades gracefully) ---------------
echo "[collector] running ir_toolkit Linux collection ..."
# --deep runs the full forensics collector (playbooks/linux/00_collect_forensics.sh).
#
# Without it the platform collected the inline snapshot only, and the endpoint lab measured
# exactly what that costs: of nine artifacts planted for a LOW-sophistication intrusion, four
# came back. The SSH backdoor key, the SUID escalation binary, the world-writable executable,
# the `.bashrc` persistence and the hash of every running binary did not — the most obvious
# evidence of the least sophisticated attack there is.
#
# It is not free: --deep walks the filesystem for SUID files and entropy-scans executables.
# That cost is accepted because a collection that misses an authorized_keys backdoor has not
# answered the question it was sent to answer. If the walk proves too heavy on a production
# endpoint, the split is a collection profile, not a return to the inline snapshot —
# planning/DECISIONS.md O-012.
bash "${TOOLKIT}/Invoke-IRCollection-Linux.sh" \
    --output-root "${EVIDENCE}/reports" \
    --incident-id "${INCIDENT_ID}" \
    --deep \
    --no-egress-monitor \
    --skip-reports 2>&1 | sed 's/^/  [toolkit] /'
echo "[collector] collection exit handled (toolkit degrades on missing privilege)"

# --- 2b. Corpus scenario (test corpora only) ----------------------------------
# Merges declared-synthetic findings/indicators into the collection BEFORE the seal, and
# feeds the scenario's memory artifacts to the synthetic sample so the server-side analyzer
# derives them from the image itself. Absent the variable, nothing here runs.
if [ -n "${IR_SCENARIO_FILE:-}" ] && [ -r "${IR_SCENARIO_FILE}" ]; then
    echo "[collector] corpus scenario: $(basename "${IR_SCENARIO_FILE}")"
    python3 "$(dirname "$0")/scenario_inject.py" "${IR_SCENARIO_FILE}" "${OUT_DIR}" \
        || echo "[collector]   WARN: scenario injection failed — bundle ships without it" >&2
    export IR_SAMPLE_ARTIFACTS_FILE="${IR_SCENARIO_FILE}"
fi

# --- 3. Capture volatile memory (real avml -> synthetic fallback) -------------
MEM_IMG="${OUT_DIR}/memory_${HOST_S}.lime"
CAPTURE_TOOL="avml"
IS_SYNTHETIC="false"
IMG_FORMAT="lime"

# Declared before the capture rather than discovered after it: the transfer is bounded by the
# size of the endpoint's RAM, and a shortfall found at the far end wastes the whole collection.
# One-way — this states a requirement and reads no answer back.
python3 "$(dirname "$0")/preflight.py" "${OUT_DIR}" "${HOST_S}" "${INCIDENT_ID}" "${EVIDENCE}" \
    || echo "[collector]   (continuing — a partial collection still carries its artifacts)" >&2

echo "[collector] capturing memory ..."
# avml 0.20 takes a subcommand; earlier releases took the output path as the only argument.
# Both spellings are attempted so the collector works across the versions an endpoint may
# already have staged, rather than falling back to a synthetic sample on a version mismatch.
CAPTURE_ERR=""
avml_acquire() {
    local out="$1"
    if "${TOOLKIT}/tools/avml" acquire "${out}" 2>"${OUT_DIR}/_avml.err"; then
        return 0
    fi
    # An older avml rejects the subcommand rather than the path; retry the flat form.
    if grep -qi "unrecognized subcommand\|unexpected argument" "${OUT_DIR}/_avml.err" 2>/dev/null; then
        "${TOOLKIT}/tools/avml" "${out}" 2>"${OUT_DIR}/_avml.err" && return 0
    fi
    return 1
}

if avml_acquire "${MEM_IMG}" && [[ -s "${MEM_IMG}" ]]; then
    echo "[collector]   avml capture ok ($(stat -c%s "${MEM_IMG}") bytes)"
    rm -f "${OUT_DIR}/_avml.err"
else
    # The reason matters: a synthetic sample analyzes cleanly and looks like a completed
    # collection, so a fallback that does not say why produces a run nobody knows to distrust.
    CAPTURE_ERR="$(tr '\n' ' ' < "${OUT_DIR}/_avml.err" 2>/dev/null | sed 's/"/'"'"'/g' | cut -c1-300)"
    rm -f "${MEM_IMG}" "${OUT_DIR}/_avml.err"
    echo "[collector]   WARN: memory capture FAILED — falling back to a synthetic sample." >&2
    echo "[collector]         reason: ${CAPTURE_ERR:-unknown}" >&2
    echo "[collector]         The sample carries planted indicators and is flagged" >&2
    echo "[collector]         is_synthetic; it exercises the pipeline and is NOT evidence." >&2
    echo "[collector]         Acquiring real memory needs CAP_SYS_ADMIN over the host's" >&2
    echo "[collector]         /proc/iomem, which a rootless container cannot hold however" >&2
    echo "[collector]         privileged it is — run the collector rootful or on the host." >&2
    MEM_IMG="${OUT_DIR}/memory_${HOST_S}_SYNTHETIC.raw"
    CAPTURE_TOOL="synthetic-fallback"
    IS_SYNTHETIC="true"
    IMG_FORMAT="raw"
    python3 "$(dirname "$0")/make_sample.py" "${MEM_IMG}"
fi

# Kernel identity for building a Volatility symbol table later. Recorded here because
# this is the only point at which the target kernel is observable; the enclave never sees
# the host, and an isolated endpoint cannot fetch symbols itself.
python3 "$(dirname "$0")/symbol_requisites.py" "${OUT_DIR}/_symbols.json" || \
    echo "[collector]   symbol requisites unavailable — analysis will run at reduced depth" >&2

MEM_SHA="$(sha256sum "${MEM_IMG}" | awk '{print $1}')"
MEM_SIZE="$(stat -c%s "${MEM_IMG}")"
cat > "${OUT_DIR}/_capture_meta.json" <<EOF
{
  "filename": "$(basename "${MEM_IMG}")",
  "capture_tool": "${CAPTURE_TOOL}",
  "image_format": "${IMG_FORMAT}",
  "is_synthetic": ${IS_SYNTHETIC},
  "sha256": "${MEM_SHA}",
  "size_bytes": ${MEM_SIZE},
  "kernel": "$(uname -r)",
  "capture_error": "${CAPTURE_ERR}"
}
EOF
echo "[collector]   memory image: $(basename "${MEM_IMG}") sha256=${MEM_SHA:0:16}…"

# --- 4. Seal the whole folder (chain of custody) ------------------------------
echo "[collector] sealing evidence (chain of custody) ..."
python3 "$(dirname "$0")/custody.py" seal "${OUT_DIR}" "${INCIDENT_ID}" >/dev/null
python3 "$(dirname "$0")/custody.py" verify "${OUT_DIR}"

# --- 5. Package for transfer --------------------------------------------------
# ship.sh sends one file; sealing happens above, so the archive is built from the folder
# exactly as sealed. Built here rather than in ship.sh because this is the step that knows
# which folder was just written, and because the archive must not be assembled on a
# read-only evidence volume — ship.sh mounts it read-only by design.
BUNDLE="${BUNDLE:-/evidence/bundle.tar.gz}"
echo "[collector] packaging -> ${BUNDLE}"
if tar -czf "${BUNDLE}" -C "$(dirname "${OUT_DIR}")" "$(basename "${OUT_DIR}")" 2>/dev/null; then
    # Size only. Hashing the archive here re-reads the whole capture to produce sixteen
    # characters of log output, on a host that has just written it twice — and the archive's
    # own hash identifies nothing: the evidence identity is the custody manifest hash, which
    # is already computed, travels inside the bundle, and is what the receiver reports back.
    echo "[collector]   $(stat -c%s "${BUNDLE}") bytes"
else
    echo "[collector]   WARN: could not write ${BUNDLE} — ship it by copying ${OUT_DIR}" >&2
fi

echo "[collector] DONE -> ${OUT_DIR}"
