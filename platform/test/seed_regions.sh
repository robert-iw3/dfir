#!/usr/bin/env bash
# Load a directory of binaries into a host's carved-region bucket as simulated carved regions.
#
# WHY THIS EXISTS. Getting real carved regions means running a memory analysis over a capture
# the size of a host's RAM — hours.
#
# This writes the same objects under the same keys with the same database rows, so those
# components run against real storage and a failure is attributable to the one under test.
#
# It proves regions can be stored, staged, bounded by host and opened. It proves NOTHING about
# whether the analyzer would have carved them — the rows are marked simulated for that reason.
#
#   ./seed_regions.sh --host ubuntu-main --source ../../test/linux/lab_mwcp/samples
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"
RUNTIME="${IR_RUNTIME:-podman}"

HOSTNAME_ARG=""
SOURCE=""
INCIDENT="${IR_INCIDENT_ID:-INC-SIMULATED}"
LIMIT="0"
PATTERN=".bin"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)     HOSTNAME_ARG="$2"; shift 2 ;;
        --source)   SOURCE="$2"; shift 2 ;;
        --incident) INCIDENT="$2"; shift 2 ;;
        --limit)    LIMIT="$2"; shift 2 ;;
        # Empty means every regular file: a system bin directory is a legitimate source of
        # simulated regions and almost nothing in one ends in .bin.
        --pattern)  PATTERN="$2"; shift 2 ;;
        *) echo "usage: seed_regions.sh --host <HOST> --source <DIR> [--incident ID] [--limit N] [--pattern SUFFIX]" >&2
           exit 2 ;;
    esac
done
[[ -n "${HOSTNAME_ARG}" ]] || { echo "--host is required" >&2; exit 2; }
[[ -d "${SOURCE}" ]] || { echo "--source must be a directory (got '${SOURCE}')" >&2; exit 2; }
SOURCE="$(cd "${SOURCE}" && pwd)"

# Run in a ONE-OFF container rather than exec'ing into the running backend. The samples are test
# material and must not be mounted into a live service just to seed them — the backend holds
# evidence, and giving it a bind mount from the working tree for a test is how test data ends up
# inside a production container.
set -a; . "${PLATFORM}/deploy/.env"; set +a

# In the BACKEND's network namespace, not on the enclave network directly. With the mesh
# enforcing, Postgres and MinIO bind loopback and are reachable only through a Connect sidecar.
BE_CONTAINER="${IR_BACKEND_CONTAINER:-ir-enclave_backend_1}"
BE_PID="$("${RUNTIME}" inspect -f '{{.State.Pid}}' "${BE_CONTAINER}" 2>/dev/null || true)"
[ "${BE_PID:-0}" -gt 0 ] || {
    echo "[seed] ${BE_CONTAINER} is not running — bring the enclave up first" >&2; exit 1; }

# `ns:<path>`, not `container:<name>`: compose places its containers in a pod, and podman
# refuses to join a pod member's network from outside the pod. The namespace path names the
# same namespace without involving the pod.
echo "[seed] ${SOURCE} -> host ${HOSTNAME_ARG} (incident ${INCIDENT})"
"${RUNTIME}" run --rm \
    --network "ns:/proc/${BE_PID}/ns/net" \
    --env-file "${PLATFORM}/deploy/.env" \
    -e POSTGRES_HOST="${IR_DB_HOST_APP:-127.0.0.1}" \
    -e S3_ENDPOINT_URL="${IR_MINIO_ENDPOINT_APP:-http://127.0.0.1:9000}" \
    -v "ir-enclave_vault-secrets:/vault/secrets:ro" \
    -v "${SOURCE}:/labs:ro,z" \
    localhost/ir-backend:latest \
    python manage.py seed_carved_regions \
        --host "${HOSTNAME_ARG}" --source /labs \
        --incident "${INCIDENT}" --limit "${LIMIT}" --pattern "${PATTERN}"
