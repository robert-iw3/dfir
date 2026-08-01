#!/usr/bin/env bash
# Provision a Volatility symbol table into the enclave, end to end.
#
# Runs on the internet-connected acquisition machine. It selects a builder matching the
# TARGET's distribution release, acquires the DWARF, converts it to an ISF, seals it, and
# ships it over the same one-way path evidence takes — the DMZ receiver, drained inward by
# the enclave puller. The enclave itself never reaches the internet.
#
#   ./provision.sh --requisites <bundle>/_symbols.json
#   ./provision.sh --requisites ~/ir-symbols/requisites/_symbols.json --store ~/ir-symbols/store
#   ./provision.sh --requisites ... --acquire-only     # build the ISF, do not ship it
#   ./provision.sh --isf <file.json> --key <symbol_key>  # ship an ISF acquired earlier
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"
RUNTIME="${IR_RUNTIME:-podman}"

REQ=""
STORE="${IR_SYMBOL_STORE:-${HOME}/ir-symbols/store}"
ISF=""
KEY=""
ACQUIRE_ONLY=0
SHIP_ONLY=0

c_grn=$'\e[1;32m'; c_ylw=$'\e[1;33m'; c_red=$'\e[1;31m'; c_cyn=$'\e[1;36m'; c_off=$'\e[0m'
say()  { printf '\n%s==> %s%s\n' "$c_cyn" "$1" "$c_off"; }
ok()   { printf '    %s✔%s %s\n' "$c_grn" "$c_off" "$1"; }
warn() { printf '    %s!%s %s\n' "$c_ylw" "$c_off" "$1"; }
die()  { printf '    %s✘%s %s\n' "$c_red" "$c_off" "$1" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --requisites) REQ="$2"; shift 2 ;;
        --store) STORE="$2"; shift 2 ;;
        --isf) ISF="$2"; SHIP_ONLY=1; shift 2 ;;
        --key) KEY="$2"; shift 2 ;;
        --acquire-only) ACQUIRE_ONLY=1; shift ;;
        *) die "unknown option: $1" ;;
    esac
done

field() { python3 -c "
import json,sys
d=json.load(open('$1'))
cur=d
for k in '$2'.split('.'):
    cur=(cur or {}).get(k) if isinstance(cur,dict) else None
print(cur or '')" 2>/dev/null; }

# ---------------------------------------------------------------- acquire
if [[ "${SHIP_ONLY}" -eq 0 ]]; then
    [[ -r "${REQ}" ]] || die "--requisites is required and must be readable"
    mkdir -p "${STORE}"

    KREL="$(field "${REQ}" kernel_release)"
    DISTRO="$(field "${REQ}" os_release.ID)"
    VERSION="$(field "${REQ}" os_release.VERSION_ID)"
    KEY="$(field "${REQ}" symbol_key)"
    [[ -n "${KREL}" ]] || die "requisites carry no kernel_release"
    [[ -n "${KEY}" ]] || KEY="${DISTRO:-linux}-${KREL}"

    say "Symbols · ${KREL} (${DISTRO:-unknown} ${VERSION:-?})"

    if [[ -s "${STORE}/${KEY}.json" ]]; then
        ok "already acquired: ${KEY}.json"
    else
        # The builder base must match the target's RELEASE, not merely its family: debug
        # packages are published per codename, so a builder on the wrong release finds
        # nothing even when the package exists.
        case "${DISTRO}" in
            ubuntu) BASE="docker.io/library/ubuntu:${VERSION:-24.04}"; FAMILY="debian" ;;
            debian) BASE="docker.io/library/debian:${VERSION:-12}"; FAMILY="debian" ;;
            "")     die "requisites carry no os_release.ID — cannot pick a builder" ;;
            *)      die "no builder for '${DISTRO}' yet (only Debian/Ubuntu exist)" ;;
        esac

        IMG="ir-symbols-${FAMILY}:${VERSION:-latest}"
        if ! ${RUNTIME} image exists "${IMG}" 2>/dev/null; then
            say "Building ${IMG} on ${BASE}"
            ${RUNTIME} build --build-arg BASE_IMAGE="${BASE}" -t "${IMG}" \
                -f "${HERE}/Dockerfile.${FAMILY}" "${HERE}" >/dev/null 2>&1 \
                || die "builder image failed to build"
            ok "builder ready"
        else
            ok "builder ${IMG} present"
        fi

        say "Acquiring DWARF and converting to ISF"
        warn "kernel debug symbols are ~2 GB — this takes several minutes"
        REQ_DIR="$(cd "$(dirname "${REQ}")" && pwd)"
        ${RUNTIME} run --rm --name ir-isf-acquire \
            -v "${REQ_DIR}":/work:ro,z -v "${STORE}":/out:z \
            -e ACQUIRE_TIMEOUT="${ACQUIRE_TIMEOUT:-3600}" \
            -e IR_REQUISITES="/work/$(basename "${REQ}")" \
            "${IMG}" || die "acquisition failed — see ../symbols/README.md"
        [[ -s "${STORE}/${KEY}.json" ]] || die "no ISF produced for ${KEY}"
        ok "ISF acquired: ${KEY}.json"
    fi

    ISF="${STORE}/${KEY}.json"
    [[ "${ACQUIRE_ONLY}" -eq 1 ]] && { ok "stopping after acquisition (--acquire-only)"; exit 0; }
fi

[[ -r "${ISF}" ]] || die "no ISF to ship (${ISF:-unset})"
[[ -n "${KEY}" ]] || die "--key is required when shipping an ISF directly"

# ---------------------------------------------------------------- seal + ship
say "Sealing for transfer"
BUNDLE_DIR="$(mktemp -d)"
trap 'rm -rf "${BUNDLE_DIR}"' EXIT
set -a; . "${PLATFORM}/deploy/.env"; set +a
python3 "${HERE}/seal_isf.py" "${ISF}" "${KEY}" --out "${BUNDLE_DIR}" >/dev/null \
    || die "sealing failed"
BUNDLE="${BUNDLE_DIR}/${KEY}.isf.tar.gz"
ok "sealed $(du -h "${BUNDLE}" | cut -f1) bundle"

say "Shipping to the DMZ receiver"
# Resolved rather than hardcoded: the receiver's address is assigned by the runtime and
# changes whenever the tier is recreated.
RECV_IP="$(${RUNTIME} inspect ir-dmz_receiver_1 \
    --format '{{with index .NetworkSettings.Networks "ir-dmzlink"}}{{.IPAddress}}{{end}}' 2>/dev/null)"
[[ -n "${RECV_IP}" ]] || die "the DMZ receiver is not running on ir-dmzlink"

RESP="$(${RUNTIME} run --rm --network ir-dmzlink -v "${BUNDLE_DIR}":/b:ro,z \
    docker.io/library/alpine:3.24 sh -c \
    "apk add --no-cache -q curl >/dev/null 2>&1; \
     curl -s --max-time 300 -X POST --data-binary @/b/$(basename "${BUNDLE}") \
     http://${RECV_IP}:8090/isf" 2>&1 | tail -1)"
printf '%s' "${RESP}" | grep -q '"verified": *true' \
    || die "receiver rejected the bundle: ${RESP}"
ok "receiver accepted and verified it"

say "Waiting for the enclave to pull it inward"
# The enclave initiates; nothing is pushed into it. Poll the store the worker reads.
for _ in $(seq 1 30); do
    if ${RUNTIME} exec ir-enclave_worker_1 test -f "/symbols/${KEY}.json" 2>/dev/null; then
        COUNT="$(${RUNTIME} exec ir-enclave_worker_1 sh -c \
            "python3 -c \"import json;print(len(json.load(open('/symbols/${KEY}.json')).get('symbols',{})))\"" 2>/dev/null)"
        ok "installed in the enclave symbol store (${COUNT:-?} symbols)"
        say "Done — captures for ${KEY} will now get the full Volatility pass"
        exit 0
    fi
    sleep 5
done
die "the puller did not install it within 150s — check: ${RUNTIME} logs ir-enclave_puller_1"
