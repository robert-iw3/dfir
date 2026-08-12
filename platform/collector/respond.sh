#!/usr/bin/env bash
# ONE COMMAND, RUN ON THE SUSPECTED ENDPOINT, AS ROOT: collect, seal, ship to the DMZ receiver.
#   sudo ./respond.sh --receiver https://dmz.example.net:8090 --incident INC-2026-0043
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNTIME="${IR_RUNTIME:-podman}"
IMAGE="${IR_COLLECTOR_IMAGE:-localhost/ir-collector:latest}"

RECEIVER="${RECEIVER_URL:-}"
INCIDENT="${IR_INCIDENT_ID:-}"
EVIDENCE="${IR_EVIDENCE_DIR:-}"
HMAC_KEY="${IR_CUSTODY_HMAC_KEY:-}"
HOSTNAME_OVERRIDE="${IR_HOSTNAME:-}"
KEEP_EVIDENCE=0
SHIP_ONLY=0
COLLECT_ONLY=0
# Container network for the shipping step — empty means the runtime default, which is what a real
# endpoint uses to reach a receiver on other hardware.
SHIP_NETWORK="${IR_SHIP_NETWORK:-}"
# The receiver's certificate. Defaults to the one this checkout generated, so a single-host
# validation run verifies properly instead of teaching operators to skip verification.
CA_CERT="${IR_RECEIVER_CA:-}"
[[ -z "${CA_CERT}" && -r "${HERE}/../dmz/certs/receiver.crt" ]] && CA_CERT="${HERE}/../dmz/certs/receiver.crt"

say()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '    \033[1;32m✔\033[0m %s\n' "$*"; }
warn() { printf '    \033[1;33m!\033[0m %s\n' "$*" >&2; }
die()  { printf '\n\033[1;31mSTOPPED\033[0m %s\n\n' "$*" >&2; exit 1; }
# Defined, not assumed. Without it the shell resolves `info` to GNU info(1), which prints a
# manual-browser error where an operator expected a status line — during an incident that reads
# as the collection having gone wrong.
info() { printf '    \033[0;37m%s\033[0m\n' "$*"; }

usage() {
    cat >&2 <<EOF
Usage: sudo ./respond.sh --receiver <URL> [options]

  --receiver <URL>    DMZ receiver, e.g. https://dmz.example.net:8090   (required)
  --incident <ID>     Incident this collection belongs to               (required)
  --evidence <DIR>    Where to write evidence (default /var/tmp/ir-evidence-<incident>)
  --hostname <NAME>   Override the detected hostname (use when /etc/hostname is wrong)
  --hmac-key <KEY>    Custody signing key; without it the bundle is sealed but unsigned
  --keep              Leave the evidence directory in place after a successful ship
  --collect-only      Collect and seal; do not ship
  --ship-only         Ship an evidence directory collected earlier
  --ca-cert <FILE>    Receiver's certificate, pinned to verify the upload. Defaults to
                      dmz/certs/receiver.crt when present.
  --network <NET>     Container network for shipping. Only needed when the receiver is
                      co-located on a container network (single-host validation); a real
                      endpoint reaches it over the ordinary network and needs no flag.
EOF
    exit 2
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --receiver) RECEIVER="${2:-}"; shift 2 ;;
        --incident) INCIDENT="${2:-}"; shift 2 ;;
        --evidence) EVIDENCE="${2:-}"; shift 2 ;;
        --hostname) HOSTNAME_OVERRIDE="${2:-}"; shift 2 ;;
        --hmac-key) HMAC_KEY="${2:-}"; shift 2 ;;
        --keep) KEEP_EVIDENCE=1; shift ;;
        --collect-only) COLLECT_ONLY=1; shift ;;
        --ship-only) SHIP_ONLY=1; shift ;;
        --network) SHIP_NETWORK="${2:-}"; shift 2 ;;
        --ca-cert) CA_CERT="${2:-}"; shift 2 ;;
        -h|--help) usage ;;
        *) echo "unknown option: $1" >&2; usage ;;
    esac
done

# ---------------------------------------------------------------- preflight
say "Checks"

# Memory acquisition needs CAP_SYS_ADMIN over the host's /proc/iomem, which a rootless
# container cannot hold however privileged it is declared. Saying so here is the difference
# between a two-second correction and a completed collection that silently contains a synthetic
# sample instead of the host's memory.
if (( ! SHIP_ONLY )); then
    [[ "$(id -u)" -eq 0 ]] || die "run as root: memory acquisition needs CAP_SYS_ADMIN over the
        host's /proc/iomem, and a rootless container cannot hold it. Re-run with sudo."
else
    # Shipping needs no privilege: it reads a directory and POSTs it. Demanding root here would
    # be least-privilege backwards, and on a deployment whose receiver is reachable only from
    # an unprivileged container network it would block the one path that works.
    [[ "$(id -u)" -eq 0 ]] && ok "running as root (not required for shipping)" \
        || ok "running unprivileged — shipping needs no capabilities"
fi

command -v "${RUNTIME}" >/dev/null 2>&1 || die "${RUNTIME} is not installed on this host."

# Shipping takes the incident from the SEALED EVIDENCE, not from the command line. It was
# recorded at collection time and travels inside the bundle, so asking for it again invites an
# operator to type a different one under pressure — and a bundle shipped under an incident that
# contradicts its own contents is worse than one that never shipped.
if (( SHIP_ONLY )) && [[ -z "${INCIDENT}" && -n "${EVIDENCE}" ]]; then
    INCIDENT="$(python3 - "${EVIDENCE}" <<'PY' 2>/dev/null
import glob, json, os, sys
for path in glob.glob(os.path.join(sys.argv[1], "reports", "*", "_status.json")):
    try:
        v = json.load(open(path)).get("incident_id")
    except Exception:
        continue
    if v:
        print(v); break
PY
)"
    [[ -n "${INCIDENT}" ]] && ok "incident read from the sealed evidence: ${INCIDENT}"
fi

[[ -n "${INCIDENT}" ]] || die "--incident is required. It ties this collection to its
        investigation; without it every host files under the default and the incident cannot
        be reconstructed."

if (( ! COLLECT_ONLY )); then
    [[ -n "${RECEIVER}" ]] || die "--receiver is required (or --collect-only to seal without
        shipping). Example: --receiver https://dmz.example.net:8090"
fi

if ! "${RUNTIME}" image exists "${IMAGE}" 2>/dev/null; then
    # Collection runs as root and reads ROOT's image store, a different store from a rootless build's
    # — 'missing' is the expected result of building rootless, not an error.
    if [[ -n "${SUDO_USER:-}" ]] \
       && sudo -u "${SUDO_USER}" "${RUNTIME}" image exists "${IMAGE}" 2>/dev/null; then
        die "${IMAGE} exists in ${SUDO_USER}'s image store but not root's, and collection runs as
        root. Copy it across, then re-run this command:

          sudo -u ${SUDO_USER} ${RUNTIME} save ${IMAGE} -o /var/tmp/ir-collector.tar
          ${RUNTIME} load -i /var/tmp/ir-collector.tar"
    fi
    die "${IMAGE} is not present. This host has no route to a registry by design; load the
        image from media:  ${RUNTIME} load -i ir-collector.tar"
fi

EVIDENCE="${EVIDENCE:-/var/tmp/ir-evidence-${INCIDENT}}"
mkdir -p "${EVIDENCE}" || die "cannot create ${EVIDENCE}"

# A memory image is the size of this host's RAM, and the bundle is written beside it, so the
# collection needs room for both. Checked before the capture rather than discovered part-way
# through: a capture that fills the disk takes the host down with it.
ram_kb="$(awk '/^MemTotal:/{print $2}' /proc/meminfo 2>/dev/null || echo 0)"
need_gib=$(( (ram_kb / 1024 / 1024) * 3 / 2 ))
free_gib="$(df -BG --output=avail "${EVIDENCE}" 2>/dev/null | tail -1 | tr -dc '0-9')"
free_gib="${free_gib:-0}"
ok "evidence: ${EVIDENCE} (${free_gib} GiB free)"
if (( need_gib > 0 && free_gib < need_gib )); then
    warn "this host has $((ram_kb / 1024 / 1024)) GiB RAM; the image plus its bundle needs"
    warn "about ${need_gib} GiB and ${EVIDENCE} has ${free_gib} GiB."
    warn "Point --evidence at a larger volume, or the capture may fail part-way."
fi
# Only meaningful when this run is going to collect. The seal is applied at collection time and
# travels inside the bundle, so shipping needs no key — warning about it here would tell an
# operator their already-signed evidence is unsigned, and invite a pointless re-collection.
if (( ! SHIP_ONLY )) && [[ -z "${HMAC_KEY}" ]]; then
    warn "no --hmac-key: the bundle will be sealed but not signed, so the receiver can verify"
    warn "it is internally consistent but not that it came from you."
fi

# ---------------------------------------------------------------- collect
if (( ! SHIP_ONLY )); then
    say "Collecting (no network — this container cannot call out)"
    collect_args=(
        run --rm --privileged --pid=host
        --network none
        -v /proc:/host/proc:ro
        -v /:/host/root:ro
        -v "${EVIDENCE}:/evidence"
        -e "IR_INCIDENT_ID=${INCIDENT}"
    )
    [[ -n "${HMAC_KEY}" ]] && collect_args+=(-e "IR_CUSTODY_HMAC_KEY=${HMAC_KEY}")
    [[ -n "${HOSTNAME_OVERRIDE}" ]] && collect_args+=(-e "IR_HOSTNAME=${HOSTNAME_OVERRIDE}")

    "${RUNTIME}" "${collect_args[@]}" "${IMAGE}" || die "collection failed — see the output above"

    # Hand ownership to whoever invoked sudo — not what makes the transfer work, but what makes the
    # evidence usable afterwards without root.
    owner_uid="${SUDO_UID:-0}"
    owner_gid="${SUDO_GID:-0}"
    if [[ "${owner_uid}" != "0" ]]; then
        chown -R "${owner_uid}:${owner_gid}" "${EVIDENCE}" \
            && ok "evidence owned by uid ${owner_uid} — readable without root"
    fi
fi

if (( COLLECT_ONLY )); then
    say "Collected, not shipped"
    ok "${EVIDENCE}"
    printf '    ship it later with:  sudo %s --ship-only --receiver <URL> --incident %s --evidence %s\n\n' \
        "$0" "${INCIDENT}" "${EVIDENCE}"
    exit 0
fi

# ---------------------------------------------------------------- ship
say "Shipping to ${RECEIVER}"
# No host mounts here, and the evidence is mounted read-only: this container has a network, so
# it gets no view of the host and no ability to alter what it is sending.
ship_args=(run --rm -v "${EVIDENCE}:/evidence:ro")
[[ -n "${SHIP_NETWORK}" ]] && ship_args+=(--network "${SHIP_NETWORK}") \
    && info "shipping on network ${SHIP_NETWORK}"

# The receiver's certificate, pinned as the trust anchor for this upload: verification is what
# stops this host's memory being handed to whoever answers on that port.
if [[ -n "${CA_CERT}" ]]; then
    [[ -r "${CA_CERT}" ]] || die "--ca-cert ${CA_CERT} is not readable; without it the upload
        cannot verify the receiver, and evidence must not be sent to an unverified server."
    ship_args+=(-v "${CA_CERT}:/ca/receiver.crt:ro")
    ship_args+=(-e "CA_BUNDLE=/ca/receiver.crt")
    ok "pinning the receiver certificate from ${CA_CERT}"
elif [[ "${RECEIVER}" == https://* ]]; then
    # A publicly-trusted certificate needs no pin; an internal one does, and silently falling
    # back to the system store would accept any CA the base image happens to trust.
    info "no --ca-cert given; verifying against the system trust store"
fi

ship_out="$("${RUNTIME}" "${ship_args[@]}" \
    -e "RECEIVER_URL=${RECEIVER}" \
    -e "SHIP_ALLOW_PLAINTEXT=${SHIP_ALLOW_PLAINTEXT:-0}" \
    --entrypoint sh "${IMAGE}" /opt/collector/ship.sh 2>&1)"
printf '%s\n' "${ship_out}" | sed 's/^/    /'

if grep -q '"verified": *true' <<<"${ship_out}"; then
    say "Done"
    ok "the receiver accepted and verified the bundle"
    printf '    Analysis runs in the enclave. Nothing further is reported to this host, and\n'
    printf '    nothing here needs to stay running.\n'
    if (( KEEP_EVIDENCE )); then
        ok "evidence kept at ${EVIDENCE}"
    else
        # The endpoint is the least trustworthy place this evidence could sit, and a copy left
        # behind is a copy nobody is tracking. The platform holds it now.
        rm -rf "${EVIDENCE}" && ok "local copy removed (the platform holds it; --keep to retain)"
    fi
    printf '\n'
    exit 0
fi

say "Not shipped"
# Distinguish 'the client died' from 'the receiver said no' — they look identical in a transcript
# and lead to different investigations.
if grep -qE '\bKilled\b|Cannot allocate memory|out of memory' <<<"${ship_out}"; then
    warn "the upload process was killed locally — the receiver never answered."
    printf '    This is the endpoint running out of memory, not the receiver refusing anything.\n'
    printf '    The bundle is %s; streaming it needs little memory, so if this recurs the host\n' \
        "$(du -h "${EVIDENCE}/bundle.tar.gz" 2>/dev/null | cut -f1)"
    printf '    is under real memory pressure — check for a cgroup limit on the container\n'
    printf '    runtime, or free memory before retrying.\n'
else
    warn "the receiver did not accept the bundle."
    printf '    Common causes, in the order worth checking:\n'
    printf '      · the receiver address or port is wrong, or is not reachable from this host.\n'
    printf '        Note %s must be reachable FROM THIS HOST — a container cannot use\n' "${RECEIVER}"
    printf '        127.0.0.1 to mean the machine it runs on.\n'
    printf '      · the receiver refused the size — it reports the limit and its free space\n'
    printf '      · custody verification failed, which the receiver names explicitly\n'
fi
printf '    The sealed evidence is intact at %s — nothing was lost.\n' "${EVIDENCE}"
printf '    Retry without re-collecting:\n'
printf '      sudo %s --ship-only --receiver %s --incident %s --evidence %s\n\n' \
    "$0" "${RECEIVER}" "${INCIDENT}" "${EVIDENCE}"
exit 1
