#!/usr/bin/env sh
# Ship a sealed evidence bundle to the DMZ receiver.
#
# Deliberately a separate container from collection, because privilege and network reach
# are independent and neither component needs both:
#
#   collection  root + privileged (memory capture, host inspection)  ·  NO network at all
#   shipping    unprivileged, no host mounts                         ·  ONE outbound target
#
# The component with root cannot reach the network. The component with network access sees
# only a sealed tarball on a volume and has no view of the host. A compromise of either
# yields materially less than a compromise of one container holding both.
#
#   RECEIVER_URL   required, e.g. https://dmz.example:8090
#   BUNDLE         path to the sealed .tar.gz (default /evidence/bundle.tar.gz)
#   CA_BUNDLE      optional CA for the receiver's TLS
set -eu

RECEIVER_URL="${RECEIVER_URL:?RECEIVER_URL is required}"
BUNDLE="${BUNDLE:-/evidence/bundle.tar.gz}"

[ -r "${BUNDLE}" ] || { echo "[ship] no bundle at ${BUNDLE}" >&2; exit 2; }

SIZE=$(stat -c%s "${BUNDLE}")
SHA=$(sha256sum "${BUNDLE}" | awk '{print $1}')
echo "[ship] ${BUNDLE} (${SIZE} bytes, sha256=${SHA%"${SHA#????????????????}"}…) -> ${RECEIVER_URL}/ingest"

# `-T` streams the file from disk. `--data-binary @file` reads all of it into memory first.
#
# A bundle is sized by the endpoint's RAM, so buffering it needs about as much memory again as
# the machine has. The kernel OOM-kills curl and the only output is `Killed` — which names
# nothing, and reads as the receiver rejecting the upload rather than the client dying before
# it sent anything. `-T` with an explicit `-X POST` streams the body and sets Content-Length
# from the file size, which is what the receiver reads the request against.
#
# The timeout is hours, not one hour: the transfer is bounded by the size of a memory image
# over whatever link the endpoint has, and a capture that ships at 10 Mb/s needs longer than
# 3600s to move.
set -- --fail --show-error --silent \
       --max-time "${SHIP_TIMEOUT:-14400}" \
       --retry "${SHIP_RETRIES:-3}" --retry-delay 10 --retry-connrefused \
       -X POST -T "${BUNDLE}" \
       -H "Content-Type: application/gzip"
# ---- transport security ---------------------------------------------------
# What goes up this connection is a memory image: every credential, key, token and open file
# the host had in RAM. The custody seal proves the bundle was not ALTERED in transit; it does
# nothing to stop it being READ. An endpoint under suspicion is usually on a segment the
# responder neither controls nor trusts, which is the case this has to hold up in.
#
# Server verification is what stops the collector handing the machine's memory to whoever
# answers on that address. curl verifies by default; CA_BUNDLE points at the DMZ's CA when the
# receiver uses an internal PKI rather than a publicly-trusted certificate.
[ -n "${CA_BUNDLE:-}" ] && set -- "$@" --cacert "${CA_BUNDLE}"

# A client certificate, when the receiver requires one, keeps third parties from filling its
# holding volume or planting bundles. It is NOT a defense against a hostile endpoint — this host
# is presumed compromised, so a key stored on it is presumed readable by the adversary too.
[ -n "${CLIENT_CERT:-}" ] && set -- "$@" --cert "${CLIENT_CERT}"
[ -n "${CLIENT_KEY:-}" ]  && set -- "$@" --key "${CLIENT_KEY}"

case "${RECEIVER_URL}" in
    https://*) : ;;
    *)
        # Plaintext has to be chosen explicitly and out loud. Defaulting to it, or quietly
        # downgrading when TLS fails, produces a collection that looks successful while the
        # host's memory crossed the wire in the clear — and nobody finds out until it matters.
        if [ "${SHIP_ALLOW_PLAINTEXT:-0}" != "1" ]; then
            echo "[ship] REFUSING to send evidence over ${RECEIVER_URL%%:*}." >&2
            echo "[ship]   This bundle contains the host's memory: credentials, keys, open files." >&2
            echo "[ship]   Use an https:// receiver, or set SHIP_ALLOW_PLAINTEXT=1 for a" >&2
            echo "[ship]   loopback/single-host test where nothing untrusted is on the path." >&2
            exit 2
        fi
        echo "[ship] WARNING: sending evidence in PLAINTEXT — readable by anything on the path." >&2
        ;;
esac

# The receiver terminates the connection after accepting; there is no channel back into
# this container beyond the response body.
if RESPONSE=$(curl "$@" "${RECEIVER_URL}/ingest"); then
    echo "[ship] accepted: ${RESPONSE}"
else
    echo "[ship] transfer failed — the bundle remains on the volume and can be re-sent" >&2
    exit 1
fi
