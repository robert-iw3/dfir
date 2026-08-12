#!/usr/bin/env sh
# Ship a sealed evidence bundle to the DMZ receiver.
#
# Deliberately a separate container from collection, because privilege and network reach
# are independent and neither component needs both:
#
#   collection  root + privileged (memory capture, host inspection)  ·  NO network at all
#   shipping    unprivileged, no host mounts                         ·  ONE outbound target
#
# The component with root cannot reach the network. The component with network access sees only
# a sealed tarball on a volume and has no view of the host.
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

# `-T` streams from disk; `--data-binary @file` buffers the whole bundle in memory. A bundle is
# sized by the endpoint's RAM, so buffering OOM-kills curl with no output but `Killed`.
set -- --fail --show-error --silent \
       --max-time "${SHIP_TIMEOUT:-14400}" \
       --retry "${SHIP_RETRIES:-3}" --retry-delay 10 --retry-connrefused \
       -X POST -T "${BUNDLE}" \
       -H "Content-Type: application/gzip"
# ---- transport security --------------------------------------------------- This carries a
# memory image: every credential, key, token and open file the host had in RAM. The custody seal
# proves the bundle was not ALTERED; it does nothing to stop it being READ, and the endpoint is
# usually on a segment the responder neither controls nor trusts.
[ -n "${CA_BUNDLE:-}" ] && set -- "$@" --cacert "${CA_BUNDLE}"

# A client certificate keeps third parties from filling the receiver's holding volume. NOT a
# defense against a hostile endpoint: this host is presumed compromised, so a key stored on it
# is presumed readable.
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
