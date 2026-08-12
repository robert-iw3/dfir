#!/usr/bin/env bash
# Certificate for the evidence receiver — the one endpoint a suspected host connects to.
#
# Separate from the platform's web certificate on purpose. That one is presented to analysts
# inside the tunnel; this one is presented to machines the responder does not trust, on networks
# the responder does not control.
#
# Self-signed by default so a deployment is secure out of the box rather than secure once
# somebody gets around to it. The collector pins THIS FILE as its trust anchor, so a self-signed
# leaf is a complete answer for a closed evidence path: there is exactly one server the
# collector should ever talk to, and pinning it is stronger than trusting a public CA that would
# vouch for anyone.
#
#   ./gen-receiver-cert.sh [--force]
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS="${IR_RECEIVER_CERT_DIR:-${HERE}/certs}"

# Every name and address an endpoint might legitimately dial. A responder points the collector
# at whatever the DMZ is reachable as from the endpoint's segment, and a certificate that does
# not cover that name fails verification — which, correctly, aborts the shipment.
PRIMARY="${IR_RECEIVER_HOST:-receiver}"
EXTRA_SANS="${IR_RECEIVER_SANS:-}"

mkdir -p "${CERTS}"
if [[ -f "${CERTS}/receiver.crt" && "${1:-}" != "--force" ]]; then
    echo "[gen-receiver-cert] cert already exists (use --force to regenerate)"; exit 0
fi

SAN="DNS:${PRIMARY},DNS:localhost,IP:127.0.0.1"
if [[ -n "${EXTRA_SANS}" ]]; then
    # Accept a comma-separated list of bare names/addresses and tag each correctly: an address
    # in a DNS SAN is not matched by any client, so a mistagged entry fails at the worst moment.
    IFS=',' read -ra _s <<<"${EXTRA_SANS}"
    for n in "${_s[@]}"; do
        n="${n//[[:space:]]/}"; [[ -z "${n}" ]] && continue
        if [[ "${n}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then SAN="${SAN},IP:${n}"
        else SAN="${SAN},DNS:${n}"; fi
    done
fi

openssl req -x509 -newkey rsa:4096 -nodes \
    -keyout "${CERTS}/receiver.key" \
    -out "${CERTS}/receiver.crt" \
    -days 825 \
    -subj "/CN=${PRIMARY}" \
    -addext "subjectAltName=${SAN}" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth" 2>/dev/null

# The key is read by the receiver process only. Evidence confidentiality depends on it: anyone
# who can read it can impersonate the receiver and be handed a host's memory.
chmod 600 "${CERTS}/receiver.key"
chmod 644 "${CERTS}/receiver.crt"
echo "[gen-receiver-cert] wrote ${CERTS}/receiver.{crt,key}"
echo "[gen-receiver-cert]   SAN: ${SAN}"
echo "[gen-receiver-cert]   collectors must trust receiver.crt (ship.sh: CA_BUNDLE=<path>)"
