#!/usr/bin/env bash
# Certificate for the tailnet control plane and its embedded DERP relay.
#
# WHY DERP NEEDS THIS AT ALL. Tailscale will not use a DERP relay that is not served over TLS,
# and it does not fail loudly about it — the node comes up, reports itself connected, and simply
# has no relay.
#
# Separate from both the platform's web certificate and the receiver's. Three different trust
# relationships: analysts inside the tunnel, endpoints under suspicion, and tailnet nodes.
#
# Self-signed by default, because the nodes PIN it (SSL_CERT_FILE) rather than consulting a
# public trust store. There is exactly one control plane a node should ever talk to; pinning it
# is stronger than trusting any CA that would vouch for whoever holds a certificate for the name.
#
#   ./gen-headscale-cert.sh [--force]
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS="${IR_HEADSCALE_CERT_DIR:-${HERE}/certs}"

# The name every node dials. It must match what HEADSCALE_LOGIN_URL carries, or verification
# fails and the node never registers — the same value has to appear in the URL, in this SAN and
# in the DERP region headscale advertises, which is why all three are rendered from one variable.
PRIMARY="${IR_HEADSCALE_HOST:-headscale}"
EXTRA_SANS="${IR_HEADSCALE_SANS:-}"

mkdir -p "${CERTS}"
if [[ -f "${CERTS}/headscale.crt" && "${1:-}" != "--force" ]]; then
    echo "[gen-headscale-cert] cert already exists (use --force to regenerate)"; exit 0
fi

SAN="DNS:${PRIMARY},DNS:localhost,IP:127.0.0.1"
if [[ -n "${EXTRA_SANS}" ]]; then
    # A multi-host deployment adds the DMZ's routable hostname or address here. An address in a
    # DNS SAN matches nothing, so each entry is tagged by shape rather than assumed to be a name.
    IFS=',' read -ra _s <<<"${EXTRA_SANS}"
    for n in "${_s[@]}"; do
        n="${n//[[:space:]]/}"; [[ -z "${n}" ]] && continue
        if [[ "${n}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then SAN="${SAN},IP:${n}"
        else SAN="${SAN},DNS:${n}"; fi
    done
fi

openssl req -x509 -newkey rsa:4096 -nodes \
    -keyout "${CERTS}/headscale.key" \
    -out "${CERTS}/headscale.crt" \
    -days 825 \
    -subj "/CN=${PRIMARY}" \
    -addext "subjectAltName=${SAN}" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth" 2>/dev/null

# Read by headscale only. Anyone holding it can impersonate the control plane, which means
# issuing node keys and standing in the middle of every relayed session.
chmod 600 "${CERTS}/headscale.key"
chmod 644 "${CERTS}/headscale.crt"
echo "[gen-headscale-cert] wrote ${CERTS}/headscale.{crt,key}"
echo "[gen-headscale-cert]   SAN: ${SAN}"
echo "[gen-headscale-cert]   nodes pin headscale.crt via SSL_CERT_FILE"
