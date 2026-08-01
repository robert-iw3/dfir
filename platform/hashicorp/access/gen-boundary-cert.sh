#!/usr/bin/env bash
# Certificate for the Boundary controller's API listener.
#
# WHAT RIDES ON THIS LISTENER. The session client authenticates against it with the analyst's
# password and then asks it to authorize a session. Without TLS both cross the DMZ-to-enclave link
# in the clear — the credential that mints enclave access, and the token that is that access.
#
# Only the `api` and `ops` listeners take TLS configuration at all. Boundary's `cluster` and
# `proxy` listeners negotiate their own ephemeral, mutually-authenticated TLS from the worker-auth
# material, so worker registration and session data are already encrypted and are not configured
# here. This certificate covers the one flow Boundary leaves to the operator.
#
# Separate from the receiver's, headscale's and the platform's web certificate. Four different
# trust relationships; one certificate across them ties the access broker's rotation to the
# console's, and a compromise of any to all.
#
# Self-signed by default, because the clients PIN it (BOUNDARY_CACERT) rather than consulting a
# trust store. There is exactly one controller they should ever talk to.
#
#   ./gen-boundary-cert.sh [--force]
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS="${IR_BOUNDARY_CERT_DIR:-${HERE}/certs}"

# The name the DMZ session client dials, which must match BOUNDARY_HOST.
PRIMARY="${BOUNDARY_HOST:-boundary}"
EXTRA_SANS="${IR_BOUNDARY_SANS:-}"

mkdir -p "${CERTS}"
if [[ -f "${CERTS}/boundary.crt" && "${1:-}" != "--force" ]]; then
    echo "[gen-boundary-cert] cert already exists (use --force to regenerate)"; exit 0
fi

# 127.0.0.1 is here because provisioning runs inside the controller's own container and talks to
# the same listener over loopback. Without it the recovery-KMS calls fail verification against a
# certificate that is otherwise correct.
SAN="DNS:${PRIMARY},DNS:localhost,IP:127.0.0.1"
if [[ -n "${EXTRA_SANS}" ]]; then
    # A multi-host deployment adds the enclave's routable name or address. An address in a DNS SAN
    # matches nothing, so each entry is tagged by shape rather than assumed to be a name.
    IFS=',' read -ra _s <<<"${EXTRA_SANS}"
    for n in "${_s[@]}"; do
        n="${n//[[:space:]]/}"; [[ -z "${n}" ]] && continue
        if [[ "${n}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then SAN="${SAN},IP:${n}"
        else SAN="${SAN},DNS:${n}"; fi
    done
fi

openssl req -x509 -newkey rsa:4096 -nodes \
    -keyout "${CERTS}/boundary.key" \
    -out "${CERTS}/boundary.crt" \
    -days 825 \
    -subj "/CN=${PRIMARY}" \
    -addext "subjectAltName=${SAN}" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth" 2>/dev/null

# Read by the controller only. Anyone holding it can impersonate the access broker: collect the
# analyst's password and hand back a token of their own choosing.
chmod 600 "${CERTS}/boundary.key"
chmod 644 "${CERTS}/boundary.crt"
echo "[gen-boundary-cert] wrote ${CERTS}/boundary.{crt,key}"
echo "[gen-boundary-cert]   SAN: ${SAN}"
echo "[gen-boundary-cert]   clients pin boundary.crt via BOUNDARY_CACERT"
