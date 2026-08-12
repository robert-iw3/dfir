#!/usr/bin/env bash
# Generate a self-signed TLS cert for the IR Platform web UI (local/dev).
# Production terminates TLS with a real cert (ACME or org PKI) — same Traefik config.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS="${HERE}/certs"
DOMAIN="${IR_PLATFORM_DOMAIN:-ir-platform.local}"
# The tailnet control plane serves its EMBEDDED DERP relay over the same certificate, and
# tailscale will not use a DERP relay without TLS. Nodes dial it by the name in HEADSCALE_ADDR,
# so that name has to appear in the SAN or every node falls back to direct-only connectivity
# with no relay behind it.
HEADSCALE_SAN="${HEADSCALE_ADDR:-headscale:8080}"
HEADSCALE_SAN="${HEADSCALE_SAN%%:*}"
mkdir -p "${CERTS}"

if [[ -f "${CERTS}/ir-platform.crt" && "${1:-}" != "--force" ]]; then
    echo "[gen-cert] cert already exists (use --force to regenerate)"; exit 0
fi

openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "${CERTS}/ir-platform.key" \
    -out "${CERTS}/ir-platform.crt" \
    -days 825 \
    -subj "/CN=${DOMAIN}" \
    -addext "subjectAltName=DNS:${DOMAIN},DNS:localhost,DNS:headscale,DNS:${HEADSCALE_SAN},IP:127.0.0.1"
chmod 644 "${CERTS}/ir-platform.crt" "${CERTS}/ir-platform.key"
echo "[gen-cert] wrote ${CERTS}/ir-platform.{crt,key} (CN=${DOMAIN}, SAN incl. ${HEADSCALE_SAN})"
