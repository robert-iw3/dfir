#!/bin/sh
# Launch the locked-down analyst browser.
#
# The container is attached only to the tunnel-side network (no internet gateway) and
# resolves names via the DMZ CoreDNS, so the ONLY origin it can reach is the platform's
# SSO-gated frontend — which is also the only origin the STIG policy's WebsiteFilter
# permits. Kiosk mode keeps the analyst in that one app.
set -eu

URL="${IR_PLATFORM_URL:-https://ir-platform.local:8443/}"
PROFILE="${HOME}/profile"
mkdir -p "$PROFILE"

# Firefox's own content-process sandbox needs to write /proc/self/uid_map, which requires
# user-namespace privileges this container deliberately drops (cap_drop ALL +
# no-new-privileges) — without this, content processes crash and pages never render. The
# CONTAINER is the isolation boundary here (dropped caps, no-new-privileges, and an edge
# network with no internet gateway), so Firefox's inner sandbox is redundant, not load-bearing.
export MOZ_DISABLE_CONTENT_SANDBOX="${MOZ_DISABLE_CONTENT_SANDBOX:-1}"
export MOZ_DISABLE_GMP_SANDBOX="${MOZ_DISABLE_GMP_SANDBOX:-1}"

# Trust the platform's CA so the SSO-gated frontend loads without a TLS interstitial.
# Mounted at run time (never baked in) from traefik/certs/ir-platform.crt.
CA=/certs/ir-platform.crt
if [ -f "$CA" ]; then
    mkdir -p /usr/lib/firefox-esr/distribution/certificates
    cp "$CA" /usr/lib/firefox-esr/distribution/certificates/ir-platform.crt 2>/dev/null || true
    cp "$CA" /usr/local/share/ca-certificates/ir-platform.crt 2>/dev/null || true
    update-ca-certificates >/dev/null 2>&1 || true
    echo "[browser] platform CA installed as trusted"
else
    echo "[browser] WARNING: platform CA not mounted at ${CA} — expect a TLS warning" >&2
fi

echo "[browser] STIG policy: $(test -f /usr/lib/firefox-esr/distribution/policies.json && echo present || echo MISSING)"
echo "[browser] target: ${URL}"
echo "[browser] DISPLAY=${DISPLAY:-<unset>}"

if [ -z "${DISPLAY:-}" ]; then
    echo "[browser] DISPLAY not set — run with -e DISPLAY and the X socket bind-mounted:" >&2
    echo "          -v /tmp/.X11-unix:/tmp/.X11-unix:ro -e DISPLAY=\$DISPLAY" >&2
    exit 2
fi

# --kiosk keeps it full-screen with no chrome to navigate elsewhere; the profile is
# ephemeral (SanitizeOnShutdown in policy also clears state).
exec firefox-esr \
    --profile "$PROFILE" \
    --no-remote \
    ${IR_BROWSER_KIOSK:+--kiosk} \
    "$URL"
