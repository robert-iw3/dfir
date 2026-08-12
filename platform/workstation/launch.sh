#!/bin/sh
# Launch the locked-down analyst browser. The container is attached only to the tunnel-side
# network (no internet gateway) and resolves names via the DMZ CoreDNS, so the ONLY origin it
# can reach is the platform's SSO-gated frontend — which is also the only origin the STIG
# policy's WebsiteFilter permits.
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

# The workstation announces itself in the User-Agent: every hop between this browser and the
# enclave ingress is L4 under end-to-end TLS, so nothing on the path can say which workstation
# carried a request — only the kiosk itself can. The platform reads the token into the sign-on
# record for attribution.
ua_override() {
    [ -n "${IR_WS_ID:-}" ] || return 0
    ver="$(firefox-esr --version 2>/dev/null | sed -n 's/.* \([0-9][0-9]*\)\..*/\1/p')"
    [ -n "$ver" ] || ver=140
    printf 'user_pref("general.useragent.override", "Mozilla/5.0 (X11; Linux x86_64; rv:%s.0) Gecko/20100101 Firefox/%s.0 IR-WS/%s");\n' \
        "$ver" "$ver" "${IR_WS_ID}" > "$PROFILE/user.js"
    echo "[browser] User-Agent announces workstation ${IR_WS_ID}"
}

# A kiosk stranded on an error page recovers itself. The supervision loop below only restarts
# Firefox when Firefox EXITS.
watchdog() {
    was_up=1
    while :; do
        sleep "${IR_KIOSK_PROBE_SECONDS:-20}"
        if wget -q --spider --no-check-certificate --timeout=8 --tries=1 "$URL" 2>/dev/null; then
            if [ "$was_up" = "0" ]; then
                echo "[watchdog] platform answering again — reopening the kiosk on it" >&2
                pkill -f firefox-esr 2>/dev/null || true
            fi
            was_up=1
        else
            # `if`, not `[ ... ] && echo`: under `set -e` a trailing test that evaluates
            # false ends the watchdog, and a supervisor that exits silently is worse than
            # the wedge it exists to clear.
            if [ "$was_up" = "1" ]; then
                echo "[watchdog] platform stopped answering — waiting for it" >&2
            fi
            was_up=0
        fi
    done
}
watchdog &

# --kiosk keeps it full-screen with no chrome to navigate elsewhere. Supervised rather than
# exec'd, and the profile is DISCARDED before every start.
while :; do
    rm -rf "$PROFILE"
    mkdir -p "$PROFILE"
    ua_override
    echo "[browser] clean profile — opening ${URL}"
    firefox-esr \
        --profile "$PROFILE" \
        --no-remote \
        ${IR_BROWSER_KIOSK:+--kiosk} \
        "$URL" || true
    echo "[browser] session ended — clearing authentication state and reopening ${URL}" >&2
    sleep 2
done
