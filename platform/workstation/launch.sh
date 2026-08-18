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

# Titles Firefox shows when the tab is somewhere the analyst cannot leave: the enterprise
# block page and the network error pages. A kiosk has no chrome, so landing on one of these
# strands the workstation until someone restarts the container.
STUCK_TITLES='Blocked Page|Problem loading|Server Not Found|Unable to connect|Secure Connection Failed|did not connect'

# True when the visible window is one of those, twice running — one sample would restart a
# page that was mid-load.
kiosk_stranded() {
    command -v xdotool >/dev/null 2>&1 || return 1
    _t="$(DISPLAY="${DISPLAY:-:0}" xdotool getactivewindow getwindowname 2>/dev/null)"
    case "${_t}" in
        "") return 1 ;;
    esac
    echo "${_t}" | grep -qE "${STUCK_TITLES}"
}

PROBE_SECONDS="${IR_KIOSK_PROBE_SECONDS:-20}"

# Alive means the origin ANSWERED, judged on the first status line rather than on wget's exit
# status. Every path here is SSO-gated, so a 302 towards Keycloak is what a healthy ingress
# returns; requiring the whole redirect chain to succeed made the verdict depend on the login
# flow, and busybox wget has no option to stop following it.
#
# This is also what the remedy can fix: reopening the kiosk reaches a login page, so "the origin
# is answering" is the only condition under which restarting the browser helps at all.
platform_answers() {
    wget -S --spider --no-check-certificate --timeout=8 --tries=2 "$URL" 2>&1 \
        | grep -qE 'HTTP/[0-9.]+ [0-9][0-9][0-9]'
}

# Reopening the kiosk discards the analyst's authenticated session, so it takes a sustained
# outage rather than one dropped probe. Two samples is the floor below which a single blip
# still restarts the browser.
DOWN_SECONDS="${IR_KIOSK_DOWN_SECONDS:-60}"
DOWN_SAMPLES=$(( DOWN_SECONDS / PROBE_SECONDS ))
[ "${DOWN_SAMPLES}" -ge 2 ] || DOWN_SAMPLES=2

# A kiosk stranded on an error page recovers itself. The supervision loop below only restarts
# Firefox when Firefox EXITS, so the two checks here are what cover the rest: the platform
# going away, and the browser being left somewhere else.
watchdog() {
    was_up=1
    stuck=0
    down=0
    while :; do
        sleep "${PROBE_SECONDS}"
        if kiosk_stranded; then
            stuck=$((stuck + 1))
            if [ "${stuck}" -ge 2 ]; then
                echo "[watchdog] kiosk is stranded off the platform — reopening ${URL}" >&2
                pkill -f firefox-esr 2>/dev/null || true
                stuck=0
                continue
            fi
        else
            stuck=0
        fi
        if platform_answers; then
            if [ "$was_up" = "0" ]; then
                echo "[watchdog] platform answering again — reopening the kiosk on it" >&2
                pkill -f firefox-esr 2>/dev/null || true
            fi
            was_up=1
            down=0
        else
            down=$((down + 1))
            # `if`, not `[ ... ] && echo`: under `set -e` a trailing test that evaluates
            # false ends the watchdog, and a supervisor that exits silently is worse than
            # the wedge it exists to clear.
            if [ "${down}" -ge "${DOWN_SAMPLES}" ] && [ "$was_up" = "1" ]; then
                echo "[watchdog] platform stopped answering for ${DOWN_SECONDS}s — waiting for it" >&2
                was_up=0
            fi
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
