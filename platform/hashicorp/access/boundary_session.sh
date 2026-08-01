#!/bin/sh
# The analyst's route into the enclave: a Boundary session, held open on the brokered port.
#
# Runs in the bastion's network namespace, so the listener binds the tailnet interface — the
# analyst reaches it over WireGuard and by no other path. The connection it accepts is carried by
# an authenticated, authorized, auditable session against one named target.
#
# It refuses to start unless it holds a session, and says which step failed when it cannot: a
# listener with nothing behind it looks identical to a working one.
#
# EVERY HOP FROM HERE IS ENCRYPTED. Authentication and authorization go to the controller's API
# over TLS pinned to its certificate; the session itself is proxied to the egress worker over the
# ephemeral mutually-authenticated TLS Boundary negotiates per session. Nothing on the
# DMZ-to-enclave link is in the clear.
set -u

: "${BOUNDARY_ADDR:?BOUNDARY_ADDR is required}"
: "${BOUNDARY_TARGET_ID:?BOUNDARY_TARGET_ID is required — run boundary_bootstrap.sh first}"
: "${BOUNDARY_AUTH_METHOD_ID:?BOUNDARY_AUTH_METHOD_ID is required}"
: "${BOUNDARY_ANALYST_LOGIN:=analyst}"
: "${BOUNDARY_ANALYST_PASSWORD:?BOUNDARY_ANALYST_PASSWORD is required}"
: "${BOUNDARY_CACERT:=/boundary/certs/boundary.crt}"
LISTEN_PORT="${BROKER_LISTEN:-8443}"

case "${BOUNDARY_ADDR}" in
    https://*) ;;
    # The analyst's password and the session token travel on this connection, across the one link
    # that leaves this tier. There is no deployment in which sending them in the clear is the
    # right default, so there is no flag to do it.
    *) echo "[broker] BOUNDARY_ADDR must be https:// — got ${BOUNDARY_ADDR}" >&2; exit 1 ;;
esac
[ -r "${BOUNDARY_CACERT}" ] || {
    echo "[broker] controller certificate not readable at ${BOUNDARY_CACERT}" >&2
    echo "[broker] run hashicorp/access/gen-boundary-cert.sh — verification is not optional here" >&2
    exit 1
}
export BOUNDARY_ADDR BOUNDARY_CACERT

echo "[broker] Boundary session broker — target ${BOUNDARY_TARGET_ID} on :${LISTEN_PORT}"
echo "[broker] controller ${BOUNDARY_ADDR}, pinned to $(basename "${BOUNDARY_CACERT}")"

# Authenticate as a real principal, so the session is attributable.
export BOUNDARY_PASSWORD="${BOUNDARY_ANALYST_PASSWORD}"

# Cancel this principal's leftover sessions. A replaced broker container abandons its session,
# which Boundary keeps "active" until expiry — the access record then over-counts live access.
# The list is filtered to sessions this principal can read, so only its own are visible.
reap_own_sessions() {
    [ -n "${BOUNDARY_PROJECT_ID:-}" ] || {
        echo "[broker] BOUNDARY_PROJECT_ID unset — stale sessions are not reaped"; return 0; }
    for _s in $(boundary sessions list -scope-id "${BOUNDARY_PROJECT_ID}" \
            -token env://BOUNDARY_TOKEN -format json 2>/dev/null \
            | grep -o '"id": *"s_[^"]*"' | cut -d'"' -f4); do
        boundary sessions cancel -id "${_s}" -token env://BOUNDARY_TOKEN >/dev/null 2>&1 \
            && echo "[broker] canceled stale session ${_s}"
    done
}

# Retries the real call and separates the two failures by what came back: a controller that is
# not answering is worth waiting on; a rejected credential never becomes valid, so it exits
# loudly instead of after two minutes of silence.
authenticate() {
    token=""
    i=1
    while [ "${i}" -le 60 ]; do
        auth_out="$(boundary authenticate password \
                -auth-method-id "${BOUNDARY_AUTH_METHOD_ID}" \
                -login-name "${BOUNDARY_ANALYST_LOGIN}" \
                -password env://BOUNDARY_PASSWORD \
                -format json 2>&1)"
        token="$(printf '%s' "${auth_out}" | grep -o '"token": *"[^"]*"' | head -1 | cut -d'"' -f4)"
        [ -n "${token}" ] && return 0

        case "${auth_out}" in
            *"connection refused"*|*"no such host"*|*"connect: "*|*"EOF"*|*"i/o timeout"*)
                [ "${i}" = 1 ] && echo "[broker] waiting for the controller at ${BOUNDARY_ADDR}"
                ;;
            *)
                # Wrong auth-method id, unset password, an unexpected response shape, a
                # certificate that does not verify — each says something different, so the
                # output is kept.
                echo "[broker] authentication to Boundary failed for ${BOUNDARY_ANALYST_LOGIN}:" >&2
                printf '%s\n' "${auth_out}" | tail -8 | sed 's/^/[broker]   /' >&2
                echo "[broker] The listener is NOT opened — an unauthenticated forwarder is not a fallback." >&2
                exit 1
                ;;
        esac
        i=$((i + 1))
        sleep 2
    done
    return 1
}

trap 'echo "[broker] terminating — canceling the session"; reap_own_sessions; exit 0' TERM INT

# THE SESSION IS SUPERVISED. `boundary connect` is one session: it exits whenever that session
# ends — the controller rebuilt, the egress worker recreated, the session's own expiry, a fatal
# proxy error. The analyst workstation runs on an endpoint device and cannot know any of that
# happened; it just sees a dead listener. So every exit re-authenticates and re-establishes
# here, and the listener is back within seconds of the enclave answering — no redeploy, no
# operator. A SIGKILL skips the trap; the reap at the top of the loop cancels whatever session
# that abandoned.
#
# `boundary connect` authorizes the session, opens the listener and proxies through the enclave
# egress worker to the target, so the browser reaches the SSO gate without the bastion having a
# route of its own.
while :; do
    if ! authenticate; then
        echo "[broker] the controller never answered at ${BOUNDARY_ADDR} — retrying" >&2
        sleep 5
        continue
    fi
    export BOUNDARY_TOKEN="${token}"
    echo "[broker] authenticated as ${BOUNDARY_ANALYST_LOGIN}"
    reap_own_sessions

    boundary connect \
        -token env://BOUNDARY_TOKEN \
        -target-id "${BOUNDARY_TARGET_ID}" \
        -listen-addr 0.0.0.0 \
        -listen-port "${LISTEN_PORT}" &
    wait $!
    rc=$?
    reap_own_sessions
    echo "[broker] session ended (exit ${rc}) — re-establishing"
    sleep 3
done
