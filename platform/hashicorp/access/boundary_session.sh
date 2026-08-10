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
# Loopback, not the analyst-facing port. The distributor owns BROKER_LISTEN in this namespace
# and spreads connections over these. Binding them where a workstation could reach them would
# let one pin itself to a single session.
SESSION_BASE="${BROKER_SESSION_BASE:-18443}"

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

echo "[broker] Boundary session broker — target ${BOUNDARY_TARGET_ID}, sessions from :${SESSION_BASE}"
echo "[broker] controller ${BOUNDARY_ADDR}, pinned to $(basename "${BOUNDARY_CACERT}")"

# Authenticate as a real principal, so the session is attributable.
export BOUNDARY_PASSWORD="${BOUNDARY_ANALYST_PASSWORD}"

# Cancel a principal's leftover sessions, using THAT principal's token. A replaced broker
# container abandons its sessions, which Boundary keeps "active" until expiry — the access
# record then over-counts live access. Each principal's list is filtered to its own sessions
# (read:self), so a reap here can only ever touch the one session that principal carries.
reap_sessions() {  # <token-env-var-name>
    [ -n "${BOUNDARY_PROJECT_ID:-}" ] || {
        echo "[broker] BOUNDARY_PROJECT_ID unset — stale sessions are not reaped"; return 0; }
    for _s in $(boundary sessions list -scope-id "${BOUNDARY_PROJECT_ID}" \
            -token "env://$1" -format json 2>/dev/null \
            | grep -o '"id": *"s_[^"]*"' | cut -d'"' -f4); do
        boundary sessions cancel -id "${_s}" -token "env://$1" >/dev/null 2>&1 \
            && echo "[broker] canceled stale session ${_s}"
    done
}

# Retries the real call and separates the two failures by what came back: a controller that is
# not answering is worth waiting on; a rejected credential never becomes valid, so it exits
# loudly instead of after two minutes of silence.
authenticate() {  # <login-name>
    # `_try`, never `i`: sh has no function scope, and a counter named `i` here clobbers the
    # caller's loop index — the provisioning loop then never advances past its first principal.
    token=""
    _try=1
    while [ "${_try}" -le 60 ]; do
        auth_out="$(boundary authenticate password \
                -auth-method-id "${BOUNDARY_AUTH_METHOD_ID}" \
                -login-name "$1" \
                -password env://BOUNDARY_PASSWORD \
                -format json 2>&1)"
        token="$(printf '%s' "${auth_out}" | grep -o '"token": *"[^"]*"' | head -1 | cut -d'"' -f4)"
        [ -n "${token}" ] && return 0

        case "${auth_out}" in
            *"connection refused"*|*"no such host"*|*"connect: "*|*"EOF"*|*"i/o timeout"*)
                [ "${_try}" = 1 ] && echo "[broker] waiting for the controller at ${BOUNDARY_ADDR}"
                ;;
            *)
                # Wrong auth-method id, unset password, an unexpected response shape, a
                # certificate that does not verify — each says something different, so the
                # output is kept. A per-session login refused here usually means the
                # controller's bootstrap has not provisioned it: run deploy.sh enclave.
                echo "[broker] authentication to Boundary failed for $1:" >&2
                printf '%s\n' "${auth_out}" | tail -8 | sed 's/^/[broker]   /' >&2
                echo "[broker] The listener is NOT opened — an unauthenticated forwarder is not a fallback." >&2
                exit 1
                ;;
        esac
        _try=$((_try + 1))
        sleep 2
    done
    return 1
}

# On stop, every principal cancels its own session so the access record never over-counts.
reap_all() {
    _j=1
    while [ "${_j}" -le "${SESSIONS:-0}" ]; do
        reap_sessions "BOUNDARY_TOKEN_${_j}"
        _j=$((_j + 1))
    done
    reap_sessions BOUNDARY_TOKEN
}
trap 'echo "[broker] terminating — canceling the sessions"; reap_all; exit 0' TERM INT

# N independent sessions, each with its own port, its own supervisor and its own PRINCIPAL.
# One session shared by the whole fleet is a single failure domain: it dies under connection
# churn and drops every analyst together. The distributor beside this container spreads the
# fleet across these, so a death costs the connections riding that session and new ones are
# redispatched past it. Distinct principals make each session individually attributable in
# the access record, and scope every list/cancel to the one session that principal carries.
SESSIONS="${BROKER_SESSIONS:-8}"

if ! authenticate "${BOUNDARY_ANALYST_LOGIN}"; then
    echo "[broker] the controller never answered at ${BOUNDARY_ADDR}" >&2
    exit 1
fi
export BOUNDARY_TOKEN="${token}"
echo "[broker] authenticated as ${BOUNDARY_ANALYST_LOGIN}"
# Leftovers of the base principal, from deployments that ran every session under it.
reap_sessions BOUNDARY_TOKEN

# One principal per session. Each supervisor authenticates as its own, so its session is
# individually attributable in the access record and its reap can only cancel itself.
i=1
while [ "${i}" -le "${SESSIONS}" ]; do
    if ! authenticate "${BOUNDARY_ANALYST_LOGIN}-s${i}"; then
        echo "[broker] the controller never answered for ${BOUNDARY_ANALYST_LOGIN}-s${i}" >&2
        exit 1
    fi
    eval "export BOUNDARY_TOKEN_${i}=\"\${token}\""
    echo "[broker] authenticated as ${BOUNDARY_ANALYST_LOGIN}-s${i}"
    reap_sessions "BOUNDARY_TOKEN_${i}"
    i=$((i + 1))
done
echo "[broker] starting ${SESSIONS} independent session(s) on 127.0.0.1:${SESSION_BASE}-$((SESSION_BASE + SESSIONS - 1))"

# Is this port bound? Read the LISTEN socket rather than dialing it: a dial to a Boundary proxy
# is itself a session connection, so polling churns the session it protects. /proc/net/tcp{,6}
# is passive. State 0A = LISTEN.
listening() {
    awk -v p=":$(printf '%04X' "$1")$" '$4=="0A" && $2 ~ p {f=1} END{exit !f}' \
        /proc/net/tcp /proc/net/tcp6 2>/dev/null
}

# One supervisor per session. A running client is not a working path: `boundary connect` can
# hold a session and report a listening proxy with nothing bound. The LISTENER is supervised,
# not the process.
supervise() {  # <port> <session-index>
    port="$1"
    tokvar="BOUNDARY_TOKEN_$2"
    log="/tmp/broker-${port}.log"
    while :; do
        # Output is KEPT: it carries the session id, and a supervisor that does not know its
        # own session cannot cancel it when it replaces it. Boundary holds an abandoned
        # session "active" until expiry, so those accumulate and over-count live access.
        : > "${log}"
        boundary connect \
            -token "env://${tokvar}" \
            -target-id "${BOUNDARY_TARGET_ID}" \
            -listen-addr 127.0.0.1 \
            -listen-port "${port}" > "${log}" 2>&1 &
        pid=$!

        bound=0
        for _ in $(seq 1 20); do
            listening "${port}" && { bound=1; break; }
            kill -0 "${pid}" 2>/dev/null || break
            sleep 1
        done
        # Read before the bind verdict: a client that authorized a session and never bound has
        # still taken one, and it has to be cancelled on that path too.
        sid="$(sed -n 's/.*Session ID:[[:space:]]*\(s_[A-Za-z0-9]*\).*/\1/p' "${log}" | head -1)"
        if [ "${bound}" != "1" ]; then
            echo "[broker:${port}] listener never bound — retrying this session only" >&2
            kill "${pid}" 2>/dev/null; wait "${pid}" 2>/dev/null
            [ -n "${sid}" ] && boundary sessions cancel -id "${sid}" \
                -token "env://${tokvar}" >/dev/null 2>&1
            sleep 3
            continue
        fi
        echo "[broker:${port}] listening on session ${sid:-unknown} — this share of the fleet has a path"

        # THREE signals, because each alone misses a real failure:
        #
        #   process    the client exited
        #   listener   the port stopped accepting while the client ran
        #   session    the CONTROLLER no longer holds this session
        #
        # The third is not redundant. A cancelled or expired session leaves `boundary connect`
        # running, the port bound and the output silent — nothing local shows it. The
        # distributor then keeps sending analysts to a port that accepts the connection and
        # fails it, which redispatch cannot route around because the accept succeeded.
        #
        # The client's error output is NOT a trigger: it logs a line per failed connection as
        # well as on session death, so acting on it makes the supervisor a source of churn.
        misses=0
        ticks=0
        while kill -0 "${pid}" 2>/dev/null; do
            sleep 5
            ticks=$((ticks + 1))

            # Consecutive misses, not one: the socket is momentarily absent while the client
            # rebinds, and replacing on the first miss makes the supervisor cause the churn.
            if listening "${port}"; then
                misses=0
            else
                misses=$((misses + 1))
                if [ "${misses}" -ge 3 ]; then
                    echo "[broker:${port}] listener gone 15s while the client runs — replacing it" >&2
                    kill "${pid}" 2>/dev/null
                    break
                fi
            fi

            # Ask the controller every third tick. One read per session per 15s costs the
            # controller nothing, and it is the only authority on whether the session exists.
            if [ -n "${sid}" ] && [ "$((ticks % 3))" -eq 0 ]; then
                st="$(boundary sessions read -id "${sid}" -token "env://${tokvar}" \
                        -format json 2>/dev/null \
                      | grep -o '"status": *"[^"]*"' | head -1 | cut -d'"' -f4)"
                case "${st}" in
                    # Empty means the controller could not be asked, which is not a verdict on
                    # the session and not grounds for replacing a working one.
                    active|pending|"") ;;
                    *)  echo "[broker:${port}] session ${sid} is ${st} while the listener stays bound — replacing it" >&2
                        kill "${pid}" 2>/dev/null
                        break ;;
                esac
            fi
        done
        wait "${pid}" 2>/dev/null
        # Cancel THIS session by id, never `reap_own_sessions`: that scopes to the principal
        # and would take every sibling with it. Without the cancel the abandoned session stays
        # "active" until expiry and the access record over-counts live access.
        if [ -n "${sid:-}" ]; then
            boundary sessions cancel -id "${sid}" -token "env://${tokvar}" >/dev/null 2>&1 \
                && echo "[broker:${port}] canceled its own ended session ${sid}"
        fi
        echo "[broker:${port}] session ended — re-establishing this one" >&2
        sleep 3
    done
}

i=0
while [ "${i}" -lt "${SESSIONS}" ]; do
    supervise "$((SESSION_BASE + i))" "$((i + 1))" &
    i=$((i + 1))
done

# Container health is "at least one session is carrying". Losing all of them is the state a
# restart fixes; in-script recovery stalls holding no listener.
while :; do
    sleep 30
    alive=0
    i=0
    while [ "${i}" -lt "${SESSIONS}" ]; do
        listening "$((SESSION_BASE + i))" && alive=$((alive + 1))
        i=$((i + 1))
    done
    [ "${alive}" -gt 0 ] || {
        echo "[broker] all ${SESSIONS} sessions are down — exiting so the container restarts clean" >&2
        exit 1
    }
done
