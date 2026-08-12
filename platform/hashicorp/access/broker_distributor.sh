#!/bin/sh
# Spreads analyst connections across the broker's independent Boundary sessions. The broker
# holds BROKER_SESSIONS separate sessions on loopback ports.
set -eu

LISTEN="${BROKER_LISTEN:-8443}"
BASE="${BROKER_SESSION_BASE:-18443}"
SESSIONS="${BROKER_SESSIONS:-8}"
# New connections accepted per second. The fragile hop is each SESSION CLIENT's connection
# setup: `boundary connect` dials its worker per proxied connection, and concurrent dials
# corrupt its stream — a 50-wide burst admitted at 24/s fails 50/50 in under two seconds with
# the distributor's server-connects refused, while 8/s carries.
ACCEPT_RATE="${BROKER_ACCEPT_RATE:-8}"

case "${SESSIONS}" in
    ''|*[!0-9]*|0) echo "[distributor] BROKER_SESSIONS must be a positive integer — got '${SESSIONS}'" >&2; exit 1 ;;
esac

# Workstation pinning map: `<ws-id> <tailnet-addr>` per line, ordinal position choosing the
# session (first line -> s1, second -> s2, ...). Written by `deploy.sh workstation` once the
# node has an address, so it is empty on first bring-up — pinning is attribution, and a fleet
# with no map just spreads leastconn as before.
MAP="${BROKER_WS_MAP_FILE:-/distributor-map/ws-map}"

CFG=/tmp/haproxy.cfg

render() {
    {
        cat <<EOF
global
    log stdout format raw local0 info
    # Above the fleet size: 50 workstations hold one HTTP/2 connection each.
    maxconn 8192

defaults
    mode tcp
    log global
    option tcplog
    timeout connect 5s
    # The analyst path carries long-lived HTTP/2 connections and streamed evidence downloads.
    timeout client 1h
    timeout server 1h
    # A dead session's port refuses connections. Retry, and redispatch so the retry lands on a
    # different session rather than failing the analyst. Refused on loopback is an instant
    # RST, so walking the whole farm costs microseconds — retries match the session count,
    # and an arrival fails only when every slot is dark at once.
    retries 8
    option redispatch

frontend analyst
    bind 0.0.0.0:${LISTEN}
    # Delays accepts past this rate rather than refusing them, so a burst is spread over a
    # second or two instead of arriving as simultaneous handshakes. It bounds SETUP rate only;
    # established connections are unaffected and stay open.
    rate-limit sessions ${ACCEPT_RATE}
EOF
        # One ACL per mapped workstation. Rendered before the default so a pinned source never
        # reaches the pool; a session's ordinal is its map line, so the enclave derives the
        # same principal<->workstation pairing from IR_WS_IDS order with no second map file.
        n=0
        if [ -r "${MAP}" ]; then
            while read -r ws addr _; do
                case "${ws}" in ''|'#'*) continue ;; esac
                n=$((n + 1))
                if [ "${n}" -gt "${SESSIONS}" ]; then
                    echo "[distributor] ${ws}: past the session count (${SESSIONS}) — pooled, not pinned" >&2
                    continue
                fi
                case "${addr}" in ''|-) continue ;; esac
                printf '    use_backend pin_s%s if { src %s }\n' "${n}" "${addr}"
            done < "${MAP}"
        fi
        cat <<EOF
    default_backend brokered

backend brokered
    # Two random candidates, the less-loaded wins: spreads like leastconn, but a REPLACING
    # session's port (zero connections, no health checks to mark it down) cannot magnetize
    # every arrival and every redispatch the way pure leastconn does.
    balance random(2)
EOF
        i=0
        while [ "${i}" -lt "${SESSIONS}" ]; do
            # No `check`: a TCP health probe against a Boundary proxy is itself a session
            # connection, so probing churns the sessions it monitors. Connection failures are
            # covered by retry + redispatch above.
            echo "    server s$((i + 1)) 127.0.0.1:$((BASE + i))"
            i=$((i + 1))
        done
        # Pinned backends, one session each. Retries stay INSIDE the pin — a pinned
        # workstation whose session is momentarily down retries it rather than leaking onto a
        # session attributed to someone else; redispatch has nowhere else to go here.
        i=0
        while [ "${i}" -lt "${SESSIONS}" ]; do
            printf 'backend pin_s%s\n    server s%s 127.0.0.1:%s\n' \
                "$((i + 1))" "$((i + 1))" "$((BASE + i))"
            i=$((i + 1))
        done
    } > "${CFG}"
}

render
pins="$(grep -c '^    use_backend' "${CFG}" || true)"
echo "[distributor] :${LISTEN} -> ${SESSIONS} brokered session(s) on 127.0.0.1:${BASE}-$((BASE + SESSIONS - 1))"
echo "[distributor] tcp pass-through, ${pins} pinned workstation(s), pool leastconn, retry+redispatch, no health probing"

# Master-worker in the foreground, so the container supervises the process. The watcher
# re-renders and reloads (SIGUSR2, graceful: established connections drain, never dropped)
# when the map changes — `deploy.sh workstation` writes it after the node registers, which
# is always after this container is already up.
haproxy -W -db -f "${CFG}" &
HAPID=$!
last="$(cat "${MAP}" 2>/dev/null || true)"
while kill -0 "${HAPID}" 2>/dev/null; do
    sleep 5
    cur="$(cat "${MAP}" 2>/dev/null || true)"
    if [ "${cur}" != "${last}" ]; then
        last="${cur}"
        render
        pins="$(grep -c '^    use_backend' "${CFG}" || true)"
        echo "[distributor] map changed — reloading with ${pins} pinned workstation(s)"
        kill -USR2 "${HAPID}" 2>/dev/null || true
    fi
done
wait "${HAPID}"
