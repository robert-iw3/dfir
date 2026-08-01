#!/bin/sh
# Administrative forwarder: exposes management interfaces of ONE tier to the management
# network, and nothing else.
#
#   ADMIN_TARGETS="19001=minio:9001,18501=consul:8501"
#
# Three properties make this safe to run, and all three are structural rather than
# conventions to remember:
#
#   1. One forwarder per tier, each joined only to that tier's network. The DMZ forwarder
#      cannot resolve or reach an enclave service and vice versa — the isolation is the
#      network membership, not this allow-list.
#   2. A target with no entry has no forwarder. There is no wildcard and no default route.
#   3. The host-side publish binds the management address only (see the compose file). An
#      admin path bound to every interface is an admin path reachable from the analyst
#      side, which is the failure this exists to prevent.
#
# This is deliberately NOT the analyst broker: analysts reach one SSO-gated origin, admins
# reach management interfaces from the management network. The two never share a path.
set -eu

# socat ships in the image. It is NOT installed at runtime: these tiers have no internet
# gateway, so an install would fail silently and leave listeners that accept connections
# and forward nothing — a forwarder that looks up while carrying no traffic.
if ! command -v socat >/dev/null 2>&1; then
    echo "adminfwd: socat missing from the image — refusing to start" >&2
    exit 1
fi

if [ -z "${ADMIN_TARGETS:-}" ]; then
    echo "adminfwd: ADMIN_TARGETS is empty — nothing to forward, refusing to idle" >&2
    exit 1
fi

echo "adminfwd: tier=${ADMIN_TIER:-unspecified}"

IFS=','
for _t in ${ADMIN_TARGETS}; do
    _listen="${_t%%=*}"
    _up="${_t#*=}"
    if [ "${_listen}" = "${_t}" ] || [ -z "${_up}" ]; then
        echo "adminfwd: malformed target '${_t}' (want listen=host:port)" >&2
        exit 1
    fi
    echo "adminfwd: :${_listen} -> ${_up}"
    socat TCP-LISTEN:"${_listen}",fork,reuseaddr TCP:"${_up}" &
done
unset IFS

trap 'kill 0' TERM INT

# Optional self-termination. An admin path is meant to exist for the length of a task, not
# the length of an uptime; a session left running is the failure mode this guards against.
if [ -n "${ADMIN_TTL:-}" ] && [ "${ADMIN_TTL}" -gt 0 ] 2>/dev/null; then
    echo "adminfwd: closing automatically in ${ADMIN_TTL}s"
    ( sleep "${ADMIN_TTL}"; echo "adminfwd: TTL reached — closing"; kill 0 ) &
fi

wait
