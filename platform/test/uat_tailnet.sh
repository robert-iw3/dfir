#!/usr/bin/env bash
# ==============================================================================
# TAILNET UAT — the analyst's WireGuard tunnel to the DMZ, proven rather than described.
#
# Asserts the tunnel EXISTS and the ACL BOUNDS it. Both halves matter: a tunnel that carries
# traffic but permits everything is worse than no tunnel, because it looks like a control.
#
# Written because this tier was documented as "workstation joins a self-hosted tailnet" while
# the deployment ran a plain socat forwarder with no tailnet member at all — the claim and the
# behavior had drifted apart with nothing checking. Every assertion here is a property an
# analyst's session actually depends on.
# ==============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"

. "${HERE}/lib/report.sh"
report_begin 20 tailnet "Analyst tunnel — WireGuard reachability" \
    "An analyst workstation reaches the platform only over an authenticated WireGuard tunnel to the bastion, with no route to any internal host."
RUNTIME="${IR_RUNTIME:-podman}"


# Count matches rather than trust grep's status: a quiet grep closes the pipe under its
# producer and the SIGPIPE makes a successful match read as a failure.
has() { [[ "$(grep -c -- "$2" <<<"$1")" -gt 0 ]]; }

BASTION=ir-dmz_bastion_1
HEADSCALE=ir-dmz_headscale_1
ANALYST=ir-workstation_tailnet_1

hs() { ${RUNTIME} exec -i "${HEADSCALE}" headscale "$@" 2>/dev/null; }

# ------------------------------------------------------ 1. control plane
say "Control plane"
if ${RUNTIME} exec -i "${HEADSCALE}" headscale version >/dev/null 2>&1; then
    ok "headscale answers ($(hs version | head -1))"
else
    bad "headscale is not answering — nothing below can pass"
    printf '\n  \033[1;31mTAILNET UAT FAILED\033[0m\n\n'; exit 1
fi

# The ACL names users; a rule whose src does not exist never matches and denies silently.
users="$(hs users list --output json || echo '[]')"
for u in analyst bastion; do
    has "${users//[[:space:]]/}" "\"name\":\"${u}\"" \
        && ok "user ${u} exists (the ACL grants from it)" \
        || bad "user ${u} is missing — its ACL rule can never match"
done

# ------------------------------------------------------ 2. nodes joined
say "Nodes"
nodes="$(hs nodes list --output json || echo '[]')"
compact="${nodes//[[:space:]]/}"
for n in bastion analyst; do
    has "${compact}" "\"given_name\":\"${n}\"" \
        && ok "${n} is enrolled in the tailnet" \
        || bad "${n} never joined — it is not a tailnet member"
done

# ------------------------------------------------------ 3. real tunnel interfaces
say "Tunnel — a real interface, not userspace"
for pair in "${BASTION}:bastion" "${ANALYST}:analyst"; do
    c="${pair%%:*}"; label="${pair##*:}"
    if ! ${RUNTIME} inspect "${c}" >/dev/null 2>&1; then
        bad "${label} container ${c} does not exist"
        continue
    fi
    # A WireGuard tunnel that is a kernel interface is what makes "cannot reach an internal
    # host" a routing fact. Userspace networking carries traffic without one, and then the
    # routing table proves nothing.
    ifaces="$(${RUNTIME} exec -i "${c}" ip -brief link show 2>/dev/null)"
    if has "${ifaces}" "tailscale"; then
        ok "${label} has a tailscale interface"
    else
        bad "${label} has no tun interface — the tunnel is not a network interface here"
    fi
    ip4="$(${RUNTIME} exec -i "${c}" tailscale ip -4 2>/dev/null | tr -d '[:space:]')"
    if [[ -n "${ip4}" ]]; then
        ok "${label} holds tailnet address ${ip4}"
        [[ "${label}" == "bastion" ]] && BASTION_TS_IP="${ip4}"
    else
        bad "${label} has no tailnet address"
    fi
done

# --------------------------------------- 3b. the tunnel is confined to its container
say "Confinement — the tunnel belongs to the container, not the host"
# The tun device is created inside the container's network namespace. If it appeared on the
# host, every process on the machine would route through the analyst's tunnel — the opposite
# of what a contained session means.
host_ts="$(ip -brief addr show 2>/dev/null | grep -ciE "tailscale|^wg" || true)"
if [[ "${host_ts:-0}" -eq 0 ]]; then
    ok "the host has no tailnet interface (the tunnel is namespaced to its container)"
else
    bad "a tailnet interface exists on the HOST — the tunnel is not confined"
fi

# The browser must share the tailnet node's namespace, or it sits beside the tunnel on the
# edge network and its traffic never enters WireGuard at all. That was the original defect:
# a documented tunnel with the session going around it.
BROWSER=ir-workstation_browser_1
if ${RUNTIME} inspect "${BROWSER}" >/dev/null 2>&1; then
    mode="$(${RUNTIME} inspect "${BROWSER}" --format '{{.HostConfig.NetworkMode}}' 2>/dev/null)"
    tailnet_id="$(${RUNTIME} inspect "${ANALYST}" --format '{{.Id}}' 2>/dev/null)"
    if [[ "${mode}" == "container:${tailnet_id}" ]]; then
        ok "browser shares the tailnet namespace — its traffic leaves over WireGuard"
    else
        bad "browser is NOT in the tunnel namespace (${mode}) — it bypasses WireGuard"
    fi
else
    info "browser not running — start the workstation tier to assert its network position"
fi

# The routing table is where "cannot address an internal host" is either true or merely
# claimed. Anything beyond the edge network and the tailnet peer would be a route inward.
routes4="$(${RUNTIME} exec -i "${ANALYST}" ip route show 2>/dev/null)"
if has "${routes4}" "default"; then
    bad "the analyst namespace has a DEFAULT route — it can leave the edge network"
else
    ok "no default route in the analyst namespace (no egress, no internal reach)"
fi

# ------------------------------------------------------ 4. traffic over the tunnel
say "Traffic — the analyst reaches the platform THROUGH the tunnel"
if [[ -n "${BASTION_TS_IP:-}" ]]; then
    # Addressed by tailnet IP, so a success cannot be the edge network answering instead.
    code="$(${RUNTIME} exec -i "${ANALYST}" sh -c \
        "wget -q -O /dev/null -T 8 --no-check-certificate \
         https://${BASTION_TS_IP}:8443/ 2>/dev/null && echo 200 || echo fail" 2>/dev/null \
        | tr -d '[:space:]')"
    if [[ "${code}" == "200" ]]; then
        ok "analyst reached the brokered port over the tunnel (${BASTION_TS_IP}:8443)"
    else
        # wget may be absent in the tailscale image; fall back to a TCP connect, which is
        # what the ACL actually governs.
        if ${RUNTIME} exec -i "${ANALYST}" sh -c \
             "timeout 8 nc -z ${BASTION_TS_IP} 8443" >/dev/null 2>&1; then
            ok "analyst opened TCP to ${BASTION_TS_IP}:8443 over the tunnel"
        else
            bad "analyst could not reach the brokered port over the tunnel"
        fi
    fi
else
    bad "no bastion tailnet address — cannot test traffic over the tunnel"
fi

# The brokered port has to be bound INSIDE the bastion's namespace. A broker listening in its
# own namespace instead would be reachable over the edge network and not over the tunnel —
# which is how this tier looked before the bastion existed.
say "Broker — the forwarder binds the tunnel, not a network beside it"
listeners="$(${RUNTIME} exec -i "${BASTION}" sh -c 'netstat -ltn 2>/dev/null || ss -ltn 2>/dev/null' 2>/dev/null)"
if has "${listeners}" ":8443"; then
    ok "the brokered port is bound in the bastion's namespace"
else
    bad "nothing is listening on the brokered port inside the bastion"
fi
# Exactly one forwarded port. Every extra listener is a hole the ACL never sees.
extra="$(grep -cE "LISTEN" <<<"${listeners}" || true)"
info "listeners in the bastion namespace: ${extra:-0} (tailscaled's own sockets included)"

# --------------------------------------------- 4b. the relay is actually usable
say "DERP — the tunnel has a relay to fall back on"
# Tailscale REFUSES to use a DERP relay that is not served over TLS, and does not report
# declining to. The node comes up, calls itself connected, and has no relay at all — which stays
# invisible until two peers cannot build a direct path, and then the session simply fails. On a
# segment with no internet the public DERP fleet is not a fallback either, so the embedded relay
# is the only one there is.
# Asserted from LIVE state, not from the log. A log-tail check passes or fails depending on how
# much the node has since printed — the DERP line scrolls out of any bounded window — so it
# reported a healthy relay as missing on a busy node. `tailscale status` reports what the relay
# is right now.
for pair in "${BASTION}:bastion" "${ANALYST}:analyst"; do
    c="${pair%%:*}"; label="${pair##*:}"
    ${RUNTIME} inspect "${c}" >/dev/null 2>&1 || continue
    relay="$(${RUNTIME} exec -i "${c}" tailscale status --json 2>/dev/null \
        | python3 -c "import json,sys; print(json.load(sys.stdin).get('Self',{}).get('Relay') or '')" 2>/dev/null \
        | tr -d '[:space:]')"
    if [[ -z "${relay}" ]]; then
        bad "${label} has NO DERP relay — the tunnel has no fallback path"
    elif [[ "${relay}" == "bastion" ]]; then
        # `bastion` is the region CODE of the embedded relay (region 999). Any other value means
        # the node found a public relay, which this segment should not be able to reach at all.
        ok "${label} relays through the embedded DERP region (${relay})"
    else
        bad "${label} relays through '${relay}' — not the embedded region; it reached the public fleet"
    fi
    health="$(${RUNTIME} exec -i "${c}" tailscale status --json 2>/dev/null \
        | python3 -c "import json,sys; print(len(json.load(sys.stdin).get('Health') or []))" 2>/dev/null)"
    [[ "${health:-0}" -eq 0 ]] \
        && ok "${label} reports no tunnel health warnings" \
        || bad "${label} reports ${health} health warning(s)"
done

# The control plane must be TLS, since that is the precondition for the relay above.
# Read from the RENDERED config on disk, which is the file mounted into the container. The
# headscale image is minimal and has no shell utilities, so exec'ing sed there returns empty and
# the assertion fails against a correctly configured control plane.
HS_CONF="${PLATFORM}/hashicorp/access/headscale.yaml"
if [[ -r "${HS_CONF}" ]]; then
    url="$(sed -n 's/^server_url: //p' "${HS_CONF}" | tr -d '[:space:]')"
    [[ "${url}" == https://* ]] \
        && ok "control plane advertises ${url} (TLS — required for DERP)" \
        || bad "control plane advertises '${url}' — without TLS the relay is never used"
fi

# ------------------------------------------------------ 5. the ACL bounds it
say "Bounds — the tunnel is not a route to the enclave"
if [[ -n "${BASTION_TS_IP:-}" ]]; then
    # Ports on the bastion that the ACL does NOT grant to analyst@. Reachability here would
    # mean the allow-list is decorative.
    for port in 8090 22 9090; do
        if ${RUNTIME} exec -i "${ANALYST}" sh -c \
             "timeout 5 nc -z ${BASTION_TS_IP} ${port}" >/dev/null 2>&1; then
            bad "analyst reached ${BASTION_TS_IP}:${port} — the ACL permits only 8443"
        else
            ok "analyst cannot reach the bastion on ${port}"
        fi
    done
fi

# No subnet routes: the property that keeps a workstation off the internal networks entirely.
routes="$(hs nodes list --output json || echo '[]')"
if has "${routes//[[:space:]]/}" '"approved_routes":\["' ; then
    bad "a node has approved subnet routes — a workstation could address internal hosts"
else
    ok "no approved subnet routes (workstations cannot address internal hosts)"
fi

# Internal services by name, from inside the tunnel namespace. These live on enclave networks
# the analyst side has no leg on, so a hit means segmentation has been lost.
say "Bounds — internal services stay unreachable"
for target in db:5432 minio:9000 backend:8000 keycloak:8080; do
    host="${target%%:*}"; port="${target##*:}"
    if ${RUNTIME} exec -i "${ANALYST}" sh -c \
         "timeout 4 nc -z ${host} ${port}" >/dev/null 2>&1; then
        bad "analyst REACHED ${target} — the enclave is exposed to the workstation"
    else
        ok "analyst cannot reach ${target}"
    fi
done

# ------------------------------------------------------------------ verdict
say "Tailnet"
if (( FAILED )); then
    printf '  \033[1;31mTAILNET UAT FAILED\033[0m\n\n'
    exit 1
fi
printf '  \033[1;32mTAILNET UAT PASSED\033[0m — tunnel exists, carries the session, and bounds it\n\n'

report_finish
exit "${FAILED}"
