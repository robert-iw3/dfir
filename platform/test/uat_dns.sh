#!/usr/bin/env bash
# ==============================================================================
# DNS UAT — name resolution is the addressing layer AND an egress control.
#
# Two things are proven here, and both matter:
#
#   1. NAMES RESOLVE. Services address each other by name, so a network can be recreated on a
#      different subnet and a second analyst workstation can start without colliding with the
#      first. Pinned addresses used to make both of those break silently.
#
#   2. NOTHING ELSE RESOLVES. DNS is a covert exfiltration channel and the enclave holds the
#      evidence — the worker parses hostile memory images. Each tier's resolver has no recursive
#      path, so a name outside its zone has nowhere to go.
#
# Every query below is made FROM A RUNNING SERVICE, using that container's own resolver
# configuration. That is deliberate and was learned the hard way: a purpose-built probe started
# with `--dns <resolver>` does not get that resolver. Podman overrides it whenever its own DNS is
# enabled on the network, so the probe silently tested a different resolution path than the one
# the platform actually uses, and both its passes and its failures were meaningless.
#
# How resolution really works here, since the assertions only make sense against it:
#
#     service ──> runtime resolver (per-network, tracks live addresses)
#                       │
#                       ├─ in-zone name ──> answers directly            [dynamic addressing]
#                       └─ anything else ─> CoreDNS ──> REFUSED         [no path out]
#
# The runtime resolver handles only names of containers sharing a network with the caller; it
# cannot invent an answer for anything else, and its one upstream is a resolver that refuses.
# ==============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"

. "${HERE}/lib/report.sh"
report_begin 10 dns "Network policy — name resolution and egress control" \
    "Services address each other by dynamic name, and no tier can resolve anything outside its zone — closing DNS as an exfiltration channel from the tier that parses hostile memory."
RUNTIME="${IR_RUNTIME:-podman}"

set -a; . "${PLATFORM}/deploy/.env" 2>/dev/null || true; set +a
PLATFORM_HOST="${IR_PLATFORM_URL#*://}"; PLATFORM_HOST="${PLATFORM_HOST%%[:/]*}"


has() { [[ "$(grep -c -- "$2" <<<"$1")" -gt 0 ]]; }

# Resolve a name from inside a running container, using whatever that image provides. The images
# differ — python services, alpine, busybox — so the lookup falls through until one works rather
# than assuming a tool is present and reading its absence as a failure to resolve.
resolve_in() {  # resolve_in <container> <name>  -> prints address, empty if unresolvable
    local c="$1" n="$2" out=""
    out="$(${RUNTIME} exec -i "${c}" getent ahostsv4 "${n}" 2>/dev/null \
           | awk 'NR==1{print $1}')"
    [[ -n "${out}" ]] && { printf '%s' "${out}"; return 0; }
    out="$(${RUNTIME} exec -i "${c}" python3 -c \
           "import socket,sys
try: print(socket.gethostbyname('${n}'))
except Exception: sys.exit(1)" 2>/dev/null | tr -d '[:space:]')"
    [[ -n "${out}" ]] && { printf '%s' "${out}"; return 0; }
    out="$(${RUNTIME} exec -i "${c}" nslookup "${n}" 2>/dev/null \
           | awk '/^Address: /{print $2; exit}')"
    printf '%s' "${out}"
}

running() { [[ "$(${RUNTIME} inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" == "true" ]]; }

# ============================================================ 1. the resolvers exist
say "Resolvers"
for pair in "ir-dmz_coredns_1:DMZ" "ir-enclave_coredns_1:enclave"; do
    c="${pair%%:*}"; label="${pair##*:}"
    running "${c}" && ok "${label} resolver is running" \
                   || bad "${label} resolver (${c}) is not running — its tier has no policy at all"
done

# ============================================================ 2. no tier can egress
say "Segmentation — no network has a route off the host"
# The resolver policy is the second line. This is the first: with no route out, a name that
# somehow resolved still could not be reached. Both are asserted because each has been the only
# thing standing between the enclave and the internet at some point in this design.
for n in ir-edge ir-dmzlink ir-enclave_internal; do
    if [[ "$(${RUNTIME} network inspect "$n" --format '{{.Internal}}' 2>/dev/null)" == "true" ]]; then
        ok "${n} is internal (no egress)"
    else
        bad "${n} has a route off the host — traffic can leave regardless of DNS policy"
    fi
done

# ============================================================ 3. analyst segment
say "Analyst segment — the platform name resolves to the BASTION, live"
# Asked from the analyst's own browser, because that is the resolver path under test — the DMZ
# resolver rewriting the platform name to the bastion. It cannot be asked anywhere else without
# testing a different path.
#
# Reported as not-run when that tier is absent, rather than failed. A tier that was never
# deployed has no resolution behavior to be wrong, and calling that a failure trains the reader
# to skim past red — which is how a real one gets missed.
if ! running ir-workstation_browser_1; then
    info "analyst workstation not running — platform-name resolution not exercised"
    info "  bring it up with: deploy/deploy.sh workstation"
    got=""
elif got="$(resolve_in ir-workstation_browser_1 "${PLATFORM_HOST}")"; [[ -n "${got}" ]]; then
    ok "${PLATFORM_HOST} resolves to ${got} from the analyst browser"
    # It must be whatever address the runtime currently holds for the bastion. Comparing against
    # the live value is what proves the mapping is dynamic — a hardcoded answer resolves too, and
    # looks identical here, right until the network is recreated on a different subnet.
    live="$(${RUNTIME} inspect ir-dmz_bastion_1 \
        --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' 2>/dev/null \
        | tr ' ' '\n' | grep -c "^${got}$")"
    [[ "${live:-0}" -gt 0 ]] \
        && ok "the answer is the bastion's CURRENT address (resolved, not pinned)" \
        || bad "answer ${got} is not an address the bastion holds — the mapping is stale or pinned"
else
    bad "${PLATFORM_HOST} did not resolve — the analyst browser cannot reach the platform"
fi

# The DMZ names the tunnel depends on. `headscale` failing to resolve is what previously forced
# a pinned address into .env and made the deployment subnet-specific.
for n in bastion headscale receiver; do
    a="$(resolve_in ir-dmz_receiver_1 "${n}")"
    [[ -n "${a}" ]] && ok "${n} resolves by name (${a})" \
                    || bad "${n} does not resolve by name — something still needs a pinned address"
done

# ============================================================ 4. enclave names
say "Enclave — services resolve each other by name"
for n in db redis minio keycloak backend worker traefik; do
    a="$(resolve_in ir-enclave_backend_1 "${n}")"
    [[ -n "${a}" ]] && ok "${n} resolves (${a})" \
                    || bad "${n} does not resolve inside the enclave"
done

say "Enclave — exactly ONE cross-tier name: the receiver"
# Asserted from the PULLER, because it is the container whose job requires it: the enclave dials
# the DMZ outbound to fetch evidence. Asking from a service that has no business reaching the
# DMZ would prove nothing about the path that matters.
a="$(resolve_in ir-enclave_puller_1 receiver)"
[[ -n "${a}" ]] && ok "receiver resolves from the puller (${a}) — the evidence path inward" \
                || bad "receiver does not resolve — the puller can never fetch evidence"
# Any OTHER DMZ name must stay unresolvable. The permitted name is one record, not a door: a
# compromised worker should not be able to enumerate what else is over there.
for n in bastion headscale; do
    a="$(resolve_in ir-enclave_backend_1 "${n}")"
    [[ -z "${a}" ]] && ok "${n} is NOT resolvable from the enclave (only receiver is)" \
                    || bad "enclave resolved DMZ name ${n} -> ${a}; only receiver is permitted"
done

# ============================================================ 5. nothing else resolves
say "Exfiltration — no service can resolve an outside name"
# The puller is listed first deliberately. It is the enclave's only bridge outward, it sits on
# the DMZ link, and it is where this leaked: the link network was not internal, so the runtime
# resolver there forwarded anything it could not answer to the HOST's resolvers and the puller
# resolved real internet addresses. The enclave's own network was already internal, which is
# exactly why the leak was invisible from inside it.
for c in ir-enclave_puller_1 ir-enclave_backend_1 ir-enclave_worker_1 \
         ir-enclave_traefik_1 ir-enclave_keycloak_1 ir-workstation_browser_1; do
    running "${c}" || { info "${c} not running — skipped"; continue; }
    leaked=0
    for n in example.com data.exfil.test controlplane.tailscale.com; do
        a="$(resolve_in "${c}" "${n}")"
        [[ -n "${a}" ]] && { bad "${c#ir-} RESOLVED ${n} -> ${a} — DNS exfiltration is possible"; leaked=1; }
    done
    (( leaked )) || ok "${c#ir-} cannot resolve any outside name"
done

say "Backstop — CoreDNS refuses when it is the one asked"
# WHAT ENFORCES WHAT, precisely, because this was not what it looked like at first:
#
#   * The control holding today is the INTERNAL NETWORK, asserted above. Podman's resolver
#     answers in-zone names itself and has no upstream to forward anything else to, so an
#     outside name dies without CoreDNS being consulted at all.
#
#   * CoreDNS is therefore NOT in the normal query path, and cannot be made to be: podman
#     overrides a container's `dns:` whenever its own resolver is enabled on the network, and
#     disabling that resolver is what would force every service back to a pinned address. The
#     two requirements — dynamic names, and a resolver we control — cannot both be satisfied on
#     this runtime, and pretending otherwise would be a control that exists only in a comment.
#
#   * What CoreDNS does do is catch the case where a network gains egress. Podman then hands it
#     the configured `dns:` as the upstream, every unresolvable name is forwarded to it, and it
#     refuses. That is not hypothetical: it is exactly how the DMZ-link leak was caught here,
#     with the enclave's own bridge container resolving real internet addresses.
#
# So the assertion is not "CoreDNS handled traffic" — it holds no traffic while the networks are
# internal, and a log-based check would fail for a healthy deployment. It is "when CoreDNS is
# asked, it answers correctly", which is the property the backstop depends on. The server is
# named explicitly so the query reaches it regardless of what resolv.conf says.
dig_at() {  # dig_at <network> <resolver-address> <name>
    ${RUNTIME} run --rm --network "$1" "${PROBE:-localhost/ir-workstation:latest}" \
        dig +time=3 +tries=1 "@$2" "$3" 2>/dev/null
}
status_of() { sed -n 's/.*status: \([A-Z]*\).*/\1/p' <<<"$1" | head -1; }

for spec in "ir-edge:${DNS_EDGE_IP}:DMZ" "ir-enclave_internal:${ENCLAVE_DNS_IP}:enclave"; do
    net="${spec%%:*}"; rest="${spec#*:}"; addr="${rest%%:*}"; label="${rest##*:}"
    st="$(status_of "$(dig_at "${net}" "${addr}" example.com)")"
    if [[ "${st}" == "REFUSED" ]]; then
        ok "${label} CoreDNS refuses outside names when queried directly"
    else
        bad "${label} CoreDNS answered example.com with ${st:-nothing} — the backstop is not armed"
    fi
    # It must still answer in-zone names, or arming the backstop would break the platform the
    # moment it took over.
    inzone="$(dig_at "${net}" "${addr}" "$([[ ${label} == DMZ ]] && echo bastion || echo db).${RUNTIME_DNS_ZONE}")"
    if [[ -n "$(sed -n 's/^[^;].*[[:space:]]A[[:space:]]\+\([0-9.]\+\)$/\1/p' <<<"${inzone}" | head -1)" ]]; then
        ok "${label} CoreDNS still resolves in-zone names (forwarding works)"
    else
        bad "${label} CoreDNS cannot resolve in-zone names — it would break the tier if it took over"
    fi
done

# ============================================================ 6. no pinned addresses
say "Addressing — nothing is pinned except the resolvers themselves"
# A resolver cannot be discovered by asking a resolver: resolv.conf holds literals. Those two
# addresses are irreducible; every other pinned address is a service that breaks on a network
# recreate, which is the defect this work removed.
pinned="$(grep -rn "ipv4_address:" "${PLATFORM}"/deploy/*/docker-compose.yml 2>/dev/null \
          | grep -v 'DNS_EDGE_IP\|ENCLAVE_DNS_IP' || true)"
[[ -z "${pinned}" ]] && ok "no service pins an address (only the two resolvers, which must)" \
                     || { bad "pinned addresses remain:"; printf '      %s\n' "${pinned}"; }

# ------------------------------------------------------------------ verdict
say "DNS"
if (( FAILED )); then
    printf '  \033[1;31mDNS UAT FAILED\033[0m\n\n'
    exit 1
fi
printf '  \033[1;32mDNS UAT PASSED\033[0m — names resolve dynamically, nothing else resolves at all\n\n'

report_finish
exit "${FAILED}"
