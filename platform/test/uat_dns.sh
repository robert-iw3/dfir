#!/usr/bin/env bash
# ==============================================================================
# DNS UAT — name resolution is both the addressing layer and an egress control. Two things are
# proven: in-zone names resolve to the right services, and out-of-zone names are refused so DNS
# cannot become an exfiltration channel.
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
# The resolver policy is the second line; this is the first — with no route out, a name that
# somehow resolved still could not be reached. Both are asserted because each has been the only
# thing holding.
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
# resolver rewriting the platform name to the bastion.
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

# The DMZ names the tunnel depends on. `headscale` failing to resolve forces a pinned address
# into .env, which makes the deployment subnet-specific.
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
# The puller is listed first deliberately: the enclave's only bridge outward, on the DMZ link, and
# where the leak was — the link network was not internal, so its resolver forwarded to the host.
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
# WHAT ENFORCES WHAT: the control holding today is the INTERNAL NETWORK (no route out). The
# resolver policy is the second line of defense, asserted separately because each has at some
# point been the only one in effect.
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

# ============================================================ 6. addressing is configuration
say "Addressing — every address is declared configuration, never a literal"
# Asserts nothing is pinned but the two resolvers — a pinned service breaks when a network
# recreate moves it, so dynamic addressing is the property under test.
literal="$(grep -rn "ipv4_address:" "${PLATFORM}"/deploy/*/docker-compose.yml 2>/dev/null \
           | grep -vE 'ipv4_address:[[:space:]]*\$\{[A-Z0-9_]+\}' || true)"
[[ -z "${literal}" ]] \
    && ok "every pinned address is a declared variable, none hard-coded" \
    || { bad "addresses hard-coded in compose — not changeable per deployment:"
         printf '      %s\n' "${literal}"; }

# And the pins are the DECLARED set: the two resolvers, which cannot be discovered because
# resolv.conf holds only literals, plus mesh participants. Anything else took an address
# without the mesh needing it to.
undeclared="$(grep -rhoE 'ipv4_address:[[:space:]]*\$\{[A-Z0-9_]+\}' \
                  "${PLATFORM}"/deploy/*/docker-compose.yml 2>/dev/null \
              | grep -oE '\{[A-Z0-9_]+\}' | tr -d '{}' \
              | grep -vE '^(DNS_EDGE_IP|ENCLAVE_DNS_IP|IR_IP_[A-Z0-9_]+)$' || true)"
[[ -z "${undeclared}" ]] \
    && ok "pins are the resolvers and IR_IP_* mesh participants, nothing else" \
    || { bad "a service pins an address outside the declared scheme:"
         printf '      %s\n' "${undeclared}"; }

# ------------------------------------------------------------------ verdict
say "DNS"
if (( FAILED )); then
    printf '  \033[1;31mDNS UAT FAILED\033[0m\n\n'
    exit 1
fi
printf '  \033[1;32mDNS UAT PASSED\033[0m — names resolve dynamically, nothing else resolves at all\n\n'

report_finish
exit "${FAILED}"
