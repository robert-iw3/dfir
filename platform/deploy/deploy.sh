#!/usr/bin/env bash
# ===========================================================================
# Deployment driver — brings up ONE tier on the hardware it belongs to, in
# dependency order, gating each stage on a health check before continuing.
#
#   deploy.sh enclave       # internal enclave host
#   deploy.sh dmz           # DMZ host
#   deploy.sh workstation   # analyst machine
#   deploy.sh all           # single-host validation (all tiers)
#   deploy.sh status        # health of every stage
#   deploy.sh down <tier|all> [--purge]   # --purge also deletes volumes:
#                                         # ALL evidence, captures and analyses
#
# Staged, not fire-and-forget: services that depend on others (the ingress on the
# SSO gate, the SSO gate on the IdP) only start once their dependency answers, so a
# request never lands on a half-started stack.
# ===========================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE="${IR_COMPOSE:-podman-compose}"
RUNTIME="${IR_RUNTIME:-podman}"
TIER="${1:-}"
[[ -f "${HERE}/.env" ]] || cp "${HERE}/.env.example" "${HERE}/.env"
set -a; . "${HERE}/.env"; set +a
# Bare hostname for DNS lookups: IR_PLATFORM_URL carries a scheme, port and path.
PLATFORM_HOST="${IR_PLATFORM_URL#*://}"; PLATFORM_HOST="${PLATFORM_HOST%%[:/]*}"

say()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '    \033[1;32m✔\033[0m %s\n' "$*"; }
warn() { printf '    \033[1;33m!\033[0m %s\n' "$*"; }
die()  { printf '    \033[1;31m✘\033[0m %s\n' "$*"; exit 1; }

proj() { case "$1" in enclave) echo ir-enclave;; dmz) echo ir-dmz;; workstation) echo ir-workstation;; agent) echo ir-agent;; esac; }
RECREATE_BLOCKED=""   # per-deploy decision, see recreate_if_stale
COMPOSE_TIMEOUT="${IR_COMPOSE_TIMEOUT:-240}"
# Tailnet pre-auth keys are minted per bring-up and live in a separate file so they are never
# committed. Exported into the environment rather than passed as a second --env-file, because
# podman-compose does not reliably merge two of them — a silently-absent key looks like a
# tunnel that will not come up.
dc() {
    local tier="$1"; shift
    local extra
    # Two independent bootstraps, two files: the tailnet one truncates its file on every run, so
    # anything sharing it is lost on the next bring-up.
    for extra in "${HERE}/.env.tailnet" "${HERE}/.env.boundary"; do
        if [[ -r "${extra}" ]]; then
            set -a
            # shellcheck source=/dev/null
            . "${extra}"
            set +a
        fi
    done
    # The multi-host overlay publishes each mesh sidecar's public listener on the host, so
    # proxies on OTHER hosts can dial it. Single host never loads it: seven services publishing
    # host ports they do not need is exactly the widened surface the enclave exists to avoid.
    local overlay=()
    if [[ "${tier}" == "enclave" && "${IR_MESH_MULTIHOST:-0}" == "1" ]]; then
        overlay=(-f docker-compose.multihost.yml)
    fi
    # The agent compose interpolates these; a `down` must parse the same file `up` did.
    if [[ "${tier}" == "agent" ]]; then
        export IR_RUNTIME_SOCKET="${IR_RUNTIME_SOCKET:-${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/podman/podman.sock}"
        IR_PLATFORM_DIR="${IR_PLATFORM_DIR:-$(cd "${HERE}/.." && pwd)}"; export IR_PLATFORM_DIR
        IR_AGENT_HOST="${IR_AGENT_HOST:-$(hostname)}"; export IR_AGENT_HOST
    fi
    timeout "${COMPOSE_TIMEOUT}" env -C "${HERE}/${tier}" \
        ${COMPOSE} -p "$(proj "$tier")" --env-file ../.env -f docker-compose.yml "${overlay[@]}" "$@"
    local rc=$?
    # 124 = timeout killed it. The stage's own health gate decides whether that is fatal.
    [[ $rc -eq 124 ]] && warn "compose call timed out after ${COMPOSE_TIMEOUT}s (tier: ${tier})"
    return 0
}

# Is the worker part-way through a memory analysis?
#
# Counted, not `grep -q`. A quiet grep exits as soon as it matches and closes the pipe under
# the producer, and the resulting SIGPIPE makes the exit status unreliable — the check
# reports "no analysis" while one is running, which is the answer that destroys it.
analysis_in_progress() { # proj
    local n
    n="$(${RUNTIME} exec "$1_worker_1" sh -c \
         'ps -eo args | grep -c "[a]nalyze_memory_linux"' 2>/dev/null)" || return 1
    [[ "${n:-0}" -gt 0 ]]
}

# Would removing these containers also remove one matching `suffix`?
#
# podman refuses to remove a container that has dependents, so removals are done with
# --depend, which takes the dependents too. compose derives those dependencies from
# depends_on and adds ones that are not obvious from the compose file — the worker turns
# out to depend on the backend — so the cascade is computed from what podman actually
# recorded rather than assumed from the service definitions.
cascade_reaches() { # proj  suffix  container...
    local proj="$1" suffix="$2"; shift 2
    local doomed=" " name id deps changed=1

    for name in "$@"; do
        id="$(${RUNTIME} inspect "${name}" --format '{{.Id}}' 2>/dev/null)" || continue
        doomed+="${id} "
    done

    # Anything depending on a doomed container is itself doomed; repeat until it settles.
    while (( changed )); do
        changed=0
        for name in $(${RUNTIME} ps -a --filter "name=${proj}_" --format '{{.Names}}'); do
            id="$(${RUNTIME} inspect "${name}" --format '{{.Id}}' 2>/dev/null)" || continue
            [[ "${doomed}" == *" ${id} "* ]] && continue
            deps="$(${RUNTIME} inspect "${name}" --format '{{range .Dependencies}}{{.}} {{end}}' 2>/dev/null)"
            for dep in ${deps}; do
                if [[ "${doomed}" == *" ${dep} "* ]]; then
                    doomed+="${id} "; changed=1; break
                fi
            done
        done
    done

    for name in $(${RUNTIME} ps -a --filter "name=${proj}_" --format '{{.Names}}'); do
        [[ "${name}" == *"${suffix}" ]] || continue
        id="$(${RUNTIME} inspect "${name}" --format '{{.Id}}' 2>/dev/null)" || continue
        [[ "${doomed}" == *" ${id} "* ]] && return 0
    done
    return 1
}

# Remove containers still running an image that has since been rebuilt.
#
# compose will not recreate a container that is already up, so after a code change
# `up -d --build` builds the new image and then leaves the old one serving: the deployment
# succeeds and the change is silently absent. `--force-recreate` fixes that but drags the
# dependency graph along, restarting the data tier for an application change.
#
# So drifted containers are removed by name and recreated on their own. Only stateless
# services belong here — anything holding state must not be replaced this way.
recreate_if_stale() { # tier  service...
    local tier="$1"; shift
    local proj; proj="$(proj "$tier")"
    local svc name running current stale=()

    for svc in "$@"; do
        name="${proj}_${svc}_1"
        running="$(${RUNTIME} inspect "${name}" --format '{{.Image}}' 2>/dev/null)" || continue
        current="$(${RUNTIME} image inspect "localhost/ir-${svc}:latest" \
                   --format '{{.Id}}' 2>/dev/null)" || continue
        if [[ -n "${running}" && -n "${current}" && "${running}" != "${current}" ]]; then
            stale+=("${name}")
        fi
    done

    (( ${#stale[@]} )) || return 0

    # Removing a container takes everything that depends on it. The worker depends on the
    # backend, so replacing the backend silently kills whatever the worker is analyzing —
    # a memory pass over a real capture runs for over an hour and leaves the run marked
    # `running` with no process behind it. That is checked against the real cascade rather
    # than against the list of containers this function meant to remove, because the
    # analysis dies as collateral either way.
    # Decided once per deploy, not per call. This runs twice to converge on the built image,
    # and re-deriving the answer let the second pass proceed after the first had refused —
    # which destroyed the analysis the refusal existed to protect.
    if [[ -z "${RECREATE_BLOCKED:-}" ]]; then
        if analysis_in_progress "${proj}" && cascade_reaches "${proj}" "_worker_1" "${stale[@]}"; then
            if [[ "${IR_FORCE_RECREATE:-0}" != "1" ]]; then
                RECREATE_BLOCKED=1
            else
                RECREATE_BLOCKED=0
                warn "worker is mid-analysis and IR_FORCE_RECREATE=1 — that analysis will be lost"
            fi
        else
            RECREATE_BLOCKED=0
        fi
    fi
    if [[ "${RECREATE_BLOCKED}" == "1" ]]; then
        warn "the worker is mid-analysis and replacing ${stale[*]} would take it down with them"
        warn "skipping — re-run once the analysis finishes, or IR_FORCE_RECREATE=1 to discard it"
        return 0
    fi

    if (( ${#stale[@]} )); then
        warn "replacing container(s) running a superseded image: ${stale[*]}"
        # --depend is required, not optional: compose turns depends_on into podman
        # container dependencies, and podman refuses to remove a container that has
        # dependents. Without it the removal fails, the old container keeps running, and
        # the deploy reports success having changed nothing.
        #
        # The cascade is safe here because the stages that own those dependents run after
        # this one and bring them back in dependency order — which is the whole reason the
        # bring-up is staged.
        ${RUNTIME} rm -f --depend "${stale[@]}" >/dev/null 2>&1 || true
    fi
}

# Assert each container is running an image built since the source last changed.
#
# The failure this catches is silent by nature: the deploy succeeds, every health check
# passes, and the running code is whatever it was before.
#
# Deliberately not an image-ID comparison. compose rebuilds on every `up --build`, so two
# builds of identical source produce two different IDs and an ID check would warn on every
# deploy — a check that cries wolf gets ignored, which is worse than not having one. What
# actually matters is whether the running image predates the code, so that is what is
# compared.
# Carved regions staged for a reverse-engineering session are live malware sitting in the
# working tree as plain files. Tearing the platform down has to take them with it: they outlive
# the stack that produced them, they are the one artifact here that is dangerous rather than
# merely sensitive, and a session directory left behind is malware nobody is tracking any more.
#
# `platform/.gitignore` keeps them out of git, but an ignored file is still a file on disk — the
# guardrail stops them being published, not from being there.
purge_re_sessions() {
    local re_dir="${HERE}/../re-workstation"
    local purged=0 dir
    shopt -s nullglob
    for dir in "${re_dir}"/session-*/; do
        # Count before removing so the figure reported is what was actually there.
        local n
        n="$(find "${dir}" -maxdepth 1 -name '*.bin' -type f 2>/dev/null | wc -l)"
        # chmod first: staging sets regions 0400, and a read-only file in a directory the user
        # owns still deletes — but the manifest and .host marker are what make the directory
        # removable in one step.
        chmod -R u+w "${dir}" 2>/dev/null || true
        rm -rf "${dir}" && purged=$((purged + n))
    done
    shopt -u nullglob
    if (( purged > 0 )); then
        say "  purged ${purged} carved region(s) from reverse-engineering sessions"
    fi
}

verify_image() { # tier  service...
    local tier="$1"; shift
    local proj; proj="$(proj "$tier")"
    local svc src image built newest

    for svc in "$@"; do
        # An image can be fed by more than one directory: the backend and worker also carry
        # shared/sysstats.py, so a change there makes them stale too. Watching only the
        # service's own directory ships the old copy without saying so.
        case "${svc}" in
            frontend) src="${HERE}/../frontend" ;;
            backend|worker) src="${HERE}/../backend ${HERE}/../shared" ;;
            *) continue ;;
        esac

        image="$(${RUNTIME} inspect "${proj}_${svc}_1" --format '{{.Image}}' 2>/dev/null)" \
            || { warn "${svc}: no container to verify"; continue; }
        built="$(${RUNTIME} image inspect "${image}" --format '{{.Created}}' 2>/dev/null)" || continue
        built="$(date -d "${built}" +%s 2>/dev/null)" || continue

        # shellcheck disable=SC2086 — src is a deliberate list of directories
        newest="$(find ${src} \( -name node_modules -o -name __pycache__ -o -name .git \) \
                  -prune -o -type f -printf '%T@\n' 2>/dev/null | sort -rn | head -1)"
        newest="${newest%%.*}"
        [[ -n "${newest}" ]] || continue

        if (( built < newest )); then
            warn "${svc} is running an image built before its source last changed — the code you built is NOT the code that is running"
        fi
    done
}

# Wait until a container both exists and passes a probe. Fails loudly rather than
# letting a later stage start against a service that never came up.
wait_for() { # name  timeout_s  probe-command...
    local name="$1" timeout="$2"; shift 2
    local waited=0
    # A probe that runs a container against a missing image can never succeed: podman
    # treats the unknown local name as a registry reference and retries the pull on every
    # attempt, turning the timeout into minutes of silence. Refuse immediately instead.
    if [[ "$1" == *"${RUNTIME}"* || "$1" == "${RUNTIME}" ]] && [[ "$*" == *"localhost/"* ]]; then
        local probe_image
        probe_image="$(printf '%s\n' "$@" | grep -o 'localhost/[^ ]*' | head -1)"
        if [[ -n "${probe_image}" ]] && ! ${RUNTIME} image exists "${probe_image}" 2>/dev/null; then
            warn "probe image ${probe_image} is missing — cannot gate on ${name}"
            return 1
        fi
    fi
    while (( waited < timeout )); do
        if [[ "$(${RUNTIME} inspect "$name" --format '{{.State.Status}}' 2>/dev/null)" == "running" ]] \
           && "$@" >/dev/null 2>&1; then
            ok "$name ready (${waited}s)"; return 0
        fi
        # A container that exited will never become ready — surface it immediately.
        if [[ "$(${RUNTIME} inspect "$name" --format '{{.State.Status}}' 2>/dev/null)" == "exited" ]]; then
            warn "$name exited — last log:"
            ${RUNTIME} logs --tail 5 "$name" 2>&1 | sed 's/^/        /'
            return 1
        fi
        sleep 3; waited=$((waited+3))
    done
    warn "$name not ready after ${timeout}s"
    ${RUNTIME} logs --tail 5 "$name" 2>&1 | sed 's/^/        /'
    return 1
}

pyprobe() { ${RUNTIME} exec "$1" python3 -c "import urllib.request as u;u.urlopen('$2',timeout=4)"; }
logmatch() { [[ "$(${RUNTIME} logs "$1" 2>&1 | grep -c "$2")" -gt 0 ]]; }

# Images the staged gates depend on, built before any tier starts.
#
# Two of them are not produced by `podman-compose up` of the tier that needs them:
#
#   ir-workstation  the probe/tools image. Health gates in the DMZ and enclave stages run
#                   their checks from it, but it is defined in the WORKSTATION compose —
#                   which deploys last. On a clean system the gates would reference an
#                   image that does not exist yet, and each attempt tries to pull it from a
#                   registry, so the wait spins instead of failing.
#   ir-worker       the analysis sandbox. It needs a staged build context that reaches
#                   outside the compose context, so compose cannot build it at all.
#
# Building both here makes a clean deployment work the same as a repeat one.
ensure_build_images() {
    say "Images · prerequisites for the staged gates"

    if ! ${RUNTIME} image exists localhost/ir-workstation:latest 2>/dev/null; then
        ${RUNTIME} build -t localhost/ir-workstation:latest \
            -f "${HERE}/../workstation/Dockerfile.tools" "${HERE}/../workstation" \
            >/dev/null 2>&1 \
            && ok "probe/tools image built" \
            || die "could not build the probe image — every health gate depends on it"
    else
        ok "probe/tools image present"
    fi

    if ! ${RUNTIME} image exists localhost/ir-worker:latest 2>/dev/null; then
        say "  building the analysis worker (Volatility + toolkit analysis stack)"
        bash "${HERE}/../backend/build_worker.sh" >/dev/null 2>&1 \
            && ok "analysis worker image built" \
            || die "could not build the analysis worker — see backend/build_worker.sh"
    else
        ok "analysis worker image present"
    fi
}

# Remove containers belonging to a tier whose service no longer exists in its compose file.
#
# Compose only manages services it can see. Delete a service and its container keeps running,
# still attached to the tier's networks, still holding whatever it was given — and `up` and `down`
# both ignore it because neither knows it exists. That is not tidiness: a removed Boundary worker
# went on running in the DMZ, still registered, still able to be handed a session, after the
# design had moved it into the enclave. The UAT saw the deployment the codebase describes and the
# host was running something else.
reap_orphans() {
    local tier="$1" project svc names live=""
    project="$(proj "${tier}")"
    live="$(dc "${tier}" config --services 2>/dev/null | tr -d '\r')"
    # No service list means compose could not parse the file. Removing everything on that basis
    # would take down the tier, so it does nothing instead.
    [[ -n "${live}" ]] || { warn "could not list ${tier} services — skipping orphan check"; return 0; }
    names="$(${RUNTIME} ps -a --format '{{.Names}}' 2>/dev/null | grep "^${project}_" || true)"
    for c in ${names}; do
        svc="${c#"${project}_"}"; svc="${svc%_*}"
        grep -qx -- "${svc}" <<<"${live}" && continue
        ${RUNTIME} rm -f "${c}" >/dev/null 2>&1 \
            && ok "removed orphaned container ${c} (no such service in ${tier})" \
            || warn "could not remove orphaned container ${c}"
    done
}

ensure_networks() {
    # `--internal` is the egress control: no route off the host, so nothing on the analyst
    # segment reaches the internet regardless of what it manages to resolve.
    #
    # The runtime's own resolver is deliberately left ENABLED here. It is what makes service
    # addresses dynamic — it tracks where each container currently is, so no service needs a
    # pinned address and a second analyst workstation cannot collide with the first. It is
    # never handed to a container directly: every service's `dns:` points at CoreDNS, which
    # forwards in-zone lookups to it and REFUSES everything else. The restriction lives in the
    # Corefile, where it is written down, rather than in the absence of a resolver.
    ${RUNTIME} network exists ir-edge 2>/dev/null || \
        ${RUNTIME} network create --internal --subnet "${EDGE_SUBNET}" ir-edge >/dev/null
    # `--internal` here too. The DMZ<->enclave link carries the puller, the ingress and the IdP,
    # and none of them has any business reaching the internet — the puller dials the receiver,
    # the ingress serves the broker, and the IdP's outbound calls are telemetry it does not need.
    #
    # It closes a real leak rather than a theoretical one. Without it the runtime's resolver on
    # this network forwards anything it cannot answer to the HOST's resolvers, so the puller —
    # the enclave's only bridge outward — could resolve arbitrary internet names and the DNS
    # exfiltration channel stayed open on the one container best placed to use it. The enclave's
    # own network was already internal, which is why this was invisible from inside it.
    ${RUNTIME} network exists ir-dmzlink 2>/dev/null || \
        ${RUNTIME} network create --internal --subnet "${DMZLINK_SUBNET}" ir-dmzlink >/dev/null
    ok "networks: ir-edge (${EDGE_SUBNET}, no egress), ir-dmzlink"
}

# The runtime assigns gateway addresses when it creates a network. Asking it is what keeps those
# addresses out of .env, where a hand-written copy silently stops matching the moment a network
# is recreated on a different subnet.
net_gateway() {
    ${RUNTIME} network inspect "$1" \
        --format '{{range .Subnets}}{{.Gateway}}{{end}}' 2>/dev/null | tr -d '[:space:]'
}

# Wait for a tailnet node to hold an address.
#
# Polled, not sampled once. Registration is not instant — the node resolves the control plane,
# completes a TLS handshake, registers, and only then is assigned an address — so a single check
# right after `up` reports a healthy node as missing. That warning sent two separate
# investigations after a tunnel that was seconds from coming up, which is worse than silence:
# a check that cries wolf gets ignored on the run where it is right.
wait_tailnet_ip() { # container  seconds
    local c="$1" limit="${2:-90}" waited=0 ip
    while (( waited < limit )); do
        ip="$(${RUNTIME} exec "${c}" tailscale ip -4 2>/dev/null | tr -d '[:space:]')"
        [[ "${ip}" =~ ^100\. ]] && { printf '%s' "${ip}"; return 0; }
        sleep 5; waited=$((waited+5))
    done
    return 1
}

# Start each sidecar in its service's CURRENT network namespace.
#
# A sidecar runs with network_mode: service:<svc>. Recreate the service — a changed image, a new
# volume — and compose leaves the unchanged sidecar running, still attached to a namespace that
# no longer exists. Envoy cannot bind there, the service reports its database unreachable, and
# nothing in that symptom names a stale namespace. Removing and recreating the sidecar every time
# also guarantees it reads the registration made moments earlier.
#
# Removing the SHARER is safe; the deadlock is in removing the SHARED service while a sharer is
# still attached.
mesh_sidecars() { # service...
    local svc names=() targets=()
    for svc in "$@"; do
        names+=("ir-enclave_${svc}-sidecar_1")
        targets+=("${svc}-sidecar")
    done
    ${RUNTIME} rm -f "${names[@]}" >/dev/null 2>&1 || true
    dc enclave up -d --no-deps "${targets[@]}" >/dev/null 2>&1
}

# Attach services to the mesh: register, start proxies, re-register, restart proxies.
#
# The repetition is not caution, it is the only order that converges. A registration must exist
# before a proxy starts, or `consul connect envoy -sidecar-for` has nothing to front. But
# bringing a proxy up through compose can RECREATE its service — a changed definition, and
# --no-deps does not reliably prevent it — giving the service a new address while the proxy is
# still trying to bind the old one. So: register so the proxies can start, let compose settle,
# register again from what is actually running, then restart the proxies through podman, which
# starts nothing compose could recreate.
mesh_attach() { # service...
    local svc cn svcs=()
    bash "${HERE}/../hashicorp/consul/register-mesh.sh" >/dev/null 2>&1 || true
    mesh_sidecars "$@"
    bash "${HERE}/../hashicorp/consul/register-mesh.sh" >/dev/null 2>&1 \
        || warn "mesh registration incomplete"

    # EVERY sidecar, not only the ones this stage created. A later stage recreates services an
    # earlier one already attached — bringing up Vault recreates the database, because the
    # provisioning one-shots share its network namespace — which leaves that proxy in a dead
    # namespace. The symptom appears two stages away, as an application unable to reach a
    # database that is running and healthy.
    while read -r cn; do
        [[ -n "${cn}" ]] || continue
        svc="${cn#ir-enclave_}"; svcs+=("${svc%-sidecar_1}")
    done < <(${RUNTIME} ps -a --format '{{.Names}}' | grep -- '-sidecar_1$' || true)
    [[ ${#svcs[@]} -gt 0 ]] && mesh_orphan_check "${svcs[@]}"

    # And once the proxies are sound, any service that gave up while they were not. Last, so the
    # namespace it comes up in is the one its proxy is already serving.
    for svc in "$@"; do
        cn="ir-enclave_${svc}_1"
        [[ "$(${RUNTIME} inspect -f '{{.State.Status}}' "${cn}" 2>/dev/null)" == "exited" ]] || continue
        if ${RUNTIME} start "${cn}" >/dev/null 2>&1; then
            ok "${svc} outwaited its proxy — restarted onto the mesh"
            # A fresh namespace again: its proxy must follow it.
            mesh_sidecars "${svc}"
        else
            warn "${svc} exited and could not be restarted"
        fi
    done
}

# Wait until a service can actually reach an upstream THROUGH its proxy.
#
# "The sidecar container is up" is the wrong gate for anything that dials through the mesh: Envoy
# binds its upstream listeners only after fetching configuration, and a proxy left in an orphaned
# namespace stays up while serving nothing. Probed from inside the namespace the service itself
# uses, which is the only place the answer means anything.
mesh_ready() { # service  port  [timeout_s]
    local svc="$1" port="$2" t="${3:-90}" cn waited=0
    cn="ir-enclave_${svc}-sidecar_1"
    while (( waited < t )); do
        ${RUNTIME} exec "${cn}" \
            sh -c "timeout 2 bash -c '</dev/tcp/127.0.0.1/${port}'" >/dev/null 2>&1 && return 0
        sleep 3; waited=$((waited+3))
    done
    return 1
}

# A sidecar is sound only if it shares its service's CURRENT network namespace. Address
# comparison cannot tell: with static addresses, a proxy orphaned in a dead namespace has bound
# the exact address the recreated service now holds — same number, wrong namespace, serving
# nothing. The namespace inode via each process's /proc entry IS the identity; podman's
# SandboxKey field is empty for restarted containers and cannot be trusted. Repaired proxies
# are recreated, not restarted — recreation is what joins the new namespace. Healthy proxies
# are left alone: bouncing the database's proxy severs the backend mid-migration for nothing.
netns_of() { # container -> net:[inode] or empty
    local pid
    pid="$(${RUNTIME} inspect -f '{{.State.Pid}}' "$1" 2>/dev/null || true)"
    [[ "${pid:-0}" -gt 0 ]] || return 0
    readlink "/proc/${pid}/ns/net" 2>/dev/null || true
}

# Converges rather than sweeping once. A service can be started BY THIS SCRIPT moments after
# its proxy was placed — the start gives it a fresh namespace and strands the proxy again — so
# a single pass repairs the mesh into a state its own later steps have already invalidated.
# Each pass re-reads the namespaces, and the loop ends when nothing needed repair.
mesh_orphan_check() { # service...
    local svc ns_svc ns_prx pass repaired
    for pass in 1 2 3; do
        repaired=0
        for svc in "$@"; do
            ns_svc="$(netns_of "ir-enclave_${svc}_1")"
            [[ -n "${ns_svc}" ]] || continue   # service not running — nothing to serve yet
            ns_prx="$(netns_of "ir-enclave_${svc}-sidecar_1")"
            [[ "${ns_prx}" == "${ns_svc}" ]] && continue
            [[ "${pass}" == "1" ]] \
                && warn "${svc}-sidecar is orphaned from its service's namespace — recreating it"
            bash "${HERE}/../hashicorp/consul/register-mesh.sh" >/dev/null 2>&1 || true
            mesh_sidecars "${svc}"
            repaired=$((repaired + 1))
        done
        [[ "${repaired}" == "0" ]] && return 0
        sleep 2
    done
    for svc in "$@"; do
        ns_svc="$(netns_of "ir-enclave_${svc}_1")"
        [[ -n "${ns_svc}" ]] || continue
        [[ "$(netns_of "ir-enclave_${svc}-sidecar_1")" == "${ns_svc}" ]] \
            || warn "${svc}-sidecar could not be kept with its service — it is serving nothing"
    done
}

# The static mesh addresses, validated BEFORE anything starts. To move a service: change its
# IR_IP_* in deploy/.env and redeploy — this is the whole mechanism, and this check is what makes
# it safe. An address outside the subnet or claimed twice otherwise surfaces as a container that
# will not start, or worse, one that does and cannot be reached.
mesh_addr_check() {
    python3 - <<'PY' || die "static mesh addressing is invalid — fix IR_IP_* in deploy/.env"
import ipaddress, os, sys
subnet = ipaddress.ip_network(os.environ["ENCLAVE_SUBNET"])
claimed = {"ENCLAVE_DNS_IP": os.environ["ENCLAVE_DNS_IP"]}
rc = 0
for svc in ("DB", "MINIO", "VAULT", "BACKEND", "WORKER", "FRONTEND", "PULLER"):
    var = f"IR_IP_{svc}"; val = os.environ.get(var, "")
    if not val:
        print(f"    {var} is unset — the mesh cannot register {svc.lower()}"); rc = 1; continue
    try:
        ip = ipaddress.ip_address(val)
    except ValueError:
        print(f"    {var}={val} is not an address"); rc = 1; continue
    if ip not in subnet.hosts():
        print(f"    {var}={val} is outside {subnet}"); rc = 1
    for other, taken in claimed.items():
        if val == taken:
            print(f"    {var}={val} collides with {other}"); rc = 1
    claimed[var] = val
sys.exit(rc)
PY
}

# --- staged tier bring-ups -------------------------------------------------

up_enclave() {
    reap_orphans enclave
    mesh_addr_check
    # The resolver comes up before anything that depends on it: every service below is given
    # this resolver and no other, so a service started first would have nothing to resolve with.
    say "Enclave · stage 0/4 — resolver"
    # Compose creates the enclave networks on first `up`, and their gateways are what the
    # resolver forwards to — so it has to exist before the Corefile can be rendered.
    ${RUNTIME} network exists ir-enclave_internal 2>/dev/null || \
        dc enclave up -d --no-start db >/dev/null 2>&1
    local enc_dns dmz_dns
    enc_dns="$(net_gateway ir-enclave_internal)"
    dmz_dns="$(net_gateway ir-dmzlink)"
    [[ -n "${enc_dns}" ]] || die "ir-enclave_internal has no gateway — the resolver cannot forward in-zone"
    [[ -n "${dmz_dns}" ]] || die "ir-dmzlink has no gateway — the puller could never resolve the receiver"
    sed -e "s|__RUNTIME_ZONE__|${RUNTIME_DNS_ZONE}|g" \
        -e "s|__ENCLAVE_DNS__|${enc_dns}|g" \
        -e "s|__DMZ_DNS__|${dmz_dns}|g" \
        "${HERE}/../hashicorp/access/Corefile.enclave.tmpl" \
        > "${HERE}/../hashicorp/access/Corefile.enclave"
    dc enclave up -d coredns >/dev/null 2>&1
    wait_for ir-enclave_coredns_1 45 true || warn "enclave resolver slow to start"
    ok "enclave resolver up — in-zone via ${enc_dns}, receiver via ${dmz_dns}, all else REFUSED"

    say "Enclave · stage 0b/4 — access broker"
    # The controller's API listener carries the analyst's password and the session token across
    # the DMZ link. It refuses to serve without a certificate, so one is generated here rather
    # than left for somebody to remember.
    BOUNDARY_HOST="${BOUNDARY_HOST}" bash "${HERE}/../hashicorp/access/gen-boundary-cert.sh" >/dev/null 2>&1 \
        || warn "could not generate the Boundary certificate"
    [[ -f "${HERE}/../hashicorp/access/certs/boundary.crt" ]] \
        || die "no Boundary certificate — the analyst credential would cross the link in the clear"

    sed -e "s|__BOUNDARY_ROOT_KEY__|${BOUNDARY_ROOT_KEY}|" \
        -e "s|__BOUNDARY_WORKER_AUTH_KEY__|${BOUNDARY_WORKER_AUTH_KEY}|" \
        -e "s|__BOUNDARY_RECOVERY_KEY__|${BOUNDARY_RECOVERY_KEY}|" \
        -e "s|__BOUNDARY_CONTROLLER__|${BOUNDARY_HOST}|" \
        "${HERE}/../hashicorp/access/boundary-controller.hcl.tmpl" \
        > "${HERE}/../hashicorp/access/boundary-controller.hcl"
    chmod 600 "${HERE}/../hashicorp/access/boundary-controller.hcl"
    sed -e "s|__BOUNDARY_WORKER_AUTH_KEY__|${BOUNDARY_WORKER_AUTH_KEY}|" \
        -e "s|__BOUNDARY_CONTROLLER__|${BOUNDARY_HOST}|" \
        -e "s|__WORKER_PUBLIC_ADDR__|${BOUNDARY_EGRESS_HOST:-boundary-egress}:9202|" \
        "${HERE}/../hashicorp/access/boundary-egress.hcl.tmpl" \
        > "${HERE}/../hashicorp/access/boundary-egress.hcl"
    chmod 600 "${HERE}/../hashicorp/access/boundary-egress.hcl"
    ok "Boundary configs rendered (TLS on the API; egress advertises ${BOUNDARY_EGRESS_HOST:-boundary-egress}:9202)"

    # Staged, like every other dependency here: the database is gated on accepting connections
    # before the controller is started against it.
    dc enclave up -d boundary-db >/dev/null 2>&1
    wait_for ir-enclave_boundary-db_1 120 \
        ${RUNTIME} exec ir-enclave_boundary-db_1 pg_isready -U boundary \
        || die "Boundary's database never became ready"
    # Recreated so a re-rendered config is actually read. Its config is bind-mounted, and
    # `compose up` leaves a running container alone — so a changed listener or key silently keeps
    # the old value. The controller holds no state in the container; its database is separate.
    ${RUNTIME} rm -f ir-enclave_boundary_1 ir-enclave_boundary-egress_1 >/dev/null 2>&1 || true
    dc enclave up -d boundary >/dev/null 2>&1
    wait_for ir-enclave_boundary_1 150 \
        ${RUNTIME} exec ir-enclave_boundary_1 wget -q -O- http://127.0.0.1:9203/health \
        || die "Boundary never became healthy — analysts have no route into the enclave"
    # One target: the SSO gate. Idempotent, so a re-deploy does not split the allow-list in two.
    # Output surfaced, not discarded: a swallowed provisioning error leaves the next failure
    # ("no target") describing a symptom rather than the cause.
    if ! bout="$(${RUNTIME} exec ir-enclave_boundary_1 sh /boundary/bootstrap.sh 2>&1)"; then
        warn "Boundary provisioning failed:"
        printf '%s\n' "${bout}" | tail -6 | sed 's/^/        /'
    fi
    if bids="$(${RUNTIME} exec ir-enclave_boundary_1 cat /boundary-state/boundary-ids.env 2>/dev/null)"; then
        # Written where dc() sources per-bring-up values, so the DMZ session client gets them
        # without them being committed.
        printf '%s\n' "${bids}" > "${HERE}/.env.boundary"
        chmod 600 "${HERE}/.env.boundary"
        set -a; eval "${bids}"; set +a
        ok "Boundary target provisioned (${BOUNDARY_TARGET_ID:-unknown})"
    else
        die "Boundary produced no target — the analyst path cannot be opened"
    fi

    # The worker that actually carries the session, started after the controller so its first
    # registration attempt has something to register with.
    dc enclave up -d boundary-egress >/dev/null 2>&1
    wait_for ir-enclave_boundary-egress_1 90 \
        ${RUNTIME} exec ir-enclave_boundary-egress_1 wget -q -O- http://127.0.0.1:9203/health \
        || die "the Boundary egress worker never became healthy"
    # Registration is its own gate. A target with no worker authorizes a session normally and
    # then carries nothing, and the failure surfaces at the far end of the path as a hung
    # connection — several tiers from the cause.
    # It also reaps registrations that no longer correspond to a running worker. Those keep
    # advertising an address nothing serves, and the controller still hands sessions to them —
    # so some sessions hang and the rest work, which reads as an intermittent network fault.
    if ! bw="$(${RUNTIME} exec ir-enclave_boundary_1 sh /boundary/workers.sh ir-egress 2>&1)"; then
        warn "no Boundary worker registered — sessions would be authorized and then carry nothing:"
        printf '%s\n' "${bw}" | tail -6 | sed 's/^/        /'
    else
        printf '%s\n' "${bw}" | while read -r line; do ok "Boundary: ${line}"; done
    fi

    # Recreating the controller and egress worker just killed any live DMZ broker session; the
    # broker then exits, compose never restarts an exited container, and the analyst path stays
    # dead until someone remembers to run `deploy.sh dmz`. If the DMZ tier is deployed, the
    # broker is re-established here — the enclave deploy broke it, so the enclave deploy fixes it.
    if ${RUNTIME} container exists ir-dmz_broker_1 2>/dev/null; then
        ${RUNTIME} rm -f ir-dmz_broker_1 >/dev/null 2>&1 || true
        dc dmz up -d broker >/dev/null 2>&1
        if wait_for ir-dmz_broker_1 90 logmatch ir-dmz_broker_1 "authenticated as"; then
            ok "DMZ session broker re-established against the new controller"
        else
            warn "the DMZ broker did not re-establish — run deploy.sh dmz"
        fi
    fi

    say "Enclave · stage 1/4 — data tier"
    dc enclave up -d --build db redis minio >/dev/null 2>&1
    wait_for ir-enclave_db_1 120 ${RUNTIME} exec ir-enclave_db_1 pg_isready -U "${POSTGRES_USER}" \
        || die "database never became ready"
    wait_for ir-enclave_redis_1 60 ${RUNTIME} exec ir-enclave_redis_1 redis-cli ping || warn "redis slow"
    # Probed from INSIDE MinIO's own namespace. With the mesh on it binds loopback, so a probe
    # across the enclave network cannot reach it by design — and reported the object store down
    # precisely when the mesh was working.
    wait_for ir-enclave_minio_1 90 \
        ${RUNTIME} exec ir-enclave_minio_1 \
        curl -fsS --max-time 4 http://127.0.0.1:9000/minio/health/live \
        || warn "object store slow to report healthy"

    # ---- service mesh -----------------------------------------------------
    # Ordering here is forced by a circularity, not by preference. A Connect registration carries
    # the address other proxies dial, so a service must be RUNNING before it can be registered;
    # its sidecar cannot start before that registration exists; and with the destinations bound to
    # loopback, consumers cannot reach anything until their own sidecar is up. So:
    #
    #   destinations up -> register them -> their sidecars -> (consumers start and retry)
    #   -> register consumers -> consumer sidecars
    #
    # The applications tolerate the gap because every one of them retries its database connection
    # at start-up; that retry is what makes this converge rather than deadlock.
    say "Enclave · stage 1a/4 — service mesh (control plane)"
    CONSUL_SEC="${HERE}/../hashicorp/consul/secrets"
    # Before Consul starts: its config refuses to load without the gossip key and management
    # token, and every sidecar bind-mounts a token file that must already exist — a missing bind
    # mount silently becomes an empty directory.
    bash "${HERE}/../hashicorp/consul/gen-consul-secrets.sh" >/dev/null 2>&1 \
        || die "could not generate Consul's TLS and ACL material"

    # Validated before it is started. An invalid config crash-loops the agent, and every stage
    # after this one then fails describing a symptom several tiers from the cause.
    if ! cval="$(${RUNTIME} run --rm \
            -v "${HERE}/../hashicorp/consul/server.hcl:/consul/config/server.hcl:ro,z" \
            -v "${CONSUL_SEC}/agent-secrets.hcl:/consul/config/zz-secrets.hcl:ro,z" \
            -v "${CONSUL_SEC}/consul-ca.pem:/consul/tls/consul-ca.pem:ro,z" \
            -v "${CONSUL_SEC}/consul-agent.pem:/consul/tls/consul-agent.pem:ro,z" \
            -v "${CONSUL_SEC}/consul-agent-key.pem:/consul/tls/consul-agent-key.pem:ro,z" \
            docker.io/hashicorp/consul:2.0.2 validate /consul/config 2>&1)"; then
        printf '%s\n' "${cval}" | tail -6 | sed 's/^/        /'
        die "Consul's configuration is invalid — the mesh would not come up"
    fi

    # Recreated so a changed config is actually read: it is bind-mounted, and `compose up` leaves
    # a running container alone. Raft state is on a volume, and the catalog is re-registered
    # below, so nothing is lost.
    ${RUNTIME} rm -f ir-enclave_consul_1 >/dev/null 2>&1 || true
    dc enclave up -d consul >/dev/null 2>&1

    # `acl token read -self` with the management token succeeds only once a leader is elected AND
    # the ACL system has initialized it, so one gate covers both.
    consul_cli() {
        ${RUNTIME} exec \
            -e CONSUL_HTTP_ADDR=https://127.0.0.1:8501 \
            -e CONSUL_CACERT=/consul/tls/consul-ca.pem \
            -e CONSUL_HTTP_TOKEN="$(cat "${CONSUL_SEC}/tokens/management.token" 2>/dev/null)" \
            ir-enclave_consul_1 consul "$@"
    }
    wait_for ir-enclave_consul_1 90 consul_cli acl token read -self \
        || die "Consul never elected a leader or never accepted its management token"
    if ! abo="$(bash "${HERE}/../hashicorp/consul/consul-acl-bootstrap.sh" 2>&1)"; then
        warn "Consul ACL bootstrap incomplete — sidecars will fail to authenticate:"
        printf '%s\n' "${abo}" | tail -6 | sed 's/^/        /'
    fi
    ok "Consul up with TLS, gossip encryption and default-deny ACLs"

    if [[ "${IR_MESH:-1}" == "1" ]]; then
        say "Enclave · stage 1b/4 — service mesh (destinations)"
        dc enclave build db-sidecar >/dev/null 2>&1
        mesh_attach db minio
        ok "data-tier sidecars up — Postgres and MinIO are reachable only through them"
    fi

    say "Enclave · stage 1c/4 — secrets"
    # Ordered by what each step needs, because none of it is inferable from depends_on:
    # certs -> server -> unseal+provision -> agent renders. The application tier starts only
    # once a rendered secrets file exists, since with IR_VAULT=1 it has no other source for
    # its database password.
    if [[ "${IR_VAULT:-1}" != "1" ]]; then
        warn "IR_VAULT=0 — the app tier will use static secrets from .env"
    else
        # The one-shots are removed first or they never run again: `compose up` will not restart
        # a container that exited 0, so a corrected bootstrap script sits bind-mounted in a dead
        # container while every deploy reports success with the old behaviour. Both converge —
        # db-bootstrap reconciles grants, vault-setup exits early once provisioned — so running
        # them every deploy is the point, not a cost.
        # --depend, and NOT silenced. podman refuses to remove a container that has dependents,
        # and vault-agent depends on the server — so a plain `rm -f` on the server failed, the
        # `|| true` swallowed it, and a corrected vault-server.hcl silently never took effect
        # while every deploy reported success. --depend takes the dependents along, which is
        # what we want here: the whole group is recreated on the next line.
        #
        # Recreating is safe — raft, certs, state and rendered secrets all live on volumes — and
        # the server comes back sealed, which the unseal step below exists to handle.
        # Namespace-sharing containers FIRST, and separately.
        #
        # A sidecar runs with network_mode: service:<svc>, and removing the service while another
        # container is still using its network namespace DEADLOCKS podman: the `rm` hangs while
        # holding the storage lock, and every later podman call in the deployment blocks behind
        # it until the process is killed by hand. --depend does not help — it computes the
        # cascade but still tears down in an order that can strand the namespace.
        ${RUNTIME} rm -f ir-enclave_vault-sidecar_1 >/dev/null 2>&1 || true
        if ! vrm="$(${RUNTIME} rm -f --depend ir-enclave_vault_1 2>&1)"; then
            case "${vrm}" in
                *"no such container"*) : ;;   # first deployment
                *) warn "could not recreate the Vault group — a config change may not take effect:"
                   printf '%s\n' "${vrm}" | tail -3 | sed 's/^/        /' ;;
            esac
        fi
        # The one-shots, in case they were not caught by the dependency cascade above: `compose
        # up` will not restart a container that exited 0, so a corrected script sits bind-mounted
        # in a dead container. Both converge — db-bootstrap reconciles grants, vault-setup exits
        # early once provisioned — so running them every deploy is the point, not a cost.
        ${RUNTIME} rm -f ir-enclave_db-bootstrap_1 ir-enclave_vault-setup_1 >/dev/null 2>&1 || true
        # ONE compose call for the whole group. Called service by service, compose walks
        # depends_on and RECREATES the server for each dependent — so Vault restarted while
        # provisioning was running against it, and came back sealed with the setup one-shot
        # already exited. Everything downstream then reported an authentication failure.
        dc enclave up -d vault-certs-init vault >/dev/null 2>&1
        # Vault is a mesh consumer: its database engine dials Postgres to mint and revoke
        # dynamic users, and with Postgres on loopback that only works through its sidecar.
        # Registered once it is running, because the registration carries its address.
        if [[ "${IR_MESH:-1}" == "1" ]]; then
            mesh_attach vault
        fi
        # ANSWERING, not unsealed. A fresh Vault comes up uninitialized and sealed by design.
        wait_for ir-enclave_vault_1 120 \
            ${RUNTIME} exec -e VAULT_ADDR=https://127.0.0.1:8200 \
            -e VAULT_CACERT=/certs/vault-ca.crt.pem ir-enclave_vault_1 \
            sh -c 'vault status -format=json 2>/dev/null | grep -q "\"initialized\""' \
            || die "Vault's API never answered — its TLS material is the usual cause"

        # Unsealing is separate from provisioning and runs EVERY deployment, because Vault seals
        # itself whenever the process restarts. Provisioning happens once; this does not.
        #
        # --user root: the unseal material is written root-owned mode 600 by the setup one-shot,
        # and the server process runs as the unprivileged vault user, which cannot read it. Under
        # rootless podman "root" here is the invoking host user, and the state volume stays
        # mounted read-only in this container regardless of who execs.
        if ! vout="$(${RUNTIME} exec --user root ir-enclave_vault_1 sh /opt/vault-unseal.sh 2>&1)"; then
            case "${vout}" in
                *"not initialized"*)
                    # First deployment: nothing has initialized Vault yet, and vault-setup is what
                    # does it — so it starts here rather than after the gate.
                    dc enclave up -d --no-deps vault-setup >/dev/null 2>&1
                    wait_for ir-enclave_vault_1 180 \
                        ${RUNTIME} exec -e VAULT_ADDR=https://127.0.0.1:8200 \
                        -e VAULT_CACERT=/certs/vault-ca.crt.pem ir-enclave_vault_1 \
                        sh -c 'vault status -format=json 2>/dev/null | grep -q "\"sealed\": *false"' \
                        || { warn "Vault never unsealed — vault-setup said:"
                             ${RUNTIME} logs ir-enclave_vault-setup_1 2>&1 | tail -10 | sed 's/^/        /'
                             die "the app tier has no credentials"; } ;;
                *)
                    printf '%s\n' "${vout}" | tail -6 | sed 's/^/        /'
                    die "Vault could not be unsealed — the app tier has no credentials" ;;
            esac
        fi
        ok "Vault unsealed"

        # The one-shots run only now, against an UNSEALED Vault. Started earlier they race this
        # gate: vault-setup unseals Vault itself to provision, then the deployment's own restart
        # re-seals it underneath, and the reconcile it exists to perform fails with "Vault is
        # sealed" while every other step reports success.
        #
        # --no-deps, or compose walks depends_on and recreates Vault, orphaning the sidecar that
        # carries its database upstream.
        # NO --no-deps. podman-compose silently SKIPS vault-setup when it is passed — it reports
        # success and creates nothing, and the platform then runs on already-issued leases while
        # every stage reports healthy. Verified by container id: the flag does not prevent the
        # recreation it was reached for, it just drops the service.
        if ! vup="$(dc enclave up -d db-bootstrap vault-setup vault-agent 2>&1)"; then
            warn "the Vault one-shots did not start — credentials will not reconcile:"
            printf '%s\n' "${vup}" | tail -5 | sed 's/^/        /'
        fi

        # Repaired around them. That compose call walks depends_on and can recreate Vault, which
        # re-seals it and orphans the proxy carrying its database upstream. vault-setup tolerates
        # exactly this — it unseals and retries the reconcile for a minute — so the mesh is
        # re-attached and gated here, inside that window.
        if [[ "${IR_MESH:-1}" == "1" ]]; then
            mesh_attach vault
            mesh_ready vault 5432 90 \
                && ok "Vault reaches Postgres through the mesh" \
                || warn "Vault's database upstream never opened — it cannot mint or revoke credentials"
        fi
        # The rendered file IS the gate. The agent starting proves nothing: it retries auth in
        # the background and a template that never renders leaves the app with no password.
        wait_for ir-enclave_vault-agent_1 150 \
            ${RUNTIME} exec ir-enclave_vault-agent_1 \
            sh -c 'grep -q POSTGRES_PASSWORD /vault/secrets/app.env' \
            || die "Vault Agent never rendered the app secrets — the app tier cannot start"
        vuser="$(${RUNTIME} exec ir-enclave_vault-agent_1 \
                 sh -c 'grep "^export POSTGRES_USER=" /vault/secrets/app.env | cut -d= -f2' 2>/dev/null)"
        ok "Vault issued the app tier a dynamic database user (${vuser:-unknown})"
    fi

    say "Enclave · stage 2/4 — identity (Keycloak takes ~60s)"
    dc enclave up -d keycloak >/dev/null 2>&1
    wait_for ir-enclave_keycloak_1 300 logmatch ir-enclave_keycloak_1 "Listening on" \
        || die "Keycloak never started — the SSO gate cannot come up without it"

    say "Enclave · stage 3/4 — application"
    # Compose cannot be trusted to leave a container on the image it just built: it walks
    # the dependency graph and creates a service before its own build has finished
    # re-tagging, so the container is pinned to whatever `:latest` meant a moment earlier.
    # One build-and-create pass therefore converges only by luck.
    #
    # So it is done in two: build once, then remove whatever ended up on the wrong image
    # and create again from the tag the build produced. The second pass does no building,
    # which is what makes it settle.
    # A running analysis takes the whole stage out of scope, not just the removal step.
    # compose recreates a service whose image changed and takes the dependency graph with
    # it, so an `up` here would do the exact damage the guard exists to prevent — by
    # compose's hand rather than ours. The check is on the analysis alone, because any
    # compose action on this tier can reach the worker.
    if [[ "${IR_FORCE_RECREATE:-0}" != "1" ]] && analysis_in_progress "$(proj enclave)"; then
        warn "a memory analysis is running — leaving the application tier as it is"
        warn "re-run when it finishes, or IR_FORCE_RECREATE=1 to deploy and discard it"
    else
        recreate_if_stale enclave backend frontend worker
        dc enclave up -d --build backend frontend worker >/dev/null 2>&1
        recreate_if_stale enclave backend frontend worker
        dc enclave up -d backend frontend worker >/dev/null 2>&1
    fi
    # Their sidecars, IMMEDIATELY — before the health gate below, not after.
    #
    # This ordering is forced. With Postgres on loopback the backend cannot reach it until its
    # own proxy exists, and the proxy cannot be registered until the backend is running and has
    # an address. The gap between those two is bounded by the application's start-up retry, so
    # registering here keeps it to a few seconds; doing it after the health gate meant the
    # backend exhausted its retries and exited, and the deployment reported an unhealthy API
    # rather than a missing sidecar.
    # --no-deps on every sidecar start. A sidecar declares depends_on its service, so compose
    # walks the graph and RECREATES that service if its definition changed — after the
    # registration above recorded the old address. The proxy then cannot bind the address it was
    # registered at, and the application reports the database unreachable, which points at the
    # mesh policy rather than at a stale registration.
    if [[ "${IR_MESH:-1}" == "1" ]]; then
        mesh_attach backend worker frontend
        ok "application sidecars up — every data-tier connection now passes an intention check"
    fi
    verify_image enclave backend frontend worker
    # AFTER verify_image, which recreates a service left on a stale image — and a recreated
    # service has a new network namespace, stranding the proxy attached a moment ago. Sweeping
    # here makes namespace reconciliation the LAST thing the stage does, so nothing that runs
    # after it can undo the attach.
    if [[ "${IR_MESH:-1}" == "1" ]]; then
        mesh_orphan_check db minio vault backend worker frontend puller
    fi
    wait_for ir-enclave_backend_1 180 pyprobe ir-enclave_backend_1 http://127.0.0.1:8000/api/health/ \
        || die "API never became healthy"

    say "Enclave · stage 4/4 — SSO gate + ingress + puller"
    dc enclave up -d oauth2-proxy >/dev/null 2>&1
    wait_for ir-enclave_oauth2-proxy_1 120 logmatch ir-enclave_oauth2-proxy_1 "OAuthProxy configured" \
        || warn "SSO gate did not report ready — check its OIDC settings"
    dc enclave up -d --build traefik puller >/dev/null 2>&1
    if [[ "${IR_MESH:-1}" == "1" ]]; then
        mesh_attach puller
    fi
    wait_for ir-enclave_traefik_1 60 true || warn "ingress slow to start"
    ok "enclave up"
}

up_dmz() {
    say "DMZ · receiver + broker + resolver"
    reap_orphans dmz
    # The receiver refuses to start without a certificate, on purpose: evidence in the clear is
    # the host's memory in the clear. Generating it here means a fresh deployment is encrypted
    # out of the box rather than once somebody remembers.
    bash "${HERE}/../dmz/gen-receiver-cert.sh" >/dev/null 2>&1 \
        || warn "could not generate the receiver certificate — the receiver will refuse to start"
    [[ -f "${HERE}/../dmz/certs/receiver.crt" ]] \
        && ok "receiver certificate present (collectors pin dmz/certs/receiver.crt)" \
        || die "no receiver certificate — evidence would ship in plaintext"
    # The control plane serves its API and its embedded DERP relay over TLS. Without it
    # tailscale silently declines to use the relay: nodes report themselves connected and have
    # no fallback when a direct path cannot be built.
    bash "${HERE}/../hashicorp/access/gen-headscale-cert.sh" >/dev/null 2>&1 \
        || warn "could not generate the control-plane certificate"
    [[ -f "${HERE}/../hashicorp/access/certs/headscale.crt" ]] \
        && ok "control-plane certificate present (nodes pin it; DERP needs TLS)" \
        || die "no control-plane certificate — headscale cannot serve TLS and DERP stays unused"
    # The resolver forwards in-zone lookups to the runtime's resolver on the edge network, so
    # it needs that network's gateway. Read from the runtime rather than .env: it is a value the
    # runtime assigns, and a stale copy here would send every lookup into a black hole.
    local edge_dns; edge_dns="$(net_gateway ir-edge)"
    [[ -n "${edge_dns}" ]] || die "ir-edge has no gateway — the resolver has nowhere to forward"
    sed -e "s|__PLATFORM_HOST__|${PLATFORM_HOST}|g" \
        -e "s|__RUNTIME_ZONE__|${RUNTIME_DNS_ZONE}|g" \
        -e "s|__EDGE_DNS__|${edge_dns}|g" \
        "${HERE}/../hashicorp/access/Corefile.tmpl" > "${HERE}/../hashicorp/access/Corefile"
    ok "resolver renders ${PLATFORM_HOST} -> bastion (resolved live, not pinned)"
    # headscale advertises its own address to every node — for the control plane AND for its
    # embedded DERP relay. Rendered from the same value the nodes are given, so the two cannot
    # drift: a server_url the nodes cannot reach leaves them with no relay at all.
    #
    # A NAME, so it survives a network recreate. Workstations on separate hardware cannot
    # resolve a container name and set HEADSCALE_ADDR to the DMZ's routable address instead;
    # both paths land on the same container.
    # Nothing Boundary-side is rendered here. This tier runs a session CLIENT and no server: the
    # controller and the egress worker are both in the enclave, and their configs are rendered
    # where they run.
    [[ -f "${HERE}/../hashicorp/access/certs/boundary.crt" ]] \
        || die "no Boundary certificate — run 'deploy.sh enclave' first; the broker pins it"

    sed "s|__HEADSCALE_ADDR__|${HEADSCALE_ADDR}|" \
        "${HERE}/../hashicorp/access/headscale.yaml.tmpl" \
        > "${HERE}/../hashicorp/access/headscale.yaml"
    ok "control plane renders at https://${HEADSCALE_ADDR} (also its DERP relay)"
    # Headscale first, alone: the bastion cannot join a tailnet whose control plane is not
    # answering, and it needs a pre-auth key that only the control plane can issue. So the
    # order is headscale -> enrol -> everything else, and the keys are in the environment
    # before the nodes that consume them are created.
    dc dmz up -d --build headscale >/dev/null 2>&1
    wait_for ir-dmz_headscale_1 60 \
        ${RUNTIME} exec ir-dmz_headscale_1 headscale version \
        || die "headscale never came up — the tailnet cannot be enrolled without it"
    if "${HERE}/../hashicorp/access/tailnet_bootstrap.sh" "${HERE}/.env.tailnet" >/dev/null 2>&1; then
        ok "tailnet enrolled (users + pre-auth keys issued)"
    else
        warn "tailnet enrollment incomplete — the tunnel may not come up; see .env.tailnet"
    fi

    # The control-plane address the NODES dial, resolved from the running container.
    #
    # This one value cannot be a name, and the reason is specific to tailscale rather than to
    # this deployment: given a hostname login server it forces TLS and dials port 443, silently
    # discarding the port in the URL. Against headscale on 8080 that is a connection refused on
    # a port nothing serves, and the node exits without joining — the tunnel is simply absent
    # and the analyst's browser has no route.
    #
    # So it is RESOLVED at deploy time instead of pinned in .env. Nothing records an address
    # that can go stale: recreate the network on a different subnet and the next bring-up picks
    # up whatever headscale now holds. A real multi-host deployment overrides HEADSCALE_ADDR
    # with the DMZ's routable address, which workstations on other machines must use anyway.

    # Everything EXCEPT the tailnet nodes. A bare `up` would create the bastion here, before
    # the control-plane address below is known, and compose will not replace a container that
    # already exists — so the node would keep whatever login server it was born with for the
    # rest of the deployment's life.
    dc dmz up -d --build receiver coredns headscale >/dev/null 2>&1

    # Provisioned by the controller in the enclave, so the ids the session client needs are read
    # from there rather than invented here.
    if [[ -r "${HERE}/.env.boundary" ]]; then
        set -a; . "${HERE}/.env.boundary"; set +a
    fi
    [[ -n "${BOUNDARY_TARGET_ID:-}" ]] \
        || die "no Boundary target — run 'deploy.sh enclave' first; the controller provisions it"
    # What the NODES dial. A NAME, resolved through the DMZ resolver, so nothing here pins an
    # address and a network can be recreated on a different subnet without breaking the tunnel.
    #
    # This has to be https. Tailscale rewrites an http:// login server for any non-loopback host
    # to TLS on port 443, discarding whatever port the URL carried — the node then dials a port
    # nothing serves and exits without registering. An https:// URL is already TLS, so its port
    # is used as written, and the certificate covers this exact name.
    #
    # A multi-host deployment sets IR_HEADSCALE_LOGIN_URL to the DMZ's routable address and adds
    # that name to the certificate via IR_HEADSCALE_SANS; workstations on other machines cannot
    # resolve a container name at all.
    local hs_login="${IR_HEADSCALE_LOGIN_URL:-https://${IR_HEADSCALE_HOST:-headscale}:${HEADSCALE_PORT}}"
    printf 'HEADSCALE_LOGIN_URL=%s\n' "${hs_login}" >> "${HERE}/.env.tailnet"
    ok "nodes will dial the control plane at ${hs_login} (TLS — required for the DERP relay)"

    # The tailnet nodes start LAST, after the address above is settled and written. Creating
    # them in the same `up` that may relocate headscale is what produced a node dialling an
    # address nothing answered on.
    # An exited broker is removed first. `compose up` does not restart a container that has
    # exited, so a session client that failed to authenticate stays dead across redeploys and
    # keeps reporting the failure it hit before the fix — its bind-mounted script is current, but
    # nothing ever runs it again.
    ${RUNTIME} rm -f ir-dmz_broker_1 >/dev/null 2>&1 || true
    dc dmz up -d --build bastion broker >/dev/null 2>&1
    # Probed over TLS, verifying against the same certificate collectors pin. A plain-HTTP probe
    # against a TLS socket fails in a way that reads as "the receiver never came up", which sent
    # the last deployment looking for a crashed service that was in fact serving correctly.
    # Verifying (rather than skipping verification) also makes this gate catch a certificate the
    # receiver cannot actually present a valid chain for.
    wait_for ir-dmz_receiver_1 90 \
        ${RUNTIME} exec ir-dmz_receiver_1 python3 -c \
        "import ssl,urllib.request as u
c=ssl.create_default_context(cafile='/certs/receiver.crt')
u.urlopen('https://localhost:8090/healthz',timeout=4,context=c)" \
        || die "evidence receiver never came up"
    for c in ir-dmz_coredns_1 ir-dmz_headscale_1 ir-dmz_bastion_1; do
        wait_for "$c" 45 true || warn "$c slow to start"
    done
    # The broker is checked by its LISTENER, not by its container being up. `true` as a readiness
    # check passes for any process that has not exited, and the broker's failure mode is exactly
    # that: it starts, logs its forwarding table, and forwards nothing. The analyst path is dead
    # while every gate reads green, which is worse than a container that simply crashed.
    #
    # The listener lives in the bastion's namespace, since that is where the broker binds.
    # Gated on an ESTABLISHED SESSION. The listener being bound is necessary and not sufficient:
    # the point of replacing socat is that this hop is authenticated and authorized, so the check
    # is that Boundary authorized it.
    wait_for ir-dmz_broker_1 90 \
        ${RUNTIME} exec ir-dmz_bastion_1 sh -c \
        "netstat -ltn 2>/dev/null | grep -q ':${BROKER_LISTEN}' || ss -ltn 2>/dev/null | grep -q ':${BROKER_LISTEN}'" \
        || die "no listener on ${BROKER_LISTEN} — analysts have no path to the platform"
    if [[ "$(${RUNTIME} logs ir-dmz_broker_1 2>&1 | grep -c 'authenticated as')" -gt 0 ]]; then
        ok "Boundary session broker authenticated and listening on ${BROKER_LISTEN}"
    else
        warn "the broker is listening but has not reported an authenticated session"
    fi
    # The tunnel is the analyst's only intended route, so its absence is reported here rather
    # than discovered as a browser that cannot reach the platform.
    local ts_ip
    ts_ip="$(wait_tailnet_ip ir-dmz_bastion_1 90)"
    if [[ -n "${ts_ip}" ]]; then
        ok "bastion joined the tailnet at ${ts_ip}"
    else
        warn "bastion has no tailnet address — analysts will not reach the platform over WireGuard"
    fi
    ok "DMZ up"
}

up_workstation() {
    say "Workstation · analyst browser"
    local waited=0 answer=""
    while (( waited < 90 )); do
        answer=$(${RUNTIME} run --rm --network ir-edge --dns "${DNS_EDGE_IP}" \
            localhost/ir-workstation:latest dig +short +time=2 +tries=1 \
            "${PLATFORM_HOST}" 2>/dev/null | head -1)
        [[ -n "$answer" ]] && break
        sleep 5; waited=$((waited+5))
    done
    if [[ -n "$answer" ]]; then
        ok "DMZ resolver answering: ${IR_PLATFORM_URL#https://} -> ${answer}"
    else
        warn "DMZ resolver not answering — the browser will not resolve the platform"
    fi
    command -v xhost >/dev/null && xhost +local: >/dev/null 2>&1 || \
        warn "xhost unavailable — the kiosk needs 'xhost +local:' to use the X display"

    # The tailnet node comes up first and alone. The browser shares its network namespace, so
    # compose cannot create the browser until the node exists — and if the node is up but has
    # not joined, the browser starts into a namespace with no route to the platform and fails
    # in a way that looks like a broken kiosk rather than an unenrolled tunnel.
    dc workstation up -d --build tailnet >/dev/null 2>&1
    wait_for ir-workstation_tailnet_1 60 true || warn "tailnet node did not start"
    local ts_ip="" waited_ts=0
    ts_ip="$(wait_tailnet_ip ir-workstation_tailnet_1 90)"
    if [[ -n "${ts_ip}" ]]; then
        ok "analyst joined the tailnet at ${ts_ip} (traffic leaves over WireGuard)"
    else
        warn "analyst has NOT joined the tailnet — the browser will have no route to the platform"
        warn "re-run 'deploy.sh dmz' to re-issue a pre-auth key, then this tier again"
    fi

    dc workstation up -d --build >/dev/null 2>&1
    wait_for ir-workstation_browser_1 90 true || warn "browser did not start (is DISPLAY set?)"
    ok "workstation up"
}

# Gate: the whole SSO chain must answer before the analyst browser is started, so the
# kiosk never opens against a half-ready gate (which shows as 502/403 in the browser).
up_agent() {
    say "Remediation agent — the executor for admin-requested repairs"
    # Its own compose project: the mesh-reattach repair runs `deploy.sh enclave`, and an
    # executor inside the enclave project could be recreated by the deploy it is running.
    #
    # The agent's whole authority is the rootless runtime socket, so that socket must exist
    # before the container that mounts it is created. Host configuration belongs to the deploy
    # script, so it is enabled here, not by hand and not by a test.
    local sock="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/podman/podman.sock"
    if [[ ! -S "${sock}" ]]; then
        systemctl --user enable --now podman.socket >/dev/null 2>&1 || true
        sleep 1
    fi
    [[ -S "${sock}" ]] || die "no podman API socket at ${sock} — 'systemctl --user enable --now podman.socket' failed"
    export IR_RUNTIME_SOCKET="${sock}"
    IR_PLATFORM_DIR="$(cd "${HERE}/.." && pwd)"; export IR_PLATFORM_DIR
    IR_AGENT_HOST="$(hostname)"; export IR_AGENT_HOST

    # Recreated every deploy: its bind-mounted script must be the current inode, and compose
    # will not restart a container that exited.
    ${RUNTIME} rm -f ir-agent_remediation-agent_1 >/dev/null 2>&1 || true
    dc agent up -d --build remediation-agent >/dev/null 2>&1
    # Gated on the poll loop being reached — past the token wait AND the runtime check, so a
    # running container that cannot drive the socket fails here, not on the first repair.
    wait_for ir-agent_remediation-agent_1 60 \
        logmatch ir-agent_remediation-agent_1 "polling every" \
        || die "the remediation agent never reached its poll loop — repairs will sit queued"
    ok "remediation agent polling (network: none, socket-only; repairs recorded on host ${IR_AGENT_HOST})"
}

verify_sso() {
    say "Validating the SSO chain before launching the analyst browser"
    local waited=0 code
    while (( waited < 150 )); do
        code=$(${RUNTIME} run --rm --network ir-edge --dns "${DNS_EDGE_IP}" \
            localhost/ir-workstation:latest curl -sk -o /dev/null -w '%{http_code}' \
            --max-time 12 -L -H "Accept: text/html" "${PLATFORM_PUBLIC_URL}/" 2>/dev/null)
        # 200 = the Keycloak login page rendered through broker → ingress → SSO gate.
        [[ "$code" == "200" ]] && { ok "SSO chain live: broker → ingress → gate → Keycloak login"; return 0; }
        sleep 5; waited=$((waited+5))
    done
    warn "SSO chain not ready (last HTTP ${code}) — see troubleshooting/RUNBOOK.md"
    return 1
}

# Seed evidence so an analyst logging in sees a populated platform rather than an
# empty dashboard. Skipped if the platform already holds runs.
seed_evidence() {
    say "Seeding evidence through the real path (endpoint → DMZ → enclave pull)"
    local runs
    runs=$(${RUNTIME} exec ir-enclave_backend_1 python -c "
import urllib.request as u, json
r=u.Request('http://127.0.0.1:8000/api/stats/',headers={'Authorization':'Token ${IR_BROKER_TOKEN}'})
print(json.load(u.urlopen(r,timeout=8))['runs'])" 2>/dev/null)
    if [[ "${runs:-0}" -gt 0 ]]; then ok "platform already holds ${runs} run(s)"; return 0; fi

    local work; work="$(mktemp -d)"
    PLATFORM="${HERE}/.." . "${HERE}/../test/lib/evidence.sh"
    PLATFORM="${HERE}/.." mk_evidence_bundle "$work" "seed-endpoint" "${IR_CUSTODY_HMAC_KEY}"
    local bundle; bundle=$(PLATFORM="${HERE}/.." tar_bundle "$work" "seed-endpoint")
    local code; code=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
        --cacert "${HERE}/../dmz/certs/receiver.crt" \
        --data-binary @"$bundle" "https://localhost:${RECEIVER_PORT}/ingest" 2>/dev/null)
    [[ "$code" == "202" ]] && ok "bundle accepted + custody-verified by the DMZ receiver" \
                           || warn "receiver returned HTTP ${code}"
    # The enclave pulls on its own schedule; wait for it to land rather than assume.
    local waited=0
    while (( waited < 90 )); do
        runs=$(${RUNTIME} exec ir-enclave_backend_1 python -c "
import urllib.request as u, json
r=u.Request('http://127.0.0.1:8000/api/stats/',headers={'Authorization':'Token ${IR_BROKER_TOKEN}'})
print(json.load(u.urlopen(r,timeout=8))['runs'])" 2>/dev/null)
        [[ "${runs:-0}" -gt 0 ]] && { ok "evidence ingested and renderable (${runs} run)"; break; }
        sleep 5; waited=$((waited+5))
    done
    [[ "${runs:-0}" -gt 0 ]] || warn "evidence did not land — check the puller"
    rm -rf "$work"
}

# --- end-to-end readiness gate --------------------------------------------
verify() {
    say "Verifying the analyst path end to end"
    local code
    code=$(${RUNTIME} run --rm --network ir-edge --dns "${DNS_EDGE_IP}" \
        localhost/ir-workstation:latest curl -sk -o /dev/null -w '%{http_code}' \
        --max-time 15 -L -H "Accept: text/html" "${PLATFORM_PUBLIC_URL}/" 2>/dev/null)
    # 200 = the login page rendered through the broker; the gate is working.
    if [[ "$code" == "200" || "$code" == "302" ]]; then
        ok "analyst path reaches the SSO login (HTTP ${code})"
    else
        warn "analyst path returned HTTP ${code} — see troubleshooting/RUNBOOK.md"
    fi
}

status() {
    say "Stage status"
    for c in ir-dmz_receiver_1 ir-dmz_broker_1 ir-dmz_coredns_1 \
             ir-enclave_db_1 ir-enclave_minio_1 ir-enclave_keycloak_1 \
             ir-enclave_backend_1 ir-enclave_oauth2-proxy_1 ir-enclave_traefik_1 \
             ir-enclave_worker_1 ir-enclave_puller_1 ir-workstation_browser_1 \
             ir-agent_remediation-agent_1; do
        s=$(${RUNTIME} inspect "$c" --format '{{.State.Status}}' 2>/dev/null || echo absent)
        [[ "$s" == "running" ]] && ok "$c" || warn "$c ($s)"
    done
}

case "${TIER}" in
    enclave|dmz|workstation|agent)
        bash "${HERE}/../traefik/gen-cert.sh" >/dev/null 2>&1 || true
        ensure_build_images; ensure_networks; "up_${TIER}" ;;
    all)
        bash "${HERE}/../traefik/gen-cert.sh" >/dev/null 2>&1 || true
        ensure_build_images
        ensure_networks
        # Enclave first: it holds the Boundary controller, and the DMZ's session client cannot
        # open the analyst path without the target the controller provisions. The puller polls
        # the DMZ receiver on a retry loop, so it tolerates the DMZ arriving second.
        up_enclave; up_dmz
        # After the enclave: the agent polls through the backend, and starting it earlier
        # would just have it waiting. Before the workstation, so repairs are available the
        # moment an admin can sign in.
        up_agent
        verify_sso || warn "continuing, but the browser may show an SSO error"
        seed_evidence
        up_workstation ;;
    status) status ;;
    down)
        # Teardown reports what actually happened. It used to discard compose's output and print
        # "torn down" unconditionally, so a compose file that failed to parse left every
        # container running behind a success message — and the next bring-up then inherited
        # containers built from the previous configuration.
        # VOLUMES ARE KEPT unless --purge is given.
        #
        # This used to pass -v unconditionally, so tearing a tier down to restart a service also
        # deleted the database, the object store and the receiver's holding area — every
        # collected capture, its custody record and its analysis, with no warning and no
        # confirmation. On a forensic platform that is evidence destruction: the bundles are
        # gone, and the endpoints they came from have usually been rebuilt by then.
        #
        # Keeping them makes `down` a restart rather than a reset, which is what it is used for
        # nine times in ten. Discarding state is now something the operator has to ask for.
        PURGE=0
        for arg in "$@"; do [[ "${arg}" == "--purge" ]] && PURGE=1; done
        vol_flag=()
        if (( PURGE )); then
            vol_flag=(-v)
            warn "--purge: deleting volumes — ALL ingested evidence, captures and analyses"
        fi
        # Namespace-sharing containers come down FIRST, across every tier being torn down.
        #
        # Sidecars and the DMZ broker run with network_mode: service:<svc>. Removing the service
        # while another container still holds its network namespace DEADLOCKS podman — the call
        # hangs holding the storage lock and every subsequent podman command blocks behind it,
        # which looks like the whole host has seized rather than like a teardown ordering bug.
        for c in $(${RUNTIME} ps -a --format '{{.Names}}' 2>/dev/null \
                   | grep -E '(-sidecar_|^ir-dmz_broker_)' || true); do
            ${RUNTIME} rm -f "${c}" >/dev/null 2>&1 || true
        done
        # The agent first: stop the executor before tearing down anything it might be repairing.
        for t in agent workstation enclave dmz; do
            [[ "${2:-all}" == "all" || "${2:-}" == "$t" ]] || continue
            if ! err="$(dc "$t" down "${vol_flag[@]}" 2>&1)"; then
                warn "${t}: teardown failed"
                printf '%s\n' "${err}" | tail -5
            fi
        done
        if [[ "${2:-all}" == "all" ]]; then
            # Networks are removed only once nothing is attached; a failure here means a
            # container survived, which is worth saying rather than swallowing.
            for n in ir-edge ir-dmzlink; do
                ${RUNTIME} network exists "$n" 2>/dev/null || continue
                ${RUNTIME} network rm "$n" >/dev/null 2>&1 || \
                    warn "${n} still has attached containers — teardown was incomplete"
            done
        fi
        purge_re_sessions
        # The verdict is drawn from the runtime, not from having reached the end of the function.
        left="$(${RUNTIME} ps --format '{{.Names}}' 2>/dev/null | grep -c '^ir-' || true)"
        if [[ "${left:-0}" -gt 0 ]]; then
            warn "${left} container(s) still running — NOT fully torn down"
            ${RUNTIME} ps --format '  {{.Names}}' | grep '^  ir-'
            exit 1
        fi
        echo "torn down" ;;
    *) sed -n '3,14p' "$0"; exit 2 ;;
esac
