#!/usr/bin/env bash
# ===========================================================================
# Deployment driver — brings up ONE tier on the hardware it belongs to, in
# dependency order, gating each stage on a health check before continuing.
#
#   deploy.sh enclave       # internal enclave host
#   deploy.sh dmz           # DMZ host
#   deploy.sh workstation [id]   # analyst machine; `id` names this workstation's tailnet
#                                # node and its compose project. With no id, every workstation
#                                # IR_WS_IDS declares comes up.
#   deploy.sh all           # single-host validation (all tiers)
#   deploy.sh status        # health of every stage
#   deploy.sh rotate <NAME>... | --all   # retire generated secrets; the next
#                                       # deploy of that tier provisions new ones
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
[[ -f "${HERE}/.env.db" ]] || cp "${HERE}/.env.db.example" "${HERE}/.env.db"
# .env.db separately: the static admin credential is data-tier-only, and compose interpolation
# for the db service still needs it in this process's environment.
set -a; . "${HERE}/.env"; . "${HERE}/.env.db"; set +a
# Bare hostname for DNS lookups: IR_PLATFORM_URL carries a scheme, port and path.
PLATFORM_HOST="${IR_PLATFORM_URL#*://}"; PLATFORM_HOST="${PLATFORM_HOST%%[:/]*}"

say()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '    \033[1;32m✔\033[0m %s\n' "$*"; }
warn() { printf '    \033[1;33m!\033[0m %s\n' "$*"; }
die()  { printf '    \033[1;31m✘\033[0m %s\n' "$*"; exit 1; }

# The compose PROJECT is what separates one workstation from another: containers and the
# tailnet state volume are both namespaced by it, so nothing per-workstation has to be written
# into the compose file. The default id keeps the historic project name, so a single-workstation
# deployment — and every UAT that names `ir-workstation_tailnet_1` — is unchanged.
proj() {
    case "$1" in
        enclave) echo ir-enclave;;
        dmz) echo ir-dmz;;
        workstation)
            if [[ "${IR_WS_ID:-analyst}" == "analyst" ]]; then echo ir-workstation
            else echo "ir-workstation-${IR_WS_ID}"; fi;;
        agent) echo ir-agent;;
    esac
}

# This workstation's own pre-auth key, from the per-id variable the tailnet bootstrap wrote.
# Falls back to the default node's key, so `deploy.sh workstation` with no id behaves as before.
ws_authkey() {
    local id="${IR_WS_ID:-analyst}" var
    # The keys live in .env.tailnet, which only dc() sources — and this runs BEFORE the first
    # dc call of a standalone `deploy.sh workstation <id>`, so the variable would be unset and
    # the node would start with no credential and retry on a backoff that reads as a broken
    # kiosk. Sourced here rather than relying on a previous stage having done it.
    if [[ -r "${HERE}/.env.tailnet" ]]; then
        set -a; . "${HERE}/.env.tailnet"; set +a
    fi
    [[ "${id}" == "analyst" ]] && { echo "${TS_ANALYST_AUTHKEY:-}"; return; }
    var="TS_WS_AUTHKEY_$(printf '%s' "${id}" | tr '[:lower:]' '[:upper:]' | tr -c '[:alnum:]\n' '_')"
    # Falls back to the default node's key so a workstation listed after the last tailnet
    # bootstrap still enrols; the node NAME is what distinguishes it either way.
    echo "${!var:-${TS_ANALYST_AUTHKEY:-}}"
}
RECREATE_BLOCKED=""   # per-deploy decision, see recreate_if_stale
COMPOSE_TIMEOUT="${IR_COMPOSE_TIMEOUT:-240}"
# Tailnet pre-auth keys are minted per bring-up in a separate never-committed file, exported into
# the environment because a second --env-file would not reach the tunnel.

# Smartcard (CAC/PIV) logon is rendered from templates and OFF by default: a certificate flow with
# no trust anchors fails closed and locks every analyst out, including whoever would turn it off.
pki_logon_render() {
    local dyn="${HERE}/../traefik/dynamic-sso/dynamic.yml"
    local pki="${HERE}/../hashicorp/keycloak/pki-logon"
    local anchors=0
    [[ -d "${pki}/trust-anchors" ]] && anchors="$(find "${pki}/trust-anchors" -name '*.pem' -o -name '*.crt' 2>/dev/null | grep -c . || echo 0)"

    if [[ "${IR_PKI_LOGON:-0}" != "1" ]]; then
        # Rendered explicitly to the disabled form rather than left as found: a deployment that
        # once had it on must not keep asking for certificates after it is turned off.
        sed -i 's|^      clientAuth:.*|      # __CLIENT_AUTH__|; /^        caFiles:/d; /^          - \/certs\/pki\//d; /^        clientAuthType:/d' "${dyn}"
        # Disabled means no ACTIVE clientAuth line — whether this run replaced one with the
        # marker or there was never one to replace. Requiring the marker reported a failure to
        # reset something nothing had set.
        if grep -qE '^[[:space:]]*clientAuth:' "${dyn}"; then
            warn "the ingress still asks for client certificates — smartcard logon is off but the block survived"
        fi
        return 0
    fi

    # Enabled. Without anchors this is a lockout, not a hardening step, so it is refused here
    # rather than discovered at the login page.
    [[ "${anchors}" -gt 0 ]] \
        || die "IR_PKI_LOGON=1 but ${pki}/trust-anchors holds no CA — see its README; enabling smartcard logon without a trust anchor locks every analyst out"

    local cafiles=""
    while read -r f; do
        [[ -n "${f}" ]] && cafiles+="\n          - /certs/pki/$(basename "${f}")"
    done < <(find "${pki}/trust-anchors" \( -name '*.pem' -o -name '*.crt' \) 2>/dev/null)

    sed -i "s|^      # __CLIENT_AUTH__|      clientAuth:\n        caFiles:${cafiles}\n        clientAuthType: RequestClientCert|" "${dyn}"
    ok "smartcard logon enabled — the ingress requests a client certificate against ${anchors} trust anchor(s)"
}

# The Vault image's config tree (generate_certs.py + vault-server.hcl). It lives in the
# `containers` checkout, whose position relative to this tree is a property of the host, not of
# the platform — so it is LOCATED, and a miss fails loudly rather than mounting nothing and
# leaving Vault waiting on certificates that never arrive.
resolve_vault_config() {
    [[ -n "${IR_VAULT_CONFIG:-}" && -f "${IR_VAULT_CONFIG}/generate_certs.py" ]] && return 0
    local base hit
    for base in "${HERE}/../.." "${HERE}/../../.." "${HOME}/Documents" "${HOME}"; do
        [[ -d "${base}" ]] || continue
        hit="$(find "${base}" -maxdepth 5 -type f -path '*/vault/config/generate_certs.py' \
               -not -path '*/node_modules/*' 2>/dev/null | head -1)"
        if [[ -n "${hit}" ]]; then
            IR_VAULT_CONFIG="$(cd "$(dirname "${hit}")" && pwd)"; export IR_VAULT_CONFIG
            return 0
        fi
    done
    die "cannot locate the Vault config tree (vault/config/generate_certs.py) — set IR_VAULT_CONFIG"
}

# The Vault image, built from the same checkout as its config. The platform does not vendor it,
# so the deployment builds it rather than declaring it a prerequisite: absent, compose tries to
# PULL localhost/vault and the failure reads as a registry error rather than a missing build.
ensure_vault_image() {
    local tag; tag="$(sed -n 's/^[[:space:]]*image:[[:space:]]*\(localhost\/vault:[^[:space:]]*\).*/\1/p' \
        "$(compose_of enclave)" | head -1)"
    tag="${tag:-localhost/vault:2.0.3}"
    ${RUNTIME} image exists "${tag}" && return 0
    local ctx; ctx="$(dirname "${IR_VAULT_CONFIG}")"
    [[ -f "${ctx}/Dockerfile" ]] || die "no Dockerfile at ${ctx} — cannot build ${tag}"
    say "  building ${tag} (absent, from ${ctx})"
    ${RUNTIME} build -t "${tag}" "${ctx}" >/dev/null 2>&1 \
        || die "failed to build ${tag} from ${ctx}"
    ok "${tag} built"
}

# The tier's compose file, located dynamically. The expected location wins; when the tree has
# been rearranged the platform root is searched, and zero or multiple matches fail LOUDLY —
# deploying a silently mis-resolved compose file is worse than refusing.
compose_of() { # tier -> absolute path
    # Two statements, necessarily: bash expands every assignment word of a `local` line
    # BEFORE binding any of them, so ${tier} in the second assignment reads the CALLER's
    # scope — unbound under set -u unless the caller happens to have one.
    local tier="$1" hits
    local expected="${HERE}/${tier}/docker-compose.yml"
    if [[ -f "${expected}" ]]; then printf '%s' "${expected}"; return 0; fi
    hits="$(find "${HERE}/.." -name docker-compose.yml -path "*/${tier}/*" \
            -not -path "*/archive/*" -not -path "*/node_modules/*" 2>/dev/null)"
    if [[ "$(grep -c . <<<"${hits}")" != "1" ]]; then
        die "cannot resolve the ${tier} compose file: expected ${expected}, found: ${hits:-none}"
    fi
    printf '%s' "${hits}"
}

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
    # Replica pairs live in their own overlay so a single-worker deployment never parses
    # them. Loaded whenever replicas are declared — including for `down`, which must parse
    # the same files `up` did or it strands the replica containers. Generated here, not by
    # hand: the walk target is a 50-worker surge and nobody maintains that as YAML.
    if [[ "${tier}" == "enclave" ]]; then
        # Runs at ANY count, because the generator both writes the pairs and DELETES the
        # overlay when none are declared. Called only above 1, a scale-down left the old
        # overlay on disk describing workers the deployment no longer runs.
        python3 "${HERE}/gen-worker-overlay.py" "${IR_WORKER_REPLICAS:-1}" >/dev/null \
            || die "worker overlay generation failed — check IR_WORKER_REPLICAS and .env addresses"
        if [[ "${IR_WORKER_REPLICAS:-1}" -gt 1 ]]; then
            overlay+=(-f docker-compose.workers.yml)
        fi
    fi
    # The agent compose interpolates these; a `down` must parse the same file `up` did.
    if [[ "${tier}" == "agent" ]]; then
        export IR_RUNTIME_SOCKET="${IR_RUNTIME_SOCKET:-${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/podman/podman.sock}"
        IR_PLATFORM_DIR="${IR_PLATFORM_DIR:-$(cd "${HERE}/.." && pwd)}"; export IR_PLATFORM_DIR
        IR_AGENT_HOST="${IR_AGENT_HOST:-$(hostname)}"; export IR_AGENT_HOST
    fi
    local cf; cf="$(compose_of "${tier}")"
    timeout "${COMPOSE_TIMEOUT}" env -C "$(dirname "${cf}")" \
        ${COMPOSE} -p "$(proj "$tier")" --env-file "${HERE}/.env" -f "${cf}" "${overlay[@]}" "$@"
    local rc=$?
    # 124 = timeout killed it. The stage's own health gate decides whether that is fatal.
    [[ $rc -eq 124 ]] && warn "compose call timed out after ${COMPOSE_TIMEOUT}s (tier: ${tier})"
    return 0
}

# Is the worker mid-analysis? Counted, not `grep -q` — a quiet grep's SIGPIPE makes the exit
# status unreliable, and the wrong answer destroys a running analysis.
analysis_in_progress() { # proj
    local n
    n="$(${RUNTIME} exec "$1_worker_1" sh -c \
         'ps -eo args | grep -c "[a]nalyze_memory_linux"' 2>/dev/null)" || return 1
    [[ "${n:-0}" -gt 0 ]]
}

# Would removing these containers cascade to one matching `suffix`? The cascade is computed from
# what podman recorded (--depend), not assumed from compose definitions.
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

# Remove containers still running an image that has since been rebuilt: compose will not recreate
# a running container, so `up --build` otherwise leaves the old image serving and the change
# silently absent. Only stateless services belong here.

# A CHANGED DEFINITION THAT DID NOT REACH THE STACK IS SAID OUT LOUD. recreate_if_stale compares
# image ids only, so command/env/mount edits to a running service are invisible — the operator is
# told exactly what is stale rather than recreating stateful services over a whitespace edit.
compose_fingerprint() { # tier -> hash of what its containers ought to have been built from
    cat "${HERE}/$1/docker-compose.yml" "${HERE}/.env" 2>/dev/null \
        | sha256sum | cut -d' ' -f1
}

compose_drift_check() { # tier
    local tier="$1" rec="${HERE}/.compose-applied" now was proj_name c created
    now="$(compose_fingerprint "${tier}")"
    was="$(awk -v t="${tier}" '$1==t {print $2}' "${rec}" 2>/dev/null)"
    # No record yet: this deploy establishes the baseline rather than crying drift at everyone
    # who has ever run it before the check existed.
    [[ -z "${was}" || "${was}" == "${now}" ]] && return 0

    proj_name="$(proj "${tier}")"
    local stale=() mtime
    mtime="$(stat -c %Y "${HERE}/${tier}/docker-compose.yml" 2>/dev/null || echo 0)"
    for c in $(${RUNTIME} ps --format '{{.Names}}' 2>/dev/null | grep "^${proj_name}_" || true); do
        created="$(date -d "$(${RUNTIME} inspect "${c}" --format '{{.Created}}' 2>/dev/null)" +%s 2>/dev/null || echo 0)"
        [[ "${created}" -lt "${mtime}" ]] && stale+=("${c}")
    done
    (( ${#stale[@]} )) || return 0

    warn "${tier}: the compose definition changed and ${#stale[@]} running container(s) predate it"
    # Named, but not all of them: a definition edit usually predates every container in the tier,
    # and thirty lines of names buries the sentence that says what to do about it.
    printf '      %s\n' "${stale[@]:0:6}"
    (( ${#stale[@]} > 6 )) && printf '      ... and %d more\n' "$(( ${#stale[@]} - 6 ))"
    warn "      compose does not recreate a running container, so their definitions are the OLD ones"
    warn "      to apply: deploy.sh down ${tier} && deploy.sh ${tier}   (volumes are kept)"
}

compose_record_applied() { # tier — called only after the tier is up
    local tier="$1" rec="${HERE}/.compose-applied" tmp
    tmp="$(mktemp)"
    awk -v t="${tier}" '$1!=t' "${rec}" 2>/dev/null > "${tmp}" || true
    printf '%s %s\n' "${tier}" "$(compose_fingerprint "${tier}")" >> "${tmp}"
    mv "${tmp}" "${rec}"
}

recreate_if_stale() { # tier  service...
    local tier="$1"; shift
    local proj; proj="$(proj "$tier")"
    local svc name running current stale=()

    for svc in "$@"; do
        name="${proj}_${svc}_1"
        # A worker replica runs the primary's image — there is no ir-worker-2 image, and
        # resolving it literally would silently exempt every replica from the check.
        local image_svc="${svc}"
        [[ "${svc}" =~ ^worker-[0-9]+$ ]] && image_svc="worker"
        running="$(${RUNTIME} inspect "${name}" --format '{{.Image}}' 2>/dev/null)" || continue
        current="$(${RUNTIME} image inspect "localhost/ir-${image_svc}:latest" \
                   --format '{{.Id}}' 2>/dev/null)" || continue
        if [[ -n "${running}" && -n "${current}" && "${running}" != "${current}" ]]; then
            stale+=("${name}")
        fi
    done

    (( ${#stale[@]} )) || return 0
    replace_containers "${proj}" "running a superseded image" "${stale[@]}"
}

# Remove containers so the staged bring-up recreates them, refusing while it would destroy
# a running analysis. Shared by the image and credential checks so both refuse alike.
replace_containers() { # proj  reason  name...
    local proj="$1" reason="$2"; shift 2
    local stale=("$@")
    (( ${#stale[@]} )) || return 0

    # Removing a container takes its dependents, so replacing the backend kills whatever the worker is
    # analyzing; checked against the real cascade because the analysis dies as collateral either way.
    # Decided once per deploy — re-deriving it per call let a second pass destroy what the first
    # refused to.
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

    warn "replacing container(s) ${reason}: ${stale[*]}"
    # --depend is required: podman refuses to remove a container with dependents, and without it the
    # removal fails while the deploy reports success. The cascade is safe because later stages bring
    # the dependents back in order.
    ${RUNTIME} rm -f --depend "${stale[@]}" >/dev/null 2>&1 || detach_then_remove "${stale[@]}"
}

# Removal that survives a shared netns: removing the owner first wedges `podman rm` on a namespace
# nothing owns. Detach from the network first and the removal is immediate — cheap enough to be
# the unconditional fallback.
detach_then_remove() { # name...
    local c nets net
    for c in "$@"; do
        nets="$(${RUNTIME} inspect "$c" --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' 2>/dev/null || true)"
        for net in ${nets}; do
            timeout 60 ${RUNTIME} network disconnect -f "${net}" "$c" >/dev/null 2>&1 || true
        done
        timeout 120 ${RUNTIME} rm -f -t 0 "$c" >/dev/null 2>&1 \
            || warn "could not remove ${c} — detach it and remove it by hand"
    done
}

# Replace containers holding a database credential Vault has superseded: the app tier reads
# /vault/secrets/app.env once at entrypoint, and Vault revokes the previous user on re-auth. The
# image check cannot see this — only the credential inside the container changed.
recreate_on_stale_credential() { # tier  service...
    local tier="$1"; shift
    local proj; proj="$(proj "$tier")"
    local rendered svc name running stale=()

    rendered="$(${RUNTIME} exec "${proj}_vault-agent_1" \
        sh -c "sed -n 's/^export POSTGRES_USER=//p' /vault/secrets/app.env" 2>/dev/null)"
    [[ -n "${rendered}" ]] || return 0

    for svc in "$@"; do
        name="${proj}_${svc}_1"
        # Read from the process, not from `inspect`: the entrypoint sources the file into the
        # environment it execs with, so the container's own definition never carries it.
        running="$(${RUNTIME} exec "${name}" sh -c \
            "tr '\0' '\n' < /proc/1/environ | sed -n 's/^POSTGRES_USER=//p'" 2>/dev/null)"
        # Absent means this service does not hold one — the puller reaches the platform over
        # HTTP — and absence is not staleness.
        [[ -n "${running}" ]] || continue
        [[ "${running}" == "${rendered}" ]] || stale+=("${name}")
    done

    (( ${#stale[@]} )) || return 0
    replace_containers "${proj}" "holding a superseded database credential" "${stale[@]}"
}

# Assert each container runs an image built since its source last changed — compared by TIME, not
# image id, because compose rebuilds identical source into new ids and a check that cries wolf
# gets ignored.

# Carved regions staged for RE sessions are live malware as plain files in the working tree;
# teardown must take them with it. .gitignore stops publication, not presence.

# Anonymous volumes from recreates of VOLUME-declaring images each hold one runtime lock from a
# fixed pool of 2048; exhaustion stops the runtime creating ANY container. Only 64-hex names are
# touched — named volumes hold evidence and `volume rm` refuses anything in use.
prune_anonymous_volumes() {
    local anon before
    before="$(${RUNTIME} volume ls -q 2>/dev/null | wc -l)"
    anon="$(${RUNTIME} volume ls -q 2>/dev/null | grep -cE '^[0-9a-f]{64}$' || true)"
    [[ "${anon:-0}" -eq 0 ]] && return 0
    ${RUNTIME} volume ls -q 2>/dev/null | grep -E '^[0-9a-f]{64}$' \
        | xargs -r -n 200 ${RUNTIME} volume rm >/dev/null 2>&1 || true
    local after
    after="$(${RUNTIME} volume ls -q 2>/dev/null | wc -l)"
    if [[ "${after}" -lt "${before}" ]]; then
        ok "reclaimed $(( before - after )) unused anonymous volume(s) — $(( after )) remain"
    fi
    # The pool is shared with containers and pods; warn well before it is gone, because the
    # failure it produces names locks and not volumes.
    if [[ "${after}" -gt 1500 ]]; then
        warn "${after} volumes against a 2048 runtime lock pool — container creation fails when it is exhausted"
    fi
}

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
            worker-*) src="${HERE}/../backend ${HERE}/../shared" ;;
            keycloak) src="${HERE}/../keycloak" ;;
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

# Wait until a container exists AND passes a probe; fail loudly rather than let a later stage
# start against nothing.

# The rendered credential is tested against 127.0.0.1, not the local socket — the socket passes on
# trust and proves nothing.
app_cred_authenticates() {
    local env_out u p
    env_out="$(${RUNTIME} exec ir-enclave_vault-agent_1 cat /vault/secrets/app.env 2>/dev/null)" || return 1
    u="$(sed -n 's/^export POSTGRES_USER=//p' <<<"${env_out}" | tr -d '"'"'"'"')"
    p="$(sed -n 's/^export POSTGRES_PASSWORD=//p' <<<"${env_out}" | tr -d '"'"'"'"')"
    [[ -n "${u}" && -n "${p}" ]] || return 1
    ${RUNTIME} exec -e "PGPASSWORD=${p}" ir-enclave_db_1 \
        psql -h 127.0.0.1 -U "${u}" -d "${POSTGRES_DB:-ir_platform}" -tAc 'select 1' >/dev/null 2>&1
}

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

# Images the staged gates depend on, built before any tier starts: ir-workstation is defined in
# the LAST tier's compose but probed by earlier gates, and ir-worker needs a staged context
# compose cannot build. Building both here makes a clean deployment behave like a repeat one.

# The code graph is warned about, not enforced: a stale manifest is a documentation defect;
# uat_baseline.sh is what fails on it.
check_code_graph() {
    local gen="${HERE}/../../gen_code_graph.py"
    [[ -f "${gen}" ]] || return 0
    python3 "${gen}" --check >/dev/null 2>&1 \
        || warn "the code graph is stale — run gen_code_graph.py (a service, script, route or UAT changed)"
}

ensure_build_images() {
    say "Images · prerequisites for the staged gates"
    check_code_graph

    if ! ${RUNTIME} image exists localhost/ir-workstation:latest 2>/dev/null; then
        ${RUNTIME} build -t localhost/ir-workstation:latest \
            -f "${HERE}/../workstation/Dockerfile.tools" "${HERE}/../workstation" \
            >/dev/null 2>&1 \
            && ok "probe/tools image built" \
            || die "could not build the probe image — every health gate depends on it"
    else
        ok "probe/tools image present"
    fi

    if worker_image_stale; then
        say "  building the analysis worker (Volatility + toolkit analysis stack)"
        bash "${HERE}/../backend/build_worker.sh" >/dev/null 2>&1 \
            && ok "analysis worker image rebuilt from current backend source" \
            || die "could not build the analysis worker — see backend/build_worker.sh"
    else
        ok "analysis worker image current with backend/ and shared/"
    fi
}

# The worker embeds the whole backend application, so any change under backend/ or shared/ makes
# its image stale — and a stale worker runs pre-migration models against a migrated database,
# failing silently three layers away. IR_REBUILD_WORKER=1 forces it for toolkit changes this
# cannot see.
worker_image_stale() {
    ${RUNTIME} image exists localhost/ir-worker:latest 2>/dev/null || return 0
    [[ "${IR_REBUILD_WORKER:-0}" == "1" ]] && return 0
    local built
    built="$(${RUNTIME} image inspect localhost/ir-worker:latest --format '{{.Created}}' 2>/dev/null)"
    built="$(date -d "${built}" +%s 2>/dev/null)" || return 0
    # One source file newer than the image settles it; no reason to walk the rest.
    [[ -n "$(find "${HERE}/../backend" "${HERE}/../shared" -type f \
             -not -path '*/__pycache__/*' -newermt "@${built}" -print -quit 2>/dev/null)" ]]
}

# Remove containers whose service no longer exists in the tier's compose file: compose only
# manages services it can see, so a deleted service keeps running, attached and credentialed,
# invisible to both `up` and `down`.
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
    # `--internal` is the egress control: no route off the host regardless of what resolves. The
    # runtime resolver stays ENABLED for dynamic addressing but is never handed to containers — every
    # `dns:` points at CoreDNS, whose Corefile is where the restriction is written.
    ${RUNTIME} network exists ir-edge 2>/dev/null || \
        ${RUNTIME} network create --internal --subnet "${EDGE_SUBNET}" ir-edge >/dev/null
    # `--internal` here too: without it the runtime resolver forwards unanswerable names to the HOST's
    # resolvers, leaving a DNS exfiltration channel open on the puller — the enclave's one outward
    # bridge.
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

# Wait for a tailnet node to hold an address — polled, because registration is not instant and a
# single check right after `up` reports a healthy node as missing.
wait_tailnet_ip() { # container  seconds
    local c="$1" limit="${2:-90}" waited=0 ip
    while (( waited < limit )); do
        ip="$(${RUNTIME} exec "${c}" tailscale ip -4 2>/dev/null | tr -d '[:space:]')"
        [[ "${ip}" =~ ^100\. ]] && { printf '%s' "${ip}"; return 0; }
        sleep 5; waited=$((waited+5))
    done
    return 1
}

# Start each sidecar in its service's CURRENT netns: a recreated service leaves the unchanged
# sidecar bound in a dead namespace, and nothing in the symptom names it. Removing the SHARER is
# safe; the deadlock is removing the shared service while a sharer is attached.
mesh_sidecars() { # service...
    local svc names=() targets=()
    for svc in "$@"; do
        names+=("ir-enclave_${svc}-sidecar_1")
        targets+=("${svc}-sidecar")
    done
    ${RUNTIME} rm -f "${names[@]}" >/dev/null 2>&1 || true
    dc enclave up -d --no-deps "${targets[@]}" >/dev/null 2>&1
}

# Register, start proxies, re-register, restart proxies — the only order that converges: a
# registration must precede its proxy, but compose can recreate the service (new address) while
# starting that proxy. The final restart goes through podman, which recreates nothing.
mesh_attach() { # service...
    local svc cn svcs=()
    bash "${HERE}/../hashicorp/consul/register-mesh.sh" >/dev/null 2>&1 || true
    mesh_sidecars "$@"
    bash "${HERE}/../hashicorp/consul/register-mesh.sh" >/dev/null 2>&1 \
        || warn "mesh registration incomplete"

    # EVERY sidecar, not only this stage's: a later stage can recreate services an earlier one
    # attached, and the symptom surfaces two stages away as an app unable to reach a healthy database.
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

# Wait until the service reaches an upstream THROUGH its proxy, probed inside the service's own
# namespace — Envoy binds upstream listeners only after fetching config, and an orphaned proxy
# stays 'up' while serving nothing.
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

# A sidecar is sound only in its service's CURRENT namespace, compared by /proc namespace inode —
# with static addresses an orphaned proxy holds the right address in the wrong namespace, and
# SandboxKey lies for restarted containers. Repaired proxies are recreated (joins the new
# namespace); healthy ones are left alone.
netns_of() { # container -> net:[inode] or empty
    local pid
    pid="$(${RUNTIME} inspect -f '{{.State.Pid}}' "$1" 2>/dev/null || true)"
    [[ "${pid:-0}" -gt 0 ]] || return 0
    readlink "/proc/${pid}/ns/net" 2>/dev/null || true
}

# Converges rather than sweeping once: this script itself can strand a proxy moments after placing
# it, so each pass re-reads namespaces until none needs repair.
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

# Static mesh addresses validated BEFORE anything starts: to move a service, edit IR_IP_* and
# redeploy. Unvalidated, a bad address surfaces as a container that will not start — or one that
# starts unreachable.
mesh_addr_check() {
    python3 - <<'PY' || die "static mesh addressing is invalid — fix IR_IP_* in deploy/.env"
import ipaddress, os, sys
subnet = ipaddress.ip_network(os.environ["ENCLAVE_SUBNET"])
# A pinned address inside the dynamic pool is handed to whatever unpinned container starts while
# the pinned service is down, and the pinned service then cannot start. Membership and uniqueness
# checks alone pass that configuration until the collision happens.
pool = os.environ.get("ENCLAVE_DYNAMIC_RANGE", "")
dynamic = ipaddress.ip_network(pool) if pool else None
claimed = {"ENCLAVE_DNS_IP": os.environ["ENCLAVE_DNS_IP"]}
rc = 0
if dynamic is None:
    print("    ENCLAVE_DYNAMIC_RANGE is unset — the runtime would allocate over the whole subnet")
    rc = 1
elif not dynamic.subnet_of(subnet):
    print(f"    ENCLAVE_DYNAMIC_RANGE={pool} is not inside {subnet}"); rc = 1

for name, val in list(claimed.items()):
    if dynamic and ipaddress.ip_address(val) in dynamic:
        print(f"    {name}={val} sits inside the dynamic pool {pool}"); rc = 1

for svc in ("DB", "MINIO", "REDIS", "VAULT", "BACKEND", "WORKER", "FRONTEND", "PULLER",
            "OAUTH2_PROXY", "LOG_SHIPPER", "KEYCLOAK", "NTP"):
    var = f"IR_IP_{svc}"; val = os.environ.get(var, "")
    if not val:
        print(f"    {var} is unset — the mesh cannot register {svc.lower()}"); rc = 1; continue
    try:
        ip = ipaddress.ip_address(val)
    except ValueError:
        print(f"    {var}={val} is not an address"); rc = 1; continue
    if ip not in subnet.hosts():
        print(f"    {var}={val} is outside {subnet}"); rc = 1
    if dynamic and ip in dynamic:
        print(f"    {var}={val} sits inside the dynamic pool {pool} — an unpinned container "
              f"will eventually be handed this address"); rc = 1
    for other, taken in claimed.items():
        if val == taken:
            print(f"    {var}={val} collides with {other}"); rc = 1
    claimed[var] = val
sys.exit(rc)
PY
}

# The pool the network was ACTUALLY created with, which is the only one that governs. A compose
# network is created once and reused: editing ip_range changes the file, never the live network,
# so a fixed configuration and a still-broken runtime look identical from the tree.
mesh_pool_applied_check() { # -> 0 when the live network matches ENCLAVE_DYNAMIC_RANGE
    local net="${1}" want="${ENCLAVE_DYNAMIC_RANGE:-}"
    [[ -n "${want}" ]] || return 0
    ${RUNTIME} network exists "${net}" 2>/dev/null || return 0   # not created yet; compose will
    python3 - "$(${RUNTIME} network inspect "${net}" 2>/dev/null)" "${want}" <<'PY'
import ipaddress, json, sys
try:
    nets = json.loads(sys.argv[1] or "[]")
except json.JSONDecodeError:
    sys.exit(0)
want = ipaddress.ip_network(sys.argv[2])
for n in nets:
    for sub in n.get("subnets", []):
        lease = sub.get("lease_range") or {}
        start, end = lease.get("start_ip"), lease.get("end_ip")
        if not start or not end:
            sys.exit(1)   # unbounded: the allocator owns the whole subnet
        if (ipaddress.ip_address(start) != want[1]
                or ipaddress.ip_address(end) != want[-1]):
            sys.exit(1)
sys.exit(0)
PY
}

# --- staged tier bring-ups -------------------------------------------------

# Bring the running Keycloak's admin password to the value this deployment holds, trying the
# credentials a previous deployment could have left behind. Silent about which one worked: the
# useful signal is whether the deployment and the store now agree.
# Retire a generated secret so the next deploy of its tier provisions a new one.
#
# Rotation is not a separate ceremony: `ensure_secret` already provisions anything absent, so
# retiring a value IS the rotation, and the deploy that follows applies it. Kept in the
# codebase rather than written down as a procedure, because a procedure is a thing an operator
# performs differently each time and cannot be asserted.
#
# The retired value is kept, commented, beside its replacement. A key that encrypted something
# still has to verify it — the custody seal's retired-key list is the reason that matters.
ROTATABLE=(BOUNDARY_WORKER_AUTH_KEY BOUNDARY_RECOVERY_KEY IR_OIDC_CLIENT_SECRET
           KC_BOOTSTRAP_ADMIN_PASSWORD RECEIVER_PULLER_TOKEN IR_SSO_PROXY_SECRET
           IR_PLATFORM_ADMIN_PASSWORD
           IR_CUSTODY_HMAC_KEY)

rotate_secrets() {  # <name...|--all>
    local env_file="${HERE}/.env" names=() n line
    if [[ "${1:-}" == "--all" ]]; then
        names=("${ROTATABLE[@]}")
    else
        names=("$@")
    fi
    [[ ${#names[@]} -gt 0 ]] || die "usage: deploy.sh rotate <NAME>... | --all   (see ROTATABLE)"
    for n in "${names[@]}"; do
        # Boundary's root key encrypts its own database. Clearing it here would generate a key
        # that cannot read what the old one wrote, and the failure surfaces later as a
        # controller that will not start. Rotating it is a Boundary operation on the store,
        # not a config edit, so this refuses rather than half-doing it.
        if [[ "${n}" == "BOUNDARY_ROOT_KEY" ]]; then
            warn "BOUNDARY_ROOT_KEY encrypts the Boundary database — rotate it through Boundary,"
            warn "  not by regenerating config. Refused."
            continue
        fi
        grep -qx -- "${n}" <<<"$(printf '%s\n' "${ROTATABLE[@]}")" \
            || { warn "${n} is not a rotatable generated secret — skipped"; continue; }
        line="$(grep -m1 "^${n}=" "${env_file}" 2>/dev/null || true)"
        if [[ -z "${line}" ]]; then
            ok "${n} is not set — the next deploy generates it"
            continue
        fi
        # Retired above the live entry, so what a bundle or an archive was sealed with is
        # still recoverable after the value it used has been replaced. Rewritten in python
        # because the value is arbitrary bytes and sed would need it escaped to be safe.
        python3 - "${env_file}" "${n}" <<'PYEOF'
import sys
path, name = sys.argv[1], sys.argv[2]
out, done = [], False
for line in open(path).read().splitlines():
    if not done and line.startswith(name + "="):
        value = line.split("=", 1)[1]
        if value:
            out.append("# retired {} — kept so material sealed under it still verifies".format(name))
            out.append("# {}_RETIRED={}".format(name, value))
        out.append(name + "=")
        done = True
    else:
        out.append(line)
open(path, "w").write("\n".join(out) + "\n")
PYEOF
        ok "retired ${n} — the next deploy of its tier provisions a new one"
    done
    say "Rotation staged. Apply it with the deploy that owns each secret:"
    printf '    deploy.sh enclave      # Boundary, Keycloak, OIDC, custody\n'
    printf '    deploy.sh dmz          # the receiver credential\n'
}

converge_kc_admin() {
    local want="${KC_BOOTSTRAP_ADMIN_PASSWORD:-}" prev
    [[ -n "${want}" ]] || return 0
    kc_auth() {  # <password>
        ${RUNTIME} exec -i ir-enclave_keycloak_1 \
            /opt/keycloak/bin/kcadm.sh config credentials --server http://127.0.0.1:8080 \
            --realm master --user "${KEYCLOAK_ADMIN:-admin}" --password "$1" >/dev/null 2>&1
    }
    if kc_auth "${want}"; then
        ok "Keycloak admin credential matches this deployment"
        return 0
    fi
    for prev in "${KEYCLOAK_ADMIN_PASSWORD:-}" admin; do
        [[ -n "${prev}" ]] || continue
        kc_auth "${prev}" || continue
        if ${RUNTIME} exec -i ir-enclave_keycloak_1 \
                /opt/keycloak/bin/kcadm.sh set-password -r master \
                --username "${KEYCLOAK_ADMIN:-admin}" --new-password "${want}" >/dev/null 2>&1; then
            ok "rotated the Keycloak admin password to this deployment's own"
            return 0
        fi
    done
    warn "could not converge the Keycloak admin password — realm and account steps may fail"
}

up_enclave() {
    ensure_enclave_secrets
    ensure_puller_token
    resolve_vault_config
    ensure_vault_image
    reap_orphans enclave
    mesh_addr_check
    # A compose network is created once and then reused, so widening or narrowing ip_range in
    # the file never reaches a network that already exists. Left undetected, the tree says the
    # addressing is bounded while the runtime keeps allocating over the pinned block.
    if ! mesh_pool_applied_check "$(proj enclave)_internal"; then
        warn "the enclave network was created without the dynamic pool ${ENCLAVE_DYNAMIC_RANGE}"
        warn "recreate it so pinned addresses stop being handed out:"
        warn "    ${COMPOSE} -p $(proj enclave) -f $(compose_of enclave) down"
        warn "    ${RUNTIME} network rm $(proj enclave)_internal"
        die  "then redeploy — an unbounded pool takes a pinned address the moment its service is down"
    fi
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

    # Time, beside the resolver and for the same reason: the segment installs no route off the
    # host, so both authorities have to live inside it. Brought up HERE, before anything that
    # timestamps — a custody seal written by a host that has not yet found a time source is
    # unanchored, and nothing downstream can tell that from a seal written correctly.
    dc enclave up -d --build ntp >/dev/null 2>&1
    wait_for ir-enclave_ntp_1 45 true || warn "enclave time service slow to start"
    ntp_stratum="$(${RUNTIME} exec ir-enclave_ntp_1 chronyc -n tracking 2>/dev/null \
                   | awk -F': *' '/^Stratum/ {print $2}')"
    if [[ -z "${ntp_stratum}" ]]; then
        warn "enclave time service is not answering — hosts have no authority to agree with"
    elif [[ "${ntp_stratum}" == "10" ]]; then
        ok "enclave time service up — serving from its LOCAL reference (set IR_NTP_UPSTREAM for a traceable source)"
    else
        ok "enclave time service up — stratum ${ntp_stratum}, disciplined by its upstream"
    fi

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
        -e "s|__WORKER_NAME__|ir-egress|" \
        "${HERE}/../hashicorp/access/boundary-egress.hcl.tmpl" \
        > "${HERE}/../hashicorp/access/boundary-egress.hcl"
    chmod 600 "${HERE}/../hashicorp/access/boundary-egress.hcl"
    # One config per egress worker. Every session dials the worker it was assigned, and
    # concurrent connection setups corrupt a single worker's handshake path — the ~8/s setup
    # ceiling belongs to the worker, so capacity scales with workers, not with sessions.
    local w
    for w in $(seq 2 "${BOUNDARY_EGRESS_WORKERS:-3}"); do
        sed -e "s|__BOUNDARY_CONTROLLER__|${BOUNDARY_HOST:-boundary}|" \
            -e "s|__BOUNDARY_WORKER_AUTH_KEY__|${BOUNDARY_WORKER_AUTH_KEY}|" \
            -e "s|__WORKER_PUBLIC_ADDR__|boundary-egress-${w}:9202|" \
            -e "s|__WORKER_NAME__|ir-egress-${w}|" \
            "${HERE}/../hashicorp/access/boundary-egress.hcl.tmpl" \
            > "${HERE}/../hashicorp/access/boundary-egress-${w}.hcl"
        chmod 600 "${HERE}/../hashicorp/access/boundary-egress-${w}.hcl"
    done
    ok "Boundary configs rendered (TLS on the API; ${BOUNDARY_EGRESS_WORKERS:-3} egress workers advertise their own names)"

    # Staged, like every other dependency here: the database is gated on accepting connections
    # before the controller is started against it.
    dc enclave up -d boundary-db >/dev/null 2>&1
    wait_for ir-enclave_boundary-db_1 120 \
        ${RUNTIME} exec ir-enclave_boundary-db_1 pg_isready -U boundary \
        || die "Boundary's database never became ready"
    # Recreated so a re-rendered bind-mounted config is actually read; `compose up` leaves a running
    # container alone. The controller holds no container state.
    ${RUNTIME} rm -f ir-enclave_boundary_1 ir-enclave_boundary-egress_1 \
        ir-enclave_boundary-egress-2_1 ir-enclave_boundary-egress-3_1 >/dev/null 2>&1 || true
    dc enclave up -d boundary >/dev/null 2>&1
    wait_for ir-enclave_boundary_1 150 \
        ${RUNTIME} exec ir-enclave_boundary_1 wget -q -O- http://127.0.0.1:9203/health \
        || die "Boundary never became healthy — analysts have no route into the enclave"
    # One target (the SSO gate), idempotent so a redeploy does not split the allow-list. Output
    # surfaced — a swallowed provisioning error leaves the next failure describing a symptom.
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

    # The workers that actually carry the sessions, started after the controller so their
    # first registration attempt has something to register with. Several of them, because
    # concurrent connection setups corrupt a single worker's handshake path — the controller
    # spreads sessions across the registered set, so setup capacity scales here.
    local nworkers wname wsvc wctr wnames=""
    nworkers="${BOUNDARY_EGRESS_WORKERS:-3}"
    for w in $(seq 1 "${nworkers}"); do
        if [[ "${w}" == "1" ]]; then wsvc="boundary-egress"; wname="ir-egress"
        else wsvc="boundary-egress-${w}"; wname="ir-egress-${w}"; fi
        wctr="ir-enclave_${wsvc}_1"
        dc enclave up -d "${wsvc}" >/dev/null 2>&1
        # `up -d` can leave the last worker in Created without ever starting it — twice in
        # one day, both cold starts, and the worker itself is fine (started by hand it
        # authenticates in under a second). Waiting on it would time out against a container
        # that was never told to run.
        if [[ "$(${RUNTIME} inspect "${wctr}" --format '{{.State.Status}}' 2>/dev/null)" == "created" ]]; then
            warn "${wsvc} was created but never started — starting it directly"
            ${RUNTIME} start "${wctr}" >/dev/null 2>&1 || true
        fi
        wait_for "${wctr}" 90 \
            ${RUNTIME} exec "${wctr}" wget -q -O- http://127.0.0.1:9203/health \
            || die "Boundary egress worker ${wname} never became healthy"
        wnames="${wnames} ${wname}"
    done
    # Registration is its own gate: a target with no worker authorizes sessions that carry nothing,
    # surfacing tiers away as a hung connection. Stale registrations are reaped — the controller still
    # hands sessions to them, which reads as an intermittent network fault.

    # shellcheck disable=SC2086
    if ! bw="$(${RUNTIME} exec ir-enclave_boundary_1 sh /boundary/workers.sh ${wnames} 2>&1)"; then
        warn "Boundary worker registration incomplete — some sessions would be authorized and then carry nothing:"
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

    # Ordering forced by a circularity: a registration carries the address other proxies dial, so
    # destinations come up, register, get sidecars; consumers start (retrying), register, get
    # sidecars. The applications' own start-up retries are what make this converge rather than
    # deadlock.
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
        mesh_attach db minio redis
        ok "data-tier sidecars up — Postgres and MinIO are reachable only through them"
    fi

    say "Enclave · stage 1c/4 — secrets"
    # Ordered by what each step needs, because none of it is inferable from depends_on:
    # certs -> server -> unseal+provision -> agent renders. The application tier starts only
    # once a rendered secrets file exists, since with IR_VAULT=1 it has no other source for
    # its database password.
    if [[ "${IR_VAULT:-1}" != "1" ]]; then
        # No static fallback exists: the admin credential lives in .env.db, which only the
        # data tier loads. An app tier without Vault has no database password at all.
        die "IR_VAULT=0 has no credential path — the app tier holds no static secret; deploy with Vault"
    else
        # One-shots are removed first or they never run again — `compose up` will not restart an exited-0
        # container. Both converge, so running them every deploy is the point.

        # --depend and NOT silenced: vault-agent depends on the server, so a plain rm fails and a
        # swallowed failure means a corrected config never takes effect. Recreating is safe — everything
        # lives on volumes, and the unseal step handles the sealed restart.

        # Namespace-sharing containers FIRST and separately: removing the service while a sharer holds its
        # netns deadlocks podman with the storage lock held.
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
        # ONE compose call for the whole group: called per service, compose recreates the server for each
        # dependent — re-sealing Vault mid-provisioning.
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

        # Unsealing runs EVERY deployment (Vault seals on any restart); provisioning runs once. --user
        # root because the unseal material is root-owned 600 and the server user cannot read it — under
        # rootless podman that is the invoking host user.
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

        # One-shots run only now, against an UNSEALED Vault — earlier they race the gate and fail with
        # 'Vault is sealed' while everything else reports success.

        # NO --no-deps: podman-compose silently SKIPS the service when it is passed, reporting success and
        # creating nothing.
        if ! vup="$(dc enclave up -d db-bootstrap vault-setup vault-agent kc-vault-agent 2>&1)"; then
            warn "the Vault one-shots did not start — credentials will not reconcile:"
            printf '%s\n' "${vup}" | tail -5 | sed 's/^/        /'
        fi

        # Repaired around them: that compose call can recreate Vault (re-sealed, proxy orphaned), and
        # vault-setup tolerates exactly this window by unsealing and retrying for a minute.
        if [[ "${IR_MESH:-1}" == "1" ]]; then
            mesh_attach vault
            mesh_ready vault 5432 90 \
                && ok "Vault reaches Postgres through the mesh" \
                || warn "Vault's database upstream never opened — it cannot mint or revoke credentials"
        fi
        # Restarted, not merely started: an agent already running holds the secret_id it read
        # at boot and backs off for minutes between auth attempts. vault-setup has just
        # reissued that credential, and the restart is what makes the agent pick it up now
        # rather than after a backoff nothing here is waiting for.
        ${RUNTIME} restart ir-enclave_vault-agent_1 ir-enclave_kc-vault-agent_1 >/dev/null 2>&1 || true

        # The rendered file is necessary, not sufficient: a file left by an earlier deploy satisfies a
        # grep while its role has been revoked. The gate is the credential WORKING against Postgres.
        wait_for ir-enclave_vault-agent_1 150 \
            ${RUNTIME} exec ir-enclave_vault-agent_1 \
            sh -c 'grep -q POSTGRES_PASSWORD /vault/secrets/app.env' \
            || die "Vault Agent never rendered the app secrets — the app tier cannot start"
        vuser="$(${RUNTIME} exec ir-enclave_vault-agent_1 \
                 sh -c 'grep "^export POSTGRES_USER=" /vault/secrets/app.env | cut -d= -f2' 2>/dev/null)"
        cred_ok=0
        for _ in $(seq 1 20); do
            app_cred_authenticates && { cred_ok=1; break; }
            sleep 3
        done
        if (( cred_ok )); then
            ok "Vault issued the app tier a dynamic database user, and it authenticates (${vuser:-unknown})"
        else
            die "the app tier's Vault credential does not authenticate to Postgres (${vuser:-unknown}) — the
        rendered secret is stale. Check: ${RUNTIME} logs ir-enclave_vault-agent_1"
        fi
        # Keycloak's credential, from ITS agent: identity cannot start without it, and a
        # gate here names the real failure instead of a login page two stages later.
        wait_for ir-enclave_kc-vault-agent_1 150 \
            ${RUNTIME} exec ir-enclave_kc-vault-agent_1 \
            sh -c 'grep -q KC_DB_PASSWORD /vault/secrets/kc-db.env' \
            || die "Keycloak's credential never rendered — identity cannot reach its store"
        kcuser="$(${RUNTIME} exec ir-enclave_kc-vault-agent_1 \
                 sh -c 'grep "^export KC_DB_USERNAME=" /vault/secrets/kc-db.env | cut -d= -f2' 2>/dev/null)"
        ok "Vault issued Keycloak a dynamic database user (${kcuser:-unknown})"
    fi

    pki_logon_render

    say "Enclave · stage 2/4 — identity (Keycloak takes ~60s)"
    # The identity store lives on Postgres: accounts and analyst-set passwords survive a
    # recreate, so recreating Keycloak is routine rather than destructive. Realm changes land
    # through realm-converge.sh below — the import applies only to a fresh database, so
    # recreating on a changed realm file stopped doing anything.
    dc enclave build keycloak >/dev/null 2>&1

    # ONE decision on whether the running Keycloak is valid, before its proxy is touched. Four things
    # invalidate it: a pre-inverted-layout namespace, a stale image (the theme is baked in), a
    # superseded database credential, and an unreadable one — where 'cannot tell' must mean recreate.
    kc_stale=""
    kc_mode="$(${RUNTIME} inspect -f '{{.HostConfig.NetworkMode}}' ir-enclave_keycloak_1 2>/dev/null || true)"
    kc_img_run="$(${RUNTIME} inspect ir-enclave_keycloak_1 --format '{{.Image}}' 2>/dev/null || true)"
    kc_img_new="$(${RUNTIME} image inspect localhost/ir-keycloak:latest --format '{{.Id}}' 2>/dev/null || true)"
    kc_rendered="$(${RUNTIME} exec ir-enclave_kc-vault-agent_1 \
        sh -c 'sed -n "s/^export KC_DB_USERNAME=//p" /vault/secrets/kc-db.env' 2>/dev/null || true)"
    kc_running="$(${RUNTIME} exec ir-enclave_keycloak_1 sh -c \
        "tr '\0' '\n' < /proc/1/environ | sed -n 's/^KC_DB_USERNAME=//p'" 2>/dev/null || true)"
    if [[ -n "${kc_img_run}" ]]; then
        [[ "${kc_mode}" == container:* ]] || kc_stale="it is not in its proxy's namespace"
        [[ -z "${kc_stale}" && -n "${kc_img_new}" && "${kc_img_run}" != "${kc_img_new}" ]] \
            && kc_stale="it runs an older image than the one just built"
        [[ -z "${kc_stale}" && -n "${kc_rendered}" && "${kc_running}" != "${kc_rendered}" ]] \
            && kc_stale="its database credential has been superseded"
    fi
    if [[ -n "${kc_stale}" ]]; then
        warn "recreating Keycloak — ${kc_stale}"
        # Dependency order resolved by the runtime: the backend depends on Keycloak, so removing Keycloak
        # alone fails however the sidecars are handled — `--depend` takes the dependents and stages 3–4
        # bring them back. Same idiom as the Vault recreate.
        if ! kcrm="$(${RUNTIME} rm -f --depend ir-enclave_keycloak_1 2>&1)"; then
            case "${kcrm}" in
                *"no such container"*) : ;;
                *) warn "could not remove Keycloak — it will keep running as it is:"
                   printf '%s\n' "${kcrm}" | tail -3 | sed 's/^/        /' ;;
            esac
        fi
    fi

    # The proxy owns the namespace and starts FIRST, exactly as for the SSO gate: Keycloak
    # exits while its database upstream is closed, and each exit of a namespace owner would
    # strand the proxy carrying the upstream it is waiting for. Registration precedes the
    # proxy; a second pass follows the service so the registration reflects what runs.
    if [[ "${IR_MESH:-1}" == "1" ]]; then
        bash "${HERE}/../hashicorp/consul/register-mesh.sh" >/dev/null 2>&1 || true
        dc enclave up -d keycloak-sidecar >/dev/null 2>&1
    fi
    dc enclave up -d keycloak >/dev/null 2>&1
    if [[ "${IR_MESH:-1}" == "1" ]]; then
        bash "${HERE}/../hashicorp/consul/register-mesh.sh" >/dev/null 2>&1 || true
        # The up above walks compose dependencies; repair anything it recreated out from
        # under an attached proxy BEFORE gating on the path those proxies serve.
        mesh_orphan_check db minio redis vault
        mesh_ready keycloak 5432 90 \
            && ok "Keycloak's database upstream is open" \
            || warn "Keycloak's database upstream never opened — identity cannot reach its store"
    fi
    wait_for ir-enclave_keycloak_1 300 logmatch ir-enclave_keycloak_1 "Listening on" \
        || die "Keycloak never started — the SSO gate cannot come up without it"

    # The bootstrap admin password is a BOOTSTRAP-ONLY write: Keycloak applies
    # KC_BOOTSTRAP_ADMIN_PASSWORD when it creates the account and never again, so a store that
    # already exists keeps whatever password first created it. Generating a new one without
    # this step leaves the deployment holding a credential the database does not have, and
    # every kcadm call after it fails for a reason that reads as "Keycloak is down".
    # Converged rather than assumed, which is the same rule the Consul config entries follow.
    converge_kc_admin
    # The realm FILE is enforced on every deploy. With the store persistent, --import-realm
    # applies only on first start; without this converge a changed password policy or
    # brute-force threshold deploys cleanly and changes nothing.
    bash "${HERE}/../hashicorp/keycloak/realm-converge.sh" | sed 's/^/    /' \
        || warn "realm converge reported a problem — the file and the running realm may differ"

    # Demo accounts are provisioned HERE, not by realm import (imports never update an existing
    # realm); idempotent, initial credential announced once, replacement forced at first login.
    # Verified even with a persistent store — absence surfaces only as 'invalid username or password'
    # at the kiosk.
    bash "${HERE}/../hashicorp/keycloak/provision-demo-users.sh" | sed 's/^/    /' \
        || warn "demo-account provisioning reported a problem — verifying regardless"
    local present
    present="$(${RUNTIME} exec -i ir-enclave_keycloak_1 sh -c '
        /opt/keycloak/bin/kcadm.sh config credentials --server http://127.0.0.1:8080 \
            --realm master --user "${KC_BOOTSTRAP_ADMIN_USERNAME:-admin}" \
            --password "${KC_BOOTSTRAP_ADMIN_PASSWORD:-admin}" >/dev/null 2>&1 &&
        /opt/keycloak/bin/kcadm.sh get users -r irplatform --fields username 2>/dev/null' \
        | grep -c '"username"' | tail -1)"
    # `grep -c` already prints 0 when nothing matches, so a `|| echo 0` fallback appends a
    # SECOND line and the comparison below dies on "0\n0" — a syntax error standing in for
    # what is really "Keycloak never came up". `tail -1` keeps one line and masks grep's
    # exit status, which is the pipeline's only failure mode here.
    if [[ "${present:-0}" -ge 4 ]]; then
        ok "demo accounts present (${present}) — initial credentials above, if any were created"
    else
        die "only ${present:-0} demo account(s) exist after provisioning — nobody could sign in; \
re-run deploy, or provision manually with hashicorp/keycloak/provision-demo-users.sh"
    fi

    say "Enclave · stage 3/4 — application"
    # Compose can pin a container to what :latest meant a moment before its own build finished, so
    # build once, then remove whatever landed on the wrong image and create again — the second pass
    # builds nothing, which is what settles it.

    # Replicas are ordinary members of the application tier: same image, same staleness
    # rules, same credential replacement. The list is empty at 1 worker, and every use below
    # expands to nothing then. Declared before the busy-guard so set -u holds on both paths.
    local wreps=() n
    for n in $(seq 2 "${IR_WORKER_REPLICAS:-1}"); do wreps+=("worker-${n}"); done
    # A running analysis takes the whole stage out of scope: any compose action here can reach the
    # worker through the graph.
    if [[ "${IR_FORCE_RECREATE:-0}" != "1" ]] && analysis_in_progress "$(proj enclave)"; then
        warn "a memory analysis is running — leaving the application tier as it is"
        warn "re-run when it finishes, or IR_FORCE_RECREATE=1 to deploy and discard it"
    else
        recreate_if_stale enclave backend frontend worker "${wreps[@]}"
        dc enclave up -d --build backend frontend worker "${wreps[@]}" >/dev/null 2>&1
        recreate_if_stale enclave backend frontend worker "${wreps[@]}"
        # A revoked credential is invisible to the image check — same image, dropped role.
        # These usually get replaced for image drift anyway, which is luck, not a guarantee.
        recreate_on_stale_credential enclave backend worker "${wreps[@]}"
        dc enclave up -d backend frontend worker "${wreps[@]}" >/dev/null 2>&1
        # podman-compose sometimes leaves the last of a batch in Created without starting
        # it — the egress workers hit this on every cold start until guarded the same way.
        for n in "${wreps[@]}"; do
            if [[ "$(${RUNTIME} inspect "ir-enclave_${n}_1" --format '{{.State.Status}}' 2>/dev/null)" == "created" ]]; then
                warn "${n} was created but never started — starting it directly"
                ${RUNTIME} start "ir-enclave_${n}_1" >/dev/null 2>&1 || true
            fi
        done
        # SCALE-DOWN: replicas beyond the declared count are removed and deregistered.
        # Without this, lowering IR_WORKER_REPLICAS leaves containers the compose files no
        # longer describe — running, consuming the queue, invisible to every later deploy.
        local extra_n
        for extra_n in $(${RUNTIME} ps -a --format '{{.Names}}' 2>/dev/null \
                         | sed -n 's/^ir-enclave_worker-\([0-9]\+\)_1$/\1/p'); do
            if [[ "${extra_n}" -gt "${IR_WORKER_REPLICAS:-1}" ]]; then
                warn "worker-${extra_n} exceeds IR_WORKER_REPLICAS=${IR_WORKER_REPLICAS:-1} — removing it"
                detach_then_remove "ir-enclave_worker-${extra_n}-sidecar_1" "ir-enclave_worker-${extra_n}_1"
                ${RUNTIME} exec ir-enclave_consul_1 sh -c \
                    "CONSUL_HTTP_ADDR=https://127.0.0.1:8501 CONSUL_CACERT=/consul/tls/consul-ca.pem \
                     consul services deregister -id=ir-worker-${extra_n}" >/dev/null 2>&1 || true
            fi
        done
    fi
    # Sidecars IMMEDIATELY, before the health gate: with Postgres on loopback the backend cannot reach
    # it until its proxy exists, and the gap is only bounded by the app's start-up retries.

    # --no-deps on every sidecar start, or compose walks depends_on and recreates the service AFTER
    # its old address was registered.
    if [[ "${IR_MESH:-1}" == "1" ]]; then
        mesh_attach backend worker frontend "${wreps[@]}"
        ok "application sidecars up — every data-tier connection now passes an intention check"
    fi
    verify_image enclave backend frontend worker keycloak "${wreps[@]}"
    # AFTER verify_image, which recreates a service left on a stale image — and a recreated
    # service has a new network namespace, stranding the proxy attached a moment ago. Sweeping
    # here makes namespace reconciliation the LAST thing the stage does, so nothing that runs
    # after it can undo the attach.
    if [[ "${IR_MESH:-1}" == "1" ]]; then
        mesh_orphan_check db minio redis vault backend worker frontend puller oauth2-proxy log-shipper keycloak "${wreps[@]}"
    fi
    wait_for ir-enclave_backend_1 180 pyprobe ir-enclave_backend_1 http://127.0.0.1:8000/api/health/ \
        || die "API never became healthy"

    # After the API is up, because it writes through it. Runs whether or not a container was
    # just removed: a health row outlives its container, so a fleet that shrank in an earlier
    # deploy still shows replicas that no longer exist as live components gone silent.
    ${RUNTIME} exec -i ir-enclave_backend_1 python manage.py retire_workers \
        "${IR_WORKER_REPLICAS:-1}" 2>/dev/null || true

    say "Enclave · stage 4/4 — SSO gate + ingress + puller"
    # The gate holds its sessions in Redis, which is loopback-bound behind a sidecar, so its
    # proxy must exist FIRST — and here the proxy owns the network namespace, so it is started
    # before the service rather than attached after it. Registration precedes both: a sidecar
    # with no registered service has nothing to front.
    if [[ "${IR_MESH:-1}" == "1" ]]; then
        bash "${HERE}/../hashicorp/consul/register-mesh.sh" >/dev/null 2>&1 || true
        dc enclave up -d oauth2-proxy-sidecar >/dev/null 2>&1
        # Gated on the REDIS LISTENER inside the sidecar's namespace — the SSO gate dials 127.0.0.1:6379
        # at start and exits when refused. Read passively from /proc: 0x18EB is 6379, 0A is LISTEN.
        wait_for ir-enclave_oauth2-proxy-sidecar_1 90 \
            ${RUNTIME} exec ir-enclave_oauth2-proxy-sidecar_1 sh -c \
            "awk '\$2 ~ /:18EB\$/ && \$4 == \"0A\" {f=1} END{exit !f}' /proc/net/tcp /proc/net/tcp6" \
            || die "the SSO gate's session-store listener never came up — the gate would exit on start"
    fi
    # An exited gate stays exited across `up -d`; it keeps reporting the failure it hit before
    # the listener existed. Removed first so the start below is a fresh container.
    ${RUNTIME} rm -f ir-enclave_oauth2-proxy_1 >/dev/null 2>&1 || true
    dc enclave up -d oauth2-proxy >/dev/null 2>&1
    # die, not warn: the gate is the analyst path. An enclave reported up without it serves
    # nobody, and the failure then surfaces as a browser error a tier away.
    wait_for ir-enclave_oauth2-proxy_1 120 logmatch ir-enclave_oauth2-proxy_1 "OAuthProxy configured" \
        || die "SSO gate did not report ready — check its OIDC settings and its session store"
    # A traefik left in Created holds container ids from before any sidecar recreate in its
    # dependency graph, and `start` then fails on a container that no longer exists. Removing
    # it first makes `up` rebuild the graph against what is actually running.
    ${RUNTIME} rm -f ir-enclave_traefik_1 >/dev/null 2>&1 || true
    dc enclave up -d --build traefik puller >/dev/null 2>&1
    # Before the shipper is brought up, not after: a container already running on a revoked
    # credential is not fixed by `up -d`, which leaves a running container alone.
    recreate_on_stale_credential enclave log-shipper
    # The shipper follows the ingress: its sidecar owns the namespace, so it starts first.
    if [[ "${IR_MESH:-1}" == "1" ]]; then
        bash "${HERE}/../hashicorp/consul/register-mesh.sh" >/dev/null 2>&1 || true
        dc enclave up -d log-shipper-sidecar >/dev/null 2>&1
    fi
    dc enclave up -d log-shipper >/dev/null 2>&1
    wait_for ir-enclave_log-shipper_1 90 logmatch ir-enclave_log-shipper_1 "following" \
        || warn "the log shipper did not start — web-tier records stay in container filesystems"
    if [[ "${IR_MESH:-1}" == "1" ]]; then
        mesh_attach puller
    fi
    # die, not warn, and gated on the LISTENER: the ingress is the only thing the brokered
    # session forwards to, so an enclave without it answers every analyst with a reset.
    wait_for ir-enclave_traefik_1 90 \
        ${RUNTIME} exec ir-enclave_traefik_1 sh -c \
        "awk '\$2 ~ /:01BB\$/ && \$4 == \"0A\" {f=1} END{exit !f}' /proc/net/tcp /proc/net/tcp6" \
        || die "ingress never bound :443 — the brokered session has nothing to forward to"
    # The deploy's LAST word is the data path: stage 4's sweep may recreate the db-side sidecar, whose
    # re-registration and fresh leaf certificate can take over a minute — a gate any earlier verifies
    # a path a later sweep rebuilds. The API probe cannot stand in (it touches no database), and
    # wait_for's name argument IS a container or the probe never runs.
    wait_for "$(proj enclave)_backend_1" 180 \
        ${RUNTIME} exec -w /app "$(proj enclave)_backend_1" python -c \
"import django,os;os.environ.setdefault('DJANGO_SETTINGS_MODULE','ir_platform.settings');django.setup();from django.db import connection;connection.ensure_connection()" \
        || die "the backend cannot reach Postgres through its sidecar — the data path is down"
    ok "backend reaches Postgres through the mesh"
    ok "enclave up"
}

# Every deployment gets its OWN secrets, generated on first bring-up and persisted to .env.
#
# A credential shipped as a literal in the tree is the same credential in every deployment
# that ever clones it, and it publishes wherever the tree publishes. Generating removes the
# operator step that gets skipped and the default that never gets changed at once.
#
# An EXISTING value is never overwritten. Several of these encrypt data at rest — Boundary's
# root key encrypts its database — so replacing one silently would strand what it protects.
# Rotating a live key is a deliberate operation, not a side effect of running the deploy.
ensure_secret() {  # <VAR_NAME> <hex|base64|pass> <description>
    local var="$1" kind="${2:-hex}" what="${3:-$1}"
    local env_file="${HERE}/.env" current="${!var:-}"
    case "${current}" in
        ""|CHANGE_ME|CHANGE-ME|changeme|admin) ;;
        *) export "${var}=${current}"; return 0 ;;
    esac
    local value
    case "${kind}" in
        base64) value="$(openssl rand -base64 32 2>/dev/null)" ;;
        pass)   value="$(openssl rand -base64 24 2>/dev/null | tr -d '/+=' | cut -c1-24)" ;;
        *)      value="$(openssl rand -hex 32 2>/dev/null)" ;;
    esac
    [[ -n "${value}" ]] || die "cannot generate ${what}: openssl is unavailable"
    if grep -q "^${var}=" "${env_file}" 2>/dev/null; then
        # `|` is not in base64's alphabet, so it cannot appear in the value being written.
        sed -i "s|^${var}=.*|${var}=${value}|" "${env_file}"
    else
        printf '\n# %s — generated on first deploy.\n%s=%s\n' "${what}" "${var}" "${value}" >> "${env_file}"
    fi
    export "${var}=${value}"
    ok "generated ${what}"
}

# The credential the receiver demands before it will serve or delete a held bundle, shared
# with the enclave's puller. Generated rather than asked of the operator: a receiver with no
# token refuses every read, which is the safe direction but reads as a broken deployment, and
# an evidence path that only works once somebody remembers a variable ships turned off.
ensure_puller_token() {
    ensure_secret RECEIVER_PULLER_TOKEN hex "the receiver's holding-area credential"
}

# The secrets a deployment must not share with any other, provisioned before the tier that
# needs them. Boundary's three KEKs are base64 AES-GCM material; the rest are passwords.
ensure_enclave_secrets() {
    ensure_secret BOUNDARY_ROOT_KEY base64 "Boundary's root key"
    ensure_secret BOUNDARY_WORKER_AUTH_KEY base64 "Boundary's worker-auth key"
    ensure_secret BOUNDARY_RECOVERY_KEY base64 "Boundary's recovery key"
    # One generator for the one Keycloak admin account. A second variable for the same account
    # left the app tier holding a password Keycloak had never been told about, and user
    # administration failed with credentials that looked provisioned.
    ensure_secret KC_BOOTSTRAP_ADMIN_PASSWORD pass "the Keycloak bootstrap admin password"
    ensure_secret IR_OIDC_CLIENT_SECRET hex "the platform's OIDC client secret"
    # The human who administers the INFRASTRUCTURE. Distinct from default-admin,
    # which is a web-application account: this one reaches Vault and the management
    # surfaces, and until it existed the only human path into Vault was the root token.
    ensure_secret IR_PLATFORM_ADMIN_PASSWORD pass "the platform-admin infrastructure credential"
}

up_dmz() {
    say "DMZ · receiver + broker + resolver"
    reap_orphans dmz
    ensure_puller_token
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
    # headscale advertises its own address for the control plane AND its embedded DERP relay, rendered
    # from the same value the nodes are given so the two cannot drift; a NAME, so it survives a
    # network recreate.

    # Nothing Boundary-side renders here: this tier runs a session CLIENT only.
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

    # The control-plane address the NODES dial, RESOLVED at deploy time: tailscale forces TLS on 443
    # for a hostname login server, silently discarding the URL's port, so a name here means the node
    # dials a port nothing serves. Multi-host overrides HEADSCALE_ADDR with the DMZ's routable
    # address.

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
    # What the NODES dial — a name through the DMZ resolver, and it must be https: tailscale rewrites
    # http:// to TLS on 443 discarding the port. Multi-host sets IR_HEADSCALE_LOGIN_URL to the DMZ's
    # routable address and adds it to the certificate via IR_HEADSCALE_SANS.
    local hs_login="${IR_HEADSCALE_LOGIN_URL:-https://${IR_HEADSCALE_HOST:-headscale}:${HEADSCALE_PORT}}"
    printf 'HEADSCALE_LOGIN_URL=%s\n' "${hs_login}" >> "${HERE}/.env.tailnet"
    ok "nodes will dial the control plane at ${hs_login} (TLS — required for the DERP relay)"

    # Tailnet nodes start LAST, after the address is settled — creating them in the same `up` that may
    # relocate headscale produces nodes dialing a dead address. An exited broker is removed first:
    # `compose up` never restarts it, so it keeps reporting a failure already fixed.
    ${RUNTIME} rm -f ir-dmz_broker_1 >/dev/null 2>&1 || true
    dc dmz up -d --build bastion broker distributor >/dev/null 2>&1
    # Probed over TLS against the certificate collectors pin: a plain-HTTP probe on a TLS socket reads
    # as 'the receiver never came up', and verifying also catches a chain the receiver cannot present.
    wait_for ir-dmz_receiver_1 90 \
        ${RUNTIME} exec ir-dmz_receiver_1 python3 -c \
        "import ssl,urllib.request as u
c=ssl.create_default_context(cafile='/certs/receiver.crt')
u.urlopen('https://localhost:8090/healthz',timeout=4,context=c)" \
        || die "evidence receiver never came up"
    for c in ir-dmz_coredns_1 ir-dmz_headscale_1 ir-dmz_bastion_1; do
        wait_for "$c" 45 true || warn "$c slow to start"
    done
    # The broker and distributor are only sound in the bastion's CURRENT namespace — a sharer left in
    # a dead one reports Up with a bound listener and routes nothing. Same class as sidecar orphans:
    # compare namespace inodes, recreate mismatched sharers.
    local ns_bastion ns_share svc
    ns_bastion="$(netns_of ir-dmz_bastion_1)"
    for c in ir-dmz_broker_1 ir-dmz_distributor_1; do
        ns_share="$(netns_of "${c}")"
        svc="${c#ir-dmz_}"; svc="${svc%_1}"
        if [[ -n "${ns_bastion}" && -n "${ns_share}" && "${ns_share}" != "${ns_bastion}" ]]; then
            warn "${svc} is orphaned in the bastion's previous namespace — recreating it"
            ${RUNTIME} rm -f "${c}" >/dev/null 2>&1 || true
            dc dmz up -d "${svc}" >/dev/null 2>&1
        fi
    done

    # The broker is checked by ESTABLISHED SESSIONS in the bastion's namespace, not by its container
    # being up — its failure mode is starting, logging, and forwarding nothing. Sessions first, THEN
    # the port: the distributor binds its port whether or not anything is behind it.
    local want_sessions="${BROKER_SESSIONS:-8}" base="${BROKER_SESSION_BASE:-18443}"
    wait_for ir-dmz_broker_1 120 \
        ${RUNTIME} exec ir-dmz_bastion_1 sh -c \
        "n=0; p=${base}; last=\$((${base} + ${want_sessions} - 1))
         while [ \"\$p\" -le \"\$last\" ]; do
             awk -v h=\":\$(printf '%04X' \"\$p\")\$\" '\$4==\"0A\" && \$2 ~ h {f=1} END{exit !f}' \
                 /proc/net/tcp /proc/net/tcp6 2>/dev/null && n=\$((n+1))
             p=\$((p+1))
         done; [ \"\$n\" -eq ${want_sessions} ]" \
        || die "fewer than ${want_sessions} brokered sessions came up — the fleet has no path, or an incomplete one"
    if [[ "$(${RUNTIME} logs ir-dmz_broker_1 2>&1 | grep -c 'authenticated as')" -gt 0 ]]; then
        ok "${want_sessions} independent Boundary sessions authenticated on ${base}-$((base + want_sessions - 1))"
    else
        warn "the sessions are listening but the broker has not reported authenticating"
    fi
    wait_for ir-dmz_distributor_1 60 \
        ${RUNTIME} exec ir-dmz_bastion_1 sh -c \
        "netstat -ltn 2>/dev/null | grep -q ':${BROKER_LISTEN}' || ss -ltn 2>/dev/null | grep -q ':${BROKER_LISTEN}'" \
        || die "no listener on ${BROKER_LISTEN} — analysts have no path to the platform"
    ok "connection distributor on ${BROKER_LISTEN} — the fleet is spread across ${want_sessions} sessions"
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

# Where an analyst's exports land on the HOST, resolved per platform so one plain compose variable
# serves Linux/macOS/WSL/Git-Bash. The directory is CREATED here — a missing bind-mount source
# becomes a root-owned directory the browser cannot write, surfacing as silently failing
# downloads.
resolve_export_dir() {
    if [[ -n "${IR_EXPORT_DIR:-}" ]]; then
        export IR_EXPORT_DIR; return 0
    fi
    local base=""
    case "$(uname -s)" in
        Linux)
            if grep -qi microsoft /proc/version 2>/dev/null && command -v wslpath >/dev/null 2>&1; then
                local winhome
                winhome="$(wslpath -u "$(cmd.exe /c 'echo %USERPROFILE%' 2>/dev/null | tr -d '\r')" 2>/dev/null || true)"
                [[ -d "${winhome}" ]] && base="${winhome}/Downloads"
            fi
            [[ -z "${base}" ]] && base="$(xdg-user-dir DOWNLOAD 2>/dev/null || true)"
            [[ -z "${base}" || ! -d "${base}" ]] && base="${HOME}/Downloads"
            ;;
        Darwin)  base="${HOME}/Downloads" ;;
        MINGW*|MSYS*|CYGWIN*)
            base="${USERPROFILE:-${HOME}}/Downloads"
            base="${base//\\//}"          # backslashes are not path separators to the runtime
            ;;
        *)       base="${HOME}/Downloads" ;;
    esac
    IR_EXPORT_DIR="${base}/ir-platform"
    export IR_EXPORT_DIR
    mkdir -p "${IR_EXPORT_DIR}" 2>/dev/null \
        || die "cannot create the export directory ${IR_EXPORT_DIR} — set IR_EXPORT_DIR to a writable path"
}

up_workstation() {
    local wsid="${IR_WS_ID:-analyst}" wsproj tn br
    wsproj="$(proj workstation)"; tn="${wsproj}_tailnet_1"; br="${wsproj}_browser_1"
    say "Workstation · analyst browser (${wsid})"
    # Its own key, and the deploy refuses to start a node that has none: without one the
    # daemon comes up, fails to authenticate and retries on a backoff, which reads as a broken
    # kiosk rather than a workstation that was never issued a credential.
    TS_WS_AUTHKEY="$(ws_authkey)"; export TS_WS_AUTHKEY IR_WS_ID
    if [[ -z "${TS_WS_AUTHKEY}" ]]; then
        warn "no pre-auth key for workstation '${wsid}' — it will not join the tailnet"
        warn "  add '${wsid}' to IR_WS_IDS in deploy/.env, then run deploy.sh dmz to mint one"
    fi
    resolve_export_dir
    [[ -w "${IR_EXPORT_DIR}" ]] \
        && ok "exports land on this host at ${IR_EXPORT_DIR}" \
        || die "the export directory is not writable: ${IR_EXPORT_DIR}"
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
    # The kiosk authenticates to the display with the operator's cookie rather than the
    # deployment running `xhost +local:`, which disabled access control for EVERY local
    # process for the life of the login session and was never revoked. The RE session — a
    # container holding live malware — shares this display.
    IR_XAUTHORITY="${XAUTHORITY:-${HOME}/.Xauthority}"
    if [[ -r "${IR_XAUTHORITY}" ]]; then
        export IR_XAUTHORITY
        ok "kiosk authenticates to the display with the operator's X cookie"
    else
        export IR_XAUTHORITY=/dev/null
        warn "no readable X cookie at ${IR_XAUTHORITY} — the kiosk window may not open."
        warn "  Export XAUTHORITY, or run from a desktop session that has one."
    fi

    # The tailnet node comes up first and alone: the browser shares its namespace and must not start
    # into one with no route. A node left from a failed join retries on a backoff that outlives the
    # check, so the PAIR is recreated — browser first, since removing the owner before the sharer
    # wedges the runtime.
    if ${RUNTIME} inspect "${tn}" >/dev/null 2>&1 && \
       ! { ts_out="$(${RUNTIME} exec "${tn}" tailscale ip -4 2>/dev/null || true)"
            case "${ts_out}" in 100.*) true ;; *) false ;; esac; }; then
        warn "tailnet node is up but unenrolled — recreating it to read the current pre-auth key"
        ${RUNTIME} rm -f "${br}" >/dev/null 2>&1
        ${RUNTIME} rm -f "${tn}" >/dev/null 2>&1
    fi
    dc workstation up -d --build tailnet >/dev/null 2>&1
    wait_for "${tn}" 60 true || warn "tailnet node did not start"
    local ts_ip="" waited_ts=0
    ts_ip="$(wait_tailnet_ip "${tn}" 90)"
    if [[ -n "${ts_ip}" ]]; then
        ok "${wsid} joined the tailnet at ${ts_ip} (traffic leaves over WireGuard)"
    else
        warn "${wsid} has NOT joined the tailnet — the browser will have no route to the platform"
        warn "re-run 'deploy.sh dmz' to re-issue a pre-auth key, then this tier again"
    fi

    # The kiosk is a LOCALLY BUILT image, so it carries the same hazard the enclave's app
    # tier does: compose will not recreate a container that is already running, and
    # `up --build` then builds the new image and leaves the old one serving. A kiosk change
    # that never reaches the workstation reads as a deploy that worked.
    #
    # Built BEFORE staleness is judged. Checking first compares the container against the image
    # it was started from, so the first workstation of a run never looks stale and keeps the old
    # script, while later ones — built by then — are replaced correctly.
    dc workstation build browser >/dev/null 2>&1 \
        || warn "could not build the kiosk image — the workstation may run the previous script"
    recreate_if_stale workstation browser
    dc workstation up -d >/dev/null 2>&1
    wait_for "${br}" 90 true || warn "browser did not start (is DISPLAY set?)"
    # The diagnostics probe shares the tailnet node's namespace, and this function may have
    # just replaced that node. A probe left attached to the dead namespace still LOOKS running
    # and reaches nothing — it is the same hazard mesh_orphan_check repairs for the sidecars,
    # on the container a UAT starts rather than one the deploy owns. Removed rather than
    # recreated: it belongs to the diagnostics profile and its caller creates it on demand.
    local probe="${wsproj}_probe_1" ns_tn ns_pr
    if ${RUNTIME} inspect "${probe}" >/dev/null 2>&1; then
        ns_tn="$(netns_of "${tn}")"; ns_pr="$(netns_of "${probe}")"
        if [[ -n "${ns_tn}" && "${ns_pr}" != "${ns_tn}" ]]; then
            ${RUNTIME} rm -f "${probe}" >/dev/null 2>&1 \
                && ok "removed the ${wsid} diagnostics probe stranded by the tailnet recreate"
        fi
    fi
    render_ws_map
    ok "workstation ${wsid} up"
}

# Every workstation this deployment DECLARES, not just the default one. `IR_WS_IDS` is the
# statement of how many there are: the distributor renders a pin for each and the enclave derives
# its session pairing from the same variable, so bringing up one of two leaves the platform
# pinning traffic for a workstation that does not exist.
up_workstations_declared() {
    local id
    for id in ${IR_WS_IDS:-analyst}; do
        IR_WS_ID="${id}"; export IR_WS_ID
        up_workstation
    done
}

# The distributor's workstation-pinning map, `<ws-id> <tailnet-addr>` in IR_WS_IDS order — the
# ordinal chooses the session and the enclave derives the same pairing from the same variable.
# Rendered to a FILE from headscale's own record; the watcher reloads gracefully, draining rather
# than dropping.
render_ws_map() {
    local map="${HERE}/dmz/rendered/ws-map" hs="ir-dmz_headscale_1" nodes rendered
    ${RUNTIME} inspect "${hs}" >/dev/null 2>&1 || return 0
    nodes="$(${RUNTIME} exec "${hs}" headscale nodes list -o json 2>/dev/null || echo '[]')"
    rendered="$(python3 - "${map}" "${IR_WS_IDS:-analyst}" <<'PYEOF' "${nodes}"
import json, sys
map_path, ws_ids, raw = sys.argv[1], sys.argv[2].split(), sys.argv[3]
try:
    nodes = json.loads(raw)
except ValueError:
    nodes = []
addr = {}
for n in nodes:
    name = n.get("given_name") or n.get("name") or ""
    ips = [ip for ip in (n.get("ip_addresses") or []) if "." in ip]
    if name and ips:
        addr[name] = ips[0]
# Every configured workstation keeps its line, "-" when unregistered: the ordinal IS
# the session assignment, and it must match the enclave's IR_WS_IDS-derived pairing.
lines = [f"{ws} {addr.get(ws, '-')}" for ws in ws_ids]
with open(map_path, "w") as f:
    f.write("\n".join(lines) + ("\n" if lines else ""))
print(f"{len(lines)}/{len(ws_ids)}")
PYEOF
)" || { warn "workstation pinning map not rendered"; return 0; }
    ok "workstation pinning map rendered (${rendered} workstations mapped to sessions)"
}

# Gate: the whole SSO chain must answer before the analyst browser is started, so the
# kiosk never opens against a half-ready gate (which shows as 502/403 in the browser).
up_agent() {
    say "Remediation agent — the executor for admin-requested repairs"
    # Its own compose project: the mesh-reattach repair runs `deploy.sh enclave`, which could recreate
    # an executor living inside that project mid-repair. The rootless runtime socket is the agent's
    # whole authority and is enabled HERE — host configuration belongs to the deploy script.
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
        # `deploy.sh workstation <id>` names this workstation. Everything downstream —
        # compose project, container names, state volume, tailnet node name, pre-auth key —
        # derives from it, so a second workstation is a second identity rather than a
        # collision with the first.
        if [[ "${TIER}" == "workstation" && -n "${2:-}" ]]; then
            IR_WS_ID="$2"; export IR_WS_ID
        fi
        bash "${HERE}/../traefik/gen-cert.sh" >/dev/null 2>&1 || true
        # Before anything is created: this deployment recreates containers, and a lock pool
        # already exhausted by previous recreates fails every one of them.
        prune_anonymous_volumes
        compose_drift_check "${TIER}"
        ensure_build_images; ensure_networks
        # Named id brings up that one; without one, every workstation IR_WS_IDS declares.
        if [[ "${TIER}" == "workstation" && -z "${2:-}" ]]; then up_workstations_declared
        else "up_${TIER}"; fi
        compose_record_applied "${TIER}" ;;
    all)
        bash "${HERE}/../traefik/gen-cert.sh" >/dev/null 2>&1 || true
        prune_anonymous_volumes
        ensure_build_images
        ensure_networks
        # Enclave first: it holds the Boundary controller, and the DMZ's session client cannot
        # open the analyst path without the target the controller provisions. The puller polls
        # the DMZ receiver on a retry loop, so it tolerates the DMZ arriving second.
        for t in enclave dmz agent workstation; do compose_drift_check "$t"; done
        up_enclave; up_dmz
        # After the enclave: the agent polls through the backend, and starting it earlier
        # would just have it waiting. Before the workstation, so repairs are available the
        # moment an admin can sign in.
        up_agent
        verify_sso || warn "continuing, but the browser may show an SSO error"
        seed_evidence
        up_workstations_declared
        for t in enclave dmz agent workstation; do compose_record_applied "$t"; done ;;
    mesh)
        # Reattach any sidecar that lost its service's namespace without a full bring-up — the repair
        # alone, which is also what a test calls after restarting a service deliberately.
        mesh_orphan_check db minio redis vault backend worker frontend puller \
                          oauth2-proxy log-shipper keycloak
        ok "mesh proxies reconciled with their services" ;;
    rotate) shift; rotate_secrets "$@" ;;
    status) status ;;
    down)
        # Teardown reports compose's actual result — success over a parse failure leaves every container
        # running. VOLUMES ARE KEPT unless --purge: they hold evidence, and discarding state is something
        # the operator must ask for.
        PURGE=0
        for arg in "$@"; do [[ "${arg}" == "--purge" ]] && PURGE=1; done
        vol_flag=()
        if (( PURGE )); then
            vol_flag=(-v)
            warn "--purge: deleting volumes — ALL ingested evidence, captures and analyses"
        fi
        # Namespace-sharing containers come down FIRST across every tier being torn down: removing the
        # service while a sharer holds its netns deadlocks podman with the storage lock held. Scoped to
        # the tiers asked for — a teardown must not reach into a tier it was not given.
        for t in agent workstation enclave dmz; do
            [[ "${2:-all}" == "all" || "${2:-}" == "$t" ]] || continue
            for c in $(${RUNTIME} ps -a --format '{{.Names}}' 2>/dev/null \
                       | grep -E "^$(proj "$t")_(.*-sidecar_|broker_)" || true); do
                ${RUNTIME} rm -f "${c}" >/dev/null 2>&1 || true
            done
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
        # After the containers are gone, so the volumes their recreates left behind are
        # unused and removable.
        prune_anonymous_volumes
        # The verdict is drawn from the runtime and SCOPED TO THE TIERS ASKED FOR: counting every ir-
        # container fails a single-tier teardown for other tiers being up, and a teardown that fails when
        # it succeeded trains everyone to ignore it.
        if [[ "${2:-all}" == "all" ]]; then
            scope='^ir-'
        else
            scope="^$(proj "${2}")_"
        fi
        left="$(${RUNTIME} ps --format '{{.Names}}' 2>/dev/null | grep -c "${scope}" || true)"
        if [[ "${left:-0}" -gt 0 ]]; then
            warn "${left} ${2:-all} container(s) still running — NOT fully torn down"
            ${RUNTIME} ps --format '  {{.Names}}' | grep "  ${scope#^}"
            exit 1
        fi
        echo "torn down" ;;
    *) sed -n '3,14p' "$0"; exit 2 ;;
esac
