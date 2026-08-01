#!/usr/bin/env bash
# ==============================================================================
# IR Platform — end-to-end data-flow diagnostics.
#
# Walks the evidence path hop by hop and reports, at each stage, whether it is
# healthy or exactly what is wrong. Read-only: it inspects and probes, it never
# changes state. Use it when a UAT fails, when evidence "disappears", or after a
# deploy to confirm the whole chain is live.
#
#   collector → (brokered) → DMZ receiver → [pull] → enclave ingest
#            → object store (MinIO) → PostgreSQL → analysis worker → web app
#
# Usage:
#   troubleshooting/diagnose.sh                 # auto-detect running projects
#   troubleshooting/diagnose.sh -p irdmz        # a specific compose project
#   troubleshooting/diagnose.sh --flow          # data-flow trace only
#   troubleshooting/diagnose.sh --net           # segmentation checks only
#   troubleshooting/diagnose.sh --silent        # silent-failure checks only
# ==============================================================================
set -uo pipefail

RUNTIME="${IR_RUNTIME:-podman}"
PLATFORM_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# The deployment's own configuration, so checks read the values in use rather than defaults.
set -a; . "${PLATFORM_ROOT}/deploy/.env" 2>/dev/null || true; set +a
PROJECT=""
MODE=all
ISSUES=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        -p|--project) PROJECT="$2"; shift 2 ;;
        --flow) MODE=flow; shift ;;
        --net)  MODE=net; shift ;;
        --silent) MODE=silent; shift ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

hdr()  { printf '\n\033[1;36m━━ %s\033[0m\n' "$*"; }
good() { printf '  \033[1;32m✔\033[0m %s\n' "$*"; }
warn() { printf '  \033[1;33m!\033[0m %s\n' "$*"; }
fail() { printf '  \033[1;31m✘\033[0m %s\n' "$*"; ISSUES=$((ISSUES+1)); }
note() { printf '    \033[0;37m%s\033[0m\n' "$*"; }

# --- helpers ---------------------------------------------------------------
have() { ${RUNTIME} inspect "$1" >/dev/null 2>&1; }
running() { [[ "$(${RUNTIME} inspect "$1" --format '{{.State.Status}}' 2>/dev/null)" == "running" ]]; }
cx() { ${RUNTIME} exec "$1" "${@:2}" 2>/dev/null; }
# python one-liner probe inside a container (works in images without curl)
probe() { cx "$1" python3 -c "import urllib.request as u,sys; u.urlopen('$2',timeout=${3:-5})" >/dev/null 2>&1 \
          || cx "$1" python -c "import urllib.request as u,sys; u.urlopen('$2',timeout=${3:-5})" >/dev/null 2>&1; }
tcp() { cx "$1" timeout "${4:-5}" sh -c "nc -z $2 $3" >/dev/null 2>&1; }
# The evidence path is TLS. Verified against the same pinned certificate the components use, so
# a probe that passes means what the puller does will also pass — skipping verification here
# would report a healthy path that the real client refuses.
probe_tls() {
    cx "$1" python3 -c "
import ssl, sys, urllib.request as u
ctx = ssl.create_default_context(cafile='${RECEIVER_CA_BUNDLE:-/certs/receiver.crt}')
u.urlopen('$2', timeout=${3:-8}, context=ctx)" >/dev/null 2>&1
}

detect_projects() {
    ${RUNTIME} ps --format '{{.Names}}' 2>/dev/null \
        | sed -n 's/^\(ir[a-z-]*\)_.*/\1/p' | sort -u
}

# --- 0. what is running ----------------------------------------------------
hdr "Running compose projects"
PROJECTS="${PROJECT:-$(detect_projects)}"
if [[ -z "$PROJECTS" ]]; then
    fail "no IR platform containers are running"
    note "start a stack first: deploy/deploy.sh enclave (then dmz, workstation, agent)"
    exit 1
fi
for p in $PROJECTS; do
    n=$(${RUNTIME} ps --format '{{.Names}}' | grep -c "^${p}_" || true)
    good "${p}: ${n} container(s) up"
done

for P in $PROJECTS; do
hdr "Project: ${P} — container health"
UNHEALTHY=0
while read -r name; do
    [[ -z "$name" ]] && continue
    st=$(${RUNTIME} inspect "$name" --format '{{.State.Status}}' 2>/dev/null)
    if [[ "$st" == "running" ]]; then
        good "$name ($st)"
    else
        ec=$(${RUNTIME} inspect "$name" --format '{{.State.ExitCode}}' 2>/dev/null)
        fail "$name is $st (exit=$ec)"
        note "last log: $(${RUNTIME} logs --tail 3 "$name" 2>&1 | tr '\n' ' ' | cut -c1-160)"
        UNHEALTHY=$((UNHEALTHY+1))
    fi
done < <(${RUNTIME} ps -a --format '{{.Names}}' | grep "^${P}_" || true)
[[ $UNHEALTHY -eq 0 ]] && good "all containers running"

# --- data-flow trace -------------------------------------------------------
if [[ "$MODE" == all || "$MODE" == flow ]]; then
hdr "Project: ${P} — data-flow trace"

# Stage 1: DMZ receiver reachable + holding state
if have "${P}_receiver_1"; then
    if probe_tls "${P}_receiver_1" "https://localhost:8090/healthz"; then
        H=$(cx "${P}_receiver_1" python3 -c "import ssl,urllib.request as u,json; print(json.load(u.urlopen('https://localhost:8090/healthz',timeout=5,context=ssl.create_default_context(cafile='/certs/receiver.crt'))))")
        good "DMZ receiver healthy — ${H}"
        HELD=$(printf '%s' "$H" | sed -n "s/.*'held': \([0-9]*\).*/\1/p")
        [[ "${HELD:-0}" -gt 0 ]] && warn "${HELD} bundle(s) still held — is the puller running/able to fetch?"
    else
        fail "DMZ receiver not answering on :8090"
    fi
fi

# Stage 2: puller can reach the receiver AND the enclave (it is the only bridge)
if have "${P}_puller_1"; then
    if running "${P}_puller_1"; then good "puller is running"; else fail "puller is NOT running (evidence will pile up in the DMZ)"; fi
    probe_tls "${P}_puller_1" "${RECEIVER_URL:-https://receiver:8090}/pending" \
        && good "puller → DMZ receiver: reachable (outbound pull path OK)" \
        || fail "puller cannot reach the DMZ receiver — evidence cannot be pulled in"
    probe "${P}_puller_1" "http://backend:8000/api/health/" \
        && good "puller → enclave API: reachable" \
        || fail "puller cannot reach the enclave API — ingest will fail"
fi

# Stage 3: enclave API health
API_C=""
for cand in "${P}_backend_1"; do have "$cand" && API_C="$cand"; done
if [[ -n "$API_C" ]]; then
    if probe "$API_C" "http://127.0.0.1:8000/api/health/"; then
        good "enclave API healthy"
    else
        fail "enclave API not healthy"
        note "$(${RUNTIME} logs --tail 5 "$API_C" 2>&1 | tr '\n' ' ' | cut -c1-200)"
    fi
    # DB identity (surfaces Vault dynamic-cred problems immediately)
    IDENT=$(cx "$API_C" sh -c '. /vault/secrets/app.env 2>/dev/null; python manage.py shell -c "
from django.db import connection
c=connection.cursor(); c.execute(\"select session_user||chr(124)||current_user\"); print(c.fetchone()[0])" 2>/dev/null' | grep '|')
    if [[ -n "$IDENT" ]]; then
        good "database identity: login=${IDENT%%|*} acting-as=${IDENT##*|}"
        [[ "${IDENT%%|*}" == v-* ]] && note "using Vault dynamic credentials"
    else
        warn "could not determine the database identity (is the DB reachable?)"
    fi
fi

# Stage 4: object store
if have "${P}_minio_1"; then
    if [[ -n "$API_C" ]] && probe "$API_C" "http://minio:9000/minio/health/live"; then
        good "object store reachable from the enclave"
    else
        fail "object store NOT reachable from the enclave — captures cannot be stored/analyzed"
    fi
fi

# Stage 5: what actually landed (the end of the flow)
if [[ -n "$API_C" ]]; then
    TOK=$(${RUNTIME} inspect "$API_C" --format '{{range .Config.Env}}{{println .}}{{end}}' | sed -n 's/^IR_BROKER_TOKEN=//p' | head -1)
    if [[ -n "$TOK" ]]; then
        STATS=$(cx "$API_C" python -c "
import urllib.request as u, json
r=u.Request('http://127.0.0.1:8000/api/stats/',headers={'Authorization':'Token ${TOK}'})
print(json.dumps(json.load(u.urlopen(r,timeout=8))))" 2>/dev/null)
        if [[ -n "$STATS" ]]; then
            good "platform data: $(printf '%s' "$STATS" | cut -c1-180)"
            RUNS=$(printf '%s' "$STATS" | sed -n 's/.*"runs": *\([0-9]*\).*/\1/p')
            CAPS=$(printf '%s' "$STATS" | sed -n 's/.*"captures": *\([0-9]*\).*/\1/p')
            [[ "${RUNS:-0}" == "0" ]] && warn "no collection runs ingested yet — the flow has not completed end to end"
            [[ "${RUNS:-0}" != "0" && "${CAPS:-0}" == "0" ]] && warn "runs present but no captures — check the object-store upload step"
        else
            warn "could not read /api/stats (token/auth issue?)"
        fi
    fi
fi

# Stage 6: analysis worker
if have "${P}_worker_1"; then
    running "${P}_worker_1" && good "analysis worker running" || fail "analysis worker not running — captures will never be analyzed"
fi
fi

# --- segmentation checks ---------------------------------------------------
if [[ "$MODE" == all || "$MODE" == net ]]; then
hdr "Project: ${P} — segmentation (these MUST fail to connect)"

check_blocked() {  # container host port label
    if tcp "$1" "$2" "$3"; then
        fail "$4 — reachable, but the design requires NO route"
    else
        good "$4 — blocked (correct)"
    fi
}
have "${P}_endpoint_1"    && { check_blocked "${P}_endpoint_1" backend 8000 "endpoint → enclave API"
                               check_blocked "${P}_endpoint_1" minio 9000 "endpoint → object store"; }
have "${P}_receiver_1"    && { check_blocked "${P}_receiver_1" backend 8000 "DMZ receiver → enclave API"
                               check_blocked "${P}_receiver_1" minio 9000 "DMZ receiver → object store"; }
have "${P}_workstation_1" && { check_blocked "${P}_workstation_1" backend 8000 "workstation → enclave API"
                               check_blocked "${P}_workstation_1" db 5432 "workstation → database"; }
have "${P}_worker_1"      && { check_blocked "${P}_worker_1" 1.1.1.1 443 "analysis sandbox → internet (C2 egress)"; }
fi
done


# --- known silent-failure modes --------------------------------------------
# Everything above traces the data path. This section covers the OTHER class of fault, the one
# that costs the most time: a component that reports success while doing nothing. None of these
# is visible in a container's status, and none is findable by reading code — the code is right
# and only the running system disagrees.
if [[ "$MODE" == all || "$MODE" == silent ]]; then
hdr "Silent failures — components that look healthy but are not"

# A build whose context is wrong FAILS, the deployment swallows the error, and the previous
# image keeps serving. Every later code change then appears to deploy while none of them do.
python3 - "${PLATFORM_ROOT}" <<'PYEOF'
import os, re, sys, yaml
root = sys.argv[1]; bad = 0
for tier in ("enclave", "dmz", "workstation"):
    f = os.path.join(root, "deploy", tier, "docker-compose.yml")
    if not os.path.exists(f): continue
    for name, svc in (yaml.safe_load(open(f)).get("services") or {}).items():
        b = svc.get("build")
        if b is None: continue
        base = os.path.dirname(f)
        if isinstance(b, str):
            ctx = os.path.normpath(os.path.join(base, b)); df = os.path.join(ctx, "Dockerfile")
        else:
            ctx = os.path.normpath(os.path.join(base, b["context"]))
            df = os.path.normpath(os.path.join(ctx, b.get("dockerfile", "Dockerfile")))
        if not os.path.exists(df):
            print(f"  \033[1;31m\u2718\033[0m {tier}/{name}: dockerfile missing ({df})"); bad += 1; continue
        missing = [m.group(1) for line in open(df)
                   if (m := re.match(r"\s*COPY\s+(?:--\S+\s+)*(\S+)\s", line))
                   and "--from" not in line
                   and not os.path.exists(os.path.join(ctx, m.group(1)))]
        if missing:
            print(f"  \033[1;31m\u2718\033[0m {tier}/{name}: COPY {missing} not under context {ctx}")
            print(f"    \033[0;37mthis build FAILS and leaves the old image running\033[0m")
            bad += 1
sys.exit(1 if bad else 0)
PYEOF
if [[ $? -eq 0 ]]; then good "all compose build contexts are valid"; else ISSUES=$((ISSUES+1)); fi

# compose will not recreate a container that is already up, so a rebuilt image can sit unused
# while the deployment reports success.
for svc in backend worker frontend puller receiver broker; do
    c="${P}_${svc}_1"
    have "$c" || continue
    cur=$(${RUNTIME} image inspect "localhost/ir-${svc}:latest" --format '{{.Id}}' 2>/dev/null) || continue
    [[ -z "$cur" ]] && continue
    if [[ "$(${RUNTIME} inspect "$c" --format '{{.Image}}' 2>/dev/null)" == "$cur" ]]; then
        good "${svc} runs the current image"
    else
        fail "${svc} runs an OLD image — code changes are not live"
        note "redeploy this tier; the build succeeded but the container was never replaced"
    fi
done

# DNS as an exfiltration channel. The enclave network being internal hides a leak on the DMZ
# link, which is where the puller sits — the one container with a reason to talk outward.
for c in "${P}_puller_1" "${P}_worker_1" "${P}_backend_1"; do
    have "$c" || continue
    a=$(cx "$c" getent ahostsv4 example.com | awk 'NR==1{print $1}')
    [[ -z "$a" ]] && good "${c#${P}_} cannot resolve outside names" \
                  || { fail "${c#${P}_} RESOLVED example.com -> ${a}"
                       note "a network on this container's path is not internal; DNS can carry data out"; }
done

# The tailnet login server. Given a HOSTNAME, tailscale forces TLS and dials 443, discarding the
# configured port — the node exits without joining and the analyst browser simply has no route,
# with nothing in the browser to say why.
# What the NODES actually dial, which is written per bring-up and is not the value in .env.
HS_LOGIN=$(sed -n 's/^HEADSCALE_LOGIN_URL=//p' "${PLATFORM_ROOT}/deploy/.env.tailnet" 2>/dev/null | tail -1)
if [[ -z "${HS_LOGIN}" ]]; then
    fail "no HEADSCALE_LOGIN_URL — nodes start with an empty login server and never register"
elif [[ "${HS_LOGIN}" =~ ^http://[a-zA-Z] ]]; then
    fail "nodes dial a hostname over http (${HS_LOGIN})"
    note "tailscale forces TLS for hostnames and dials :443, discarding the port"
else
    good "nodes dial the control plane at ${HS_LOGIN}"
fi
for c in ir-dmz_bastion_1 ir-workstation_tailnet_1; do
    have "$c" || continue
    if ! running "$c"; then
        fail "$c is not running — the tunnel is absent"
        note "$(${RUNTIME} logs "$c" 2>&1 | grep -iE 'register request|failed to auth' | tail -1 | cut -c1-150)"
    elif [[ -z "$(cx "$c" tailscale ip -4 | tr -d '[:space:]')" ]]; then
        fail "$c is up but holds no tailnet address"
    else
        good "$c joined the tailnet"
    fi
done

# A broker that starts and carries nothing: every health check reads green while the analyst
# path is dead.
if have ir-dmz_bastion_1 && running ir-dmz_bastion_1; then
    cx ir-dmz_bastion_1 sh -c "netstat -ltn 2>/dev/null | grep -q ':8443' || ss -ltn 2>/dev/null | grep -q ':8443'" \
        && good "broker is listening on the brokered port" \
        || { fail "nothing listening on the brokered port inside the bastion"
             note "the broker is a Boundary session CLIENT and opens this listener only once it"
             note "holds a session, so an absent listener means an earlier step failed:"
             note "  podman logs ir-dmz_broker_1     names which one"
             note "authentication, the target id and worker registration are the usual three"; }
fi

# The links behind a session, checked where each one lives.
#
# `authorize-session` refuses with a bare 403 whichever link is missing, so the chain is walked
# rather than guessed at from the failure.
if have ir-enclave_boundary_1; then
    if running ir-enclave_boundary_1; then
        good "Boundary controller is running in the enclave"
        # A registered worker is what a session actually runs on. With none, the controller still
        # authorizes and the connection then hangs — a failure that looks like the far end.
        w="$(${RUNTIME} exec ir-enclave_boundary_1 sh /boundary/workers.sh 2>&1)" \
            && good "Boundary worker registered: $(printf '%s' "${w}" | tr '\n' ' ')" \
            || { fail "no Boundary worker registered"
                 note "sessions are authorized and then carry nothing; the analyst sees a hang"; }
        note "authorization chain:  podman exec ir-enclave_boundary_1 sh /boundary/authz.sh"
    else
        fail "Boundary controller is not running — there is no analyst path into the enclave"
    fi
fi
if have ir-enclave_boundary-egress_1; then
    running ir-enclave_boundary-egress_1 \
        && good "Boundary egress worker is running in the enclave" \
        || { fail "the Boundary egress worker is not running"
             note "it carries the session to the ingress; without it there is no data path"; }
fi

# Sign-out then sign-in dead-ending at 403.
if have "${P}_oauth2-proxy_1"; then
    n=$(${RUNTIME} logs "${P}_oauth2-proxy_1" 2>&1 | grep -c "CSRF cookie" || true)
    [[ "${n:-0}" -eq 0 ]] && good "no CSRF cookie failures" \
        || { fail "${n} CSRF cookie failure(s) — re-login dead-ends at 403"
             note "set --cookie-csrf-per-request=true; one fixed cookie breaks every retry"; }
fi

# Evidence volumes. Their absence means a purge happened and ingested evidence is gone.
for v in ir-enclave_pgdata ir-enclave_miniodata ir-dmz_receiver-holding; do
    ${RUNTIME} volume exists "$v" 2>/dev/null && good "volume ${v} present" \
        || fail "volume ${v} MISSING — ingested evidence was destroyed"
done

# A headless JDK cannot open a GUI at any DISPLAY setting, and reports "headless environment" —
# which reads as a broken X socket and sends you looking at the host instead of the image.
if ${RUNTIME} image exists ir-re-ghidra:latest 2>/dev/null; then
    ${RUNTIME} run --rm --entrypoint sh ir-re-ghidra:latest \
        -c 'ls "${JAVA_HOME}/lib/libawt_xawt.so"' >/dev/null 2>&1 \
        && good "ghidra image has a GUI-capable JDK" \
        || { fail "ghidra image has a HEADLESS JDK — its GUI cannot start"
             note "install openjdk-N-jdk, not -jdk-headless, then rebuild"; }
fi
fi

# --- summary ---------------------------------------------------------------
hdr "Summary"
if [[ $ISSUES -eq 0 ]]; then
    printf '  \033[1;32mNo issues found\033[0m — the data flow and segmentation look correct.\n'
else
    printf '  \033[1;31m%d issue(s) found\033[0m — see the ✘ lines above.\n' "$ISSUES"
fi
exit $(( ISSUES > 0 ? 1 : 0 ))
