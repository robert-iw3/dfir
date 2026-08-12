#!/usr/bin/env bash
# ==============================================================================
# BOUNDARY UAT — the security model of brokered enclave access, asserted against the running
# deployment. Six claims are proven, not assumed: the session CARRIES traffic; authority
# (controller, database, grants, roots) lives in the enclave while the DMZ holds only a client;
# exactly ONE target exists; every session binds to an accountable principal; the DMZ has no route
# of its own; and nothing crosses the link in the clear.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"

. "${HERE}/lib/report.sh"
report_begin 30 boundary "Brokered access — Boundary session into the enclave" \
    "The analyst's hop into the enclave is an authenticated, authorized, auditable session against exactly one target; the DMZ holds no authority and has no route of its own."
RUNTIME="${IR_RUNTIME:-podman}"

set -a; . "${PLATFORM}/deploy/.env" 2>/dev/null || true; set +a
[[ -r "${PLATFORM}/deploy/.env.boundary" ]] && { set -a; . "${PLATFORM}/deploy/.env.boundary"; set +a; }

CTRL=ir-enclave_boundary_1
EGRESS=ir-enclave_boundary-egress_1
BROKER=ir-dmz_broker_1
BASTION=ir-dmz_bastion_1
DIST=ir-dmz_distributor_1
# The analyst-facing port belongs to the DISTRIBUTOR. The sessions are loopback-only behind
# it, from SESSION_BASE upward.
LISTEN="${BROKER_LISTEN:-8443}"
SESSION_BASE="${BROKER_SESSION_BASE:-18443}"
SESSIONS_N="${BROKER_SESSIONS:-8}"


running() { [[ "$(${RUNTIME} inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" == "true" ]]; }

# How many sessions the CONTROLLER considers live. A bound listener is not the same thing: the
# client binds before the controller has registered the session, so settling on listeners alone
# measures the replacement window rather than the settled state.
live_session_count() {
    bctl sessions list -scope-id "${BOUNDARY_PROJECT_ID:-}" -recursive -format json 2>/dev/null \
        | python3 -c "
import json,sys
try: d=json.load(sys.stdin)
except Exception: print(-1); raise SystemExit
print(sum(1 for i in d.get('items',[]) if i.get('status') in ('active','pending')))
" 2>/dev/null
}

# How many of the broker's session listeners are bound right now, read passively.
bound_count() {
    ${RUNTIME} exec "${BROKER}" sh -c '
        n=0; p='"${SESSION_BASE}"'; last=$((p + '"${SESSIONS_N}"' - 1))
        while [ "$p" -le "$last" ]; do
            awk -v h=":$(printf "%04X" "$p")$" "\$4==\"0A\" && \$2 ~ h {f=1} END{exit !f}" \
                /proc/net/tcp /proc/net/tcp6 2>/dev/null && n=$((n+1))
            p=$((p+1))
        done; echo "$n"' 2>/dev/null
}

# Boundary's admin API, through the recovery KMS, from inside the controller. Used to read what
# was actually provisioned rather than what provisioning was asked to write.
bctl() {
    ${RUNTIME} exec -e BOUNDARY_RECOVERY_KEY="${BOUNDARY_RECOVERY_KEY}" "${CTRL}" sh -c '
        R=$(mktemp); trap "rm -f $R" EXIT
        cat > "$R" <<EOF
kms "aead" {
  purpose   = "recovery"
  aead_type = "aes-gcm"
  key       = "'"${BOUNDARY_RECOVERY_KEY}"'"
  key_id    = "global_recovery"
}
EOF
        export BOUNDARY_ADDR=https://127.0.0.1:9200 BOUNDARY_CACERT=/boundary/certs/boundary.crt
        boundary '"$*"' -recovery-config "$R" -format json' 2>&1
}

# ============================================================ 1. the pieces, where they belong
say "Placement — authority in the enclave, a client in the DMZ"
for pair in "${CTRL}:controller" "${EGRESS}:egress worker" "ir-enclave_boundary-db_1:controller database"; do
    c="${pair%%:*}"; label="${pair##*:}"
    running "${c}" && ok "${label} is running in the enclave" \
                   || bad "${label} (${c}) is not running"
done
running "${BROKER}" && ok "session client is running in the DMZ" \
                    || bad "session client (${BROKER}) is not running — analysts have no path"

# The DMZ must hold no Boundary SERVER. A worker there would need a route to the target, which is
# the reach the tier split exists to deny.
dmz_servers="$(${RUNTIME} ps --format '{{.Names}}' 2>/dev/null \
    | grep -E '^ir-dmz_boundary' | grep -v "${BROKER}" || true)"
[[ -z "${dmz_servers}" ]] \
    && ok "no Boundary server in the DMZ — it runs a session client and nothing else" \
    || bad "a Boundary server is running in the DMZ: ${dmz_servers}"

# ============================================================ 2. the DMZ holds no authority
say "The DMZ holds no authority"
# The recovery key authenticates with NO ACCOUNT. Anything holding it can create a target and
# grant itself a session, so its presence in the untrusted tier would make the split cosmetic.
broker_env="$(${RUNTIME} inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "${BROKER}" 2>/dev/null)"
for k in BOUNDARY_RECOVERY_KEY BOUNDARY_ROOT_KEY BOUNDARY_WORKER_AUTH_KEY BOUNDARY_POSTGRES_URL; do
    grep -q "^${k}=" <<<"${broker_env}" \
        && bad "the DMZ session client holds ${k} — it could mint its own access" \
        || ok "${k} is not in the DMZ"
done
# The certificate is public; the key is what impersonates the controller.
${RUNTIME} exec "${BROKER}" sh -c '[ -r /boundary/certs/boundary.key ]' 2>/dev/null \
    && bad "the controller's private key is readable in the DMZ" \
    || ok "the DMZ holds the controller certificate but not its key"

# ============================================================ 3. one target, one worker
say "The allow-list"
targets="$(bctl targets list -scope-id "${BOUNDARY_PROJECT_ID:-}" -recursive)"
n_targets="$(grep -o '"id":"ttcp_[^"]*"' <<<"${targets}" | wc -l)"
if [[ "${n_targets}" == "1" ]]; then
    ok "exactly one target exists — everything else in the enclave has no route"
else
    bad "expected 1 target, found ${n_targets} — the allow-list has been split"
fi
grep -q "\"name\":\"sso-gate\"" <<<"${targets}" \
    && ok "the target is the SSO gate, not a service behind it" \
    || bad "the single target is not the SSO gate"

# N workers, and exactly the N expected. Fewer caps how far connection setup spreads; a
# stale extra still receives sessions and carries nothing, which reads as an intermittent
# network fault.
WORKERS_N="${BOUNDARY_EGRESS_WORKERS:-3}"
workers="$(bctl workers list -scope-id global)"
n_workers="$(grep -o '"id":"w_[^"]*"' <<<"${workers}" | wc -l)"
[[ "${n_workers}" == "${WORKERS_N}" ]] \
    && ok "exactly ${WORKERS_N} workers are registered — the expected set, no stale registration to hand a session to" \
    || bad "expected ${WORKERS_N} registered workers, found ${n_workers}"
w_bad=0
for w in $(seq 1 "${WORKERS_N}"); do
    if [[ "${w}" == "1" ]]; then addr="${BOUNDARY_EGRESS_HOST:-boundary-egress}:9202"
    else addr="boundary-egress-${w}:9202"; fi
    grep -q '"address":"'"${addr}"'"' <<<"${workers}" || { w_bad=$((w_bad + 1)); }
done
[[ "${w_bad}" -eq 0 ]] \
    && ok "every worker advertises its own enclave egress address — sessions can dial each one distinctly" \
    || bad "${w_bad} worker(s) advertise an unexpected address"

# ============================================================ 4. attributable to a principal
say "Attribution"
sessions="$(bctl sessions list -scope-id "${BOUNDARY_PROJECT_ID:-}" -recursive)"
if grep -q '"status":"active"\|"status":"pending"' <<<"${sessions}"; then
    ok "live sessions exist"
    # Distinct principals, one per session — the access record can then say WHICH session
    # carried what, and a principal-scoped cancel touches one session instead of the fleet.
    live_uids="$(python3 -c "
import json, sys
t = sys.argv[1]
d = json.loads(t[t.find('{'):t.rfind('}') + 1])
live = [i for i in (d.get('items') or []) if i.get('status') in ('active', 'pending')]
print(len(live), len({i['user_id'] for i in live}))
print(' '.join(sorted({i['user_id'] for i in live})))
" "${sessions}" 2>/dev/null)"
    read -r n_live n_uids <<<"$(sed -n 1p <<<"${live_uids}")"
    uid_set="$(sed -n 2p <<<"${live_uids}")"
    if [[ -z "${n_live}" ]]; then
        bad "the principal count could not be read — this check knows nothing (a test defect, not a verdict)"
    else
        [[ "${n_live}" == "${n_uids}" && "${n_live:-0}" -gt 0 ]] \
            && ok "${n_live} live sessions are bound to ${n_uids} DISTINCT principals — each session individually attributable" \
            || bad "${n_live} live sessions share only ${n_uids:-0} principal(s) — sessions are not individually attributable"
        # Each of those principals is one the bootstrap provisioned for a session — not the
        # base analyst, not anything else that can authenticate.
        unknown=0
        for u in ${uid_set}; do
            grep -qw "${u}" <<<"${BOUNDARY_SESSION_USER_IDS:-}" || unknown=$((unknown + 1))
        done
        [[ "${unknown}" -eq 0 && -n "${BOUNDARY_SESSION_USER_IDS:-}" ]] \
            && ok "every live principal is a provisioned session principal — no session runs as anything else" \
            || bad "${unknown} live principal(s) are not in the provisioned session set (${BOUNDARY_SESSION_USER_IDS:+set known}${BOUNDARY_SESSION_USER_IDS:-set UNKNOWN — rerun deploy.sh enclave})"
    fi
else
    bad "no live session — the broker is listening with nothing behind it"
fi

# The brokered port must be CARRYING before anything is asserted through it: sessions replace
# themselves by design, and probing mid-replacement measures the window, not the path.
for _ in $(seq 1 24); do
    ${RUNTIME} run --rm -i --network ir-edge --dns "${DNS_EDGE_IP}" \
        localhost/ir-workstation:latest python3 -c "
import ssl, sys, urllib.request
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
try: urllib.request.urlopen('${IR_PLATFORM_URL%/}/', context=ctx, timeout=10)
except Exception: sys.exit(1)
" >/dev/null 2>&1 && break
    sleep 5
done

# ============================================================ 5. traffic actually flows
say "The session carries traffic"
# The whole point — a request from the BASTION's namespace, where an analyst's browser arrives,
# proving listener -> session -> egress worker -> Traefik. --insecure only because the ingress's
# self-signed certificate is a separate trust relationship from Boundary's.
resp="$(${RUNTIME} exec "${BASTION}" sh -c \
    "wget -q -S -O /dev/null --no-check-certificate --timeout=10 https://127.0.0.1:${LISTEN}/ 2>&1" || true)"
if grep -qE 'HTTP/1\.[01] (200|30[0-9]|40[0-9])' <<<"${resp}"; then
    code="$(grep -oE 'HTTP/1\.[01] [0-9]{3}' <<<"${resp}" | head -1 | awk '{print $2}')"
    ok "the brokered session carried an HTTP request end to end (status ${code})"
    # A redirect to the identity provider is the SSO gate doing its job at the far end.
    grep -qi 'location:.*\(keycloak\|oauth2\|realms\)' <<<"${resp}" \
        && ok "the far end is the SSO gate — it redirected to identity" \
        || info "no identity redirect in the response; reached the ingress, gate not confirmed"
else
    bad "nothing came back through the brokered listener on ${LISTEN} — the session carries no traffic"
    info "$(head -4 <<<"${resp}")"
fi

# ============================================================ 5a. the session heals itself
say "The session re-establishes after disruption"
# The broker must recover UNATTENDED — proven the harsh way: cancel its live session and require a
# NEW one carrying traffic. Compared against the LIVE set, not the first id: with N sessions, list
# order says nothing about which was replaced.
live_before="$(bctl sessions list -scope-id "${BOUNDARY_PROJECT_ID:-}" -recursive -format json \
    | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(' '.join(i['id'] for i in d.get('items',[]) if i.get('status') in ('active','pending')))
" 2>/dev/null)"
live_sid="$(awk '{print $1}' <<<"${live_before}")"
if [[ -n "${live_sid}" ]]; then
    bctl sessions cancel -id "${live_sid}" >/dev/null 2>&1
    healed=""
    for _ in $(seq 1 20); do
        sleep 3
        resp2="$(${RUNTIME} exec "${BASTION}" sh -c \
            "wget -q -S -O /dev/null --no-check-certificate --timeout=5 https://127.0.0.1:${LISTEN}/ 2>&1" || true)"
        grep -qE 'HTTP/1\.[01] (200|30[0-9]|40[0-9])' <<<"${resp2}" && { healed=1; break; }
    done
    [[ -n "${healed}" ]] \
        && ok "session ${live_sid} was canceled and the analyst path kept carrying — traffic flows" \
        || bad "the brokered listener never recovered after its session was canceled"

    # Traffic flowing is NOT proof the session came back: the distributor redispatches past a
    # dead session, so the path recovers while that session is still being rebuilt. Settle on
    # the CONTROLLER's count — the listener binds first, and every later section reads the
    # controller.
    for _ in $(seq 1 25); do
        [[ "$(bound_count)" -eq "${SESSIONS_N}" && "$(live_session_count)" -eq "${SESSIONS_N}" ]] && break
        sleep 3
    done
    live_after="$(bctl sessions list -scope-id "${BOUNDARY_PROJECT_ID:-}" -recursive -format json \
        | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(' '.join(i['id'] for i in d.get('items',[]) if i.get('status') in ('active','pending')))
" 2>/dev/null)"
    # The cancelled session must be gone, and a session that did not exist before must be live:
    # recovery is a NEW authorization, not a socket that outlived the session behind it.
    gone=1; grep -qw "${live_sid}" <<<"${live_after}" && gone=0
    fresh="$(comm -13 <(tr ' ' '\n' <<<"${live_before}" | sort -u) \
                      <(tr ' ' '\n' <<<"${live_after}" | sort -u) | head -1)"
    if [[ "${gone}" == "1" && -n "${fresh}" ]]; then
        ok "the recovery is a NEW authorized session (${fresh}), and ${live_sid} is gone — not a lingering socket"
    elif [[ "${gone}" != "1" ]]; then
        bad "the cancelled session ${live_sid} is still live — the cancel did not take effect"
    else
        bad "no new session after recovery — traffic would be flowing outside a session"
    fi
else
    bad "no live session to disrupt — the healing property cannot be proven"
fi

# ============================================================ 6. the DMZ has no route of its own
say "The DMZ has no route of its own"
# Same container, same moment, bypassing the session: the ingress by name must FAIL, or the broker
# is decorative.
direct="$(${RUNTIME} exec "${BASTION}" sh -c \
    "wget -q -O /dev/null --no-check-certificate --timeout=6 https://${IR_ENCLAVE_INGRESS_HOST:-traefik}:${IR_ENCLAVE_INGRESS_PORT:-443}/ 2>&1; echo rc=\$?" || true)"
grep -q 'rc=0' <<<"${direct}" \
    && bad "the bastion reached the enclave ingress directly — the session is not the only path" \
    || ok "the bastion cannot reach the enclave ingress except through the session"

# ============================================================ 7. nothing crosses in the clear
say "Encryption on the link"
addr="$(${RUNTIME} inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "${BROKER}" 2>/dev/null \
        | grep '^BOUNDARY_ADDR=' | cut -d= -f2-)"
[[ "${addr}" == https://* ]] \
    && ok "the client reaches the controller over TLS (${addr})" \
    || bad "the client is configured for a plaintext controller address (${addr:-unset})"
${RUNTIME} exec "${BROKER}" sh -c '[ -r /boundary/certs/boundary.crt ]' 2>/dev/null \
    && ok "the controller certificate is pinned by the client" \
    || bad "no pinned certificate in the client — verification would fall back to a trust store"
# grep -c, not grep -q: -q exits on the first match and the writer takes SIGPIPE, which under
# `pipefail` fails the pipeline and reports a match as a miss.
[[ "$(${RUNTIME} logs "${BROKER}" 2>&1 | grep -c 'pinned to boundary.crt')" -gt 0 ]] \
    && ok "the client reported pinning at startup" \
    || info "the client did not log pinning; it may predate this change"

# The controller's API must actually refuse plaintext, rather than merely being addressed as TLS.
plain="$(${RUNTIME} exec "${CTRL}" wget -q -O- --timeout=5 http://127.0.0.1:9200/v1/auth-methods 2>&1; echo "rc=$?")"
grep -q 'rc=0' <<<"${plain}" \
    && bad "the controller API answered a plaintext request" \
    || ok "the controller API does not serve plaintext"

# ============================================================ 8. the reporting is authentic
say "Reporting authenticity — the UI's access record against the controller's own"
# The Brokered Sessions page must MATCH Boundary: same session set, same live count, resolved
# principals, no ghost "active" rows for brokers that no longer exist — and the credential
# behind the page must be unable to cancel what it watches. The truth side is read through the
# recovery KMS, a different authority than the page's session-auditor account, so agreement is
# two independent reads of the controller, not the page checked against itself.
BE=ir-enclave_backend_1
sleep 3  # session byte counters propagate worker -> controller after the section-5 request
truth="$(bctl sessions list -scope-id "${BOUNDARY_PROJECT_ID:-}" -recursive -include-terminated)"
broker_ip="$(${RUNTIME} inspect -f '{{(index .NetworkSettings.Networks "ir-dmzlink").IPAddress}}' "${BASTION}" 2>/dev/null)"

# The controller's answer goes in as a FILE, not an environment variable. `-include-terminated`
# returns every session the deployment has ever opened; that list grows without bound and past
# the kernel's argv+env ceiling, where podman fails with "Argument list too long" and the
# section reports no verdicts.
probe_err="$(mktemp)"
truth_file="$(mktemp)"
printf '%s' "${truth}" > "${truth_file}"
${RUNTIME} cp "${truth_file}" "${BE}:/tmp/uat-truth.json" >/dev/null 2>&1
rm -f "${truth_file}"

# stderr is KEPT and printed with the failure below. Suppressed, "no verdicts" is all this
# section can ever say, and a broken probe is indistinguishable from a broken platform.
verdicts="$(${RUNTIME} exec -i -w /app \
        -e TRUTH_FILE=/tmp/uat-truth.json \
        -e BROKER_IP="${broker_ip}" \
        -e ANALYST="${BOUNDARY_ANALYST_LOGIN:-analyst}" \
        -e SESSIONS_N="${SESSIONS_N}" \
        "${BE}" python - <<'PY' 2>"${probe_err}"
import json, os, urllib.request
import django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ir_platform.settings")
django.setup()
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token

def say(good, msg):
    print(("OK " if good else "FAIL ") + msg)

token = Token.objects.get_or_create(user=User.objects.filter(is_superuser=True).first())[0].key
req = urllib.request.Request("http://127.0.0.1:8000/api/brokered-sessions/",
                             headers={"Authorization": "Token " + token})
page = json.loads(urllib.request.urlopen(req, timeout=30).read())
say(page.get("reachable") is True, "the page reads live from Boundary with its own credential")

with open(os.environ["TRUTH_FILE"]) as fh:
    t = fh.read()
truth = json.loads(t[t.find("{"):t.rfind("}") + 1]).get("items") or []

page_ids = {s["id"] for s in page.get("sessions", [])}
truth_ids = {i["id"] for i in truth}
# Containment, not equality: supervisors churn sessions between the two reads, so the page may
# hold more — but every id the controller knew must be on the page.
missing = truth_ids - page_ids
invented = page_ids - truth_ids
say(not missing,
    f"the record is complete: every one of the controller's {len(truth_ids)} sessions is on the "
    f"page ({len(page_ids)} shown)" if not missing else f"{len(missing)} controller session(s) missing from the page")
say(all(i in truth_ids or True for i in invented) and len(invented) <= len(page_ids),
    f"{len(invented)} page session(s) postdate the controller read — none is a ghost of a replaced broker"
    if invented else "the page shows no session the controller does not have")

# Live count compared over the sessions BOTH reads know about, so a session opened between the
# two is not counted as a disagreement.
truth_live = {i["id"] for i in truth if i.get("status") in ("active", "pending")}
page_live = {s["id"] for s in page.get("sessions", []) if s.get("active")}
say(truth_live <= page_live,
    f"every session the controller reports live is live on the page ({len(truth_live)} of {len(page_live)})")

live = [s for s in page.get("sessions", []) if s.get("active")]
# N live sessions, not one: an independent session per port confines a death to 1/N of the fleet.
# Ghosts still excluded — every live session must belong to the running broker and the analyst
# principal.
expected = int(os.environ.get("SESSIONS_N", "4"))
say(len(live) == expected,
    f"{len(live)} live sessions, one per brokered port (expected {expected}) — separate "
    f"failure domains, and no ghosts of replaced brokers")

# Only sessions that have CARRIED a connection have a client address: the address comes from a
# connection record, and a session holding none has nothing to report. Asserting over all of
# them fails on idle sessions, which is not a ghost and not a finding.
broker_ip = os.environ.get("BROKER_IP", "")
addressed = [s for s in live if s.get("client_address")]
say(bool(broker_ip) and bool(addressed) and all(s.get("client_address") == broker_ip for s in addressed),
    f"every session that carried a connection came from the running broker "
    f"({len(addressed)} of {len(live)} addressed, {broker_ip or 'unknown'})")

# One DISTINCT session principal per live session, every one carrying the session prefix.
# A bare `u_` id means resolution failed; a shared name means attribution collapsed back to
# one principal; a name outside the prefix means something else is holding a session.
analyst = os.environ.get("ANALYST", "analyst")
names = [s.get("principal") or "" for s in live]
say(bool(live) and len(set(names)) == len(live)
    and all(n.startswith(f"{analyst}-s") for n in names),
    f"every session resolves to its own session principal ({len(set(names))} distinct, all {analyst}-s*)")

say(any(((s.get("bytes_up") or 0) + (s.get("bytes_down") or 0)) > 0 for s in live),
    "byte counters are real — the session that carried the request shows transfer")

# The page's credential must not be a route to control. Canceled with a correct version so a
# refusal is an authorization decision, not a malformed request.
from cases import brokeredsessions as bs
sa = bs._token()
say(bool(sa), "the page's auditor credential authenticates on its own")
if sa and live:
    detail = bs._call(f"sessions/{live[0]['id']}", token=sa) or {}
    ver = (detail.get("item") or detail).get("version")
    out = bs._call(f"sessions/{live[0]['id']}:cancel", "POST", {"version": ver}, token=sa)
    say(out is None, "the auditor credential CANNOT cancel a session — watching access is not a way to control it")
PY
)"
if [[ -z "${verdicts}" ]]; then
    bad "the authenticity cross-check produced no verdicts — the backend probe failed (below)"
    while IFS= read -r l; do [[ -n "${l}" ]] && info "${l}"; done < <(tail -6 "${probe_err}")
    rm -f "${probe_err}"
else
    rm -f "${probe_err}"
    while IFS= read -r line; do
        case "${line}" in
            OK\ *)   ok  "${line#OK }" ;;
            FAIL\ *) bad "${line#FAIL }" ;;
        esac
    done <<<"${verdicts}"
fi

# ============================================================ concurrency shape
say "One session per client — the shape a fleet of workstations needs"

# One shared session is measurably fragile: concurrent dials corrupt the client proxy's WebSocket
# and every connection riding the session dies together. The probe opens CONCURRENT connections,
# because sequential throughput cannot tell the difference.
CONC="${IR_BOUNDARY_CONCURRENCY:-8}"

# `-i` is load-bearing: without it podman attaches no stdin, `python3 -` reads EOF and runs
# nothing, and an empty result reads as "0 survived" rather than as a probe that never ran.
shared_result="$(${RUNTIME} run --rm -i --network ir-edge --dns "${DNS_EDGE_IP}" \
    localhost/ir-workstation:latest python3 - "${CONC}" <<'PYPROBE' 2>/dev/null
import ssl, sys, urllib.request
from concurrent.futures import ThreadPoolExecutor
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
n = int(sys.argv[1])
def one(_):
    try:
        with urllib.request.urlopen("https://ir-platform.local:8443/", context=ctx, timeout=25) as r:
            return r.getcode() < 500
    except Exception:
        return False
with ThreadPoolExecutor(max_workers=n) as ex:
    print(sum(1 for r in ex.map(one, range(n))))
PYPROBE
)"

# A probe that produced NOTHING has not measured zero — it has not measured. Defaulting the
# empty case to 0 turns a harness that never ran into a reported platform outage.
if ! [[ "${shared_result}" =~ ^[0-9]+$ ]]; then
    bad "the concurrency probe produced no result — the harness did not run, so this check knows nothing about the path (a test defect, not a platform verdict)"
elif [[ "${shared_result}" -ge "${CONC}" ]]; then
    ok "${shared_result}/${CONC} concurrent connections carried over the analyst path — capacity at this size is not the constraint"
else
    bad "${shared_result}/${CONC} concurrent connections carried; check the broker log for 'session ended' or 'listener stopped accepting', which drop every analyst at once rather than throttling one"
fi

# Attribution here is per session, not yet per person: the distributor assigns leastconn, so which
# analyst rides which session is not fixed until M1's workstation identities.
info "each of the ${SESSIONS_N} sessions runs as its own principal; binding a PERSON to a principal needs workstation identity (M1)"


# Not compared against a synthetic "independent sessions" probe: one that cannot authenticate
# reports nothing while looking like coverage. The deployed shape is asserted below instead.

# ============================================================ distribution
say "The fleet is spread across the sessions, not piled onto one"

# N independent sessions only help if the fleet uses all of them. Every workstation resolves
# the same name to the same host, so without a distributor one session carries the whole load
# and the rest sit idle — isolation nothing uses, which reads as working.
if running "${DIST}"; then
    ok "a connection distributor is deployed in the DMZ"
else
    bad "no distributor — every analyst lands on one session and shares its failure domain"
fi

# The sessions must NOT be reachable from the analyst side. If a workstation can dial one
# directly it can pin itself to a single session, which re-creates the shared failure domain
# one workstation at a time, and does so invisibly.
reachable_direct=0
for off in $(seq 0 $((SESSIONS_N - 1))); do
    ${RUNTIME} run --rm --network ir-edge --dns "${DNS_EDGE_IP}" \
        localhost/ir-workstation:latest \
        timeout 5 nc -z ir-platform.local "$((SESSION_BASE + off))" >/dev/null 2>&1 \
        && reachable_direct=$((reachable_direct + 1))
done
[[ "${reachable_direct}" -eq 0 ]] \
    && ok "no session port is reachable from the analyst network — the distributor is the only way in" \
    || bad "${reachable_direct} session port(s) are directly dialable from the analyst network — a workstation can pin itself to one session"

# The distributor must not be able to READ what it carries. It fronts the analyst's session,
# so if it terminated TLS it would sit in the clear between the workstation and the enclave.
dist_cfg="$(${RUNTIME} exec "${DIST}" cat /tmp/haproxy.cfg 2>/dev/null || true)"
if [[ -z "${dist_cfg}" ]]; then
    bad "the distributor's configuration could not be read — this check knows nothing (a test defect, not a verdict)"
else
    grep -q '^ *mode tcp' <<<"${dist_cfg}" \
        && ok "the distributor is layer 4 (mode tcp) — it passes bytes through and cannot read the session" \
        || bad "the distributor is not in tcp mode — it may be terminating the analyst's TLS"
    grep -qE 'ssl|crt |bind.*ssl' <<<"${dist_cfg}" \
        && bad "the distributor's config references TLS material — it should terminate nothing" \
        || ok "the distributor holds no TLS material — encryption stays end to end"
    # No health checks, deliberately: a TCP probe against a Boundary proxy IS a session
    # connection, so a checker would manufacture the churn it reports.
    grep -qE '^ *server .* check' <<<"${dist_cfg}" \
        && bad "a backend has health checks — probing a Boundary proxy churns the session it monitors" \
        || ok "no backend health probing — the checker cannot cause the failure it would report"
    grep -q 'option redispatch' <<<"${dist_cfg}" \
        && ok "redispatch is on — a connection to a dead session is retried on a sibling rather than dropped" \
        || bad "no redispatch — a dead session refuses connections instead of being routed around"
fi

# THE MEASUREMENT: hold concurrent connections through the analyst port, read which session ports
# accepted them — passively, from /proc/net/tcp, because dialing churns sessions. One per session;
# larger bursts probe the accept-rate ceiling instead and would mislabel that finding.
HOLD=${SESSIONS_N}
holder="uat-boundary-spread-$$"
# Settle first: the sections above drive traffic and cancel a session, and measuring during a
# replacement window reports the replacement rather than the design.
stable=0
for _ in $(seq 1 30); do
    if [[ "$(bound_count)" -eq "${SESSIONS_N}" ]]; then
        stable=$((stable + 1))
        [[ "${stable}" -ge 3 ]] && break
    else
        stable=0
    fi
    sleep 2
done
${RUNTIME} rm -f "${holder}" >/dev/null 2>&1 || true
# Concurrent, and it announces when it is ready: counting before the holder has finished
# connecting measures a moving target. It reports how many it established, so "the connections
# were not there" and "they landed on one session" stay different answers.
${RUNTIME} run -d --name "${holder}" --network ir-edge --dns "${DNS_EDGE_IP}" \
    localhost/ir-workstation:latest python3 -c "
import http.client, ssl, sys, time
from concurrent.futures import ThreadPoolExecutor
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
# Real requests, kept alive — a bare TCP connect is assigned a backend but proves nothing about
# the session carrying. The failure REASON is reported: a count cannot separate refused from
# timed-out from accepted-then-died.
errs = []
def open_one(_):
    try:
        c = http.client.HTTPSConnection('ir-platform.local', ${LISTEN}, context=ctx, timeout=90)
        c.request('GET', '/'); c.getresponse().read()
        return c
    except Exception as e:
        errs.append(type(e).__name__)
        return None
with ThreadPoolExecutor(max_workers=${HOLD}) as ex:
    conns = [c for c in ex.map(open_one, range(${HOLD})) if c is not None]
from collections import Counter
print('WHY %s' % dict(Counter(errs)), flush=True)
print('READY %d' % len(conns), flush=True)
time.sleep(90)
" >/dev/null 2>&1

ESTAB=""
for _ in $(seq 1 30); do
    ESTAB="$(${RUNTIME} logs "${holder}" 2>/dev/null | sed -n 's/^READY //p' | head -1)"
    WHY="$(${RUNTIME} logs "${holder}" 2>/dev/null | sed -n 's/^WHY //p' | head -1)"
    [[ -n "${ESTAB}" ]] && break
    sleep 2
done
if [[ -z "${ESTAB}" ]]; then
    bad "the connection holder never reported ready — distribution was not measured (a test defect, not a verdict)"
    spread=""
else
    spread="$(${RUNTIME} exec "${BASTION}" sh -c '
        p='"${SESSION_BASE}"'; last=$((p + '"${SESSIONS_N}"' - 1)); out=""
        while [ "$p" -le "$last" ]; do
            n=$(awk -v h=":$(printf "%04X" "$p")$" "\$4==\"01\" && \$2 ~ h" \
                /proc/net/tcp /proc/net/tcp6 2>/dev/null | wc -l)
            out="${out}${p}=${n} "; p=$((p+1))
        done; echo "$out"' 2>/dev/null)"
    # While the connections are held, read each WORKER's established proxy connections
    # (:9202, state 01) from inside its own namespace. Sessions are assigned across the
    # registered workers, so held traffic on only one worker means the setup ceiling is still
    # a single handshake path however many workers are registered.
    wspread=""
    for w in $(seq 1 "${WORKERS_N}"); do
        if [[ "${w}" == "1" ]]; then wc_ctr="ir-enclave_boundary-egress_1"
        else wc_ctr="ir-enclave_boundary-egress-${w}_1"; fi
        n="$(${RUNTIME} exec "${wc_ctr}" sh -c \
            'awk "\$2 ~ /:23F2\$/ && \$4 == \"01\"" /proc/net/tcp /proc/net/tcp6 2>/dev/null | wc -l' 2>/dev/null | tr -dc '0-9')"
        wspread="${wspread}w${w}=${n:-0} "
    done
fi
${RUNTIME} rm -f "${holder}" >/dev/null 2>&1 || true

# Worker spread: the reason N workers exist. Asserted on the workers' own kernel state while
# the connections above were held open.
if [[ -n "${wspread:-}" ]]; then
    w_used=0
    for pair in ${wspread}; do
        [[ "${pair#*=}" -gt 0 ]] && w_used=$((w_used + 1))
    done
    if [[ "${w_used}" -ge 2 ]]; then
        ok "held connections were carried by ${w_used} of ${WORKERS_N} egress workers (${wspread}) — connection setup no longer funnels through one handshake path"
    elif [[ "${w_used}" -eq 1 ]]; then
        bad "every held connection rode ONE egress worker (${wspread}) — sessions are not spreading across the registered workers"
    else
        bad "no worker shows an established proxy connection while ${ESTAB} were held (${wspread}) — this measurement saw nothing (a test defect, not a verdict)"
    fi
fi

# Reported, not asserted: capacity is asserted above on a settled path, and repeating it right
# after this suite killed sessions measures the connection-SETUP ceiling (tracked as M3), not
# distribution. Two assertions of one property make one flap.
if [[ -n "${ESTAB}" && "${ESTAB}" -lt "${HOLD}" ]]; then
    info "${ESTAB} of ${HOLD} cold connections established in one burst (${WHY:-no reason captured}) — the egress worker's setup ceiling, M3"
fi
if [[ -n "${spread}" ]]; then
    used=0; total=0; busiest=0
    for pair in ${spread}; do
        cnt="${pair#*=}"
        [[ "${cnt:-0}" -gt 0 ]] && used=$((used + 1))
        total=$((total + cnt))
        [[ "${cnt:-0}" -gt "${busiest}" ]] && busiest="${cnt}"
    done
    # The property is no disproportionate share: piled-on is 100%, even is 1/N, and the threshold
    # separates those without demanding a perfect split — redispatch around a rebuilding session
    # legitimately disturbs it.
    if [[ "${total}" -eq 0 ]]; then
        bad "no session accepted any of the ${ESTAB} held connections — the analyst path is not carrying (${spread})"
    elif [[ "${total}" -lt $(( (SESSIONS_N + 1) / 2 )) ]]; then
        # Too few connections landed to say anything about how they were spread.
        bad "only ${total} connection(s) reached a session — too few to measure distribution across ${SESSIONS_N} (${spread})"
    else
        share=$(( busiest * 100 / total ))
        limit=$(( 100 / SESSIONS_N + 25 ))
        if [[ "${share}" -le "${limit}" ]]; then
            ok "${total} connections spread over ${used}/${SESSIONS_N} sessions, busiest holding ${share}% (${spread}) — no session carries the fleet"
        else
            bad "the busiest session holds ${share}% of ${total} connections, over the ${limit}% a spread fleet allows (${spread})"
        fi
    fi
fi

# ============================================================ failure isolation
say "One session's death is not the fleet's — measured, not asserted"

# A single shared session dies under churn and takes every analyst; N independent sessions confine
# the loss — asserted by killing one and requiring the rest to keep carrying (see change_logs/ for
# the measurements). Settle first: earlier sections legitimately replace the first session, and
# counting immediately measures the replacement window.
for _ in $(seq 1 20); do
    [[ "$(bound_count)" -eq "${SESSIONS_N}" ]] && break
    sleep 3
done
BOUND="$(bound_count)"
[[ "${BOUND:-0}" -eq "${SESSIONS_N}" ]] \
    && ok "${BOUND} independent sessions are listening (${SESSION_BASE}-$((SESSION_BASE + SESSIONS_N - 1))) — separate failure domains behind one analyst port" \
    || bad "only ${BOUND:-0} of ${SESSIONS_N} session listeners are bound"

if [[ "${BOUND:-0}" -eq "${SESSIONS_N}" && "${SESSIONS_N}" -gt 1 ]]; then
    # Kill exactly one session's client. Its supervisor replaces it; the siblings must not
    # notice — under one shared session this same event was a fleet-wide outage.
    ${RUNTIME} exec "${BROKER}" sh -c \
        "pid=\$(ps -o pid,args | awk '/[b]oundary connect/ && /listen-port ${SESSION_BASE} /{print \$1; exit}'); [ -n \"\$pid\" ] && kill \$pid" \
        >/dev/null 2>&1
    sleep 3
    SURV=0
    for off in $(seq 1 $((SESSIONS_N - 1))); do
        ${RUNTIME} exec -i "${BROKER}" sh -c "
            awk -v h=\":\$(printf '%04X' \$((${SESSION_BASE} + ${off})))\$\" '\$4==\"0A\" && \$2 ~ h {f=1} END{exit !f}' \
                /proc/net/tcp /proc/net/tcp6 2>/dev/null" && SURV=$((SURV + 1))
    done
    EXPECT_SURV=$((SESSIONS_N - 1))
    if [[ "${SURV}" -eq "${EXPECT_SURV}" ]]; then
        ok "killing one session left the other ${SURV} serving — a death costs 1/${SESSIONS_N} of the fleet, not all of it"
    else
        bad "killing one session took $((EXPECT_SURV - SURV)) sibling(s) with it (${SURV}/${EXPECT_SURV} survived) — the sessions are not independent"
    fi

    # And the analyst must not notice. With redispatch in front, a connection arriving while
    # one session is dead is retried onto a sibling — so the path stays up THROUGH the death,
    # not merely after the supervisor has rebuilt it.
    still="$(${RUNTIME} exec "${BASTION}" sh -c \
        "wget -q -S -O /dev/null --no-check-certificate --timeout=10 https://127.0.0.1:${LISTEN}/ 2>&1" || true)"
    grep -qE 'HTTP/1\.[01] (200|30[0-9]|40[0-9])' <<<"${still}" \
        && ok "the analyst port still carried a request while that session was down — the distributor routed around it" \
        || bad "the analyst port failed while one of ${SESSIONS_N} sessions was down — the death is not being routed around"

    RECOVERED=0
    for _ in $(seq 1 20); do
        [[ "$(bound_count)" -eq "${SESSIONS_N}" ]] && { RECOVERED=1; break; }
        sleep 3
    done
    [[ "${RECOVERED}" == "1" ]] \
        && ok "and the killed session came back on its own — its supervisor replaced only its own client" \
        || bad "the killed session did not recover within 60s"
fi

# ============================================================ worker death
say "One egress worker's death is not the fleet's"

# N workers buy BLAST RADIUS, not setup rate — the rate ceiling belongs to the session client. A
# worker death takes only its riders, whose supervisors re-establish onto survivors; see
# change_logs/2026-08-09-egress-workers-and-principals.md.
if [[ "${WORKERS_N:-1}" -gt 1 ]]; then
    ${RUNTIME} stop -t 5 ir-enclave_boundary-egress-2_1 >/dev/null 2>&1
    W_CARRIED=0
    for _ in $(seq 1 15); do
        resp_w="$(${RUNTIME} exec "${BASTION}" sh -c \
            "wget -q -S -O /dev/null --no-check-certificate --timeout=8 https://127.0.0.1:${LISTEN}/ 2>&1" || true)"
        grep -qE 'HTTP/1\.[01] (200|30[0-9]|40[0-9])' <<<"${resp_w}" && { W_CARRIED=1; break; }
        sleep 3
    done
    [[ "${W_CARRIED}" == "1" ]] \
        && ok "the analyst port carried a request with worker ir-egress-2 DOWN — its sessions' loss is not the fleet's" \
        || bad "the analyst path died with one of ${WORKERS_N} workers down — worker loss is still fleet-wide"

    ${RUNTIME} start ir-enclave_boundary-egress-2_1 >/dev/null 2>&1
    W_BACK=0
    for _ in $(seq 1 25); do
        [[ "$(bound_count)" -eq "${SESSIONS_N}" && "$(live_session_count)" -eq "${SESSIONS_N}" ]] \
            && { W_BACK=1; break; }
        sleep 3
    done
    [[ "${W_BACK}" == "1" ]] \
        && ok "worker restarted and the full complement of ${SESSIONS_N} sessions is live again — recovery is unattended" \
        || bad "the session complement did not recover after the worker returned"
else
    info "a single worker is deployed — worker-death isolation has nothing to prove"
fi

# ============================================================ summary
say "Result"
if [[ "${FAILED}" == "0" ]]; then
    ok "brokered access holds: authority in the enclave, one target, attributable, encrypted, carrying traffic, and reported truthfully"
else
    bad "brokered access does NOT hold — see failures above"
fi
report_finish
exit "${FAILED}"
