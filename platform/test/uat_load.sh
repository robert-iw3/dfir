#!/usr/bin/env bash
# ==============================================================================
# LOAD, CONTENTION AND CIA UNDER CONCURRENCY — track M's measuring instrument: can the deployed
# design carry 50+ simultaneous analysts, and what breaks first. Every agent rides the real
# analyst path; nothing is stubbed.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"

. "${HERE}/lib/report.sh"
report_begin 58 load "Load — 50 concurrent analysts, contention, CIA" \
    "Under a fleet's worth of concurrent real logins and colliding writes, the platform provisions correctly, answers within thresholds, refuses what RBAC forbids, loses no write, keeps every agent's identity its own, and its audit chain still verifies."
RUNTIME="${IR_RUNTIME:-podman}"
set -a; . "${PLATFORM}/deploy/.env" 2>/dev/null || true; set +a

# ---- knobs -------------------------------------------------------------------
N_USERS="${IR_LOAD_USERS:-50}"              # the design target
ACTIVITY_S="${IR_LOAD_ACTIVITY_S:-60}"
# ARRIVALS PER SECOND — the fleet shape this run models: analysts arrive over minutes and browsers
# hold connections, so arrival rate and concurrency are different knobs.
ARRIVAL_RATE="${IR_LOAD_ARRIVAL_RATE:-2}"
# Think time per view, jittered — without it each agent loops as fast as the platform answers and
# the run measures the harness.
THINK_S="${IR_LOAD_THINK_S:-3}"
# Login p95 ceiling: a forced-change OIDC flow is ~6 round trips through gate+IdP; 8s under
# a 50-wide storm keeps the 09:00 case usable. Reads at 1.5s is where a table stops feeling
# live; writes carry an audit insert + run recount so they get 2.5s; the knee judges reads
# at 3s because past that the platform is not usable even if it is technically up.
LOGIN_P95="${IR_LOAD_LOGIN_P95_MS:-8000}"
READ_P95="${IR_LOAD_READ_P95_MS:-1500}"
WRITE_P95="${IR_LOAD_WRITE_P95_MS:-2500}"
KNEE_P95="${IR_LOAD_KNEE_P95_MS:-3000}"
TARGET_KNEE="${IR_LOAD_TARGET:-50}"
AVAIL_MIN="${IR_LOAD_AVAILABILITY_PCT:-99}"

BE=ir-enclave_backend_1
GATE=ir-enclave_oauth2-proxy_1
DB=ir-enclave_db_1
SCRATCH="$(mktemp -d)"
# The samplers run in their own container and their own subshell, so an abort anywhere between
# here and the summary leaves them running: the availability sampler keeps dialing the analyst
# path for as long as the host is up, which is exactly the connection churn the brokered
# sessions are sensitive to. Cleaned up on EVERY exit, not only the successful one.
cleanup() {
    rm -rf "${SCRATCH}"
    [[ -n "${PGPID:-}" ]] && { kill "${PGPID}" 2>/dev/null; wait "${PGPID}" 2>/dev/null; }
    [[ -n "${SAMPLER:-}" ]] && ${RUNTIME} rm -f "${SAMPLER}" >/dev/null 2>&1
    return 0
}
trap cleanup EXIT INT TERM
RUNID="$(date +%s)"
MARKER="loadtest-${RUNID}"

be_py() { ${RUNTIME} exec -i "${BE}" python3 - "$@"; }
edge_run() { # detached container on the analyst path; prints container id
    ${RUNTIME} run -d --name "$1" --network ir-edge --dns "${DNS_EDGE_IP}" \
        -v "${HERE}/lib/load_agents.py:/t.py:ro,z" -v "$2:/cfg.json:ro,z" \
        localhost/ir-workstation:latest python3 "${@:3}"
}

# ---- preflight: targets and their pre-state ----------------------------------
say "Preflight — targets, snapshots, samplers"

TARGETS="$(be_py <<'PY'
import json, os, django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ir_platform.settings"); django.setup()
from cases.models import Finding, Investigation, Note
from django.db.models import Count
inv = (Investigation.objects.annotate(n=Count("runs__findings"))
       .order_by("-n").first())
# The churn set: five findings from DIFFERENT runs of that investigation would dodge the
# run-row contention this test wants, so take five from the SAME run where possible.
fs = list(Finding.objects.filter(run__investigation=inv)
          .order_by("run_id", "id")[:5])
print(json.dumps({
    "investigation": inv.id, "name": inv.name,
    "findings": [{"id": f.id, "verdict": f.verdict, "confidence": f.confidence,
                  "adjudicated_by": f.adjudicated_by} for f in fs],
    "notes_before": Note.objects.count(),
}))
PY
)"
INV_ID="$(python3 -c "import json,sys;print(json.loads(sys.argv[1])['investigation'])" "${TARGETS}")"
FIDS="$(python3 -c "import json,sys;print(','.join(str(f['id']) for f in json.loads(sys.argv[1])['findings']))" "${TARGETS}")"
[[ -n "${INV_ID}" && -n "${FIDS}" ]] \
    && ok "contention targets: investigation ${INV_ID}, findings ${FIDS} (verdicts snapshotted for restore)" \
    || { bad "no investigation with findings — seed evidence first"; report_finish; exit 1; }
printf '%s' "${TARGETS}" > "${SCRATCH}/targets.json"

# The analyst path must be CARRYING before load is applied. Without this the run starts
# while the brokered session is still re-establishing from a previous run and attributes the
# outage to whatever phase happened to go first — provisioning got the blame twice.
PATH_READY=0
for _ in $(seq 1 24); do
    if ${RUNTIME} run --rm -i --network ir-edge --dns "${DNS_EDGE_IP}" \
        localhost/ir-workstation:latest python3 -c "
import ssl, sys, urllib.request
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
try:
    urllib.request.urlopen('${IR_PLATFORM_URL%/}/', context=ctx, timeout=10)
except Exception:
    sys.exit(1)
" >/dev/null 2>&1; then PATH_READY=1; break; fi
    sleep 5
done
[[ "${PATH_READY}" == "1" ]] \
    && ok "the analyst path is carrying traffic before any load is applied — the baseline is a working platform" \
    || bad "the analyst path never came up within 120s — load was not applied, and nothing below measures this platform"

# The admin drives provisioning; re-armed to its known initial state first.
bash "${PLATFORM}/hashicorp/keycloak/provision-demo-users.sh" --force default-admin >/dev/null 2>&1
ADMIN_PW="${IR_DEMO_ADMIN_PASSWORD:-default-admin-Pw1!}"

# Availability: an independent 1 Hz observer on the analyst path for the whole run. It
# must not share the agents' process, or a wedged driver would stop the very measurement
# that should record the outage.
SAMPLER="loadtest-sampler-${RUNID}"
# Any sampler an earlier run abandoned goes too — a stray one dials the analyst path once a
# second forever and shows up later as unexplained session churn.
for _stale in $(${RUNTIME} ps -a --format '{{.Names}}' 2>/dev/null | grep '^loadtest-sampler-' || true); do
    ${RUNTIME} rm -f "${_stale}" >/dev/null 2>&1 || true
done
${RUNTIME} run -d --name "${SAMPLER}" --network ir-edge --dns "${DNS_EDGE_IP}" \
    localhost/ir-workstation:latest python3 -c "
import http.client,ssl,time
ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
# Availability of the ANALYST PATH: any HTTP answer proves tailnet, broker, ingress and gate are
# carrying. A 401 is the gate working; only a TRANSPORT failure counts against availability.
conn=None
def probe():
    global conn
    if conn is None:
        conn=http.client.HTTPSConnection('ir-platform.local',8443,context=ctx,timeout=5)
    conn.request('GET','/'); r=conn.getresponse(); r.read()
    return r.status
while True:
    t0=time.monotonic()
    # A sample asks whether the platform answers THIS second: a kept-alive connection the far end
    # closed fails once and succeeds on reconnect, so the probe retries once before recording an
    # outage.
    last=None
    for attempt in (1,2):
        try:
            st=probe()
            print(f'{time.time():.0f} {st} {int((time.monotonic()-t0)*1000)}',flush=True)
            break
        except Exception as e:
            last=e
            try: conn.close()
            except Exception: pass
            conn=None
    else:
        print(f'{time.time():.0f} 0 {int((time.monotonic()-t0)*1000)} {type(last).__name__}',flush=True)
    time.sleep(1)
" >/dev/null 2>&1 && ok "availability sampler running (1 Hz, own container, analyst path)" \
                  || bad "could not start the availability sampler"

# The database, watched from inside its own container: connections, deadlocks, rollbacks.
PGLOG="${SCRATCH}/pg.samples"
( while :; do
    ${RUNTIME} exec "${DB}" psql -U postgres -tA -c \
      "select (select count(*) from pg_stat_activity),
              (select coalesce(sum(deadlocks),0) from pg_stat_database),
              (select coalesce(sum(xact_rollback),0) from pg_stat_database)" 2>/dev/null
    sleep 2
  done > "${PGLOG}" ) & PGPID=$!
GATE_SINCE="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
REDIS_BEFORE="$(${RUNTIME} exec ir-enclave_redis_1 redis-cli -n 1 dbsize 2>/dev/null | tr -dc '0-9')"

# ---- phase K: provisioning under concurrency ---------------------------------
if [[ "${ARRIVAL_RATE%%.*}" == "0" ]]; then
    say "K — ${N_USERS} users provisioned through the platform's own API, all at once (herd)"
else
    say "K — ${N_USERS} users provisioned through the platform's own API, ${ARRIVAL_RATE}/s arrivals"
fi

python3 - "${SCRATCH}/prov.json" <<PY
import json, sys
json.dump({"phase": "provision", "base_url": "${IR_PLATFORM_URL%/}",
           "admin_user": "default-admin", "admin_password": "${ADMIN_PW}",
           "n_users": ${N_USERS}, "provision_concurrency": 10,
           "arrival_rate": ${ARRIVAL_RATE},
           "marker": "${MARKER}"}, open(sys.argv[1], "w"))
PY
PROV_CID="$(edge_run "loadtest-prov-${RUNID}" "${SCRATCH}/prov.json" /t.py /cfg.json)"
${RUNTIME} wait "${PROV_CID}" >/dev/null 2>&1
${RUNTIME} logs "${PROV_CID}" 2>/dev/null | tail -1 > "${SCRATCH}/prov.out"
${RUNTIME} rm -f "${PROV_CID}" >/dev/null 2>&1

pj() { python3 -c "import json,sys;d=json.load(open('${SCRATCH}/prov.out'));print($1)" 2>/dev/null; }
CREATED="$(pj "d['provision']['created']")"
PROV_P95="$(pj "round(d['provision']['p95'] or 0)")"
[[ "${CREATED:-0}" -eq "${N_USERS}" ]] \
    && ok "all ${N_USERS} users provisioned concurrently (p95 ${PROV_P95}ms per create)" \
    || bad "provisioned ${CREATED:-0}/${N_USERS} — $(pj "d['provision'].get('failed') or d['provision'].get('fatal','')" | head -c 200)"

# Fidelity of provisioning: BOTH stores must hold every account with the right group.
BOTH="$(be_py <<PY
import json, os, subprocess, django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ir_platform.settings"); django.setup()
from django.contrib.auth.models import User
qs = User.objects.filter(username__startswith="${MARKER}")
roles = {u.username: sorted(u.groups.values_list("name", flat=True)) for u in qs}
bad_roles = [u for u, g in roles.items() if g not in (["analyst"], ["auditor"])]
print(json.dumps({"django": qs.count(), "bad_roles": bad_roles[:5]}))
PY
)"
KC_COUNT="$(${RUNTIME} exec ir-enclave_keycloak_1 sh -c '
    /opt/keycloak/bin/kcadm.sh config credentials --server http://127.0.0.1:8080 \
        --realm master --user "${KC_BOOTSTRAP_ADMIN_USERNAME:-admin}" \
        --password "${KC_BOOTSTRAP_ADMIN_PASSWORD:-admin}" >/dev/null 2>&1 &&
    /opt/keycloak/bin/kcadm.sh get users -r irplatform -q "search='"${MARKER}"'" --fields username' \
    2>/dev/null | grep -c username)"
DJ_COUNT="$(python3 -c "import json,sys;print(json.loads(sys.argv[1])['django'])" "${BOTH}")"
[[ "${DJ_COUNT:-0}" -eq "${N_USERS}" && "${KC_COUNT:-0}" -eq "${N_USERS}" ]] \
    && ok "provisioning fidelity: ${DJ_COUNT} in Django and ${KC_COUNT} in Keycloak — no half-created account" \
    || bad "store mismatch under concurrent provisioning: Django ${DJ_COUNT:-0}, Keycloak ${KC_COUNT:-0} of ${N_USERS}"
[[ "$(python3 -c "import json,sys;print(len(json.loads(sys.argv[1])['bad_roles']))" "${BOTH}")" == "0" ]] \
    && ok "every provisioned account carries exactly its intended role group" \
    || bad "role groups wrong on: $(python3 -c "import json,sys;print(json.loads(sys.argv[1])['bad_roles'])" "${BOTH}")"

# The export right for a subset of analysts — a Keycloak group, because that is where the
# right lives (B1.4); the SSO layer reconciles it into Django on their first request.
EXPORTERS=0
${RUNTIME} exec -i ir-enclave_keycloak_1 sh -c '
    /opt/keycloak/bin/kcadm.sh config credentials --server http://127.0.0.1:8080 \
        --realm master --user "${KC_BOOTSTRAP_ADMIN_USERNAME:-admin}" \
        --password "${KC_BOOTSTRAP_ADMIN_PASSWORD:-admin}" >/dev/null 2>&1
    gid=$(/opt/keycloak/bin/kcadm.sh get groups -r irplatform -q search=export --fields id,name 2>/dev/null \
          | sed -n "s/.*\"id\" : \"\([^\"]*\)\".*/\1/p" | head -1)
    for u in '"$(python3 -c "
import json
d=json.load(open('${SCRATCH}/prov.out'))
print(' '.join(s['username'] for s in d['users'] if s['role']=='analyst')[:2000])" | awk '{print $1, $2, $3, $4, $5}')"'; do
        uid=$(/opt/keycloak/bin/kcadm.sh get users -r irplatform -q "username=$u" -q exact=true --fields id 2>/dev/null \
              | sed -n "s/.*\"id\" : \"\([^\"]*\)\".*/\1/p")
        [ -n "$uid" ] && [ -n "$gid" ] && /opt/keycloak/bin/kcadm.sh update "users/$uid/groups/$gid" -r irplatform -n >/dev/null 2>&1 && echo granted
    done' 2>/dev/null | grep -c granted > "${SCRATCH}/exporters" || true
EXPORTERS="$(cat "${SCRATCH}/exporters")"
# Named separately from "no analysts were provisioned": with nobody to grant to, the export
# boundary is unmeasured rather than broken, and the two need different fixes.
PROV_ANALYSTS="$(python3 -c "
import json
d=json.load(open('${SCRATCH}/prov.out'))
print(sum(1 for u in d['users'] if u['role']=='analyst'))" 2>/dev/null || echo 0)"
if [[ "${PROV_ANALYSTS:-0}" -eq 0 ]]; then
    bad "no analyst accounts were provisioned — the export right had nobody to grant to (a provisioning failure, not an export one)"
elif [[ "${EXPORTERS:-0}" -ge 3 ]]; then
    ok "export right granted to ${EXPORTERS} of ${PROV_ANALYSTS} analysts — holders and non-holders both exist, so the boundary is testable in both directions"
else
    bad "granted the export right to only ${EXPORTERS:-0} of ${PROV_ANALYSTS} provisioned analysts — check the kcadm group update"
fi

# ---- phases L, A, R ----------------------------------------------------------
say "L/A/R — login storm, contended activity (${ACTIVITY_S}s), ramp to the knee"

python3 - "${SCRATCH}/run.json" "${SCRATCH}/prov.out" <<PY
import json, sys
prov = json.load(open(sys.argv[2]))
users = prov["users"]
exporters = {u["username"] for u in users if u["role"] == "analyst"}
exporters = set(sorted(exporters)[:${EXPORTERS:-0}])
for u in users:
    u["export"] = u["username"] in exporters
json.dump({"base_url": "${IR_PLATFORM_URL%/}", "users": users,
           "investigation_id": ${INV_ID}, "finding_ids": [${FIDS}],
           "activity_seconds": ${ACTIVITY_S}, "knee_p95_ms": ${KNEE_P95},
           "accept_rate": ${BROKER_ACCEPT_RATE:-8},
           "arrival_rate": ${ARRIVAL_RATE}, "think_seconds": ${THINK_S},
           "marker": "${MARKER}"}, open(sys.argv[1], "w"))
PY
# The provisioning container has just exited, closing its connections at once, and that
# burst can end the brokered session. Wait for the path to carry again before the storm, so
# the storm measures the storm rather than the previous phase's teardown.
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

RUN_CID="$(edge_run "loadtest-run-${RUNID}" "${SCRATCH}/run.json" /t.py /cfg.json)"
${RUNTIME} wait "${RUN_CID}" >/dev/null 2>&1
# The driver's LAST line is its JSON result; everything before it is progress or a traceback.
# Keeping the whole log means "produced no result" can say WHY instead of only that it did.
${RUNTIME} logs "${RUN_CID}" 2>&1 > "${SCRATCH}/run.full" 2>&1
grep -v '^\[load\]' "${SCRATCH}/run.full" | tail -1 > "${SCRATCH}/run.out"
${RUNTIME} rm -f "${RUN_CID}" >/dev/null 2>&1
kill "${PGPID}" 2>/dev/null; wait "${PGPID}" 2>/dev/null

rj() { python3 -c "import json;d=json.load(open('${SCRATCH}/run.out'));print($1)" 2>/dev/null; }
DRIVER_OK=1
[[ -s "${SCRATCH}/run.out" ]] && rj "d['agents']" >/dev/null 2>&1 || DRIVER_OK=0
if [[ "${DRIVER_OK}" != "1" ]]; then
    # The driver's own output, so a crashed driver is distinguishable from a failed platform.
    while IFS= read -r l; do [[ -n "${l}" ]] && info "${l}"; done \
        < <(tail -8 "${SCRATCH}/run.full" 2>/dev/null)
fi
[[ "${DRIVER_OK}" == "1" ]] \
    || bad "the agent driver produced no result — the phases below did not run (measurements still reported)"

if [[ "${DRIVER_OK}" == "1" ]]; then

# Storm.
S_DONE="$(rj "d['storm']['completed']")"; S_P95="$(rj "round(d['storm']['p95'] or 0)")"
[[ "${S_DONE:-0}" -eq "${N_USERS}" ]] \
    && ok "login storm: ${S_DONE}/${N_USERS} full OIDC flows (forced change included) completed concurrently" \
    || bad "login storm: only ${S_DONE:-0}/${N_USERS} completed — $(rj "d['storm']['failures'][:3]")"
# A latency percentile over zero completions is not fast — it is unmeasured. Every
# storm-derived assertion below carries the same gate: an empty population must read as
# "not measured", never as a pass earned by the absence of the thing being measured.
if [[ "${S_DONE:-0}" -eq 0 ]]; then
    bad "storm p95 not measured — zero logins completed, so there is no latency to bound"
elif [[ "${S_P95:-999999}" -le "${LOGIN_P95}" ]]; then
    ok "storm p95 ${S_P95}ms over ${S_DONE} completed logins, within the ${LOGIN_P95}ms ceiling (max $(rj "round(d['storm']['max'] or 0)")ms)"
else
    bad "storm p95 ${S_P95}ms EXCEEDS ${LOGIN_P95}ms — the 09:00 problem is real at this size"
fi
REDIS_AFTER="$(${RUNTIME} exec ir-enclave_redis_1 redis-cli -n 1 dbsize 2>/dev/null | tr -dc '0-9')"
[[ $(( ${REDIS_AFTER:-0} - ${REDIS_BEFORE:-0} )) -ge "${N_USERS}" ]] \
    && ok "${N_USERS} DISTINCT server-side sessions created (redis db1 ${REDIS_BEFORE} -> ${REDIS_AFTER})" \
    || bad "session store grew by $(( ${REDIS_AFTER:-0} - ${REDIS_BEFORE:-0} )), expected >= ${N_USERS}"
# THE SECURITY MODEL, ASSERTED UNDER LOAD — a load test that quietly weakens authentication
# measures a platform nobody deploys.
GATE_WINDOW="$(${RUNTIME} logs --since "${GATE_SINCE}" "${GATE}" 2>&1 || true)"
CALLBACKS="$(grep -c '/oauth2/callback' <<<"${GATE_WINDOW}" || true)"
AUTHOK="$(grep -c 'AuthSuccess' <<<"${GATE_WINDOW}" || true)"
[[ "${CALLBACKS:-0}" -ge "${N_USERS}" ]] \
    && ok "every session was minted through an OIDC callback (${CALLBACKS} for ${N_USERS} agents) — no agent was admitted by a shortcut around the identity provider" \
    || bad "only ${CALLBACKS:-0} OIDC callbacks for ${N_USERS} logins — some session did not come from the identity provider"
[[ "${AUTHOK:-0}" -ge "${N_USERS}" ]] \
    && ok "the gate recorded ${AUTHOK} successful authentications — each agent's session is the gate's own, not a forged cookie" \
    || bad "the gate recorded ${AUTHOK:-0} authentications for ${N_USERS} agents"
# The forced credential change is enforcement, not decoration: every account was provisioned
# temporary, so an agent that reached the app WITHOUT changing its password would mean
# Keycloak admitted a credential it had marked single-use.
STILL_TEMP="$(${RUNTIME} exec ir-enclave_keycloak_1 sh -c '
    /opt/keycloak/bin/kcadm.sh config credentials --server http://127.0.0.1:8080 \
        --realm master --user "${KC_BOOTSTRAP_ADMIN_USERNAME:-admin}" \
        --password "${KC_BOOTSTRAP_ADMIN_PASSWORD:-admin}" >/dev/null 2>&1 &&
    /opt/keycloak/bin/kcadm.sh get users -r irplatform -q "search='"${MARKER}"'" \
        --fields username,requiredActions' 2>/dev/null | grep -c UPDATE_PASSWORD || true)"
if [[ "${S_DONE:-0}" -eq 0 ]]; then
    bad "credential-rotation completion not measured — zero logins completed, so no rotation was exercised"
elif [[ "${STILL_TEMP:-1}" -eq 0 ]]; then
    ok "no loadtest account still carries a forced password change — every one of the ${S_DONE} logins actually completed the credential rotation the platform demanded"
else
    bad "${STILL_TEMP} account(s) reached the platform with the forced change still pending — a single-use credential was accepted as a durable one"
fi

CSRF_FAILS="$(${RUNTIME} logs --since "${GATE_SINCE}" "${GATE}" 2>&1 | grep -cE 'unable to obtain CSRF cookie' || true)"
[[ "${CSRF_FAILS:-0}" -eq 0 ]] \
    && ok "zero CSRF-cookie failures at the gate across the whole storm" \
    || bad "${CSRF_FAILS} CSRF failures under concurrent login — the eviction defect returns at scale"

# Activity: latency, error budget, RBAC.
act() { rj "d['activity'].get('$1',{}).get('$2')"; }
for cls in read_stats read_findings; do
    p95="$(act "${cls}" p95)"; p95="${p95%.*}"
    [[ -n "${p95}" && "${p95}" != "None" && "${p95}" -le "${READ_P95}" ]] \
        && ok "${cls}: p95 ${p95}ms within ${READ_P95}ms under ${N_USERS}-wide contention" \
        || bad "${cls}: p95 ${p95:-unmeasured}ms against a ${READ_P95}ms ceiling"
done
for cls in write_note write_verdict; do
    p95="$(act "${cls}" p95)"; p95="${p95%.*}"
    [[ -n "${p95}" && "${p95}" != "None" && "${p95}" -le "${WRITE_P95}" ]] \
        && ok "${cls}: p95 ${p95}ms within ${WRITE_P95}ms while colliding on one investigation" \
        || bad "${cls}: p95 ${p95:-unmeasured}ms against a ${WRITE_P95}ms ceiling"
done
ERR5="$(rj "sum(v['errors_5xx']+v['resets'] for v in d['activity'].values())")"
ACT_N="$(rj "sum(v['n'] for v in d['activity'].values())")"
THROTTLED="$(rj "sum(v.get('throttled_429', 0) for v in d['activity'].values())")"
# The ingress rate limit is sized per SOURCE, and every analyst arrives from the distributor's
# one address — so it bounds the FLEET rather than each member. Reported as its own number:
# throttling is the platform refusing deliberately, not failing, and folding it into the error
# budget hides the capacity finding that matters (M4).
if [[ "${THROTTLED:-0}" -gt 0 ]]; then
    pct_thr=$(( THROTTLED * 100 / (ACT_N > 0 ? ACT_N : 1) ))
    info "${THROTTLED} of ${ACT_N} requests (${pct_thr}%) were throttled 429 at the ingress — the per-source limit bounds the whole fleet; re-deriving it is M4"
fi
# Two different failures, never merged: the APPLICATION erroring under load has a budget of zero;
# a brokered session being replaced costs only the connections riding it.
APP_ERRS="$(${RUNTIME} logs --since "${GATE_SINCE}" ir-enclave_backend_1 2>&1     | grep -cE '^[A-Za-z_.]*(Error|Exception)' || true)"
SESSION_SWAPS="$(${RUNTIME} logs --since "${GATE_SINCE}" ir-dmz_broker_1 2>&1     | grep -cE 'session ended|replacing' || true)"
if [[ "${ACT_N:-0}" -eq 0 ]]; then
    bad "error budget not measured — zero operations ran (no agent survived login into the activity phase)"
else
    [[ "${APP_ERRS:-1}" -eq 0 ]] \
        && ok "the application raised nothing across ${ACT_N} operations — every loss below is transport, not logic" \
        || bad "${APP_ERRS} unhandled application exception(s) during sustained activity"
    # Transport losses, bounded as a RATE and attributed to the sessions that were replaced.
    err_pct=$(( ERR5 * 100 / (ACT_N > 0 ? ACT_N : 1) ))
    budget="${IR_LOAD_TRANSPORT_BUDGET_PCT:-3}"
    if [[ "${ERR5:-0}" -eq 0 ]]; then
        ok "no connection was lost across ${ACT_N} operations"
    elif [[ "${err_pct}" -le "${budget}" ]]; then
        ok "${ERR5} of ${ACT_N} operations (${err_pct}%) lost their connection, within the ${budget}% a brokered path allows — ${SESSION_SWAPS} session replacement(s) account for them, and each costs only its own share"
    else
        bad "${ERR5} of ${ACT_N} operations (${err_pct}%) lost their connection, over the ${budget}% budget — ${SESSION_SWAPS} session replacement(s)"
    fi
fi
# Judged over attempts that REACHED authorization: a 5xx never got there, and counting it as a
# failure-to-refuse reports a server error as a permission slip.
RB_403="$(rj "d['confidentiality']['expected_403']")"
RB_UNSERVED="$(rj "d['confidentiality'].get('rbac_unserved', 0)")"
RB_VIOL="$(rj "len([v for v in d['confidentiality']['violations'] if 'auditor' in v])")"
if [[ "${RB_403:-0}" -eq 0 ]]; then
    bad "RBAC under load not measured — no auditor write reached an authorization decision (${RB_UNSERVED:-0} unserved)"
elif [[ "${RB_VIOL:-1}" -eq 0 ]]; then
    ok "RBAC under load: all ${RB_403} auditor writes that reached authorization were refused 403 (${RB_UNSERVED:-0} never served)"
else
    bad "RBAC under load: ${RB_VIOL} auditor write(s) were NOT refused — a slip here is a confidentiality finding"
fi

# An unauthenticated caller must still be refused while the platform is under load. Shedding
# authentication to keep up would be the worst possible way to pass a performance test, and
# nothing else in this suite would notice — every other check here holds a valid session.
ANON="$(${RUNTIME} run --rm -i --network ir-edge --dns "${DNS_EDGE_IP}" \
    localhost/ir-workstation:latest python3 - <<'PY' 2>/dev/null
import ssl, urllib.error, urllib.request
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
codes = []
for path in ("/api/me/", "/api/findings/", "/api/investigations/"):
    try:
        r = urllib.request.urlopen("https://ir-platform.local:8443" + path, context=ctx, timeout=20)
        codes.append(r.getcode())
    except urllib.error.HTTPError as e:
        codes.append(e.code)
    except Exception:
        codes.append(0)
print(",".join(str(c) for c in codes))
PY
)"
if [[ "${ANON}" =~ ^(401|403)(,(401|403))*$ ]]; then
    ok "an unauthenticated caller was refused on every data path during the storm (${ANON}) — the platform did not shed authentication to keep up"
else
    bad "unauthenticated requests answered ${ANON:-nothing} under load — anything other than 401/403 means the gate let load change who may read evidence"
fi

# Confidentiality.
VIOL="$(rj "len(d['confidentiality']['violations'])")"
CONF_N="$(rj "d['confidentiality'].get('checks', 0)")"
UNSERVED="$(rj "d['confidentiality'].get('rbac_unserved', 0) + d['confidentiality'].get('export_unserved', 0)")"
if [[ "${CONF_N:-0}" -eq 0 ]]; then
    bad "confidentiality not measured — zero concurrent identity checks ran"
elif [[ "${VIOL:-1}" -eq 0 ]]; then
    ok "confidentiality: zero identity-bleed or privilege violations across ${CONF_N} concurrent checks (${UNSERVED:-0} requests never served, excluded)"
else
    bad "CONFIDENTIALITY VIOLATIONS: $(rj "d['confidentiality']['violations'][:3]")"
fi
EXP_OK="$(rj "d['ledger']['export_ok']")"; EXP_DEN="$(rj "d['ledger']['export_denied']")"
[[ "${EXP_OK:-0}" -ge 1 && "${EXP_DEN:-0}" -ge 1 ]] \
    && ok "export boundary exercised both ways under load (${EXP_OK} completed, ${EXP_DEN} refused)" \
    || bad "export boundary not proven both ways (ok=${EXP_OK:-0} denied=${EXP_DEN:-0})"

# Fidelity: the ledger against the rows, EXACTLY.
FID="$(be_py <<PY
import json, os, django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ir_platform.settings"); django.setup()
from cases.models import ExportLedger, FindingReclassification, Note
print(json.dumps({
    "notes": Note.objects.filter(summary__startswith="${MARKER}").count(),
    "reclass": FindingReclassification.objects.filter(note__startswith="${MARKER}").count(),
    "reclass_ids": list(FindingReclassification.objects.filter(
        note__startswith="${MARKER}").values_list("id", flat=True)),
    "exp_ok": ExportLedger.objects.filter(actor__startswith="${MARKER}", outcome="completed").count(),
    "exp_den": ExportLedger.objects.filter(actor__startswith="${MARKER}", outcome="denied").count(),
}))
PY
)"
L_NOTES="$(rj "d['ledger']['notes']")"; L_RC="$(rj "len(d['ledger']['reclassify'])")"
D_NOTES="$(python3 -c "import json,sys;print(json.loads(sys.argv[1])['notes'])" "${FID}")"
D_RC="$(python3 -c "import json,sys;print(json.loads(sys.argv[1])['reclass'])" "${FID}")"
# The two directions are not the same defect, and only one of them is data loss.
#
#   DB < accepted   a write the agent was TOLD had been accepted is not there. Data loss.
#   DB > accepted   the row committed and the response was lost on the way back, so the
#                   agent recorded a failure that had in fact succeeded. Nothing is missing;
#                   under load at this concurrency it is the expected outcome, and failing on
#                   it reports the safe direction as a fault.
#
# A large excess is still a defect — that is a retry writing twice — so the tolerance is
# bounded rather than open.
num_or_0() { local v="${1//[^0-9]/}"; printf '%s' "${v:-0}"; }
# A write whose connection dropped before the response arrived may well have committed. The
# agents counted those per operation, so the excess has a CAUSE to be measured against
# instead of a percentage that is only ever a guess about how much drift looks normal.
RC_RESETS="$(rj "d['activity']['write_verdict']['resets']")"
EXP_RESETS="$(rj "d['activity']['export']['resets']")"
FID_SLACK=$(( (L_NOTES + 199) / 200 ))       # 0.5%, at least 1
if [[ "${L_NOTES:-0}" -eq 0 ]]; then
    bad "note fidelity not measured — the agents recorded zero accepted notes to compare against"
elif [[ "${L_NOTES}" == "${D_NOTES}" ]]; then
    ok "data fidelity: ${D_NOTES} notes in the database — exactly the ${L_NOTES} the agents recorded as accepted, none lost, none duplicated"
elif [[ "${D_NOTES}" -lt "${L_NOTES}" ]]; then
    bad "FIDELITY: agents were told ${L_NOTES} notes were accepted, the database holds ${D_NOTES} — $(( L_NOTES - D_NOTES )) acknowledged write(s) LOST"
elif [[ $(( D_NOTES - L_NOTES )) -le "${FID_SLACK}" ]]; then
    ok "data fidelity: ${D_NOTES} notes for ${L_NOTES} the agents counted as accepted — $(( D_NOTES - L_NOTES )) committed with the response lost on the way back, which loses nothing"
else
    bad "FIDELITY: ${D_NOTES} notes for only ${L_NOTES} accepted — $(( D_NOTES - L_NOTES )) more than any lost acknowledgement explains; a retry is writing twice"
fi
# Totals cannot tell a lost write from an unacknowledged one, and the two have opposite
# meanings. The agents recorded the id of every adjudication the platform said it had
# accepted, so the sets are joined by id: an id the agent holds and the database does not is
# data loss; a row the database holds and the agent never heard of is a commit whose response
# was lost on the way back, which loses nothing. Deliberate contention makes repeats on the
# same finding normal, so identity has to come from the row id, not from the values.
L_RC_IDS="$(rj "json.dumps([x['id'] for x in d['ledger']['reclassify'] if x.get('id')])")"
L_RC_ANON="$(rj "sum(1 for x in d['ledger']['reclassify'] if not x.get('id'))")"
D_RC_IDS="$(python3 -c "import json,sys;print(json.dumps(json.loads(sys.argv[1])['reclass_ids']))" "${FID}")"
RC_JOIN="$(python3 -c "
import json, sys
led, db = set(json.loads(sys.argv[1])), set(json.loads(sys.argv[2]))
print(len(led - db), len(db - led))" "${L_RC_IDS}" "${D_RC_IDS}" 2>/dev/null)"
read -r RC_LOST RC_UNACKED <<<"${RC_JOIN}"
if [[ "${L_RC:-0}" -eq 0 ]]; then
    bad "adjudication fidelity not measured — zero accepted adjudications to compare against"
elif [[ -z "${RC_JOIN}" ]]; then
    bad "adjudication fidelity not measured — the ledger and the database could not be joined by row id"
elif [[ "${L_RC_ANON:-0}" =~ ^[0-9]+$ && "${L_RC_ANON}" -gt 0 ]]; then
    bad "FIDELITY: ${L_RC_ANON} accepted adjudication(s) came back without a row id — the platform confirmed a write it cannot name"
elif [[ ! "${RC_LOST}" =~ ^[0-9]+$ || "${RC_LOST}" -gt 0 ]]; then
    bad "FIDELITY: ${RC_LOST} adjudication(s) the platform said it had accepted are NOT in the database — acknowledged writes LOST"
elif [[ "${RC_UNACKED}" -eq 0 ]]; then
    ok "data fidelity: every one of ${L_RC} accepted adjudications is in the database by id, and the database holds no others"
elif [[ "${RC_UNACKED}" -le "$(num_or_0 "${RC_RESETS}")" ]]; then
    ok "data fidelity: all ${L_RC} accepted adjudications are present; ${RC_UNACKED} further row(s) committed with the response lost on the way back — one for each of the ${RC_RESETS} connection(s) the agents saw dropped, which loses nothing"
else
    bad "FIDELITY: ${RC_UNACKED} history rows beyond the ${L_RC} accepted, but only ${RC_RESETS} response(s) were lost — the excess is a retry writing twice"
fi
D_EOK="$(python3 -c "import json,sys;print(json.loads(sys.argv[1])['exp_ok'])" "${FID}")"
D_EDEN="$(python3 -c "import json,sys;print(json.loads(sys.argv[1])['exp_den'])" "${FID}")"
if [[ "$(( ${EXP_OK:-0} + ${EXP_DEN:-0} ))" -eq 0 ]]; then
    bad "export ledger accounting not measured — the agents attempted zero exports"
elif [[ "${D_EOK}" == "${EXP_OK}" && "${D_EDEN}" == "${EXP_DEN}" ]]; then
    ok "the export ledger accounts for every attempt under load (${D_EOK} completed, ${D_EDEN} denied — matching the agents exactly)"
elif [[ "${D_EOK}" -lt "${EXP_OK}" || "${D_EDEN}" -lt "${EXP_DEN}" ]]; then
    bad "export ledger SHORT: agents were told ${EXP_OK}/${EXP_DEN}, the ledger holds ${D_EOK}/${D_EDEN} — an export decision was not recorded"
elif [[ $(( (D_EOK - EXP_OK) + (D_EDEN - EXP_DEN) )) -le "$(num_or_0 "${EXP_RESETS}")" ]]; then
    ok "the export ledger accounts for every attempt (${D_EOK} completed, ${D_EDEN} denied); $(( (D_EOK - EXP_OK) + (D_EDEN - EXP_DEN) )) decision(s) recorded whose response never reached the agent, within the ${EXP_RESETS} dropped connection(s)"
else
    bad "export ledger drift beyond dropped connections: agents ${EXP_OK}/${EXP_DEN}, ledger ${D_EOK}/${D_EDEN}, only ${EXP_RESETS} response(s) lost"
fi

# Integrity after the storm.
CHAIN="$(be_py <<'PY'
import json, os, django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ir_platform.settings"); django.setup()
from cases.audit import verify_audit_chain
from cases.models import Finding
ok, broken = verify_audit_chain()
churned = Finding.objects.filter(reclassifications__note__startswith="loadtest-").distinct()
print(json.dumps({"intact": ok, "first_broken": broken, "churned_total": churned.count(),
                  "churned_not_analyst": churned.exclude(adjudicated_by="analyst").count()}))
PY
)"
python3 -c "import json,sys;sys.exit(0 if json.loads(sys.argv[1])['intact'] else 1)" "${CHAIN}" \
    && ok "the audit hash chain verifies over the entire storm's entries" \
    || bad "AUDIT CHAIN BROKEN after concurrent load: $(python3 -c "import json,sys;print(json.loads(sys.argv[1])['first_broken'])" "${CHAIN}")"
CHURNED_T="$(python3 -c "import json,sys;print(json.loads(sys.argv[1])['churned_total'])" "${CHAIN}")"
if [[ "${CHURNED_T:-0}" -eq 0 ]]; then
    bad "adjudication precedence not measured — zero findings were churned under contention"
elif [[ "$(python3 -c "import json,sys;print(json.loads(sys.argv[1])['churned_not_analyst'])" "${CHAIN}")" == "0" ]]; then
    ok "adjudication precedence survived contention: all ${CHURNED_T} churned findings are analyst-owned with full history"
else
    bad "precedence violated: churned findings not marked analyst-owned"
fi

fi   # DRIVER_OK — the agent-derived assertions end here

# Availability and the database are measured by INDEPENDENT observers, read whatever the driver
# did — gating them on the driver discards the only evidence a failed run leaves.
${RUNTIME} logs "${SAMPLER}" 2>/dev/null > "${SCRATCH}/avail"; ${RUNTIME} rm -f "${SAMPLER}" >/dev/null 2>&1
AV="$(python3 - "${SCRATCH}/avail" <<'PY'
import sys
rows = [l.split() for l in open(sys.argv[1]) if l.strip()]
# Any HTTP status is a reachable platform; only a transport failure (code 0) is downtime.
ok = [r for r in rows if r[1] != "0"]
lat = sorted(int(r[2]) for r in ok)
print(f"{len(rows)} {len(ok)} "
      f"{100.0*len(ok)/len(rows) if rows else 0:.2f} "
      f"{lat[int(len(lat)*0.95)] if lat else 0}")
PY
)"
read -r AV_N AV_OK AV_PCT AV_P95 <<<"${AV}"
python3 -c "import sys;sys.exit(0 if float('${AV_PCT:-0}') >= float('${AVAIL_MIN}') else 1)" \
    && ok "availability ${AV_PCT}% over ${AV_N} independent 1 Hz samples (health p95 ${AV_P95}ms) — floor ${AVAIL_MIN}%" \
    || bad "availability ${AV_PCT:-0}% (${AV_OK:-0}/${AV_N:-0} samples) — below the ${AVAIL_MIN}% floor"

# The database under it all.
PG="$(python3 - "${PGLOG}" <<'PY'
import sys
rows = [l.strip().split("|") for l in open(sys.argv[1]) if "|" in l]
if not rows: print("0 0 0"); raise SystemExit
conns = [int(r[0]) for r in rows]
print(max(conns), int(rows[-1][1]) - int(rows[0][1]), int(rows[-1][2]) - int(rows[0][2]))
PY
)"
read -r PG_PEAK PG_DEAD PG_RB <<<"${PG}"
[[ "${PG_PEAK:-100}" -lt 90 ]] \
    && ok "database peak ${PG_PEAK} connections of ${IR_PG_MAX_CONNECTIONS:-100} — headroom held under the whole storm" \
    || bad "database connections peaked at ${PG_PEAK:-?} of ${IR_PG_MAX_CONNECTIONS:-100} — the pool is the next wall"
[[ "${PG_DEAD:-1}" -eq 0 ]] \
    && ok "zero deadlocks while ${N_USERS} writers collided on one investigation (${PG_RB:-0} rollbacks)" \
    || bad "${PG_DEAD} DEADLOCKS under write contention — the locking design does not scale"

if [[ "${DRIVER_OK}" == "1" ]]; then
# The knee.
KNEE="$(rj "d['ramp']['knee']")"; DEG="$(rj "d['ramp']['degraded_at']")"
if [[ -n "${KNEE}" && "${KNEE}" != "None" && "${KNEE}" -ge "${TARGET_KNEE}" ]]; then
    ok "measured capacity: the design held at ${KNEE} concurrent agents (target ${TARGET_KNEE}); degradation: ${DEG}"
else
    bad "measured capacity is ${KNEE:-<first step>} concurrent agents against a target of ${TARGET_KNEE} — first degradation: ${DEG}"
fi

fi   # DRIVER_OK

# ---- teardown ----------------------------------------------------------------
say "Teardown — the stack keeps nothing of the storm but the ledgers"

be_py "${MARKER}" <<'PY' > "${SCRATCH}/teardown.json"
import json, os, sys, django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ir_platform.settings"); django.setup()
from django.contrib.auth.models import User
from cases.models import Finding, FindingReclassification, Note
marker = sys.argv[1]
notes = Note.objects.filter(summary__startswith=marker).delete()[0]
rc = FindingReclassification.objects.filter(note__startswith=marker).delete()[0]
users = User.objects.filter(username__startswith=marker).delete()[0]
print(json.dumps({"notes": notes, "reclass": rc, "django_users": users}))
PY
# Restore the churned findings to their snapshotted verdicts, then recount their runs. The
# snapshot is fed on STDIN so no file content is spliced into the source — a value carrying
# a quote would otherwise break the program, which is how these one-off restores go wrong.
${RUNTIME} exec -i "${BE}" python3 - <<'PY' < "${SCRATCH}/targets.json"
import json, os, sys, django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ir_platform.settings"); django.setup()
from cases.models import Finding
snap = json.load(sys.stdin)
runs = set()
for s in snap["findings"]:
    f = Finding.objects.filter(id=s["id"]).first()
    if not f:
        continue
    f.verdict, f.confidence, f.adjudicated_by = s["verdict"], s["confidence"], s["adjudicated_by"]
    f.save(update_fields=["verdict", "confidence", "adjudicated_by"])
    runs.add(f.run)
for r in runs:
    r.tp_count = r.findings.filter(verdict="True Positive").count()
    r.evaluate_compromise(); r.save(update_fields=["tp_count", "compromised"])
print("restored", len(snap["findings"]))
PY
KC_DEL="$(${RUNTIME} exec ir-enclave_keycloak_1 sh -c '
    /opt/keycloak/bin/kcadm.sh config credentials --server http://127.0.0.1:8080 \
        --realm master --user "${KC_BOOTSTRAP_ADMIN_USERNAME:-admin}" \
        --password "${KC_BOOTSTRAP_ADMIN_PASSWORD:-admin}" >/dev/null 2>&1
    n=0
    for uid in $(/opt/keycloak/bin/kcadm.sh get users -r irplatform -q "search='"${MARKER}"'" --fields id 2>/dev/null \
                 | sed -n "s/.*\"id\" : \"\([^\"]*\)\".*/\1/p"); do
        /opt/keycloak/bin/kcadm.sh delete "users/${uid}" -r irplatform >/dev/null 2>&1 && n=$((n+1))
    done; echo $n' 2>/dev/null | tail -1)"
LEFT="$(be_py <<PY
import os, django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ir_platform.settings"); django.setup()
from django.contrib.auth.models import User
from cases.models import FindingReclassification, Note
print(User.objects.filter(username__startswith="${MARKER}").count()
      + Note.objects.filter(summary__startswith="${MARKER}").count()
      + FindingReclassification.objects.filter(note__startswith="${MARKER}").count())
PY
)"
[[ "${KC_DEL:-0}" -eq "${N_USERS}" && "${LEFT:-1}" -eq 0 ]] \
    && ok "torn down: ${KC_DEL} Keycloak accounts and every loadtest note, reclassification and Django account removed; churned verdicts restored" \
    || bad "teardown incomplete: ${KC_DEL:-0}/${N_USERS} Keycloak accounts removed, ${LEFT:-?} loadtest rows remain"
info "export-ledger rows from the storm are KEPT — an export that happened is a record, not residue"
bash "${PLATFORM}/hashicorp/keycloak/provision-demo-users.sh" --force default-admin >/dev/null 2>&1 \
    && ok "default-admin restored to provisioned state" \
    || bad "default-admin could not be restored"

# A load test whose output is only pass/fail has thrown away the thing it was run for: the numbers
# are recorded alongside the verdicts.
say "Results"
MEAS_MD="${PLATFORM}/test/results/58-load-measurements.md"
MEAS_JSON="${PLATFORM}/test/results/58-load-measurements.json"

python3 - "${SCRATCH}/run.out" "${SCRATCH}/prov.out" "${MEAS_MD}" "${MEAS_JSON}" \
         "${N_USERS}" "${ACTIVITY_S}" "${AV_PCT:-0}" "${AV_N:-0}" "${AV_P95:-0}" \
         "${PG_PEAK:-0}" "${PG_DEAD:-0}" "${PG_RB:-0}" "${IR_PG_MAX_CONNECTIONS:-100}" \
         "${ARRIVAL_RATE}" <<'PY'
import json, sys, time

run_f, prov_f, md_f, json_f = sys.argv[1:5]
n_users, activity_s = int(sys.argv[5]), int(sys.argv[6])
av_pct, av_n, av_p95 = sys.argv[7], sys.argv[8], sys.argv[9]
pg_peak, pg_dead, pg_rb, pg_max = sys.argv[10], sys.argv[11], sys.argv[12], sys.argv[13]
arrival = sys.argv[14] if len(sys.argv) > 14 else "0"

def load(path):
    try:
        return json.load(open(path))
    except Exception:
        return {}

run, prov = load(run_f), load(prov_f)
def num(v):
    return "—" if v in (None, "") else (f"{v:.0f}" if isinstance(v, float) else str(v))

L = []
L.append("## Load — measured\n")
# The shape is named in the report. A paced run and a simultaneous one answer different
# questions, and a number that does not say which it measured invites being read as the other.
try:
    _r = float(arrival)
except ValueError:
    _r = 0.0
shape = (f"arrivals paced at {arrival}/s — a fleet" if _r > 0
         else "all arriving at once — a thundering herd, not a fleet")
L.append(f"_{n_users} agents · {activity_s}s sustained activity · {shape} · "
         f"generated {time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime())}_\n")

p = prov.get("provision", {})
L.append(f"### Provisioning (through the platform's own admin API, {shape.split(' — ')[0]})\n")
L.append("| Attempted | Created | p50 ms | p95 ms |\n|---|---|---|---|")
L.append(f"| {p.get('attempted','—')} | {p.get('created','—')} | "
         f"{num(p.get('p50'))} | {num(p.get('p95'))} |\n")
# A row of dashes says the phase produced nothing; it does not say WHY, and why is the only
# actionable part of a failed run.
if p.get("fatal"):
    L.append(f"**Did not run:** {p['fatal']}\n")
if p.get("failed"):
    L.append("Create failures: " + "; ".join(
        f"HTTP {f.get('code')} {f.get('error','')}".strip() for f in p["failed"][:3]) + "\n")

s = run.get("storm", {})
L.append("### Login storm (full OIDC, forced credential change included)\n")
L.append("| Attempted | Completed | Failed | p50 ms | p95 ms | max ms |\n|---|---|---|---|---|---|")
L.append(f"| {s.get('attempted','—')} | {s.get('completed','—')} | {s.get('failed','—')} | "
         f"{num(s.get('p50'))} | {num(s.get('p95'))} | {num(s.get('max'))} |\n")
if s.get("transport_retries"):
    L.append(f"**{s['transport_retries']} login(s) had to retry through a refused connection** — "
             "the brokered session turned over mid-run; the availability figure below covers "
             "the same window.\n")
if s.get("failures"):
    L.append("Failures seen: " + "; ".join(str(f) for f in s["failures"][:3]) + "\n")

act = run.get("activity", {})
if act:
    L.append("### Sustained activity, with writes colliding on one investigation\n")
    L.append("| Operation | n | ok | 5xx | resets | p50 ms | p95 ms | p99 ms |")
    L.append("|---|---|---|---|---|---|---|---|")
    for cls in sorted(act):
        v = act[cls]
        L.append(f"| {cls} | {v['n']} | {v['ok']} | {v['errors_5xx']} | {v['resets']} | "
                 f"{num(v['p50'])} | {num(v['p95'])} | {num(v['p99'])} |")
    L.append("")

r = run.get("ramp", {})
L.append("### Ramp\n")
L.append(f"- **Knee (largest concurrency that held): {r.get('knee') if r.get('knee') is not None else 'not reached'}**")
L.append(f"- Read-p95 ceiling used: {r.get('ceiling_ms','—')} ms · steps attempted: {r.get('steps_run', [])}")
if r.get("degraded_at"):
    d = r["degraded_at"]
    L.append(f"- First degradation at {d.get('step')} agents — read p95 {num(d.get('read_p95'))} ms, "
             f"{d.get('errors')} error(s)")
L.append("")

L.append("### Availability, database, and what was written\n")
L.append("| Measure | Value |\n|---|---|")
L.append(f"| Availability (independent 1 Hz sampler) | {av_pct}% over {av_n} samples |")
L.append(f"| Health-probe p95 | {av_p95} ms |")
L.append(f"| Peak DB connections | {pg_peak} of {pg_max} |")
L.append(f"| Deadlocks / rollbacks during contention | {pg_dead} / {pg_rb} |")
led = run.get("ledger", {})
L.append(f"| Notes written (agent ledger) | {led.get('notes','—')} |")
L.append(f"| Adjudications written | {len(led.get('reclassify', []))} |")
L.append(f"| Exports completed / refused | {led.get('export_ok','—')} / {led.get('export_denied','—')} |")
conf = run.get("confidentiality", {})
L.append(f"| RBAC refusals counted as correct | {conf.get('expected_403','—')} |")
L.append(f"| Confidentiality violations | {len(conf.get('violations', []))} |")
L.append("")

open(md_f, "w").write("\n".join(L))
json.dump({"agents": n_users, "activity_seconds": activity_s,
           "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "provision": p, "storm": s, "activity": act, "ramp": r,
           "availability": {"pct": av_pct, "samples": av_n, "p95_ms": av_p95},
           "database": {"peak_connections": pg_peak, "max_connections": pg_max,
                        "deadlocks": pg_dead, "rollbacks": pg_rb},
           "ledger": led, "confidentiality": conf},
          open(json_f, "w"), indent=2)
print("\n".join(L))
PY

info "measurements: test/results/58-load-measurements.md (table) + .json (for comparison against the next run)"

report_finish
exit "${FAILED}"
