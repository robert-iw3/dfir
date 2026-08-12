#!/usr/bin/env bash
# ==============================================================================
# CAPSTONE UAT — the consolidated deployment, end to end. The segment UATs each prove one
# property.
#
#
#
# ==============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"

. "${HERE}/lib/report.sh"
report_begin 60 full_stack "Evidence pipeline — collection to enclave" \
    "Sealed evidence ships from a collector over pinned TLS, is held opaque in the DMZ, and is pulled inward by the enclave with custody intact."
DEPLOY="${PLATFORM}/deploy"
RUNTIME="${IR_RUNTIME:-podman}"


# shellcheck source=lib/evidence.sh
. "${HERE}/lib/evidence.sh"

[[ -f "${DEPLOY}/.env" ]] || cp "${DEPLOY}/.env.example" "${DEPLOY}/.env"
set -a; . "${DEPLOY}/.env"; set +a
PLATFORM_HOST="${IR_PLATFORM_URL#*://}"; PLATFORM_HOST="${PLATFORM_HOST%%[:/]*}"

c()  { ${RUNTIME} exec "$1" "${@:2}"; }
# Portable TCP reachability probe. The minimal tier images ship python but not nc/curl,
# so probing with nc would hang or false-pass; python is present everywhere.
tcp() { # container host port [timeout]
    ${RUNTIME} exec "$1" sh -c "python3 -c \"import socket;socket.create_connection(('$2',$3),timeout=${4:-4})\" 2>/dev/null || python -c \"import socket;socket.create_connection(('$2',$3),timeout=${4:-4})\" 2>/dev/null" >/dev/null 2>&1
}
be() { c ir-enclave_backend_1 "$@"; }

say "1/9  Deploy all tiers (enclave + DMZ + workstation)"
bash "${DEPLOY}/deploy.sh" down all >/dev/null 2>&1
bash "${DEPLOY}/deploy.sh" all >/dev/null 2>&1 || { bad "deployment failed"; }
echo "  waiting for the enclave API ..."
for i in $(seq 1 80); do be curl -fsS --max-time 3 http://127.0.0.1:8000/api/health/ >/dev/null 2>&1 && break
                        be python -c "import urllib.request as u;u.urlopen('http://127.0.0.1:8000/api/health/',timeout=3)" >/dev/null 2>&1 && break; sleep 3; done
be python -c "import urllib.request as u;u.urlopen('http://127.0.0.1:8000/api/health/',timeout=4)" >/dev/null 2>&1 \
    && ok "enclave API healthy" || bad "enclave API never came up"
for svc in ir-dmz_receiver_1 ir-dmz_broker_1 ir-dmz_coredns_1 ir-enclave_puller_1 ir-enclave_worker_1 ir-enclave_traefik_1; do
    [[ "$(${RUNTIME} inspect "$svc" --format '{{.State.Status}}' 2>/dev/null)" == "running" ]] \
        && ok "$svc running" || bad "$svc not running"
done

say "2/9  Tier isolation: the DMZ cannot reach into the enclave"
for t in "backend 8000 enclave API" "db 5432 database" "minio 9000 object store"; do
    set -- $t; h="$1"; p="$2"; label="${3} ${4:-}"
    if tcp ir-dmz_receiver_1 "$h" "$p"; then
        bad "DMZ receiver reached the ${label} — must have NO route"
    else
        ok "DMZ receiver → ${label}: BLOCKED"
    fi
done

# And from the ENDPOINT's side: a probe on the edge segment — where a possibly compromised
# collector lives — reaches the receiver and nothing past it. The receiver's own containment
# above does not imply this: these are two different segments with two different routes.
RECV_ADDR="$(${RUNTIME} inspect ir-dmz_receiver_1 \
    --format '{{(index .NetworkSettings.Networks "ir-edge").IPAddress}}' 2>/dev/null)"
edgeprobe() { # host port
    ${RUNTIME} run --rm --network ir-edge localhost/ir-workstation:latest \
        python3 -c "import socket;socket.create_connection(('$1',$2),timeout=4)" >/dev/null 2>&1
}
if [[ -n "${RECV_ADDR}" ]]; then
    edgeprobe "${RECV_ADDR}" 8090 \
        && ok "edge endpoint → DMZ receiver: reachable (the ONE permitted flow)" \
        || bad "edge endpoint cannot reach the receiver — collection is dead"
else
    bad "receiver has no address on ir-edge — collectors have nothing to ship to"
fi
for t in "backend 8000" "db 5432" "minio 9000"; do
    set -- $t
    edgeprobe "$1" "$2" \
        && bad "edge endpoint reached enclave $1:$2 — a compromised collector must have NO route inward" \
        || ok "edge endpoint → enclave $1:$2: BLOCKED"
done

say "3/9  Endpoint ships evidence to the DMZ (the only thing it can reach)"
WORK="$(mktemp -d)"; HOST=capstone-endpoint
IR_INCIDENT_ID="${IR_INCIDENT_ID}" mk_evidence_bundle "$WORK" "$HOST" "${IR_CUSTODY_HMAC_KEY}"
BUNDLE=$(tar_bundle "$WORK" "$HOST")
# Over TLS with the receiver's own certificate as the ONLY trust anchor — the same pinning a
# collector uses. Plain HTTP reaches nothing here, which is the point of the listener.
recv() { curl -s --cacert "${PLATFORM}/dmz/certs/receiver.crt" \
              --resolve "receiver:${RECEIVER_PORT}:127.0.0.1" \
              "$@" "https://receiver:${RECEIVER_PORT}${RECV_PATH}"; }
RECV_PATH=/ingest
CODE=$(recv -o /dev/null -w '%{http_code}' -X POST --data-binary @"$BUNDLE")
[[ "$CODE" == "202" ]] && ok "DMZ receiver accepted + custody-verified the bundle over pinned TLS (${CODE})" \
                       || bad "receiver rejected a good bundle (${CODE})"
# and a tampered one is refused
cp -r "$WORK/$HOST" "$WORK/bad"; echo tampered >> "$WORK/bad/memory_${HOST}.raw"
tar czf "$WORK/bad.tar.gz" -C "$WORK" bad
BCODE=$(recv -o /dev/null -w '%{http_code}' -X POST --data-binary @"$WORK/bad.tar.gz")
[[ "$BCODE" == "400" ]] && ok "tampered bundle quarantined (${BCODE})" || bad "tampered bundle not rejected (${BCODE})"
# The listener is TLS-only: an unencrypted post must not be served at all.
PLAIN=$(curl -s -o /dev/null -w '%{http_code}' --max-time 6 \
        -X POST --data-binary @"$BUNDLE" "http://127.0.0.1:${RECEIVER_PORT}/ingest" 2>/dev/null)
[[ "${PLAIN}" == "000" ]] && ok "the receiver refuses plaintext — evidence cannot be shipped unencrypted" \
                          || bad "the receiver answered a plaintext post (${PLAIN})"

say "4/9  The enclave PULLS it in (nothing pushed inward)"
INGESTED=0
for i in $(seq 1 40); do
    S=$(platform_stats ir-enclave_backend_1 "${IR_BROKER_TOKEN}")
    printf '%s' "$S" | grep -q '"runs": *[1-9]' && { INGESTED=1; break; }
    sleep 3
done
[[ $INGESTED -eq 1 ]] && ok "enclave pulled and ingested the evidence" || bad "evidence never reached the enclave"
# The puller polls on an interval; give it a few cycles before asserting the drain.
for _ in $(seq 1 12); do
    RECV_PATH=/pending
    PEND=$(recv -f 2>/dev/null | python3 -c "import sys,json;print(len(json.load(sys.stdin)['pending']))" 2>/dev/null)
    RECV_PATH=/ingest
    [[ "${PEND:-1}" == "0" ]] && break; sleep 5
done
[[ "${PEND:-1}" == "0" ]] && ok "DMZ holding drained after the pull" || bad "DMZ still holding ${PEND} bundle(s)"

say "5/9  DATA FLOW: evidence is stored, analyzed and renderable"
assert_data_flow ir-enclave_backend_1 "${IR_BROKER_TOKEN}" 4
# server-side analysis of the capture actually produced findings
# Counted from `finding_count`, not from an embedded list: a Volatility pass yields thousands
# of findings, so the serializer reports analyses by shape and the detail is paginated
# separately. Reading a `findings` array here would assert a response the API does not send.
# THIS suite's run, resolved by the hostname it collected — never a hardcoded id, which
# names whatever happened to ingest first on this database.
for i in $(seq 1 40); do
    RUN=$(be python -c "
import urllib.request as u, json
def get(p):
    r=u.Request('http://127.0.0.1:8000/api'+p,headers={'Authorization':'Token ${IR_BROKER_TOKEN}'})
    return json.load(u.urlopen(r,timeout=8))
h=get('/hosts/?search=${HOST}')
rows=h.get('results',h) if isinstance(h,dict) else h
rows=[x for x in rows if x.get('hostname')=='${HOST}']
runs=get('/hosts/%d/runs/'%rows[0]['id']) if rows else []
runs=runs.get('results',runs) if isinstance(runs,dict) else runs
rid=max((r['id'] for r in runs),default=None)
d=get('/runs/%d/'%rid) if rid else {}
caps=d.get('captures',[])
print(sum(a.get('finding_count',0) for c in caps for a in c.get('analyses',[])))" 2>/dev/null)
    [[ "${RUN:-0}" -gt 0 ]] && break; sleep 3
done
[[ "${RUN:-0}" -gt 0 ]] && ok "sandboxed memory analysis produced ${RUN} finding(s) from the stored capture" \
                        || bad "server-side memory analysis produced no findings"

say "6/9  The analysis sandbox has no egress; the enclave cannot phone home"
c ir-enclave_worker_1 python -c "import socket;socket.create_connection(('1.1.1.1',80),timeout=5)" >/dev/null 2>&1 \
    && bad "analysis sandbox reached the internet" || ok "analysis sandbox → internet: BLOCKED (no C2 egress)"

say "7/9  Analyst path: brokered to the SSO app, blind to everything else"
# Note: analysts (VLAN 40) and collection endpoints (VLAN 50) are separate segments in the
# deployed design, so a workstation cannot reach the evidence receiver. Both share ir-edge
# in this single-host model, so that separation is asserted by the firewall policy in
# deploy/NETWORKING.md (rows 1 and 2), not here.
WS=ir-workstation_probe_1
# Start the probe with the DMZ resolver explicitly — it must resolve exactly as the
# analyst browser does, or the DNS-containment assertion tests the wrong path.
${RUNTIME} rm -f "$WS" >/dev/null 2>&1
${RUNTIME} run -d --name "$WS" --network ir-edge --dns "${DNS_EDGE_IP}" \
    localhost/ir-workstation:latest sleep infinity >/dev/null 2>&1
sleep 4
FE=$(c "$WS" curl -sk -o /dev/null -w '%{http_code}' --max-time 8 "${IR_PLATFORM_URL}" 2>/dev/null)
[[ "$FE" == "200" || "$FE" == "401" || "$FE" == "302" ]] \
    && ok "workstation → SSO-gated web app via the broker (HTTP ${FE})" || bad "workstation cannot reach the app (${FE})"
for t in "backend 8000 API" "db 5432 database" "minio 9000 object store"; do
    set -- $t; h="$1"; p="$2"; label="${3} ${4:-}"
    if tcp "$WS" "$h" "$p"; then
        bad "workstation reached ${label} — must have NO route"
    else
        ok "workstation → ${label}: BLOCKED"
    fi
done
RES=$(c "$WS" dig +short +time=2 +tries=1 ir-platform.local A 2>/dev/null | head -1)
[[ -n "$RES" ]] && ok "platform name resolves to the broker (${RES})" || bad "platform name did not resolve"
# Asserted as "no address comes back", not as an rcode. The container runtime runs its own DNS
# proxy at the network gateway and forwards to the resolver named by --dns; that proxy rewrites
# the resolver's REFUSED into NXDOMAIN, so a client can never observe the policy's own rcode.
ANS=$(c "$WS" dig +short +time=2 +tries=1 exfil.attacker.example A 2>/dev/null | grep -c .)
PUB=$(c "$WS" dig +short +time=3 +tries=1 example.com A 2>/dev/null | grep -c .)
[[ "${ANS:-1}" == "0" && "${PUB:-1}" == "0" ]] \
    && ok "no out-of-zone name resolves from the analyst segment (no DNS exfil)" \
    || bad "DNS resolved an out-of-zone name — exfil channel open (attacker=${ANS}, public=${PUB})"
# And the policy itself, read from the resolver directly — REFUSED is the DMZ resolver's
# answer for anything outside its zones, which is what the proxy above is masking.
POLICY=$(c "$WS" dig "@${DNS_EDGE_IP}" +time=3 +tries=1 exfil.attacker.example A 2>/dev/null | grep -c "status: REFUSED")
[[ "${POLICY:-0}" -ge 1 ]] \
    && ok "the DMZ resolver REFUSES out-of-zone queries (in-zone answers only)" \
    || bad "the DMZ resolver did not refuse an out-of-zone query"

say "8/9  All roles complete the REAL browser OIDC flow"
for _ in $(seq 1 12); do
    ${RUNTIME} run --rm --network ir-edge --dns "${DNS_EDGE_IP}" localhost/ir-workstation:latest \
        [[ $(dig +short +time=2 +tries=1 "${PLATFORM_HOST}" 2>/dev/null | grep -c .) -gt 0 ]] && break
    sleep 5
done
#
# A ROPC token request does NOT exercise the callback — an issuer/host bug once hid behind a
# green SSO UAT for exactly that reason. This drives the true authorization-code flow.
via_broker() {  # <driver.py> <args...>
    local driver="$1"; shift
    local out
    for _ in 1 2 3; do
        out=$(${RUNTIME} run --rm --network ir-edge --dns "${DNS_EDGE_IP}" \
            -v "${HERE}/lib/${driver}:/t.py:ro,z" localhost/ir-workstation:latest \
            python3 /t.py "${PLATFORM_PUBLIC_URL}" "${IR_PLATFORM_URL}" "$@" 2>&1 | tail -1)
        grep -qE "URLError|Connection reset|Connection refused" <<<"${out}" || break
        sleep 8
    done
    printf '%s' "${out}"
}

#
# THROWAWAY accounts, one per role, created and deleted here. NOT `provision-demo-users.sh
# --force default-<role>`: that deletes and recreates the real account, resetting every password
# an analyst set to the .env default with a forced change pending.
kc() {
    ${RUNTIME} exec -i ir-enclave_keycloak_1 sh -c '
        /opt/keycloak/bin/kcadm.sh config credentials --server http://127.0.0.1:8080 \
            --realm master --user "${KC_BOOTSTRAP_ADMIN_USERNAME:-admin}" \
            --password "${KC_BOOTSTRAP_ADMIN_PASSWORD:-admin}" >/dev/null 2>&1 &&
        /opt/keycloak/bin/kcadm.sh "$@" 2>&1' -- "$@"
}
kc_uid() { kc get users -r irplatform -q "username=$1" -q exact=true --fields id \
    | tr -d ' \n' | sed -n 's/.*"id":"\([^"]*\)".*/\1/p'; }

INITIAL='Uat-Initial-Pw1!aaaa'
for role in admin analyst auditor; do
    U="uat-flow-${role}"
    # A full profile: an account without one carries a pending profile action, and the
    # authorization-code flow then fails "Account is not fully set up" — which reads as a
    # broken login rather than an incomplete fixture.
    OLD="$(kc_uid "${U}")"; [[ -n "${OLD}" ]] && kc delete "users/${OLD}" -r irplatform >/dev/null 2>&1
    kc create users -r irplatform -s "username=${U}" -s enabled=true \
        -s firstName=UAT -s "lastName=${role}" \
        -s "email=${U}@uat.invalid" -s emailVerified=true >/dev/null 2>&1
    UID_="$(kc_uid "${U}")"
    [[ -n "${UID_}" ]] || bad "${U}: could not be created — the flow below proves nothing"
    # Same group as the real account, so role mapping is exercised, and the same forced
    # first-login change the deployed accounts carry.
    GID="$(kc get groups -r irplatform -q "search=${role}" --fields id,name \
        | python3 -c "import json,sys; gs=json.load(sys.stdin); print(next((g['id'] for g in gs if g['name']=='${role}'), ''))" 2>/dev/null)"
    [[ -n "${GID}" ]] && kc update "users/${UID_}/groups/${GID}" -r irplatform -n >/dev/null 2>&1
    kc set-password -r irplatform --userid "${UID_}" --new-password "${INITIAL}" >/dev/null 2>&1
    kc update "users/${UID_}" -r irplatform -s 'requiredActions=["UPDATE_PASSWORD"]' >/dev/null 2>&1

    ROTATED="Uat-Rotated-Pw1!$(date +%s)"
    OUT=$(via_broker oidc_login.py "${U}" "${INITIAL}" "${ROTATED}")
    printf '%s' "$OUT" | grep -q '^OK:' && ok "${role}: browser OIDC login end to end (forced first-login change completed)" \
                                        || bad "${role} login failed — ${OUT}"

    # Sign-out must end the IdP session too, not just the gate cookie. A surviving Keycloak
    # session re-authenticates the next request silently, so the app still answers 200 and
    # the user is never signed out — this asserts the browser lands back on the login form.
    OUT=$(via_broker oidc_logout.py "${U}" "${ROTATED}")
    printf '%s' "$OUT" | grep -q '^OK:' && ok "${role}: sign-out ends app + IdP session" \
                                        || bad "${role} sign-out incomplete — ${OUT}"

    UID2="$(kc_uid "${U}")"
    [[ -n "${UID2}" ]] && kc delete "users/${UID2}" -r irplatform >/dev/null 2>&1
done
# The real accounts must be exactly as the deploy left them — untouched by the run above.
for role in admin analyst auditor reverse-engineer; do
    kc_uid "default-${role}" >/dev/null
done
STILL="$(kc get users -r irplatform --fields username 2>/dev/null | grep -c '"username"')"
[[ "${STILL:-0}" -ge 4 ]] \
    && ok "the deployed accounts are still present and untouched (${STILL} users) — this suite set no analyst password" \
    || bad "demo accounts are missing after the login suite (${STILL})"

say "8a/9  A dead sign-in callback offers the analyst a way back"
#
# The failure an analyst actually hits: an expired or evicted CSRF cookie, or Keycloak recreated
# mid-flow, produces a callback it no longer recognizes. Refreshing resubmits the same dead
# callback, and in the kiosk there is no address bar — so a page with no link out stranded the
# analyst until an operator restarted the browser container.
#
DEAD=$(${RUNTIME} exec ir-enclave_backend_1 python3 -c "
import urllib.request as u
url = ('http://keycloak:8080/realms/irplatform/login-actions/authenticate'
       '?code=dead-uat-code&execution=00000000-0000-0000-0000-000000000000'
       '&client_id=ir-platform&tab_id=uat')
try:
    print(u.urlopen(url, timeout=10).read().decode())
except Exception as e:
    body = getattr(e, 'read', lambda: b'')()
    print(body.decode() if body else '')
" 2>/dev/null)
if [[ -z "${DEAD}" ]]; then
    bad "the identity provider returned nothing for a dead callback — cannot assert recovery"
else
    grep -q 'id="backToApplication"' <<<"${DEAD}" \
        && ok "the error page carries a return link — the analyst is not stranded" \
        || bad "the error page has NO way back (the stock template omits it without a client context)"
    grep -qi 'Returning to sign-in\|irAuthRetryCount' <<<"${DEAD}" \
        && ok "it returns to a fresh sign-in on its own, for a kiosk nobody is sitting at" \
        || bad "no automatic return — an unattended kiosk stays on the dead page"
    # A hot redirect loop hides the error text and looks like a hung platform; the counter
    # is what keeps self-healing from becoming that.
    grep -q 'LIMIT' <<<"${DEAD}" \
        && ok "the automatic return is bounded — it stops rather than looping on a persistent fault" \
        || bad "the automatic return is unbounded — a persistent fault would spin"
fi

say "8b/9  The kiosk can SAVE an export without the dialog that aborts it"
# Exporting an IOC bundle crashed Firefox every time: 'ask where to save' opens the GTK file
# chooser, and this container has no desktop portal, no dbus and software rendering — the
# dialog aborts the process. The server-side export assertion stayed green throughout, which
# is why it hid, so the proof has to happen in the browser that actually crashed.
BR=ir-workstation_browser_1
if [[ "$(${RUNTIME} inspect "${BR}" --format '{{.State.Status}}' 2>/dev/null)" != "running" ]]; then
    bad "${BR} is not running — the analyst's download path cannot be proven"
else
    DLDIR=/home/analyst/downloads
    ${RUNTIME} exec "${BR}" test -w "${DLDIR}" \
        && ok "the kiosk has a writable fixed download directory (${DLDIR})" \
        || bad "${DLDIR} is missing or unwritable — Firefox falls back to the dialog that aborts"

    # The export has to reach the HOST. Writing into the container's own filesystem looks
    # identical from inside and is destroyed with the container, so the analyst's handoff
    # is only real if a file written in the kiosk appears on the host side of the mount.
    HOSTDIR="$(${RUNTIME} inspect "${BR}" \
        --format '{{range .Mounts}}{{if eq .Destination "'"${DLDIR}"'"}}{{.Source}}{{end}}{{end}}' 2>/dev/null)"
    if [[ -z "${HOSTDIR}" ]]; then
        bad "nothing is mounted at ${DLDIR} — an export dies with the container"
    else
        # The path is used, never recorded. What matters is that the mount resolves to the
        # host at all; naming the operator's home directory in a report that is published
        # tells a reader nothing they need and identifies the machine the run happened on.
        ok "the download directory resolves to a path on the host, not inside the container"
        STAMP="uat-export-$(date +%s).json"
        ${RUNTIME} exec "${BR}" sh -c "printf '{\"uat\":\"handoff\"}' > ${DLDIR}/${STAMP}" 2>/dev/null
        if [[ -f "${HOSTDIR}/${STAMP}" ]]; then
            ok "a file written in the kiosk IS readable on the host — the handoff completes"
            rm -f "${HOSTDIR}/${STAMP}"
        else
            bad "written in the kiosk but absent on the host — the export never leaves the container"
        fi
    fi
    # The DEPLOYED policy, read out of the running container: the repo file proves the repo.
    POL=$(${RUNTIME} exec "${BR}" cat /etc/firefox/policies/policies.json 2>/dev/null)
    UDD=$(printf '%s' "${POL}" | python3 -c "
import json,sys
p=json.load(sys.stdin)['policies']['Preferences']
print(p.get('browser.download.useDownloadDir',{}).get('Value'), p.get('browser.download.dir',{}).get('Value'))" 2>/dev/null)
    [[ "${UDD}" == "True ${DLDIR}" ]] \
        && ok "the running kiosk saves to that directory and cannot be redirected (${UDD})" \
        || bad "the deployed policy still asks where to save (${UDD:-unreadable})"
    # Attempt the thing that crashed: a real save, in the real image, of the real MIME type.
    ${RUNTIME} exec "${BR}" sh -c '
        rm -f /home/analyst/downloads/uat-save-probe* 2>/dev/null
        timeout 40 firefox --headless --profile /tmp/uat-dl-probe \
            "data:application/json;base64,eyJ1YXQiOiJzYXZlLXByb2JlIn0=" >/dev/null 2>&1
        sleep 3; ls /home/analyst/downloads/ | head -3' >/tmp/uat-dl.out 2>&1
    RC=$?
    # 134 = SIGABRT, the crash this fixes. A timeout (124) is not a pass either.
    [[ "${RC}" != "134" ]] \
        && ok "Firefox did not abort handling a download (rc=${RC})" \
        || bad "Firefox ABORTED on the save path — the file dialog is still being opened"
fi

say "9/9  Identity + audit are enforced across the consolidated stack"
KC=$(${RUNTIME} logs ir-enclave_keycloak_1 2>&1 | grep -c "Listening on")
[[ "${KC:-0}" -ge 1 ]] && ok "Keycloak serving (SSO identity source)" || bad "Keycloak not available"
AUD=$(be python -c "
import urllib.request as u, json
r=u.Request('http://127.0.0.1:8000/api/audit/',headers={'Authorization':'Token ${IR_BROKER_TOKEN}'})
try: print(json.load(u.urlopen(r,timeout=8)).get('chain_intact'))
except Exception as e: print('denied')" 2>/dev/null)
[[ "$AUD" == "True" || "$AUD" == "denied" ]] && ok "tamper-proof audit chain present (service token scope: ${AUD})" \
                                              || bad "audit chain unavailable (${AUD})"

rm -rf "$WORK"
say "Result"
if [[ ${FAILED} -eq 0 ]]; then
    printf '\033[1;32m  CAPSTONE PASSED\033[0m — consolidated deployment proves the end-state vision end to end.\n'
else
    printf '\033[1;31m  CAPSTONE FAILED\033[0m (see above)\n'
fi
info "Web app (via broker): ${IR_PLATFORM_URL}   ·  tiers: ir-enclave / ir-dmz / ir-workstation"
[[ "${KEEP_UP:-0}" == "1" ]] || bash "${DEPLOY}/deploy.sh" down all >/dev/null 2>&1
report_finish
exit ${FAILED}
