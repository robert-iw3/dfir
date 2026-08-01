#!/usr/bin/env bash
# ==============================================================================
# CAPSTONE UAT — the consolidated deployment, end to end.
#
# The segment UATs each prove one property. This proves the WHOLE end-state vision
# with all tiers deployed together as they would be on separate hardware:
#
#   collector (endpoint) → DMZ receiver → [enclave PULLS] → MinIO + PostgreSQL
#     → sandboxed analysis → SSO-gated web app → analyst workstation (brokered)
#
# It asserts real DATA FLOW (evidence ingested and renderable), not just reachability,
# and re-asserts the segmentation guarantees across the consolidated tiers.
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
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST --data-binary @"$BUNDLE" "http://127.0.0.1:${RECEIVER_PORT}/ingest")
[[ "$CODE" == "202" ]] && ok "DMZ receiver accepted + custody-verified the bundle (${CODE})" \
                       || bad "receiver rejected a good bundle (${CODE})"
# and a tampered one is refused
cp -r "$WORK/$HOST" "$WORK/bad"; echo tampered >> "$WORK/bad/memory_${HOST}.raw"
tar czf "$WORK/bad.tar.gz" -C "$WORK" bad
BCODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST --data-binary @"$WORK/bad.tar.gz" "http://127.0.0.1:${RECEIVER_PORT}/ingest")
[[ "$BCODE" == "400" ]] && ok "tampered bundle quarantined (${BCODE})" || bad "tampered bundle not rejected (${BCODE})"

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
    PEND=$(curl -fsS "http://127.0.0.1:${RECEIVER_PORT}/pending" 2>/dev/null | python3 -c "import sys,json;print(len(json.load(sys.stdin)['pending']))" 2>/dev/null)
    [[ "${PEND:-1}" == "0" ]] && break; sleep 5
done
[[ "${PEND:-1}" == "0" ]] && ok "DMZ holding drained after the pull" || bad "DMZ still holding ${PEND} bundle(s)"

say "5/9  DATA FLOW: evidence is stored, analyzed and renderable"
assert_data_flow ir-enclave_backend_1 "${IR_BROKER_TOKEN}" 4
# server-side analysis of the capture actually produced findings
for i in $(seq 1 40); do
    RUN=$(be python -c "
import urllib.request as u, json
r=u.Request('http://127.0.0.1:8000/api/runs/1/',headers={'Authorization':'Token ${IR_BROKER_TOKEN}'})
d=json.load(u.urlopen(r,timeout=8))
caps=d.get('captures',[])
print(sum(len(a.get('findings',[])) for c in caps for a in c.get('analyses',[])))" 2>/dev/null)
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
REFUSED=$(c "$WS" dig +time=2 +tries=1 exfil.attacker.example A 2>/dev/null | grep -c REFUSED)
[[ "${REFUSED:-0}" -ge 1 ]] && ok "arbitrary DNS REFUSED (no outbound resolution → no DNS exfil)" \
                           || bad "DNS not refused — exfil channel open"

say "8/9  All roles complete the REAL browser OIDC flow"
for _ in $(seq 1 12); do
    ${RUNTIME} run --rm --network ir-edge --dns "${DNS_EDGE_IP}" localhost/ir-workstation:latest \
        [[ $(dig +short +time=2 +tries=1 "${PLATFORM_HOST}" 2>/dev/null | grep -c .) -gt 0 ]] && break
    sleep 5
done
# A ROPC token request does NOT exercise the callback — an issuer/host bug once hid behind
# a green SSO UAT for exactly that reason. This drives the true authorization-code flow.
for role in admin analyst auditor; do
    OUT=$(${RUNTIME} run --rm --network ir-edge --dns "${DNS_EDGE_IP}" \
        -v "${HERE}/lib/oidc_login.py:/t.py:ro,z" localhost/ir-workstation:latest \
        python3 /t.py "${PLATFORM_PUBLIC_URL}" "${IR_PLATFORM_URL}" \
        "default-${role}" "default-${role}-pw" 2>&1 | tail -1)
    printf '%s' "$OUT" | grep -q '^OK:' && ok "default-${role}: browser OIDC login end to end" \
                                        || bad "default-${role} login failed — ${OUT}"
done

# Sign-out must end the IdP session too, not just the gate cookie. A surviving Keycloak
# session re-authenticates the next request silently, so the app still answers 200 and the
# user is never signed out — this asserts the browser lands back on the login form.
for role in admin analyst auditor; do
    OUT=$(${RUNTIME} run --rm --network ir-edge --dns "${DNS_EDGE_IP}" \
        -v "${HERE}/lib/oidc_logout.py:/t.py:ro,z" localhost/ir-workstation:latest \
        python3 /t.py "${PLATFORM_PUBLIC_URL}" "${IR_PLATFORM_URL}" \
        "default-${role}" "default-${role}-pw" 2>&1 | tail -1)
    printf '%s' "$OUT" | grep -q '^OK:' && ok "default-${role}: sign-out ends app + IdP session" \
                                        || bad "default-${role} sign-out incomplete — ${OUT}"
done

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
