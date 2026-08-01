#!/usr/bin/env bash
# ==============================================================================
# BOUNDARY UAT — the security model of brokered enclave access, asserted.
#
# The analyst's hop into the enclave is a Boundary SESSION. This proves the claims the design
# rests on, rather than that the containers are running:
#
#   1. IT CARRIES TRAFFIC. A session that authorizes and then carries nothing looks identical to
#      a working one from every other angle — the container is up, the listener is bound, the
#      controller shows a session. Only a request that comes back proves the path.
#
#   2. AUTHORITY IS IN THE ENCLAVE. The controller, its database, the grants and the encryption
#      roots are all in the tier the design trusts. The DMZ holds no recovery key, no database,
#      no grants and no worker — losing it yields a session client and the analyst credential,
#      not the ability to mint access.
#
#   3. THE ALLOW-LIST IS ONE TARGET. Exactly one target exists, so a service in the enclave with
#      no target has no route regardless of what the network permits.
#
#   4. SESSIONS ARE ATTRIBUTABLE. Each is bound to a principal with an account. A session that
#      cannot be traced to an identity is an unauthenticated forwarder with extra steps.
#
#   5. THE DMZ HAS NO ROUTE OF ITS OWN. The bastion cannot reach the enclave ingress directly;
#      only the brokered session gets there.
#
#   6. NOTHING CROSSES THE LINK IN THE CLEAR. The credential and the session token go over TLS
#      pinned to the controller's certificate; the session data path is Boundary's own per-session
#      TLS. The client refuses a plaintext controller address outright.
#
# Every check runs from a running container, against the deployment the codebase produced.
# ==============================================================================
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
LISTEN="${BROKER_LISTEN:-8443}"


running() { [[ "$(${RUNTIME} inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" == "true" ]]; }

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

workers="$(bctl workers list -scope-id global)"
n_workers="$(grep -o '"id":"w_[^"]*"' <<<"${workers}" | wc -l)"
[[ "${n_workers}" == "1" ]] \
    && ok "exactly one worker is registered — no stale registration to hand a session to" \
    || bad "expected 1 registered worker, found ${n_workers} (a stale one makes some sessions hang)"
grep -q '"address":"'"${BOUNDARY_EGRESS_HOST:-boundary-egress}"':9202"' <<<"${workers}" \
    && ok "the worker advertises the enclave egress address" \
    || bad "the registered worker advertises an unexpected address"

# ============================================================ 4. attributable to a principal
say "Attribution"
sessions="$(bctl sessions list -scope-id "${BOUNDARY_PROJECT_ID:-}" -recursive)"
if grep -q '"status":"active"\|"status":"pending"' <<<"${sessions}"; then
    ok "a live session exists"
    uid="$(grep -o '"user_id":"u_[^"]*"' <<<"${sessions}" | head -1 | cut -d'"' -f4)"
    if [[ -n "${uid}" ]]; then
        ok "the session is bound to principal ${uid}"
        [[ "${uid}" == "${BOUNDARY_ANALYST_USER_ID:-}" ]] \
            && ok "that principal is the provisioned analyst" \
            || bad "the session belongs to ${uid}, not the analyst ${BOUNDARY_ANALYST_USER_ID:-unset}"
    else
        bad "the session carries no user — it is an anonymous forwarder"
    fi
else
    bad "no live session — the broker is listening with nothing behind it"
fi

# ============================================================ 5. traffic actually flows
say "The session carries traffic"
# The whole point, and the one thing every other check can pass without. The request is made from
# the BASTION's namespace, which is where the broker's listener lives and where an analyst's
# browser arrives. A response proves: listener -> session -> egress worker -> Traefik.
#
# --insecure only because the ingress presents the platform's own self-signed certificate, which
# is a separate trust relationship from Boundary's; what is under test here is reachability.
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
# Enclave rebuilds, worker recreation, expiry and fatal proxy errors all end the session, and
# the analyst workstation — on an endpoint device — cannot know any of it happened. The broker
# must come back on its own. Proven by the harshest version: cancel its live session out from
# under it and require a NEW session carrying traffic, unattended.
before="$(bctl sessions list -scope-id "${BOUNDARY_PROJECT_ID:-}" -recursive)"
live_sid="$(grep -o '"id": *"s_[^"]*"' <<<"${before}" | head -1 | cut -d'"' -f4)"
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
        && ok "session ${live_sid} was canceled and the broker re-established unattended — traffic flows again" \
        || bad "the brokered listener never recovered after its session was canceled"
    after_sid="$(bctl sessions list -scope-id "${BOUNDARY_PROJECT_ID:-}" -recursive \
        | grep -o '"id": *"s_[^"]*"' | head -1 | cut -d'"' -f4)"
    [[ -n "${after_sid}" && "${after_sid}" != "${live_sid}" ]] \
        && ok "the recovery is a NEW authorized session (${after_sid}), not a lingering socket" \
        || bad "no new session after recovery — traffic would be flowing outside a session"
else
    bad "no live session to disrupt — the healing property cannot be proven"
fi

# ============================================================ 6. the DMZ has no route of its own
say "The DMZ has no route of its own"
# Same container, same moment, bypassing the session: the ingress by name, directly. It must fail.
# If this succeeds the broker is decorative — the session is one way in among others.
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

verdicts="$(${RUNTIME} exec -i -w /app \
        -e TRUTH="${truth}" \
        -e BROKER_IP="${broker_ip}" \
        -e ANALYST="${BOUNDARY_ANALYST_LOGIN:-analyst}" \
        "${BE}" python - <<'PY' 2>/dev/null
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

t = os.environ["TRUTH"]
truth = json.loads(t[t.find("{"):t.rfind("}") + 1]).get("items") or []

page_ids = {s["id"] for s in page.get("sessions", [])}
truth_ids = {i["id"] for i in truth}
say(page_ids == truth_ids,
    f"the record is complete: page {len(page_ids)} sessions, controller {len(truth_ids)}, id sets match")

truth_live = [i for i in truth if i.get("status") in ("active", "pending")]
say(page.get("active") == len(truth_live),
    f"live count matches the controller ({page.get('active')} == {len(truth_live)})")

live = [s for s in page.get("sessions", []) if s.get("active")]
say(len(live) == 1,
    f"exactly one live session — the running broker, no ghosts of replaced brokers ({len(live)} live)")

broker_ip = os.environ.get("BROKER_IP", "")
got = live[0].get("client_address") if live else None
say(bool(broker_ip) and got == broker_ip,
    f"the live session's client address is the running broker ({got} == {broker_ip or 'unknown'})")

analyst = os.environ.get("ANALYST", "analyst")
say(bool(live) and live[0].get("principal") == analyst,
    f"the principal resolves to a name, not an id ({live[0].get('principal') if live else '-'})")

say(bool(live) and ((live[0].get("bytes_up") or 0) + (live[0].get("bytes_down") or 0)) > 0,
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
    bad "the authenticity cross-check produced no verdicts — the backend probe failed"
else
    while IFS= read -r line; do
        case "${line}" in
            OK\ *)   ok  "${line#OK }" ;;
            FAIL\ *) bad "${line#FAIL }" ;;
        esac
    done <<<"${verdicts}"
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
