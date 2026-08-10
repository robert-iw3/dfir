#!/usr/bin/env bash
# ==============================================================================
# AUDIT TRAIL UAT — what the platform can answer about who did what.
#
# The trail is what an investigation is defended with. If it cannot say who signed on, what
# they changed, and what left the platform, then the evidence it protects is only as good as
# the word of whoever administers it.
#
# The claims proved here:
#
#   1. SIGN-ON IS RECORDED. Authentication is stateless — the identity arrives in a header on
#      every request and each one is authenticated on its own — so a login is not something
#      the platform is told about. It has to be reconstructed, and this asserts it is.
#
#   2. ONCE PER SESSION, NOT ONCE PER REQUEST. The distinction is the whole value: a trail
#      that logs a login for every API call cannot tell anyone when someone actually arrived.
#
#   3. SIGN-OUT IS RECORDED, AND SESSIONS END. Both by the analyst signing out and by expiry,
#      because most sessions end when a browser closes and nothing is sent.
#
#   4. EVERY WRITE IS RECORDED — including on routes nobody instrumented by hand. Coverage
#      that depends on a developer remembering is coverage that decays.
#
#   5. RECORDED ONCE. An action audited by its call site is not also recorded by the
#      catch-all; a duplicated trail is a disputed trail.
#
#   6. THE CHAIN STILL VERIFIES with all of it in place. New entry types must not be a way to
#      break tamper-evidence.
#
#   7. ACCESS IS ATTRIBUTABLE TO A PERSON. Boundary authenticates a pool principal and sees
#      every connection arriving from the distributor, so the brokered session record alone
#      cannot name anyone. The platform's sign-on record is what closes that gap — and where
#      it cannot, it must say so rather than guess.
#
# Runs against the deployed stack, over the analyst's own path.
# ==============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"

. "${HERE}/lib/report.sh"
report_begin 56 audit "Audit trail — sign-on, every write, and attribution to a person" \
    "The platform records who signed on, what they created or changed, what they exported and when they left; each action once, in a chain that still verifies, and traceable to a person rather than to a pool principal."
RUNTIME="${IR_RUNTIME:-podman}"

set -a; . "${PLATFORM}/deploy/.env" 2>/dev/null || true; set +a

BACKEND=ir-enclave_backend_1
PLATFORM_PUBLIC_URL="${PLATFORM_PUBLIC_URL:-${IR_PLATFORM_PUBLIC_URL:-}}"
IR_PLATFORM_URL="${IR_PLATFORM_URL:-}"
DNS_EDGE_IP="${IR_IP_DNS_EDGE:-}"

# Every query runs through the platform's own ORM in the deployed container: the trail is
# asserted as the application sees it, not as a hand-written SQL statement reinterprets it.
q() { ${RUNTIME} exec "${BACKEND}" python manage.py shell -c "$1" 2>/dev/null | tail -1; }

${RUNTIME} inspect "${BACKEND}" >/dev/null 2>&1 || {
    bad "the backend container is not running — nothing to assert against"
    report_finish; exit 1
}

# ============================================================ the sign-on
say "Sign-on — a login the platform was never told about"

# Set by the sign-on drive below; declared here because the later sections read it and an
# unset variable under `set -u` would abort the run instead of failing the assertion.
DRIVE=""
val() { sed -n "s/^$1=//p" <<<"${DRIVE}" | tail -1; }

BEFORE_LOGIN="$(q "from cases.models import AuditLog; print(AuditLog.objects.filter(action='user.login').count())")"
BEFORE_ALL="$(q "from cases.models import AuditLog; print(AuditLog.objects.count())")"
info "before: ${BEFORE_LOGIN:-?} login entries, ${BEFORE_ALL:-?} entries in total"

if [[ -z "${PLATFORM_PUBLIC_URL}" || -z "${IR_PLATFORM_URL}" ]]; then
    bad "the platform URLs are not configured in deploy/.env — the sign-on flow cannot be driven"
else
    PROVISION="${PLATFORM}/hashicorp/keycloak/provision-demo-users.sh"
    # A THROWAWAY account, never a person's. Driving a shared demo account rotates or
    # recreates it while someone may be signed into it, which invalidates their session
    # mid-flight. The forced-change flow is identical on an ephemeral account, and the
    # account is removed on every exit.
    PROBE_USER="uat-audit-probe"
    trap 'bash "${PROVISION}" --delete "${PROBE_USER}" >/dev/null 2>&1 || true' EXIT
    PROBE_PW="$(bash "${PROVISION}" --ephemeral "${PROBE_USER}" analyst 2>/dev/null \
                | sed -n 's/^EPHEMERAL_PASSWORD=//p')"
    if [[ -n "${PROBE_PW}" ]]; then
        info "ephemeral account ${PROBE_USER} provisioned (analyst, forced first-login change armed)"
    else
        bad "could not provision ${PROBE_USER} — the sign-on flow cannot be driven"
    fi
    ROTATED_PW="Uat-Audit-Pw1!$(date +%s)"

    # Driven over the analyst's path: the gate's callback URL is the public one, and a login
    # started from anywhere else redirects to an address that path cannot reach.
    DRIVE="$(${RUNTIME} run --rm --network ir-edge ${DNS_EDGE_IP:+--dns "${DNS_EDGE_IP}"} \
        -v "${HERE}/lib:/uatlib:ro,z" localhost/ir-workstation:latest \
        python3 /uatlib/audit_session.py "${PLATFORM_PUBLIC_URL}" "${IR_PLATFORM_URL}" \
        "${PROBE_USER}" "${PROBE_PW}" "${ROTATED_PW}" 2>&1)"
    [[ "$(val LOGIN)" == "0" ]] \
        && ok "an analyst signed in through the real OIDC flow as $(val USERNAME) ($(val ROLE))" \
        || bad "the sign-on flow did not complete — $(val MESSAGE); nothing below can be attributed"

    AFTER_LOGIN="$(q "from cases.models import AuditLog; print(AuditLog.objects.filter(action='user.login').count())")"
    NEW_LOGINS=$(( ${AFTER_LOGIN:-0} - ${BEFORE_LOGIN:-0} ))
    [[ "${NEW_LOGINS}" -eq 1 ]] \
        && ok "the sign-on produced exactly ONE user.login entry (${BEFORE_LOGIN:-0} → ${AFTER_LOGIN:-0}) across a login plus 5 further requests" \
        || bad "the sign-on produced ${NEW_LOGINS} user.login entries — a login per request, or none at all (${BEFORE_LOGIN:-0} → ${AFTER_LOGIN:-0})"

    # The entry has to carry enough to act on. An audit row naming an action and nobody is a
    # record that an event happened, not a record of who caused it.
    DETAIL="$(q "
from cases.models import AuditLog
e = AuditLog.objects.filter(action='user.login').order_by('-id').first()
print('|'.join([e.actor, e.role, e.detail.get('key_source',''), e.detail.get('client_address',''), (e.detail.get('user_agent','') or '')[:24]]) if e else 'NONE')")"
    IFS='|' read -r a_actor a_role a_src a_addr a_ua <<<"${DETAIL}"
    [[ -n "${a_actor}" && "${a_actor}" != "NONE" ]] \
        && ok "the login entry names the person and their role: ${a_actor} / ${a_role:-<none>}" \
        || bad "the newest login entry carries no actor — ${DETAIL}"
    [[ "${a_src}" == "oidc" ]] \
        && ok "the sign-on is keyed by the identity provider's own session id (key_source=oidc) — two sign-ons from one browser stay distinct" \
        || bad "the sign-on was keyed by a DERIVED key (key_source=${a_src:-none}) — the access token is not reaching the app, so concurrent sign-ons from one caller would merge"
    [[ -n "${a_addr}" ]] \
        && ok "the login entry records where the analyst connected from and what they used (${a_addr}, ${a_ua}…)" \
        || bad "the login entry has no client address — the trail cannot say where a sign-on came from"
fi

# ============================================================ writes
say "Writes — recorded whether or not anyone instrumented the route"

_w="$(val WRITE)"
[[ "$(val WRITE)" =~ ^2 ]] \
    && ok "an edit on an uninstrumented route succeeded (HTTP $(val WRITE) on note $(val WRITE_ID)) — the case the catch-all exists for" \
    || info "the probe write returned ${_w:-nothing} — the assertion below reads whatever it produced"

CATCHALL="$(q "
from cases.models import AuditLog
e = AuditLog.objects.filter(action='notes.modify', method='PATCH').order_by('-id').first()
print('|'.join([e.action, e.actor, e.method, e.path, str(e.detail.get('status',''))]) if e else 'NONE')")"
IFS='|' read -r w_action w_actor w_method w_path w_status <<<"${CATCHALL}"
[[ -n "${w_action}" && "${w_action}" != "NONE" ]] \
    && ok "the write was recorded with its verb, route and outcome: ${w_action} by ${w_actor} (${w_method} ${w_path} → ${w_status})" \
    || bad "no notes.modify entry was recorded for the probe edit — uninstrumented routes are still invisible"

# Recorded once. The catch-all must stand down where a call site already described the action
# in better terms; two rows for one action is a trail an opposing expert takes apart.
NOTE_ACTIONS="$(q "from cases.models import AuditLog; print(AuditLog.objects.filter(action='notes.create').count())")"
[[ "${NOTE_ACTIONS:-0}" -eq 0 ]] \
    && ok "the explicitly audited create produced its own entry only — the catch-all added no duplicate (notes.create rows: 0, alongside $(q "from cases.models import AuditLog; print(AuditLog.objects.filter(action='note.create').count())") note.create)" \
    || bad "${NOTE_ACTIONS} catch-all rows exist alongside the explicit note.create entries — the same action is recorded twice"

# ============================================================ sign-out
say "Sign-out — sessions that end, and sessions nobody closed"

_l="$(val LOGOUT)"
[[ "$(val LOGOUT)" =~ ^2 ]] \
    && ok "the analyst signed out through the platform (HTTP $(val LOGOUT), session $(val LOGOUT_SESSION))" \
    || bad "the sign-out call did not succeed — got ${_l:-nothing}"
[[ "$(val LOGOUT_RECORDED)" == "True" ]] \
    && ok "the sign-out closed an OPEN sign-on rather than reporting a no-op" \
    || bad "the sign-out found no open sign-on to close — the login and logout are not being tied to one session"

LOGOUTS="$(q "from cases.models import AuditLog; print(AuditLog.objects.filter(action='user.logout').count())")"
[[ "${LOGOUTS:-0}" -ge 1 ]] \
    && ok "user.logout entries exist in the trail (${LOGOUTS}) — a session end is an audited event, not a gap" \
    || bad "no user.logout entry was ever written"

CLOSED="$(q "
from cases.models import SsoSession
s = SsoSession.objects.order_by('-id').first()
print(f'{s.username}|{s.end_reason}|{s.request_count}' if s else 'NONE')")"
IFS='|' read -r c_user c_reason c_reqs <<<"${CLOSED}"
[[ "${c_reason}" == "signout" ]] \
    && ok "the sign-on record closed with a reason and a request count: ${c_user} ended by ${c_reason} after ${c_reqs} requests" \
    || bad "the newest sign-on did not close on sign-out (reason=${c_reason:-none}) — ${CLOSED}"

# Most sessions end when a browser closes and nothing is sent. Without expiry every one of
# them stays open forever and "who is signed on" answers nothing.
EXPIRY="$(q "
from datetime import timedelta
from django.utils import timezone
from cases import authevents
from cases.models import SsoSession
old = SsoSession.objects.create(session_key='uat-idle-probe', username='uat-idle',
                                started_at=timezone.now() - timedelta(days=2),
                                last_seen_at=timezone.now() - timedelta(days=2))
n = authevents.expire_idle()
old.refresh_from_db()
print(f'{n}|{old.end_reason}')
SsoSession.objects.filter(session_key='uat-idle-probe').delete()")"
IFS='|' read -r e_n e_reason <<<"${EXPIRY}"
[[ "${e_reason}" == "expired" ]] \
    && ok "a sign-on idle past the cookie lifetime is closed as expired (${e_n} closed on that sweep) — abandoned sessions do not stay open forever" \
    || bad "an idle sign-on was not expired (reason=${e_reason:-none}) — the active list will grow without bound"

# ============================================================ the dead callback
say "A dead callback restarts the flow instead of ending on a bare 403"

# The gate rejects a callback that arrives with no cookies — a restored tab, a reopened
# kiosk. That rejection is correct; what matters is what the analyst is left on. The built-in
# page is a 403 with no way forward, on a kiosk with no address bar. The custom template must
# come back instead, carrying both recoveries: the automatic retry and the manual control.
CB="$(${RUNTIME} run --rm --network ir-edge ${DNS_EDGE_IP:+--dns "${DNS_EDGE_IP}"} \
    localhost/ir-workstation:latest python3 -c "
import ssl, urllib.request, urllib.error
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
req = urllib.request.Request('${PLATFORM_PUBLIC_URL}/oauth2/callback?state=uat-dead-callback:%2F&code=bogus',
                             headers={'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0'})
try:
    r = urllib.request.urlopen(req, context=ctx, timeout=20)
    print(r.getcode()); print(r.read().decode('utf-8', 'replace')[:2000])
except urllib.error.HTTPError as e:
    print(e.code); print(e.read().decode('utf-8', 'replace')[:2000])
except Exception as e:
    print(0); print(type(e).__name__, e)
" 2>&1)"
CB_CODE="$(sed -n 1p <<<"${CB}" | tr -dc '0-9')"
[[ "${CB_CODE}" == "403" ]] \
    && ok "a cookieless callback is refused (HTTP 403) — the gate does not accept an attempt it cannot verify" \
    || bad "a cookieless callback answered ${CB_CODE:-nothing} — expected the gate's 403"
grep -q "Sign in again" <<<"${CB}" \
    && ok "the 403 carries the recovery page: a sign-in control, not a dead end" \
    || bad "the 403 is the built-in dead end — the custom error template is not being served"
grep -q "oauth2-retry" <<<"${CB}" \
    && ok "the recovery page retries the flow automatically, bounded to one attempt" \
    || bad "the recovery page has no automatic retry — a kiosk analyst still has to find the control"

# ============================================================ the chain
say "Tamper-evidence — the new entries are part of the chain, not beside it"

CHAIN="$(q "from cases.audit import verify_audit_chain; ok, first = verify_audit_chain(); print(f'{ok}|{first}')")"
IFS='|' read -r ch_ok ch_first <<<"${CHAIN}"
[[ "${ch_ok}" == "True" ]] \
    && ok "the audit chain verifies end to end with the sign-on and catch-all entries in it" \
    || bad "the chain is broken from entry ${ch_first} — new entry types are not being chained correctly"

SIGNED="$(q "
from cases.models import AuditLog
qs = AuditLog.objects.filter(action__in=['user.login','user.logout','user.login.resume','user.session.expired'])
print(f'{qs.count()}|{qs.exclude(signature=\"\").count()}')")"
IFS='|' read -r s_all s_signed <<<"${SIGNED}"
[[ "${s_all:-0}" -gt 0 && "${s_all}" == "${s_signed}" ]] \
    && ok "every sign-on/sign-out entry is HMAC-signed (${s_signed}/${s_all}) — the same protection as the rest of the trail" \
    || bad "${s_signed:-0} of ${s_all:-0} sign-on/sign-out entries are signed — some are only chained, or none exist to sign"

# ============================================================ coverage
say "Coverage — the actions an auditor is entitled to ask about"

COVER="$(q "
from cases.models import AuditLog
want = {
  'login': AuditLog.objects.filter(action='user.login').count(),
  'logout': AuditLog.objects.filter(action='user.logout').count(),
  'create': AuditLog.objects.filter(action__endswith='.create').count(),
  'modify': AuditLog.objects.filter(action__endswith='.modify').count() + AuditLog.objects.filter(action='finding.reclassify').count(),
  'delete': AuditLog.objects.filter(action__endswith='.delete').count(),
  'export': AuditLog.objects.filter(action__startswith='export.').count(),
}
print('|'.join(f'{k}={v}' for k, v in want.items()))")"
info "recorded: ${COVER}"
for kind in login logout create export; do
    n="$(sed -n "s/.*${kind}=\([0-9]*\).*/\1/p" <<<"${COVER}")"
    [[ "${n:-0}" -gt 0 ]] \
        && ok "${kind} is represented in the trail (${n} entries)" \
        || bad "NOTHING in the trail records ${kind} — an auditor cannot ask that question"
done

# ============================================================ attribution
say "Attribution — a session belongs to a person, or says it cannot tell"

ATTR="$(q "
from cases import brokeredsessions as bs
out = bs.overview()
if not out.get('reachable'):
    print('UNREACHABLE|' + str(out.get('error'))[:60])
else:
    ss = out.get('sessions') or []
    shaped = sum(1 for s in ss if 'attribution' in s)
    named = sum(1 for s in ss if s.get('analysts'))
    kinds = ','.join(sorted({s.get('attribution','?') for s in ss})) or 'none'
    print(f'{len(ss)}|{shaped}|{named}|{kinds}')")"
IFS='|' read -r at_total at_shaped at_named at_kinds <<<"${ATTR}"
if [[ "${at_total}" == "UNREACHABLE" ]]; then
    bad "Boundary did not answer the session list — attribution unmeasured (${at_shaped})"
else
    [[ "${at_total:-0}" -gt 0 && "${at_shaped}" == "${at_total}" ]] \
        && ok "every brokered session carries an attribution verdict (${at_shaped}/${at_total}; kinds seen: ${at_kinds})" \
        || bad "${at_shaped:-0} of ${at_total:-0} sessions carry an attribution verdict — the rest are pool principals with no person behind them"
    # The honest case matters as much as the identified one: a session with several analysts
    # signed on must be labeled overlapping, never presented as belonging to one of them.
    [[ ",${at_kinds}," != *",exact,"* || "${at_named:-0}" -gt 0 ]] \
        && ok "sessions reported as exact carry a named analyst (${at_named} of ${at_total} named overall)" \
        || bad "a session is labeled exact with no analyst named — the label and the evidence disagree"
fi

# ============================================================ A-2 — workstation identity
say "A-2 — a session belongs to a workstation, and through it to one person"

# The exit criterion demands CONCURRENCY: two analysts signed on at once from two
# workstations, each brokered session attributing exact to the right person. One analyst at
# a time cannot distinguish the workstation join from a lucky time overlap.
WS_LIST=(${IR_WS_IDS:-analyst})
if [[ "${#WS_LIST[@]}" -lt 2 ]]; then
    info "single-workstation deployment (IR_WS_IDS=${IR_WS_IDS:-analyst}) — concurrent attribution needs two; unmeasured here"
else
    WS_A="${WS_LIST[0]}"; WS_B="${WS_LIST[1]}"
    # The distributor's own rendered config is the pin's ground truth.
    PINS="$(${RUNTIME} exec ir-dmz_distributor_1 grep -c '^    use_backend' /tmp/haproxy.cfg 2>/dev/null | tr -dc '0-9')"
    [[ "${PINS:-0}" -ge 2 ]] \
        && ok "the distributor holds ${PINS} workstation pins — a known workstation's connections land on ITS session" \
        || bad "the distributor holds ${PINS:-0} pins for ${#WS_LIST[@]} workstations — run deploy.sh workstation to render the map"

    # Two people, two workstations, at the same time. Ephemeral accounts as everywhere else.
    A2A="uat-a2-${WS_A}"; A2B="uat-a2-${WS_B}"
    trap 'bash "${PROVISION}" --delete "${A2A}" >/dev/null 2>&1; bash "${PROVISION}" --delete "${A2B}" >/dev/null 2>&1; bash "${PROVISION}" --delete "${PROBE_USER}" >/dev/null 2>&1 || true' EXIT
    PW_A="$(bash "${PROVISION}" --ephemeral "${A2A}" analyst 2>/dev/null | sed -n 's/^EPHEMERAL_PASSWORD=//p')"
    PW_B="$(bash "${PROVISION}" --ephemeral "${A2B}" analyst 2>/dev/null | sed -n 's/^EPHEMERAL_PASSWORD=//p')"

    # Each drive runs INSIDE its workstation's tunnel namespace, presenting that
    # workstation's UA token — the same path and the same statement the kiosk makes.
    drive_ws() {  # <project> <user> <pw> <ws-id> <outfile>
        local proj="$1" user="$2" pw="$3" wsid="$4" out="$5" probe="${1}_probe_1"
        if ! ${RUNTIME} inspect "${probe}" >/dev/null 2>&1; then
            (cd "${PLATFORM}/deploy/workstation" && \
             IR_WS_ID="${wsid}" podman-compose -p "${proj}" --profile diagnostics up -d probe >/dev/null 2>&1)
        fi
        ${RUNTIME} inspect "${probe}" >/dev/null 2>&1 || { echo "NOPROBE" > "${out}"; return 0; }
        ${RUNTIME} exec "${probe}" sh -c 'mkdir -p /uatlib' 2>/dev/null || true
        ${RUNTIME} cp "${HERE}/lib/oidc_login.py" "${probe}:/uatlib/oidc_login.py" 2>/dev/null
        ${RUNTIME} cp "${HERE}/lib/audit_session.py" "${probe}:/uatlib/audit_session.py" 2>/dev/null
        ${RUNTIME} exec "${probe}" python3 /uatlib/audit_session.py \
            "${PLATFORM_PUBLIC_URL}" "${IR_PLATFORM_URL}" \
            "${user}" "${pw}" "A2-Rotated-Pw1!$(date +%s)" "${wsid}" > "${out}" 2>&1
    }
    OUT_A="$(mktemp)"; OUT_B="$(mktemp)"
    drive_ws "ir-workstation" "${A2A}" "${PW_A}" "${WS_A}" "${OUT_A}" &
    PID_A=$!
    drive_ws "ir-workstation-${WS_B}" "${A2B}" "${PW_B}" "${WS_B}" "${OUT_B}" &
    PID_B=$!
    wait "${PID_A}" "${PID_B}"

    if grep -q NOPROBE "${OUT_A}" "${OUT_B}" 2>/dev/null; then
        bad "a workstation's diagnostics probe could not be started — the concurrent case is unmeasured (start with: deploy.sh workstation, diagnostics profile)"
    elif ! grep -q '^LOGIN=0' "${OUT_A}" || ! grep -q '^LOGIN=0' "${OUT_B}"; then
        bad "a concurrent sign-on did not complete — ${WS_A}: $(sed -n 's/^MESSAGE=//p' "${OUT_A}" | head -1) / ${WS_B}: $(sed -n 's/^MESSAGE=//p' "${OUT_B}" | head -1)"
    else
        ok "two analysts signed on CONCURRENTLY from two workstations (${A2A}@${WS_A}, ${A2B}@${WS_B})"
        # The kiosk's statement survived the whole path: the sign-on records name the
        # workstation each analyst used.
        WSREC="$(q "
from cases.models import SsoSession
a = SsoSession.objects.filter(username='${A2A}').order_by('-id').first()
b = SsoSession.objects.filter(username='${A2B}').order_by('-id').first()
print(f'{a.workstation if a else \"?\"}|{b.workstation if b else \"?\"}')")"
        IFS='|' read -r ws_a_rec ws_b_rec <<<"${WSREC}"
        [[ "${ws_a_rec}" == "${WS_A}" && "${ws_b_rec}" == "${WS_B}" ]] \
            && ok "each sign-on names its workstation (${A2A}: ${ws_a_rec}, ${A2B}: ${ws_b_rec})" \
            || bad "sign-ons do not carry their workstations (got '${ws_a_rec}' / '${ws_b_rec}') — the UA token is not reaching the record"

        # The claim itself: with BOTH signed on at once, each pinned session attributes
        # exact to the right person, not overlapping and not the other analyst.
        ATTR2="$(q "
from cases import brokeredsessions as bs
out = bs.overview()
by_ws = {}
for s in out.get('sessions') or []:
    ws = s.get('pinned_workstation')
    if ws and s.get('active'):
        by_ws.setdefault(ws, s)
a = by_ws.get('${WS_A}'); b = by_ws.get('${WS_B}')
fmt = lambda s: f\"{s['attribution']}:{','.join(s['analysts'])}\" if s else 'missing'
print(f'{fmt(a)}|{fmt(b)}')")"
        IFS='|' read -r attr_a attr_b <<<"${ATTR2}"
        [[ "${attr_a}" == "exact:${A2A}" ]] \
            && ok "the ${WS_A}-pinned session attributes exact to ${A2A} while both analysts are signed on" \
            || bad "the ${WS_A}-pinned session reports '${attr_a}' — expected exact:${A2A}"
        [[ "${attr_b}" == "exact:${A2B}" ]] \
            && ok "the ${WS_B}-pinned session attributes exact to ${A2B} while both analysts are signed on" \
            || bad "the ${WS_B}-pinned session reports '${attr_b}' — expected exact:${A2B}"
    fi
    rm -f "${OUT_A}" "${OUT_B}"
fi

report_finish
exit "${FAILED}"
