#!/usr/bin/env bash
# Assessment findings, each closed by an assertion rather than by a patch (CHANGE-MANAGEMENT
# rule 8). Every section names the finding it holds shut and exercises the path an attacker
# would take, so a refactor that reopens the weakness by another route still fails here.
# Ephemeral accounts and fixtures only; every trace removed on exit.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"
. "${HERE}/lib/report.sh"
report_begin 57 security "Security — assessment findings, held shut by assertion" \
    "Each closed finding from the 2026-08-16 assessment is re-attempted here as its attacker would attempt it: the compartment bypass on the platform's only sanctioned egress, and the aggregate surface that reached a restricted case by direct id. A weakness that returns fails this suite rather than waiting for the next audit."
RUNTIME="${IR_RUNTIME:-podman}"
BE=ir-enclave_backend_1
be() { ${RUNTIME} exec -i "${BE}" "$@"; }

${RUNTIME} inspect "${BE}" >/dev/null 2>&1 || {
    bad "backend is not running — nothing to assert against"; exit 1; }

cleanup() {
    be python manage.py shell -c '
from django.contrib.auth.models import User
from cases.models import Investigation
Investigation.objects.filter(incident_id__startswith="INC-UAT-SEC").delete()
User.objects.filter(username__startswith="uat-sec-").delete()
User.objects.filter(email__startswith="uat-sec-").delete()' >/dev/null 2>&1 || true
}
trap cleanup EXIT

say "0/10 A restricted case, a member, and an outsider who HOLDS the export right"
# The outsider is the actor the finding names: a legitimate analyst with export, not on the
# case. Export says what a reader may carry out, never which cases they may read.
SETUP="$(be python manage.py shell -c '
import hashlib
from django.contrib.auth.models import Group, User
from rest_framework.authtoken.models import Token
from cases.models import (CaseAssignment, CollectionRun, Finding, Host, IOC, Investigation)
Investigation.objects.filter(incident_id__startswith="INC-UAT-SEC").delete()
User.objects.filter(username__startswith="uat-sec-").delete()
User.objects.filter(email__startswith="uat-sec-").delete()
analysts, _ = Group.objects.get_or_create(name="analyst")
exporters, _ = Group.objects.get_or_create(name="export")
member = User.objects.create_user("uat-sec-member")
outsider = User.objects.create_user("uat-sec-outsider")
for u in (member, outsider):
    u.groups.add(analysts); u.groups.add(exporters)
inv = Investigation.objects.create(name="uat-sec-restricted",
                                   incident_id="INC-UAT-SEC-R", compartment="restricted")
host, _ = Host.objects.get_or_create(hostname="uat-sec-host",
    defaults={"machine_id": hashlib.sha256(b"uat-sec").hexdigest()[:32], "platform": "linux"})
run = CollectionRun.objects.create(investigation=inv, host=host,
                                   overall_status="COMPLETED", compromised=True)
Finding.objects.create(run=run, finding_type="uat-sec-secret-finding",
                       target="uat-sec-secret-target", verdict="True Positive")
IOC.objects.create(run=run, ioc_type="domain", value="uat-sec-secret.invalid")
CaseAssignment.objects.create(investigation=inv, username="uat-sec-member",
                              assigned_by="seed")
print("IDS", inv.id, Token.objects.get_or_create(user=member)[0].key,
      Token.objects.get_or_create(user=outsider)[0].key)' 2>/dev/null | sed -n "s/^IDS //p")"
read -r RINV TOK_M TOK_O <<<"${SETUP}"
[[ -n "${TOK_O:-}" ]] \
    && ok "fixture: restricted case ${RINV}, both identities hold export, only one is assigned" \
    || { bad "could not seed the security fixture"; exit 1; }

# Rows an identity actually receives from an export, by counting the payload rather than
# trusting the status code: a 200 carrying another compartment's rows is the defect.
export_rows() {  # token query
    be python -c "
import json, urllib.request, urllib.error
req = urllib.request.Request('http://127.0.0.1:8000/api/findings/export/$2',
                             headers={'Authorization': 'Token $1'})
try:
    body = urllib.request.urlopen(req, timeout=20).read().decode()
except urllib.error.HTTPError as e:
    print('HTTP', e.code); raise SystemExit
try:
    d = json.loads(body)
    print(len(d.get('indicators', d)) if isinstance(d, dict) else len(d))
except Exception:
    print(max(0, len([l for l in body.splitlines() if l.strip()]) - 1))" 2>/dev/null | tail -1
}
code() {  # token path
    be python -c "
import urllib.request, urllib.error
req = urllib.request.Request('http://127.0.0.1:8000/api$2',
                             headers={'Authorization': 'Token $1'})
try: print(urllib.request.urlopen(req, timeout=10).getcode())
except urllib.error.HTTPError as e: print(e.code)
except Exception: print(0)" 2>/dev/null | tail -1
}

say "1/10 W4a — the export route scopes, and holding export is not membership"
# Unscoped, this returned every finding on the platform to any export holder, and the ledger
# filed it as an authorized export — so nothing read as a breach afterwards.
LEAK="$(be python -c "
import json, urllib.request
req = urllib.request.Request('http://127.0.0.1:8000/api/findings/export/?fmt=json',
                             headers={'Authorization': 'Token ${TOK_O}'})
body = urllib.request.urlopen(req, timeout=20).read().decode()
print(sum(1 for r in json.loads(body) if r.get('finding_type') == 'uat-sec-secret-finding'))" \
    2>/dev/null | tail -1)"
[[ "${LEAK}" == "0" ]] \
    && ok "unfiltered export by a non-member carries 0 rows of the restricted case — the compartment survives the widest door the platform has" \
    || bad "the restricted case leaked ${LEAK} row(s) into a non-member's unfiltered export"

TARGETED="$(export_rows "${TOK_O}" "?fmt=json&investigation=${RINV}")"
[[ "${TARGETED}" == "0" ]] \
    && ok "export aimed straight at the restricted case returns 0 rows for a non-member" \
    || bad "a non-member exported ${TARGETED} row(s) by naming the case id directly"

IOCS="$(be python -c "
import json, urllib.request
req = urllib.request.Request('http://127.0.0.1:8000/api/findings/export/?fmt=ioc',
                             headers={'Authorization': 'Token ${TOK_O}'})
d = json.loads(urllib.request.urlopen(req, timeout=20).read().decode())
print(sum(1 for i in d.get('indicators', []) if 'uat-sec-secret' in str(i.get('value'))))" \
    2>/dev/null | tail -1)"
[[ "${IOCS}" == "0" ]] \
    && ok "the IOC bundle — the artifact meant to be shared onward — carries none of the restricted case's indicators" \
    || bad "${IOCS} restricted indicator(s) reached a non-member's IOC bundle"

MEMBER_ROWS="$(export_rows "${TOK_M}" "?fmt=json&investigation=${RINV}")"
[[ "${MEMBER_ROWS}" == "1" ]] \
    && ok "the assigned member exports the same case normally (1 row) — the scope permits, it does not merely refuse" \
    || bad "the assigned member exported ${MEMBER_ROWS} rows, expected 1 — a scope that refuses everyone proves nothing"

say "2/10 W4b — the aggregate surface cannot be reached by direct id"
for ep in "stats" "coverage"; do
    C="$(code "${TOK_O}" "/investigations/${RINV}/${ep}/")"
    [[ "${C}" == "404" ]] \
        && ok "${ep} by direct id: 404 for a non-member — and 404, not 403, so the case's existence is not confirmed" \
        || bad "a non-member read /investigations/${RINV}/${ep}/ (got ${C})"
done
MEM_STATS="$(code "${TOK_M}" "/investigations/${RINV}/stats/")"
[[ "${MEM_STATS}" == "200" ]] \
    && ok "the assigned member reads stats normally (200)" \
    || bad "the member was refused their own case's stats (${MEM_STATS})"

say "3/10 W4c — a lifecycle transition is a write, and membership decides it"
TRANS="$(be python -c "
import json, urllib.request, urllib.error
req = urllib.request.Request('http://127.0.0.1:8000/api/investigations/${RINV}/transition/',
                             data=json.dumps({'status': 'concluded'}).encode(),
                             headers={'Authorization': 'Token ${TOK_O}',
                                      'Content-Type': 'application/json'}, method='POST')
try: print(urllib.request.urlopen(req, timeout=10).getcode())
except urllib.error.HTTPError as e: print(e.code)
except Exception: print(0)" 2>/dev/null | tail -1)"
[[ "${TRANS}" == "404" ]] \
    && ok "a non-member cannot move someone else's case through its lifecycle (404)" \
    || bad "a non-member transitioned a restricted case (got ${TRANS}) — a write into a compartment they cannot even list"

STILL="$(be python manage.py shell -c "
from cases.models import Investigation
print(Investigation.objects.get(id=${RINV}).status)" 2>/dev/null | tail -1)"
[[ "${STILL}" != "concluded" ]] \
    && ok "the case's status is unchanged (${STILL}) — the refusal held in the database, not only in the response" \
    || bad "the case was concluded by a non-member despite the response"

say "4/10 W1 — the caller cannot name their own role"
# The trust decision under test is the backend's: given the shared proxy secret (which every
# request through nginx carries), does a client-supplied identity header decide the role? The
# probe presents the secret exactly as nginx does, so it exercises the same code path an
# escalating caller would reach, and asks what the platform CONCLUDED rather than what it
# answered — a 200 with the right role is fine; admin is the defect.
spoof_role() {  # <header-name> <email>
    be python -c "
import django, os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ir_platform.settings'); django.setup()
from django.conf import settings
from django.contrib.auth.models import User
from django.test import RequestFactory
from rest_framework import exceptions
from cases.authentication import SSOHeaderAuthentication
# NO X-Forwarded-Groups: the actor is a valid Keycloak session carrying no group, which is
# where the old fallback chain fell through to whatever the client sent. Supplying a genuine
# claim alongside would let it win the 'or' — and the probe would pass with the hole open.
h = {'HTTP_X_PROXY_AUTH': settings.SSO_PROXY_SECRET,
     'HTTP_X_FORWARDED_EMAIL': '$2',
     '$1': 'admin'}
req = RequestFactory().get('/api/investigations/', **h)
try:
    SSOHeaderAuthentication().authenticate(req)
except exceptions.AuthenticationFailed:
    pass
u = User.objects.filter(email='$2').first()
print('none' if not u else ('admin' if u.is_superuser else ','.join(
    sorted(u.groups.values_list('name', flat=True))) or 'no-groups'))" 2>/dev/null | tail -1
}
for hdr in HTTP_X_AUTH_REQUEST_GROUPS HTTP_REMOTE_GROUPS; do
    name="$(printf '%s' "${hdr#HTTP_}" | tr '_' '-')"
    R="$(spoof_role "${hdr}" "uat-sec-spoof-${RANDOM}@example.invalid")"
    [[ "${R}" == "none" || "${R}" == "no-groups" ]] \
        && ok "${name}: an un-grouped session stays un-grouped (${R}) — the spoofed header names no role" \
        || bad "${name}: a client-supplied header produced '${R}' — the caller named their own identity"
done

say "5/10 W1 — an absent role claim is a revocation, not 'keep what you had'"
REVOKED="$(be python -c "
import django, os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ir_platform.settings'); django.setup()
from django.conf import settings
from django.contrib.auth.models import Group, User
from django.test import RequestFactory
from rest_framework import exceptions
from cases.authentication import SSOHeaderAuthentication
User.objects.filter(username='uat-sec-revoked').delete()
u = User.objects.create_user('uat-sec-revoked', email='uat-sec-revoked@example.invalid')
u.groups.add(Group.objects.get_or_create(name='admin')[0])
u.is_superuser = u.is_staff = True; u.save()
# The same account signs in again with the group withdrawn in Keycloak: no role in the claim.
h = {'HTTP_X_PROXY_AUTH': settings.SSO_PROXY_SECRET,
     'HTTP_X_FORWARDED_EMAIL': 'uat-sec-revoked@example.invalid',
     'HTTP_X_FORWARDED_GROUPS': ''}
try:
    SSOHeaderAuthentication().authenticate(RequestFactory().get('/api/investigations/', **h))
    print('ADMITTED')
except exceptions.AuthenticationFailed:
    u.refresh_from_db()
    print('refused' if not (u.is_superuser or u.groups.exists()) else 'refused-but-kept-rights')
" 2>/dev/null | tail -1)"
[[ "${REVOKED}" == "refused" ]] \
    && ok "withdrawing the role group refuses the request AND strips the local groups and superuser flag — revocation revokes" \
    || bad "an account whose role was withdrawn came back '${REVOKED}' — the platform's answer to a suspect insider has to actually withdraw something"

say "6/10 W2 — the receiver serves the holding area to the puller only"
# The actor is a compromised endpoint: the fleet is permitted to reach this port, and the
# bundles behind it are every other host's memory. Reading is bad; DELETE is worse, because
# it destroys evidence that has no second copy yet and leaves no custody row for the loss.
PU=ir-enclave_puller_1
${RUNTIME} inspect "${PU}" >/dev/null 2>&1 && {
  RECV_PROBE="$(${RUNTIME} exec "${PU}" python3 -c "
import os, ssl, urllib.request, urllib.error
ctx = ssl.create_default_context(cafile='/certs/receiver.crt'); ctx.check_hostname = False
base = os.environ['RECEIVER_URL'].rstrip('/')
tok = os.environ.get('RECEIVER_PULLER_TOKEN', '')
def code(path, auth=False, method='GET'):
    h = {'Authorization': f'Bearer {tok}'} if auth else {}
    try:
        return urllib.request.urlopen(
            urllib.request.Request(base + path, headers=h, method=method),
            timeout=10, context=ctx).getcode()
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0
print(code('/pending'), code('/fetch/deadbeef'), code('/isf/pending'),
      code('/fetch/deadbeef', method='DELETE'), code('/healthz'), code('/pending', auth=True))" 2>/dev/null | tail -1)"
  read -r C_PEND C_FETCH C_ISF C_DEL C_HEALTH C_AUTH <<<"${RECV_PROBE}"
  [[ "${C_PEND}" == "401" ]] \
      && ok "GET /pending without the puller credential: 401 — the bundle list is not public" \
      || bad "GET /pending answered ${C_PEND} to an unauthenticated caller"
  [[ "${C_FETCH}" == "401" ]] \
      && ok "GET /fetch/<id> without it: 401 — a held memory image is not served to the fleet" \
      || bad "GET /fetch/<id> answered ${C_FETCH} unauthenticated"
  [[ "${C_ISF}" == "401" ]] \
      && ok "GET /isf/pending without it: 401 — the symbol path is gated too" \
      || bad "GET /isf/pending answered ${C_ISF} unauthenticated"
  [[ "${C_DEL}" == "401" ]] \
      && ok "DELETE /fetch/<id> without it: 401 — evidence cannot be destroyed by whoever asks" \
      || bad "DELETE /fetch/<id> answered ${C_DEL} unauthenticated — the sharpest of these paths"
  [[ "${C_HEALTH}" == "200" ]] \
      && ok "/healthz stays open (200) — the gate is on evidence, not on liveness" \
      || bad "/healthz answered ${C_HEALTH} — the gate over-reached"
  [[ "${C_AUTH}" == "200" ]] \
      && ok "the puller's own credential still reads the holding area (200) — the evidence path works" \
      || bad "the puller was refused its own holding area (${C_AUTH}) — a gate that blocks the pipeline"
} || info "puller not running — the receiver gate is unmeasured here"

say "7/10 W3 — an evidence-controlled hostname cannot reach the generated script"
# The hostname is the bundle's own top-level directory name, so an adversary who controls the
# memory image controls it. It is written into run.sh, which the kit tells an analyst to run
# on the machine that owns the podman socket.
W3="$(be python manage.py shell -c '
from cases.reversing import _safe_host
class H: hostname = "host\nrm -rf /tmp/pwned #"
class W:
    host = H()
    investigation_id = 1
    slug = "ws-x"
out = _safe_host(W())
print("SAFE" if ("\n" not in out and ";" not in out and " " not in out) else "UNSAFE:" + repr(out))' 2>/dev/null | tail -1)"
[[ "${W3}" == "SAFE" ]] \
    && ok "a hostname carrying a newline and a shell command is flattened before it reaches the kit" \
    || bad "the generated script would carry ${W3}"

say "8/10 W6 — the verifier decides whether a seal is ATTRIBUTABLE, not the bundle"
W6="$(be python -c "
import json, os, sys, tempfile
sys.path.insert(0, '/app')
os.environ['IR_CUSTODY_HMAC_KEY'] = 'uat-sec-key-A'
os.environ.pop('IR_CUSTODY_HMAC_KEYS_RETIRED', None)
import custody

def mk():
    p = tempfile.mkdtemp(); open(os.path.join(p, 'e.txt'), 'w').write('memory'); return p

def state(p):
    ok, why, _ = custody.verify(p)
    return int(ok), int(custody.attributable(why)), why.replace(' ', '_')

d = mk(); custody.seal(d, 'INC-UAT-SEC')
s_ok, s_attr, _ = state(d)
# The attack: the bundle declares itself unsigned and drops the HMAC.
c = os.path.join(d, custody.CUSTODY_NAME)
rec = json.load(open(c)); rec['signed'] = False; rec['hmac_sha256'] = ''
json.dump(rec, open(c, 'w'))
u_ok, u_attr, _ = state(d)
# A collector that was never issued a key — the supported unsigned collection path.
d3 = mk(); k = os.environ.pop('IR_CUSTODY_HMAC_KEY')
custody.seal(d3, 'INC-UAT-SEC'); os.environ['IR_CUSTODY_HMAC_KEY'] = k
n_ok, n_attr, _ = state(d3)
# A signature that is present and wrong.
d4 = mk(); custody.seal(d4, 'INC-UAT-SEC')
c4 = os.path.join(d4, custody.CUSTODY_NAME)
rec = json.load(open(c4)); rec['hmac_sha256'] = '0' * 64; json.dump(rec, open(c4, 'w'))
g_ok = state(d4)[0]
# Rotation: sealed under A, verified under B with A retired.
d2 = mk(); custody.seal(d2, 'INC-UAT-SEC')
os.environ['IR_CUSTODY_HMAC_KEY'] = 'uat-sec-key-B'
os.environ['IR_CUSTODY_HMAC_KEYS_RETIRED'] = 'uat-sec-key-A'
r_ok, r_attr, r_why = state(d2)
os.environ.pop('IR_CUSTODY_HMAC_KEYS_RETIRED')
f_ok = state(d2)[0]
print(s_ok, s_attr, u_ok, u_attr, n_ok, n_attr, g_ok, r_ok, r_attr, r_why, f_ok)" 2>/dev/null | tail -1)"
read -r S_OK S_ATTR U_OK U_ATTR N_OK N_ATTR G_OK R_OK R_ATTR R_WHY F_OK <<<"${W6}"
[[ "${S_OK}" == "1" && "${S_ATTR}" == "1" ]] \
    && ok "a correctly sealed bundle verifies and is attributable" \
    || bad "a correctly sealed bundle failed to verify (ok=${S_OK} attributable=${S_ATTR}) — the fix broke the good path"
[[ "${U_ATTR}" == "0" ]] \
    && ok "a bundle declaring itself unsigned is NEVER attributable — the seal is not the bundle's decision to make" \
    || bad "a bundle set its own 'signed' to false and was still counted as cryptographically verified"
[[ "${N_OK}" == "1" && "${N_ATTR}" == "0" ]] \
    && ok "a bundle collected without a signing key still ingests, and is recorded unverified rather than trusted" \
    || bad "unsigned collection returned ok=${N_OK} attributable=${N_ATTR} — a supported collection path is quarantined or over-trusted"
[[ "${G_OK}" == "0" ]] \
    && ok "a signature that is present and wrong is REFUSED — a forged seal is not an unsigned one" \
    || bad "a bundle carrying a mismatched HMAC was accepted — forgery reads as absence"
[[ "${R_OK}" == "1" && "${R_ATTR}" == "1" && "${R_WHY}" == "superseded_key" ]] \
    && ok "a seal from a retired key verifies as SUPERSEDED and stays attributable — rotation does not read as forgery, and an archived case stays restorable" \
    || bad "after rotation the seal reported '${R_WHY}' (ok=${R_OK} attributable=${R_ATTR}) — one rotation would strand every archive"
[[ "${F_OK}" == "0" ]] \
    && ok "the same seal with the key neither current nor retired is refused — superseded is not a wildcard" \
    || bad "an unknown key still verified — the third state swallowed the failure"

say "9/10 W7 — the RE session does not disable the analyst's display"
XH="$(grep -c '^[^#]*xhost' "${PLATFORM}/re-workstation/launch.sh" "${PLATFORM}/deploy/deploy.sh" 2>/dev/null | awk -F: '{s+=$2} END{print s+0}')"
[[ "${XH}" == "0" ]] \
    && ok "no xhost invocation remains — access control is not disabled for every local process" \
    || bad "${XH} live xhost call(s) remain — a malware-facing container shares that display"
BOTH="$(grep -c "XAUTH_ARGS\|XAUTHORITY" "${PLATFORM}/re-workstation/launch.sh" 2>/dev/null || echo 0)"
[[ "${BOTH}" -ge 3 ]] \
    && ok "both tool paths authenticate with a cookie instead" \
    || bad "a tool path still opens the display without a cookie (${BOTH} references)"

say "10/10 W8 — a generated credential is one the service it names accepts"
# Per-deployment generation replaces shared defaults, and two variables for one account then
# hold two different random values. The account is the authority on its own password, so each
# credential is spent against the service rather than compared between files.
KCP="$(be sh -c 'printf %s "${KC_BOOTSTRAP_ADMIN_PASSWORD:-}"' 2>/dev/null)"
KCU="$(be sh -c 'printf %s "${KC_BOOTSTRAP_ADMIN_USERNAME:-admin}"' 2>/dev/null)"
if [[ -z "${KCP}" ]]; then
    bad "the app tier holds no Keycloak admin password — user administration cannot work"
else
    KCLOGIN="$(${RUNTIME} exec -i -e TPW="${KCP}" -e TUSER="${KCU}" ir-enclave_keycloak_1 sh -c \
        '/opt/keycloak/bin/kcadm.sh config credentials --server http://127.0.0.1:8080 \
           --realm master --user "$TUSER" --password "$TPW" >/dev/null 2>&1 && echo OK' 2>/dev/null \
        | tr -dc 'A-Z')"
    [[ "${KCLOGIN}" == "OK" ]] \
        && ok "the credential the app tier carries authenticates to Keycloak as ${KCU} — the generator and the account agree" \
        || bad "the app tier's Keycloak admin credential is REJECTED by Keycloak — user administration fails with a password that looks provisioned"
fi

# The same credential through the app's own configuration, which is the path the admin UI uses:
# a matching environment variable is not proof the setting reads it.
KCADMIN="$(be python manage.py shell -c "
from django.conf import settings
import json, urllib.parse, urllib.request, urllib.error
kc = settings.KEYCLOAK
data = urllib.parse.urlencode({'grant_type': 'password', 'client_id': 'admin-cli',
                               'username': kc['ADMIN_USER'], 'password': kc['ADMIN_PASSWORD']}).encode()
try:
    urllib.request.urlopen(kc['URL'].rstrip('/') + '/realms/master/protocol/openid-connect/token',
                           data=data, timeout=15)
    print('SETTINGS_OK')
except urllib.error.HTTPError as e:
    print('SETTINGS_REJECTED', e.code)
except Exception as e:
    print('SETTINGS_UNREACHABLE', type(e).__name__)" 2>/dev/null | grep -oE 'SETTINGS_[A-Z]+' | tail -1)"
case "${KCADMIN}" in
    SETTINGS_OK)
        ok "settings.KEYCLOAK's admin credential authenticates too — the admin's user-management API works" ;;
    SETTINGS_REJECTED)
        bad "settings.KEYCLOAK carries a REJECTED admin credential — list/create/delete user fail for every admin" ;;
    *)
        bad "settings.KEYCLOAK could not reach Keycloak to spend the credential (${KCADMIN:-no result})" ;;
esac

report_finish
exit "${FAILED}"
