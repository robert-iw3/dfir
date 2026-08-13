#!/usr/bin/env bash
# Logs, end to end: a request is made, every tier that handled it writes a record, the
# shipper moves those records off the containers into object storage, and an admin reads
# them back through the platform.
#
# The property that matters is the LAST one: a log that only exists inside a running
# container disappears with it, and reading it needs the host shell this design exists to
# remove. So the suite asserts the bytes reached the archive and came back through the API.
#
# And the corollary, tested negatively: an analyst cannot read any of it. Log lines carry
# paths, identifiers and tokens from cases the reader may not be cleared for.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"
. "${HERE}/lib/report.sh"
report_begin 22 logging "Every tier's logs reach the archive and an admin can read them" \
    "A request crosses the ingress, the web tier and the API; each writes its own record; the shipper moves all of them into object storage away from evidence; and an admin reads and exports them through the platform rather than by shelling into the host. An analyst is refused throughout."

num() { local v="${1//[^0-9]/}"; printf '%s' "${v:-0}"; }
RUNTIME="${IR_RUNTIME:-podman}"
BE=ir-enclave_backend_1
SHIPPER=ir-enclave_log-shipper_1

cleanup() {
    ${RUNTIME} exec -i "${BE}" python manage.py shell -c "
from django.contrib.auth.models import User
User.objects.filter(username__startswith='uat-logs-').delete()" >/dev/null 2>&1 || true
}
trap cleanup EXIT

say "1/5  Every tier writes a log FILE, not just container output"
for c in "${BE}" ir-enclave_worker_1; do
    ${RUNTIME} ps --format '{{.Names}}' | grep -qx "${c}" \
        || { bad "${c} is not running — logging cannot be validated"; report_finish; exit 1; }
done
TOKENS="$(${RUNTIME} exec -i "${BE}" python manage.py shell -c "
from django.contrib.auth.models import Group, User
from rest_framework.authtoken.models import Token
g, _ = Group.objects.get_or_create(name='analyst')
u, _ = User.objects.get_or_create(username='uat-logs-analyst')
u.is_superuser = False; u.is_staff = False; u.save(); u.groups.set([g])
admin = User.objects.filter(is_superuser=True).first()
print(Token.objects.get_or_create(user=u)[0].key,
      Token.objects.get_or_create(user=admin)[0].key)" 2>/dev/null | tail -1)"
read -r T_ANALYST T_ADMIN <<<"${TOKENS}"
[[ -n "${T_ADMIN:-}" ]] && ok "an analyst and an admin, to test the read boundary" \
                        || { bad "could not provision identities"; report_finish; exit 1; }

req() { # token method path
    ${RUNTIME} exec -i "${BE}" python -c "
import sys, urllib.request, urllib.error
tok, method, path = sys.argv[1:4]
r = urllib.request.Request('http://127.0.0.1:8000/api' + path, method=method,
                           headers={'Authorization': 'Token ' + tok})
try:
    resp = urllib.request.urlopen(r, timeout=60)
    print(resp.getcode(), resp.read().decode().replace(chr(10), ' ')[:200000])
except urllib.error.HTTPError as e:
    print(e.code, e.read().decode().replace(chr(10), ' ')[:300])
except Exception as e:
    print(0, e)" "$1" "$2" "$3" 2>/dev/null | tail -1
}
jqf() { python3 -c "
import json, sys
p = sys.stdin.read().split(' ', 1)
d = json.loads(p[1]) if len(p) > 1 and p[1].strip().startswith(('{', '[')) else {}
$1" 2>/dev/null; }

# A request that is certain to be logged by name, so the assertions below are looking for
# something this run actually caused rather than for traffic that happened to be there.
MARK="uat-logging-$(date +%s)"
req "${T_ADMIN}" GET "/investigations/?probe=${MARK}" >/dev/null
req "${T_ANALYST}" GET "/investigations/?probe=${MARK}" >/dev/null
sleep 2

APPFILES="$(${RUNTIME} exec -i "${BE}" sh -c '
for f in /logs/app/backend-app.log /logs/app/backend-access.log; do
    [ -s "$f" ] && echo "yes" || echo "no"
done' 2>/dev/null | tr '\n' ' ')"
read -r HAS_APP HAS_ACCESS <<<"${APPFILES}"
[[ "${HAS_APP}" == "yes" ]] \
    && ok "the API writes its application log to a file, not only to container output" \
    || bad "no /logs/app/backend-app.log — the API's own log dies with the container"
[[ "${HAS_ACCESS}" == "yes" ]] \
    && ok "and its access log too" || bad "no /logs/app/backend-access.log"
MARKED="$(${RUNTIME} exec -i "${BE}" sh -c "grep -c '${MARK}' /logs/app/backend-access.log 2>/dev/null || true" 2>/dev/null | tail -1)"
[[ "$(num "${MARKED:-}")" -ge 1 ]] \
    && ok "this run's own request is in it (${MARKED} line(s) carrying ${MARK})" \
    || bad "the request this suite just made was not logged"
WORKER="$(${RUNTIME} exec -i ir-enclave_worker_1 sh -c '[ -s /logs/app/worker-app.log ] && echo yes || echo no' 2>/dev/null | tail -1)"
[[ "${WORKER}" == "yes" ]] \
    && ok "the analysis worker writes its own, separately from the API's" \
    || bad "no /logs/app/worker-app.log — worker failures leave no durable record"
STDOUT="$(${RUNTIME} logs --tail 40 "${BE}" 2>&1 | grep -c . || true)"
[[ "$(num "${STDOUT:-}")" -ge 1 ]] \
    && ok "and container output still works — the file copy did not replace it" \
    || bad "container output is empty; logging to a file silenced the console"

say "2/5  The shipper moves them off the container into object storage"
${RUNTIME} ps --format '{{.Names}}' | grep -qx "${SHIPPER}" \
    && ok "the log shipper is running as its own service" \
    || bad "${SHIPPER} is not running"
# One pass, run explicitly, so the assertion does not depend on where the interval timer sits.
SHIP="$(${RUNTIME} exec -i "${SHIPPER}" python manage.py ship_logs 2>&1 | tail -3)"
printf '%s' "${SHIP}" | grep -qiE "shipped|bytes|nothing|up to date" \
    && ok "a shipping pass completes and says what it moved" \
    || bad "the shipper failed: ${SHIP:0:300}"

SOURCES="$(req "${T_ADMIN}" GET "/opslog/logs/sources/")"
read -r AVAIL NSRC NAMES <<<"$(printf '%s' "${SOURCES}" | jqf "
ss = d.get('sources', [])
print(int(bool(d.get('available'))), len(ss), ','.join(s['source'] for s in ss))")"
[[ "${AVAIL}" == "1" && "$(num "${NSRC:-}")" -ge 1 ]] \
    && ok "the archive is readable and lists ${NSRC} source(s)" \
    || bad "the log archive is not available: ${SOURCES:0:300}"
for want in backend-app backend-access; do
    [[ "${NAMES}" == *"${want}"* ]] \
        && ok "${want} reached object storage" \
        || bad "${want} is not in the archive — it is written but never shipped"
done
[[ "${NAMES}" == *"traefik-access"* || "${NAMES}" == *"frontend-access"* ]] \
    && ok "so did the web tier's own logs" \
    || bad "no web-tier log in the archive (have: ${NAMES})"

say "3/5  An admin reads them back through the platform, not by shelling into the host"
KEY="$(req "${T_ADMIN}" GET "/opslog/logs/objects/?source=backend-access" | jqf "
os_ = d.get('objects', [])
print(os_[0]['key'] if os_ else '')")"
[[ -n "${KEY}" ]] && ok "the objects for a source are listed newest first" \
                  || bad "no objects listed for backend-access"
BODY="$(req "${T_ADMIN}" GET "/opslog/logs/objects/?key=${KEY}")"
read -r NBYTES HAS_NOTE <<<"$(printf '%s' "${BODY}" | jqf "
print(d.get('bytes', 0), int('not evidence' in (d.get('note') or '').lower()))")"
[[ "$(num "${NBYTES:-}")" -ge 1 ]] \
    && ok "and one can be read back, ${NBYTES} bytes of it" || bad "the object read empty: ${BODY:0:200}"
[[ "${HAS_NOTE}" == "1" ]] \
    && ok "labelled as an operational record and NOT evidence — it carries no custody seal and must not imply one" \
    || bad "a log was served without saying it is not evidence"
CONTENT="$(printf '%s' "${BODY}" | jqf "print(1 if '${MARK}' in (d.get('text') or '') else 0)")"
[[ "${CONTENT}" == "1" ]] \
    && ok "THE LINE THIS RUN CAUSED IS IN THE ARCHIVE — written by a container, read through the API" \
    || bad "the archived copy does not contain this run's request; the chain is broken somewhere"

say "4/5  Reading logs is admin-only"
for path in "/opslog/logs/sources/" "/opslog/logs/objects/?source=backend-access" \
            "/opslog/requests/" "/opslog/client-errors/list/"; do
    CODE="$(req "${T_ANALYST}" GET "${path}")"
    [[ "${CODE%% *}" == "403" ]] \
        && ok "an analyst is refused ${path%%\?*}" \
        || bad "an analyst read ${path} (${CODE%% *}) — log lines carry other cases' identifiers"
done
DL_DENIED="$(req "${T_ANALYST}" GET "/opslog/logs/download/?key=${KEY}")"
[[ "${DL_DENIED%% *}" == "403" ]] \
    && ok "and cannot export one" || bad "an analyst downloaded a log (${DL_DENIED%% *})"
TRAVERSAL="$(req "${T_ADMIN}" GET "/opslog/logs/objects/?key=../_state/offsets.json")"
[[ "${TRAVERSAL%% *}" == "404" ]] \
    && ok "a key that climbs out of the bucket is refused, even for an admin" \
    || bad "path traversal returned ${TRAVERSAL%% *}"

say "5/5  Every privileged read of a log is itself in the audit ledger"
AUDITED="$(${RUNTIME} exec -i "${BE}" python manage.py shell -c "
from cases.models import AuditLog
from cases.audit import verify_audit_chain
acts = set(AuditLog.objects.filter(action__startswith='log.').values_list('action', flat=True))
ok, at = verify_audit_chain()
print(len(acts), ','.join(sorted(acts)), int(bool(ok)))" 2>/dev/null | tail -1)"
read -r NACTS ACTS CHAIN <<<"${AUDITED}"
[[ "$(num "${NACTS:-}")" -ge 1 ]] \
    && ok "reading a log is recorded (${ACTS})" \
    || bad "log reads are not audited; who looked at the operational record is unanswerable"
[[ "${CHAIN:-0}" == "1" ]] \
    && ok "and the ledger still verifies after them" || bad "the audit chain broke"

REQLOG="$(req "${T_ADMIN}" GET "/opslog/requests/?limit=50" | jqf "
rs = d.get('results') or d.get('requests') or []
print(len(rs))")"
[[ "$(num "${REQLOG:-}")" -ge 1 ]] \
    && ok "the API's own request log is readable alongside the archive (${REQLOG} row(s))" \
    || bad "the request log returned nothing"

report_finish
exit "${FAILED}"
