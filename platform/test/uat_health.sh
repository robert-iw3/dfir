#!/usr/bin/env bash
# Component health tells the truth about errors: current ones are current, recovered ones
# read as history, and the counters can tell the two apart.
#
# `last_error` is sticky by design — the record that something ever failed. Rendered
# without its age, history reads as a live fault, and an admin either chases ghosts or
# learns to ignore the page.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"
. "${HERE}/lib/report.sh"
report_begin 21 health "Component health separates live errors from history" \
    "A component that errors shows it with a count and a message; one that recovers keeps the record but reads as recovered, with the moment it happened; and the roll-up degrades a component only for what is wrong NOW."

num() { local v="${1//[^0-9]/}"; printf '%s' "${v:-0}"; }
RUNTIME="${IR_RUNTIME:-podman}"
BE=ir-enclave_backend_1

cleanup() {
    ${RUNTIME} exec -i "${BE}" python manage.py shell -c "
from django.contrib.auth.models import User
from cases.models import ComponentHealth
ComponentHealth.objects.filter(component__startswith='uat-health-').delete()
User.objects.filter(username__startswith='uat-health-').delete()" >/dev/null 2>&1 || true
}
trap cleanup EXIT

say "1/4  The self-report carries what an honest error record needs"
# Straight through the shared collector every tier uses, so what is asserted is what every
# component actually ships — not a hand-built lookalike.
SNAP="$(${RUNTIME} exec -i "${BE}" python manage.py shell -c "
import json
from sysstats import LogCounter
c = LogCounter()
c.error('first failure: connection refused')
s1 = c.snapshot()
s2 = c.snapshot()
c.error('second failure: timeout')
s3 = c.snapshot()
print(json.dumps([s1, s2, s3]))" 2>/dev/null | tail -1)"
python3 - "$SNAP" <<'PY' > /tmp/uat_health_counter 2>&1
import json, sys
s1, s2, s3 = json.loads(sys.argv[1])
checks = [
    ("an error counts once, with its message and WHEN it happened",
     s1["errors_since_last_report"] == 1 and "refused" in s1["last_error"]
     and bool(s1.get("last_error_at"))),
    ("a quiet interval reports zero since — while the total and the record persist",
     s2["errors_since_last_report"] == 0 and s2["errors_total"] == 1
     and "refused" in s2.get("last_error", "")),
    ("a NEW error replaces the record and moves the timestamp forward",
     s3["errors_since_last_report"] == 1 and "timeout" in s3["last_error"]
     and s3["last_error_at"] >= s1["last_error_at"]),
]
for label, okv in checks:
    print(("PASSCHK " if okv else "FAILCHK ") + label)
PY
while read -r line; do
    case "${line}" in
        PASSCHK*) ok "${line#PASSCHK }" ;;
        FAILCHK*) bad "${line#FAILCHK }" ;;
    esac
done < /tmp/uat_health_counter

say "2/4  A component that errors NOW is shown as degraded, with the reason"
TOK="$(${RUNTIME} exec -i "${BE}" python manage.py shell -c "
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
print(Token.objects.get_or_create(user=User.objects.filter(is_superuser=True).first())[0].key)" 2>/dev/null | tail -1)"
req() { # path
    ${RUNTIME} exec -i "${BE}" python -c "
import sys, urllib.request, urllib.error
try:
    r = urllib.request.Request('http://127.0.0.1:8000/api' + sys.argv[2],
                               headers={'Authorization': 'Token ' + sys.argv[1]})
    resp = urllib.request.urlopen(r, timeout=45)
    print(resp.getcode(), resp.read().decode().replace(chr(10), ' ')[:400000])
except urllib.error.HTTPError as e:
    print(e.code, e.read().decode()[:300])
except Exception as e:
    print(0, e)" "${TOK}" "$1" 2>/dev/null | tail -1
}

# Two synthetic components through the same store the real reporters use: one erroring
# now, one that errored once and has been clean since.
${RUNTIME} exec -i "${BE}" python manage.py shell -c "
import time
from cases import componenthealth

def store(name, since, total, last, at):
    componenthealth.report_component(name, 'application', {
        'collected_at': time.time(), 'hostname': 'uat',
        'memory': {'used_percent': 10}, 'cpu': {'load_1m': 0.1, 'load_per_cpu': 0.05},
        'disk': {}, 'network': {}, 'process': {},
        'logs': {'errors_total': total, 'errors_since_last_report': since,
                 'warnings_total': 0, 'warnings_since_last_report': 0,
                 'last_error': last, 'last_error_at': at}})

store('uat-health-live', 2, 5, 'live failure: broker unreachable', time.time() - 30)
store('uat-health-recovered', 0, 9, 'old failure: api restarting', time.time() - 4 * 3600)
print('stored')" >/dev/null 2>&1

BODY="$(req "/admin/component-health/")"
read -r LIVE_ALERT LIVE_SINCE REC_ALERT REC_KEEPS REC_AT <<<"$(printf '%s' "${BODY}" | python3 -c "
import json, sys
raw = sys.stdin.read().split(' ', 1)[1]
d = json.loads(raw)
comps = {c.get('component'): c for c in d.get('components', [])}
live = comps.get('uat-health-live', {})
rec = comps.get('uat-health-recovered', {})
def alert_text(c): return ' '.join(a.get('message', '') for a in (c.get('alerts') or []))
print(int('broker unreachable' in alert_text(live)),
      int((live.get('logs') or {}).get('errors_since_last_report', 0) == 2),
      int('api restarting' in alert_text(rec)),
      int((rec.get('logs') or {}).get('last_error', '') != ''),
      int(bool((rec.get('logs') or {}).get('last_error_at'))))" 2>/dev/null)"
[[ "${LIVE_ALERT}" == "1" && "${LIVE_SINCE}" == "1" ]] \
    && ok "errors since the last report raise an alert carrying the message, and the count survives to the row" \
    || bad "a live error did not surface as an alert with its reason"

say "3/4  A recovered component is NOT degraded — while the record survives"
[[ "${REC_ALERT}" == "0" ]] \
    && ok "zero errors since the last report raises NO alert — recovered is not degraded" \
    || bad "a component clean since its last report still raises an alert"
[[ "${REC_KEEPS}" == "1" && "${REC_AT}" == "1" ]] \
    && ok "and the last error is still on the record WITH its timestamp, so the UI can age it" \
    || bad "recovery erased the record, or it has no timestamp to age by"

say "4/4  The page renders the age, and every real component is fresh"
UIJS="$(${RUNTIME} exec ir-enclave_frontend_1 sh -c 'cat /usr/share/nginx/html/assets/*.js /usr/share/nginx/html/assets/*.css' 2>/dev/null)"
printf '%s' "${UIJS}" | grep -q "recovered — last error" \
    && ok "the card labels a recovered error as recovered, with when it happened" \
    || bad "the deployed UI does not carry the recovered-error treatment"
printf '%s' "${UIJS}" | grep -q "ch-error-stale" \
    && ok "and visually mutes it — history must not read as a live fault" \
    || bad "the stale-error style is not in the deployed bundle"

STALE="$(req "/admin/component-health/" | python3 -c "
import json, sys
raw = sys.stdin.read().split(' ', 1)[1]
d = json.loads(raw)
rows = [c for c in d.get('components', [])
        if not str(c.get('component', '')).startswith('uat-health-')]
stale = [c['component'] for c in rows if c.get('stale')]
print(len(rows), ','.join(stale) or '-')" 2>/dev/null)"
read -r NCOMP STALE_LIST <<<"${STALE}"
if [[ "$(num "${NCOMP:-}")" -ge 1 && "${STALE_LIST}" == "-" ]]; then
    ok "all ${NCOMP} real components have reported within two intervals — the page shows the present, not a cache"
elif [[ "${STALE_LIST}" != "-" ]]; then
    bad "component(s) silent past two report intervals: ${STALE_LIST} — the card shows their past as if current"
else
    bad "no real components in the health report at all"
fi

report_finish
exit "${FAILED}"
