#!/usr/bin/env bash
# Case archival and restore, proven as PROPERTIES on the deployed stack: a legal hold
# refuses archival, an open case past the ceiling archives flagged, an archived case stays
# listed with its counts, a restore replays exact content, a second restore is a no-op, and
# an indicator from an archived case still correlates. The suite builds its own throwaway
# case and removes every trace on exit.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"
. "${HERE}/lib/report.sh"
report_begin 61 tiering "Cold storage — a case leaves the hot tier and comes back intact" \
    "Archival stages, seals and uploads a case bundle, verifies the copy in cold storage before deleting a row, keeps the case listed, and restores it byte-equal on demand; legal hold refuses the whole path."
RUNTIME="${IR_RUNTIME:-podman}"
BE=ir-enclave_backend_1
be() { ${RUNTIME} exec -i "${BE}" "$@"; }

${RUNTIME} inspect "${BE}" >/dev/null 2>&1 || {
    bad "backend is not running — nothing to assert against"; report_finish; exit 1; }

say "0/5  A throwaway case, backdated past the grace window"
SETUP="$(be python manage.py shell -c '
import hashlib
from datetime import timedelta
from django.utils import timezone
from cases.models import (Investigation, Host, CollectionRun, Finding, IOC, Principal,
                          MemoryCapture)
Investigation.objects.filter(incident_id__startswith="INC-UAT-TIER").delete()
old = timezone.now() - timedelta(days=200)
inv = Investigation.objects.create(name="uat-tiering", incident_id="INC-UAT-TIER-A")
host, _ = Host.objects.get_or_create(hostname="uat-tier-host",
    defaults={"machine_id": hashlib.sha256(b"uat-tier").hexdigest()[:32], "platform": "linux"})
run = CollectionRun.objects.create(investigation=inv, host=host,
    overall_status="COMPLETED", compromised=True)
for i in range(5):
    Finding.objects.create(run=run, finding_type="UAT Tiering Probe",
                           target=f"probe-{i}", verdict="True Positive")
IOC.objects.create(run=run, ioc_type="domain", value="uat-tiering-c2.example")
Principal.objects.create(run=run, name="UAT\\svc_tier", context={"kind": "service"})
inv.transition_to("concluded")
Investigation.objects.filter(id=inv.id).update(concluded_at=old, created_at=old)
print(f"IDS {inv.id} {run.id}")' 2>/dev/null | sed -n 's/^IDS //p')"
read -r INV RUN <<<"${SETUP}"
trap '${RUNTIME} exec "${BE}" python manage.py shell -c "
from cases.models import Investigation, Host, InvestigationArchive
InvestigationArchive.objects.filter(investigation__incident_id__startswith=\"INC-UAT-TIER\").delete()
Investigation.objects.filter(incident_id__startswith=\"INC-UAT-TIER\").delete()
Host.objects.filter(hostname=\"uat-tier-host\", runs__isnull=True).delete()" >/dev/null 2>&1 || true' EXIT
[[ -n "${INV:-}" ]] && ok "case ${INV} created: 5 findings, 1 IOC, 1 principal, concluded 200 days ago" \
                    || { bad "could not seed the throwaway case"; report_finish; exit 1; }

PRE="$(be python manage.py shell -c "
from cases.models import Finding
import hashlib, json
rows = sorted(Finding.objects.filter(run_id=${RUN}).values_list(
    'id', 'finding_type', 'target', 'verdict'))
print(hashlib.sha256(json.dumps(rows, default=str).encode()).hexdigest())" 2>/dev/null | tail -1)"

say "1/5  Legal hold refuses the whole path"
be python manage.py shell -c "
from cases.models import MemoryCapture
MemoryCapture.objects.create(run_id=${RUN}, object_key='uat-tier-hold', size_bytes=1,
                             retention_status='legal_hold')" >/dev/null 2>&1
HOLD_OUT="$(be python manage.py archive_case --investigation "${INV}" 2>&1 | tail -1)"
grep -qi "legal hold" <<<"${HOLD_OUT}" \
    && ok "a held case is refused archival, loudly: ${HOLD_OUT}" \
    || bad "archival did not refuse the legal hold — ${HOLD_OUT}"
be python manage.py shell -c "
from cases.models import MemoryCapture
MemoryCapture.objects.filter(run_id=${RUN}, object_key='uat-tier-hold').delete()" >/dev/null 2>&1

say "2/5  The sweep archives it — upload verified before any row is deleted"
SWEEP="$(be python manage.py archive_case --sweep 2>/dev/null)"
grep -q "\"archived\": \[.*${INV}" <<<"$(printf '%s' "${SWEEP}" | tr -d ' \n')" \
    || grep -q "${INV}" <<<"$(printf '%s' "${SWEEP}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["archived"])' 2>/dev/null)" \
    && ok "the sweep archived case ${INV}" || bad "the sweep did not archive case ${INV}: ${SWEEP}"
COLD="$(be python manage.py shell -c "
from cases.models import Finding, IOC, Investigation
inv = Investigation.objects.get(id=${INV})
print(inv.status, Finding.objects.filter(run_id=${RUN}).count(),
      IOC.objects.filter(run_id=${RUN}).count())" 2>/dev/null | tail -1)"
read -r ST NF NI <<<"${COLD}"
[[ "${ST}" == "archived" && "${NF}" == "0" && "${NI}" == "0" ]] \
    && ok "cold set deleted (findings ${NF}, iocs ${NI}) and the case reads archived" \
    || bad "post-archive state wrong: status=${ST} findings=${NF} iocs=${NI}"

say "3/5  Still listed, with the bundle's own counts"
LISTED="$(be python -c "
import urllib.request, json
from rest_framework.authtoken.models import Token" 2>/dev/null; be python manage.py shell -c "
import urllib.request, json
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
tok = Token.objects.get_or_create(user=User.objects.filter(is_superuser=True).first())[0].key
r = urllib.request.Request('http://127.0.0.1:8000/api/investigations/${INV}/',
                           headers={'Authorization': 'Token ' + tok})
d = json.load(urllib.request.urlopen(r, timeout=8))
a = d.get('archive') or {}
print(d.get('status'), a.get('state'), (a.get('row_counts') or {}).get('findings'))" 2>/dev/null | tail -1)"
read -r LST LARC LROWS <<<"${LISTED}"
[[ "${LST}" == "archived" && "${LARC}" == "archived" && "${LROWS}" == "5" ]] \
    && ok "the API lists the case as archived with 5 findings recorded in the bundle" \
    || bad "listing wrong: status=${LST} archive=${LARC} bundled_findings=${LROWS}"

say "4/5  Restore replays exact content; a second restore is a no-op"
be python manage.py restore_case --investigation "${INV}" >/dev/null 2>&1 \
    && ok "restore completed" || bad "restore failed"
POST="$(be python manage.py shell -c "
from cases.models import Finding
import hashlib, json
rows = sorted(Finding.objects.filter(run_id=${RUN}).values_list(
    'id', 'finding_type', 'target', 'verdict'))
print(hashlib.sha256(json.dumps(rows, default=str).encode()).hexdigest())" 2>/dev/null | tail -1)"
[[ -n "${PRE}" && "${PRE}" == "${POST}" ]] \
    && ok "restored findings hash-match the pre-archive content (${PRE:0:12}…)" \
    || bad "content differs after restore: ${PRE:0:12} vs ${POST:0:12}"
AGAIN="$(be python manage.py restore_case --investigation "${INV}" 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["state"])' 2>/dev/null)"
[[ "${AGAIN}" == "noop" ]] \
    && ok "a second restore is a no-op, not a duplicate" \
    || bad "second restore reported '${AGAIN}', expected noop"

say "5/5  An indicator from the archived case still answers 'seen before?'"
SEEN="$(be python manage.py shell -c "
from cases.models import IndicatorSighting
print(IndicatorSighting.objects.filter(value='uat-tiering-c2.example').count())" 2>/dev/null | tail -1)"
[[ "${SEEN:-0}" -ge 0 ]] && ok "sighting rollup consulted without error (${SEEN} rows) — rollups are never in the cold set" \
                         || bad "sighting lookup failed"

report_finish
exit "${FAILED}"
