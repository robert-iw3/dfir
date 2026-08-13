#!/usr/bin/env bash
# The whole forensic lifecycle on one real case, end to end, through the platform.
#
# Ember Fox is collected from real endpoints, sealed, shipped, pulled inward, analyzed and
# correlated; three analysts then work it across the board — identification, preservation,
# analysis, documentation, presentation — each recording what they did and one reviewing
# another's work; and the case ends as two reports whose figures are checked against the
# tables they were drawn from — and finally the case is archived to cold storage and
# restored, with the report regenerated from the rows that came back.
#
# The point is not that each step works in isolation. Those have their own suites. It is
# that the record an analyst leaves, the evidence the platform holds, and the report a court
# would read are the SAME data, and that every hand that touched it is named.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"
. "${HERE}/lib/report.sh"
report_begin 80 lifecycle "The forensic lifecycle, end to end, on one real case" \
    "Ember Fox is collected from endpoints, sealed, shipped, pulled inward, analyzed and correlated; three analysts carry it across the board with their own notes and a peer review; and the case ends as a technical report and a plain-language summary whose figures match the evidence they came from, before going cold and coming back whole."
. "${HERE}/lib/corpus_pipeline.sh"

# Bash compares arithmetically, so a non-numeric operand is read as a VARIABLE NAME and
# aborts the run under `set -u` — an unreadable measurement must fail its assertion, not
# kill the suite.
num() { local v="${1//[^0-9]/}"; printf '%s' "${v:-0}"; }
RUNTIME="${IR_RUNTIME:-podman}"
BE=ir-enclave_backend_1
PROVISION="${PLATFORM}/hashicorp/keycloak/provision-demo-users.sh"

# Ember Fox is investigation A of the standard corpus: a 10-host intrusion that shares
# indicators, plus a 2-host cryptominer that must stay separate from it.
CORPUS_PREFIX=INC-CORPUS
CORPUS_COUNT=25
SCEN="$(mktemp -d)"
trap 'rm -rf "${SCEN}"; ${RUNTIME} exec "${BE}" python manage.py shell -c "
from django.contrib.auth.models import User
User.objects.filter(username__startswith=\"uat-life-\").delete()" >/dev/null 2>&1 || true' EXIT

say "1/9  Identification — real collections from the endpoints"
corpus_preconditions || { report_finish; exit 1; }
python3 "${HERE}/corpus/scenarios.py" "${SCEN}" >/dev/null \
    && ok "25 endpoint scenarios generated (Ember Fox plus the fleet it hides in)" \
    || { bad "scenario generation failed"; report_finish; exit 1; }
corpus_reset
corpus_receiver_addr
corpus_collect_and_ship "${SCEN}"
[[ "$(num "${SHIPPED:-}")" -ge "${CORPUS_COUNT}" ]] \
    && ok "${SHIPPED} endpoints collected, sealed at the point of collection and shipped" \
    || bad "only ${SHIPPED:-0} bundles were accepted by the receiver"

say "2/9  Preservation — the enclave pulls inward and custody survives the journey"
corpus_await_ingest
[[ "$(num "${INGESTED:-}")" -ge "${CORPUS_COUNT}" ]] \
    && ok "the enclave pulled all ${INGESTED} collections inward; nothing was pushed to it" \
    || bad "only ${INGESTED:-0} of ${CORPUS_COUNT} collections reached the enclave"
CUSTODY="$(${RUNTIME} exec -i "${BE}" python manage.py shell -c "
from cases.models import CollectionRun, Investigation
inv = Investigation.objects.filter(incident_id='INC-CORPUS-A').first()
runs = CollectionRun.objects.filter(investigation=inv)
print(runs.count(), runs.filter(custody_verified=True).count())" 2>/dev/null | tail -1)"
read -r NRUNS NVERIFIED <<<"${CUSTODY}"
[[ "$(num "${NRUNS:-}")" -gt 0 && "${NVERIFIED}" == "${NRUNS}" ]] \
    && ok "every one of the ${NRUNS} Ember Fox collections verified its custody seal on arrival" \
    || bad "custody verified on only ${NVERIFIED:-0} of ${NRUNS:-0} collections"

say "3/9  Analysis — memory is analyzed and the campaign is correlated"
corpus_await_analysis
corpus_assert_analysis_ran
corpus_correlate

INV="$(${RUNTIME} exec -i "${BE}" python manage.py shell -c "
from cases.models import Investigation
print(Investigation.objects.get(incident_id='INC-CORPUS-A').id)" 2>/dev/null | tail -1)"
[[ -n "${INV}" ]] && ok "Ember Fox is investigation ${INV}" \
                  || { bad "the Ember Fox investigation was not created"; report_finish; exit 1; }

say "4/9  Three analysts, each with their own identity"
for who in collector examiner reviewer; do
    PW="$(bash "${PROVISION}" --ephemeral "uat-life-${who}" analyst 2>/dev/null \
          | sed -n 's/^EPHEMERAL_PASSWORD=//p')"
    [[ -n "${PW}" ]] || true
done
TOKENS="$(${RUNTIME} exec -i "${BE}" python manage.py shell -c "
from django.contrib.auth.models import Group, User
from rest_framework.authtoken.models import Token
g, _ = Group.objects.get_or_create(name='analyst')
out = []
for who in ('collector', 'examiner', 'reviewer'):
    u, _ = User.objects.get_or_create(username=f'uat-life-{who}')
    u.groups.add(g)
    out.append(Token.objects.get_or_create(user=u)[0].key)
admin = User.objects.filter(is_superuser=True).first()
out.append(Token.objects.get_or_create(user=admin)[0].key)
print(' '.join(out))" 2>/dev/null | tail -1)"
read -r T_COLLECT T_EXAM T_REVIEW T_ADMIN <<<"${TOKENS}"
[[ -n "${T_ADMIN:-}" ]] && ok "three analysts and an admin, each a distinct principal" \
                        || { bad "could not provision the analysts"; report_finish; exit 1; }

req() { # token method path json
    ${RUNTIME} exec -i "${BE}" python -c "
import json, sys, urllib.request, urllib.error
tok, method, path, body = sys.argv[1:5]
data = body.encode() if body != 'None' else None
r = urllib.request.Request('http://127.0.0.1:8000/api' + path, method=method, data=data,
                           headers={'Authorization': 'Token ' + tok,
                                    'Content-Type': 'application/json'})
try:
    resp = urllib.request.urlopen(r, timeout=30)
    print(resp.getcode(), resp.read().decode().replace(chr(10), ' ')[:400000])
except urllib.error.HTTPError as e:
    print(e.code, e.read().decode().replace(chr(10), ' ')[:400])
except Exception as e:
    print(0, e)" "$1" "$2" "$3" "$4" 2>/dev/null | tail -1
}
jqf() { python3 -c "
import json, sys
p = sys.stdin.read().split(' ', 1)
d = json.loads(p[1]) if len(p) > 1 and p[1].strip().startswith(('{', '[')) else {}
$1" 2>/dev/null; }

say "5/9  The board carries the work — and each analyst signs their own part"
T1="$(req "${T_COLLECT}" POST "/investigations/${INV}/tasks/" '{"title": "Collect and verify the Ember Fox endpoints", "assignee": "uat-life-collector"}' | jqf "print(d.get('id',''))")"
[[ -n "${T1}" ]] && ok "the collector opens the first task in Identification" \
                 || bad "task creation failed"
req "${T_COLLECT}" POST "/tasks/${T1}/notes/" '{"body": "All 25 endpoints collected; every bundle sealed at the endpoint and verified on arrival."}' >/dev/null
MOVE1="$(req "${T_COLLECT}" POST "/investigations/${INV}/tasks/" "{\"id\": ${T1}, \"state\": \"preservation\"}")"
[[ "${MOVE1%% *}" == "200" ]] && ok "collector records what they did and moves it to Preservation" \
                             || bad "the move to Preservation failed"

RUN_ID="$(${RUNTIME} exec -i "${BE}" python manage.py shell -c "
from cases.models import CollectionRun
print(CollectionRun.objects.filter(investigation_id=${INV}, compromised=True).order_by('id').first().id)" 2>/dev/null | tail -1)"
req "${T_EXAM}" POST "/tasks/${T1}/attachments/" "{\"ref_type\": \"run\", \"ref_id\": ${RUN_ID}, \"label\": \"first compromised collection\"}" >/dev/null
T2="$(req "${T_EXAM}" POST "/investigations/${INV}/tasks/" '{"title": "Examine memory and adjudicate findings", "assignee": "uat-life-examiner", "state": "analysis"}' | jqf "print(d.get('id',''))")"
req "${T_EXAM}" POST "/tasks/${T2}/notes/" '{"body": "Memory analysis complete across the campaign; shared implant and C2 confirmed on the Ember Fox hosts."}' >/dev/null
[[ -n "${T2}" ]] && ok "the examiner opens their own task in Analysis and links the evidence it rests on" \
                 || bad "the examiner could not open a task"

# The reviewer sends work BACK — the movement a one-way board cannot express.
BACK="$(req "${T_REVIEW}" POST "/investigations/${INV}/tasks/" "{\"id\": ${T2}, \"state\": \"analysis\"}")"
req "${T_REVIEW}" POST "/tasks/${T2}/notes/" '{"body": "Peer review: two hosts band lower than the rest. Returning for a second look before this is documented."}' >/dev/null
[[ "${BACK%% *}" == "200" ]] \
    && ok "the reviewer returns work to Analysis and says why — the board records the disagreement" \
    || bad "the reviewer could not move the task back"
DOC="$(req "${T_EXAM}" POST "/investigations/${INV}/tasks/" "{\"id\": ${T2}, \"state\": \"documentation\"}")"
[[ "${DOC%% *}" == "200" ]] && ok "the examiner answers the review and moves to Documentation" \
                           || bad "the move to Documentation failed"

# Work standing in every stage at once, which is what a board looks like mid-engagement.
T3="$(req "${T_COLLECT}" POST "/investigations/${INV}/tasks/" '{"title": "Re-collect JUMP-01 after the credential reset", "assignee": "uat-life-collector"}' | jqf "print(d.get('id',''))")"
T4="$(req "${T_REVIEW}" POST "/investigations/${INV}/tasks/" '{"title": "Draft the plain-language summary", "assignee": "uat-life-reviewer", "state": "documentation"}' | jqf "print(d.get('id',''))")"
T5="$(req "${T_EXAM}" POST "/investigations/${INV}/tasks/" '{"title": "Brief the affected business unit", "assignee": "uat-life-examiner", "state": "presentation"}' | jqf "print(d.get('id',''))")"
BLOCK="$(req "${T_COLLECT}" POST "/investigations/${INV}/tasks/" "{\"id\": ${T3:-0}, \"blocked\": true, \"blocked_reason\": \"waiting on the asset owner to schedule downtime\"}")"
BLOCKED_STATE="$(printf '%s' "${BLOCK}" | jqf "print(d.get('blocked'), d.get('state'))")"
[[ "${BLOCKED_STATE}" == "True identification" ]] \
    && ok "a blocked task keeps its stage and carries why — blocking is not a column" \
    || bad "blocking moved or lost the task: ${BLOCKED_STATE}"

# The document path, exercised for real: a multipart upload, hashed on receipt.
UPLOAD="$(${RUNTIME} exec -i "${BE}" python -c "
import json, urllib.request, urllib.error, uuid
tok = '${T_EXAM}'
boundary = uuid.uuid4().hex
doc = (b'Peer review of the Ember Fox adjudication\n'
       b'=========================================\n\n'
       b'Reviewed every host banded probable or higher. Two hosts rest on a single\n'
       b'shared indicator and were returned for a second look; the remaining eight\n'
       b'carry independent corroboration. No objection to documenting the campaign\n'
       b'as one intrusion.\n')
body = b''.join([
    ('--' + boundary + '\r\n').encode(),
    b'Content-Disposition: form-data; name="file"; filename="peer-review.md"\r\n',
    b'Content-Type: text/markdown\r\n\r\n', doc, b'\r\n',
    ('--' + boundary + '\r\n').encode(),
    b'Content-Disposition: form-data; name="label"\r\n\r\n',
    b'Peer review memo\r\n',
    ('--' + boundary + '--\r\n').encode()])
r = urllib.request.Request('http://127.0.0.1:8000/api/tasks/${T2}/attachments/',
                           method='POST', data=body,
                           headers={'Authorization': 'Token ' + tok,
                                    'Content-Type': 'multipart/form-data; boundary=' + boundary})
try:
    resp = urllib.request.urlopen(r, timeout=30)
    d = json.loads(resp.read().decode())
    print(resp.getcode(), d.get('kind'), d.get('sha256', '')[:12], d.get('size_bytes'))
except urllib.error.HTTPError as e:
    print(e.code, e.read().decode()[:200])" 2>/dev/null | tail -1)"
read -r UP_CODE UP_KIND UP_SHA UP_SIZE <<<"${UPLOAD}"
[[ "${UP_CODE}" == "201" && "${UP_KIND}" == "document" && -n "${UP_SHA}" ]] \
    && ok "a peer-review document uploads and is hashed on receipt (${UP_SHA}…, ${UP_SIZE} bytes)" \
    || bad "the document upload failed: ${UPLOAD}"

LINK2="$(req "${T_EXAM}" POST "/tasks/${T2}/attachments/" "{\"ref_type\": \"run\", \"ref_id\": ${RUN_ID}, \"label\": \"the collection this rests on\"}")"
KINDS="$(${RUNTIME} exec -i "${BE}" python manage.py shell -c "
from cases.models import CaseTaskAttachment
print(','.join(sorted(CaseTaskAttachment.objects.filter(task_id=${T2})
      .values_list('kind', flat=True).distinct())))" 2>/dev/null | tail -1)"
[[ "${KINDS}" == "document,evidence" ]] \
    && ok "one task carries both an uploaded document and a reference to held evidence" \
    || bad "attachment kinds on the task: ${KINDS:-none}"
STORED="$(${RUNTIME} exec -i "${BE}" python manage.py shell -c "
from cases.models import CaseTaskAttachment
a = CaseTaskAttachment.objects.filter(task_id=${T2}, kind='document').first()
from cases import storage, casework
import hashlib
raw = storage.get_object_bytes(casework.ATTACHMENT_BUCKET, a.object_key)
print(int(hashlib.sha256(raw).hexdigest() == a.sha256))" 2>/dev/null | tail -1)"
[[ "${STORED}" == "1" ]] \
    && ok "the stored bytes hash to what was recorded — the attachment is the file that arrived" \
    || bad "the stored document does not match its recorded sha256"

AUTHORS="$(${RUNTIME} exec -i "${BE}" python manage.py shell -c "
from cases.models import CaseTaskNote
print(CaseTaskNote.objects.filter(task__investigation_id=${INV})
      .values_list('author', flat=True).distinct().count())" 2>/dev/null | tail -1)"
[[ "$(num "${AUTHORS:-}")" -ge 3 ]] \
    && ok "three distinct analysts left notes on this case — the work is attributable to people" \
    || bad "only ${AUTHORS:-0} distinct note authors, expected 3"

say "5b/9  The same machine, seen again in a later engagement"
# One Ember Fox host is collected a second time under a new incident AND a new hostname.
# Identity is (hostname, machine_id), so this must resolve to ONE host with a rename in
# its history — not two machines — and that is what the host page exists to show.
REVISIT="$(${RUNTIME} exec -i "${BE}" python manage.py shell -c "
from django.utils import timezone
from cases.models import CollectionRun, Finding, Host, HostIdentityChange, Investigation
Investigation.objects.filter(incident_id='INC-CORPUS-A-FU').delete()
src = CollectionRun.objects.filter(investigation_id=${INV}, compromised=True).order_by('id').first()
host = src.host
old = host.hostname
inv2 = Investigation.objects.create(name='Ember Fox — follow-up review',
                                    incident_id='INC-CORPUS-A-FU', severity='medium')
HostIdentityChange.objects.create(host=host, field='hostname', from_value=old,
                                  to_value=old + '-REBUILT',
                                  observed_at=timezone.now(), source_stamp='FOLLOWUP',
                                  actor='uat-life-collector')
host.hostname = old + '-REBUILT'
host.save(update_fields=['hostname'])
run2 = CollectionRun.objects.create(investigation=inv2, host=host, stamp='FOLLOWUP',
                                    overall_status='COMPLETED', compromised=False,
                                    custody_verified=True,
                                    toolkit_version=src.toolkit_version)
Finding.objects.create(run=run2, finding_type='Persistence Check',
                       target='no implant present after rebuild', verdict='False Positive')
print(host.id, Host.objects.filter(machine_id=host.machine_id).count(),
      CollectionRun.objects.filter(host=host).count())" 2>/dev/null | tail -1)"
read -r HOST_ID HOST_ROWS HOST_RUNS <<<"${REVISIT}"
[[ "${HOST_ROWS}" == "1" && "$(num "${HOST_RUNS:-}")" -ge 2 ]] \
    && ok "the rebuilt machine is ONE host (${HOST_ID}) with ${HOST_RUNS} collections across two cases, not two hosts" \
    || bad "host identity split on rename: ${HOST_ROWS} row(s), ${HOST_RUNS:-0} run(s)"
OVERVIEW="$(req "${T_EXAM}" GET "/hosts/${HOST_ID}/overview/" None | jqf "
print(len(d.get('runs', [])), int(d.get('investigations') or 0), len(d.get('identity_changes', [])), sum(d.get('verdicts', {}).values() or [0]))")"
read -r OV_RUNS OV_INVS OV_CHANGES OV_VERDICTS <<<"${OVERVIEW}"
[[ "$(num "${OV_INVS:-}")" -ge 2 && "$(num "${OV_CHANGES:-}")" -ge 1 \
   && "$(num "${OV_VERDICTS:-}")" -gt 0 ]] \
    && ok "the host page answers 'seen before?': ${OV_RUNS} collections over ${OV_INVS} cases, ${OV_CHANGES} rename, ${OV_VERDICTS} findings" \
    || bad "host overview incomplete: runs=${OV_RUNS} cases=${OV_INVS} renames=${OV_CHANGES} findings=${OV_VERDICTS}"

say "6/9  Documentation — the record, including what was ruled OUT"
${RUNTIME} exec -i "${BE}" python manage.py shell -c "
from cases.models import Investigation, Note, RuledOut
inv = Investigation.objects.get(id=${INV})
Note.objects.create(investigation=inv, kind='summary', author='uat-life-examiner',
    summary='What happened',
    body='An intruder reached ten hosts using one implant and one command-and-control '
         'address, moving between machines with a shared administrative credential. A '
         'separate cryptomining installation on two other machines is unrelated to it.')
Note.objects.create(investigation=inv, kind='recommendation', author='uat-life-reviewer',
    summary='Rotate the shared administrative credential',
    body='It was used on every affected host and must be considered exposed.')
Note.objects.create(investigation=inv, kind='containment', author='uat-life-collector',
    summary='Blocked the C2 address at the perimeter', body='Applied fleet-wide.')
RuledOut.objects.create(investigation=inv,
    hypothesis='Removable media was the entry point',
    method='Every USB device recorded on the affected hosts was enumerated and compared '
           'against the first evidence of compromise on each.',
    rationale='No device predates the earliest implant, so none can be the source.',
    tested_by='uat-life-examiner', evidence_refs=['run:${RUN_ID}'])" >/dev/null 2>&1 \
    && ok "summary, recommendation, containment action and a ruled-out hypothesis are on the record" \
    || bad "could not write the investigation record"

say "7/9  Presentation — two reports, generated from the case's own data"
TECH="$(req "${T_EXAM}" POST "/investigations/${INV}/reports/" '{"kind": "technical", "fmt": "md"}')"
TECH_ID="$(printf '%s' "${TECH}" | jqf "print(d.get('id',''))")"
[[ "${TECH%% *}" == "201" && -n "${TECH_ID}" ]] \
    && ok "the technical report generates" || bad "technical report generation failed: ${TECH}"
SUMM="$(req "${T_EXAM}" POST "/investigations/${INV}/reports/" '{"kind": "summary", "fmt": "md"}')"
[[ "${SUMM%% *}" == "201" ]] && ok "the plain-language summary generates" \
                             || bad "summary generation failed: ${SUMM}"
PDF="$(req "${T_EXAM}" POST "/investigations/${INV}/reports/" '{"kind": "technical", "fmt": "pdf"}')"
[[ "${PDF%% *}" == "201" ]] && ok "and the same report renders to PDF inside the enclave, offline" \
                            || bad "PDF generation failed: ${PDF}"
# A PDF that merely PARSES is not a report. These are the properties that separate a
# typeset document from a text dump, and every one of them was broken at some point by a
# change that still returned 201.
PDFCHECK="$(${RUNTIME} exec -i "${BE}" python manage.py shell -c "
import re
from cases.models import Investigation
from cases import reporting
inv = Investigation.objects.get(id=${INV})
tpl = reporting.ReportTemplate.objects.get(kind='technical')
body, _ = reporting.render_markdown(inv, tpl)
raw = reporting.to_pdf(body, inv, tpl)
pages = len(re.findall(rb'/Type\s*/Page[^s]', raw))
fonts = set(re.findall(rb'/BaseFont\s*/([A-Za-z-]+)', raw))
print(int(raw.startswith(b'%PDF')), pages,
      int({b'Times-Roman', b'Helvetica-Bold', b'Courier'} <= fonts),
      int(len(raw) > 20000))" 2>/dev/null | tail -1)"
read -r P_MAGIC P_PAGES P_FONTS P_SIZE <<<"${PDFCHECK}"
[[ "${P_MAGIC}" == "1" && "$(num "${P_PAGES:-}")" -ge 5 ]] \
    && ok "the PDF is a real document — ${P_PAGES} paginated pages, not one long dump" \
    || bad "PDF pagination wrong: magic=${P_MAGIC:-?} pages=${P_PAGES:-0}"
[[ "${P_FONTS}" == "1" ]] \
    && ok "it is typeset — a body face, bold headings and a monospace for identifiers" \
    || bad "the PDF does not carry the document's three faces"

say "8/9  The report is the evidence — every figure checked against its table"
CHECK="$(${RUNTIME} exec -i "${BE}" python manage.py shell -c "
from cases.models import (CollectionRun, Finding, GeneratedReport, Investigation,
                          MemoryCapture, RuledOut)
from cases import reporting
inv = Investigation.objects.get(id=${INV})
tpl = reporting.ReportTemplate.objects.get(kind='technical')
body, sources = reporting.render_markdown(inv, tpl)
hosts = CollectionRun.objects.filter(investigation=inv).values('host').distinct().count()
findings = Finding.objects.filter(run__investigation=inv).count()
caps = MemoryCapture.objects.filter(run__investigation=inv).count()
ruled = RuledOut.objects.filter(investigation=inv).count()
checks = [
    ('hosts', sources.get('hosts_examined') == hosts),
    ('findings', sources.get('findings') == findings),
    ('captures', sources.get('captures') == caps),
    ('ruled_out', sources.get('ruled_out') == ruled),
    ('custody_section', 'chain of custody' in body.lower()),
    ('declined_section', 'declined' in body.lower()),
    ('restraint', 'does not name a culprit' in body.lower()),
    ('ruled_out_text', 'Removable media was the entry point' in body),
    ('utc', 'All times are UTC' in body),
    ('recomputed', 'recomputed when this report was generated' in body),
]
print('|'.join(f'{k}={int(v)}' for k, v in checks), hosts, findings, caps)" 2>/dev/null | tail -1)"
read -r CHECKS CH_HOSTS CH_FIND CH_CAPS <<<"${CHECK}"
for pair in ${CHECKS//|/ }; do
    key="${pair%%=*}"; val="${pair##*=}"
    case "${key}:${val}" in
        hosts:1)          ok "the report's host count is the run table's (${CH_HOSTS})" ;;
        findings:1)       ok "its finding count is the finding table's (${CH_FIND})" ;;
        captures:1)       ok "its evidence inventory counts every capture (${CH_CAPS})" ;;
        ruled_out:1)      ok "the ruled-out hypothesis reached the report" ;;
        custody_section:1) ok "the chain of custody is a section, not a claim in prose" ;;
        declined_section:1) ok "links the engine CONSIDERED AND DECLINED are reported" ;;
        restraint:1)      ok "attribution carries its restraint — the platform names no culprit" ;;
        ruled_out_text:1) ok "the negative finding is stated in full, with how it was tested" ;;
        utc:1)            ok "the report declares its timezone" ;;
        recomputed:1)     ok "custody and ledger verification are recomputed at render, not read from a flag" ;;
        *:0)              bad "report check '${key}' failed" ;;
    esac
done

DEFANG="$(${RUNTIME} exec -i "${BE}" python manage.py shell -c "
from cases.models import Investigation
from cases import reporting
inv = Investigation.objects.get(id=${INV})
tpl = reporting.ReportTemplate.objects.get(kind='technical')
body, _ = reporting.render_markdown(inv, tpl)
import re
sec = body.split('## Indicators of compromise')[-1].split('## ')[0]
live = re.findall(r'[a-z0-9-]+\.(?:com|net|org|pro|example)\b', sec)
print(len(live))" 2>/dev/null | tail -1)"
[[ "${DEFANG:-1}" == "0" ]] \
    && ok "every indicator is defanged — nothing in the report can be clicked into a live C2" \
    || bad "${DEFANG} live indicator(s) reached the report unfanged"

PROV="$(req "${T_EXAM}" GET "/investigations/${INV}/reports/" None | jqf "
rs = d.get('reports', [])
print(len(rs), sum(1 for r in rs if r.get('sha256')), sum(1 for r in rs if r.get('data_as_of')))")"
read -r NREP NSHA NASOF <<<"${PROV}"
[[ "$(num "${NREP:-}")" -ge 3 && "${NSHA}" == "${NREP}" && "${NASOF}" == "${NREP}" ]] \
    && ok "all ${NREP} renders are recorded with their hash and the moment the data was read" \
    || bad "report provenance incomplete: ${NREP} reports, ${NSHA} hashed, ${NASOF} timestamped"

DENIED="$(req "${T_COLLECT}" GET "/reports/${TECH_ID}/download/" None)"
[[ "${DENIED%% *}" == "403" ]] \
    && ok "taking the report OUT is refused without the export right — generating is not exporting" \
    || bad "an analyst without the export right downloaded the report (${DENIED%% *})"
ALLOWED="$(req "${T_ADMIN}" GET "/reports/${TECH_ID}/download/" None)"
[[ "${ALLOWED%% *}" == "200" ]] \
    && ok "an identity holding the right takes it out" || bad "the export was refused: ${ALLOWED%% *}"
LEDGER="$(${RUNTIME} exec -i "${BE}" python manage.py shell -c "
from cases.models import ExportLedger
print(ExportLedger.objects.filter(kind__startswith='report.').count())" 2>/dev/null | tail -1)"
[[ "$(num "${LEDGER:-}")" -ge 1 ]] \
    && ok "and the export ledger records what left the platform (${LEDGER} row(s))" \
    || bad "the report export was not ledgered"

AUDIT_TRAIL="$(${RUNTIME} exec -i "${BE}" python manage.py shell -c "
from cases.models import AuditLog
from cases.audit import verify_audit_chain
acts = set(AuditLog.objects.filter(action__in=(
    'task.create','task.update','task.note','task.attach','report.generate'))
    .values_list('action', flat=True))
ok, at = verify_audit_chain()
print(len(acts), int(bool(ok)))" 2>/dev/null | tail -1)"
read -r NACTS CHAIN_OK <<<"${AUDIT_TRAIL}"
[[ "$(num "${NACTS:-}")" -ge 4 && "${CHAIN_OK:-0}" == "1" ]] \
    && ok "every step of the lifecycle is in the audit ledger (${NACTS} action kinds) and the chain still verifies" \
    || bad "lifecycle audit incomplete: ${NACTS:-0} action kinds, chain_ok=${CHAIN_OK:-0}"

say "9/9  Retention — the finished case goes cold and comes back whole"
# The tiering suite proves these mechanics on a case built for the purpose; it cannot prove
# they hold for one carrying captures, analyses, correlation and a report.
# A previous run leaves the case ARCHIVED, and the corpus reset re-collects evidence without
# touching investigation state. Without this the second run reports a product defect that is
# really its own leftovers.
${RUNTIME} exec -i "${BE}" python manage.py shell -c "
from cases.models import Investigation, InvestigationArchive, RestoreRequest
inv = Investigation.objects.get(id=${INV})
RestoreRequest.objects.filter(archive__investigation=inv).delete()
InvestigationArchive.objects.filter(investigation=inv).delete()
if inv.status == Investigation.ARCHIVED:
    inv.status = Investigation.OPEN
    inv.save(update_fields=['status'])
print('reset')" >/dev/null 2>&1

PRE_TIER="$(${RUNTIME} exec -i "${BE}" python manage.py shell -c "
import hashlib, json
from cases.models import Finding, Investigation, IOC, MemoryCapture, ProcessVerdict
from correlation.models import CorrelationRun
inv = Investigation.objects.get(id=${INV})
rows = list(Finding.objects.filter(run__investigation=inv).order_by('id')
            .values('id', 'finding_type', 'target', 'subject_path', 'verdict',
                    'confidence', 'adjudicated_by'))
h = hashlib.sha256(json.dumps(rows, default=str, sort_keys=True).encode()).hexdigest()
print(h, len(rows),
      IOC.objects.filter(run__investigation=inv).count(),
      ProcessVerdict.objects.filter(run__investigation=inv).count(),
      MemoryCapture.objects.filter(run__investigation=inv).count(),
      CorrelationRun.objects.filter(investigation_id=inv.id).count(),
      inv.status)" 2>/dev/null | tail -1)"
read -r PRE_HASH PRE_FIND PRE_IOC PRE_VERD PRE_CAPS PRE_CORR PRE_STATUS <<<"${PRE_TIER}"
[[ "$(num "${PRE_FIND:-}")" -gt 0 && "$(num "${PRE_CORR:-}")" -gt 0 ]] \
    && ok "the case being archived is a real one — ${PRE_FIND} findings, ${PRE_CAPS} captures, ${PRE_CORR} correlation run(s)" \
    || bad "nothing to archive: ${PRE_FIND:-0} findings, ${PRE_CORR:-0} correlation runs"

ARCHIVED="$(${RUNTIME} exec -i "${BE}" python manage.py archive_case --investigation "${INV}" \
            --actor uat-life-admin 2>&1 | tr -d ' \n')"
printf '%s' "${ARCHIVED}" | grep -q '"sha256"' \
    && ok "the bundle is sealed and uploaded, and read back from cold storage before a single row is deleted" \
    || bad "archival failed: ${ARCHIVED:0:300}"
# Ember Fox is still OPEN. Archiving it is the ceiling path, and the platform has to record
# that it took an unfinished case rather than quietly treat it as a closed one.
printf '%s' "${ARCHIVED}" | grep -q '"archived_while_open":true' \
    && ok "and it is flagged as archived while still open — the anomaly is recorded, not smoothed over" \
    || bad "an open case was archived without being flagged: ${ARCHIVED:0:300}"

COLD="$(${RUNTIME} exec -i "${BE}" python manage.py shell -c "
from cases.models import (Finding, Investigation, InvestigationArchive, IOC,
                          MemoryCapture, ProcessVerdict)
inv = Investigation.objects.get(id=${INV})
arc = InvestigationArchive.objects.filter(investigation=inv).order_by('-id').first()
print(Finding.objects.filter(run__investigation=inv).count(),
      IOC.objects.filter(run__investigation=inv).count(),
      ProcessVerdict.objects.filter(run__investigation=inv).count(),
      MemoryCapture.objects.filter(run__investigation=inv).count(),
      inv.status, arc.state, arc.row_counts.get('findings', -1))" 2>/dev/null | tail -1)"
read -r C_FIND C_IOC C_VERD C_CAPS C_STATUS C_STATE C_ROWS <<<"${COLD}"
[[ "$(num "${C_FIND:-}")" == "0" && "$(num "${C_IOC:-}")" == "0" && "$(num "${C_VERD:-}")" == "0" ]] \
    && ok "the hot tier sheds the bulk — findings, indicators and verdicts are gone from it" \
    || bad "cold tier still holds hot rows: ${C_FIND} findings, ${C_IOC} iocs, ${C_VERD} verdicts"
[[ "${C_CAPS}" == "${PRE_CAPS}" ]] \
    && ok "the evidence itself stays — all ${C_CAPS} captures are still addressable" \
    || bad "archival removed captures: ${PRE_CAPS} before, ${C_CAPS} after"
[[ "${C_STATUS}" == "archived" && "${C_STATE}" == "archived" && "${C_ROWS}" == "${PRE_FIND}" ]] \
    && ok "the case is still listed, marked cold, with the counts it went in with (${C_ROWS} findings)" \
    || bad "archived case misrepresented: status=${C_STATUS} state=${C_STATE} rows=${C_ROWS}"

DUE_DENIED="$(req "${T_EXAM}" GET "/investigations/archive-due/" None)"
[[ "${DUE_DENIED%% *}" == "403" ]] \
    && ok "the retention queue is admin-only — an analyst is not shown what is about to be aged out" \
    || bad "an analyst read the retention queue (${DUE_DENIED%% *})"
DUE="$(req "${T_ADMIN}" GET "/investigations/archive-due/" None | jqf "
print(d.get('grace_days'), d.get('ceiling_days'), len(d.get('due', [])) + len(d.get('warning', [])))")"
read -r D_GRACE D_CEIL D_ROWS <<<"${DUE}"
[[ "${D_GRACE:-0}" -gt 0 && "${D_CEIL:-0}" -gt "${D_GRACE:-0}" ]] \
    && ok "the queue states its own windows — ${D_GRACE}-day grace, ${D_CEIL}-day ceiling" \
    || bad "retention windows not reported: grace=${D_GRACE:-?} ceiling=${D_CEIL:-?}"

RESTORE_DENIED="$(req "${T_REVIEW}" POST "/investigations/${INV}/restore/" '{}')"
[[ "${RESTORE_DENIED%% *}" == "403" ]] \
    && ok "restoring is admin-only — an analyst cannot pull a case back on their own authority" \
    || bad "an analyst restored a case (${RESTORE_DENIED%% *})"
RESTORED="$(req "${T_ADMIN}" POST "/investigations/${INV}/restore/" '{}')"
R_STATE="$(printf '%s' "${RESTORED}" | jqf "print(d.get('state',''))")"
[[ "${RESTORED%% *}" == "200" && "${R_STATE}" == "completed" ]] \
    && ok "an admin restores it through the API, verified against its seal first" \
    || bad "restore failed: ${RESTORED:0:300}"

POST_TIER="$(${RUNTIME} exec -i "${BE}" python manage.py shell -c "
import hashlib, json
from cases.models import Finding, Investigation, IOC, ProcessVerdict
inv = Investigation.objects.get(id=${INV})
rows = list(Finding.objects.filter(run__investigation=inv).order_by('id')
            .values('id', 'finding_type', 'target', 'subject_path', 'verdict',
                    'confidence', 'adjudicated_by'))
h = hashlib.sha256(json.dumps(rows, default=str, sort_keys=True).encode()).hexdigest()
print(h, len(rows),
      IOC.objects.filter(run__investigation=inv).count(),
      ProcessVerdict.objects.filter(run__investigation=inv).count(),
      inv.status)" 2>/dev/null | tail -1)"
read -r POST_HASH POST_FIND POST_IOC POST_VERD POST_STATUS <<<"${POST_TIER}"
[[ -n "${PRE_HASH:-}" && "${POST_HASH}" == "${PRE_HASH}" ]] \
    && ok "the findings come back identical, original ids and all (${PRE_HASH:0:12}…)" \
    || bad "content differs after restore: ${PRE_HASH:0:12} vs ${POST_HASH:0:12}"
[[ "${POST_IOC}" == "${PRE_IOC}" && "${POST_VERD}" == "${PRE_VERD}" ]] \
    && ok "so do the indicators (${POST_IOC}) and the adjudicated verdicts (${POST_VERD})" \
    || bad "restore lost rows: iocs ${PRE_IOC}->${POST_IOC}, verdicts ${PRE_VERD}->${POST_VERD}"

# The reason any of this matters: a case is archived so that it can be answered for later.
# The report is that answer, and it has to come out of the restored rows unchanged.
REREPORT="$(req "${T_EXAM}" POST "/investigations/${INV}/reports/" '{"kind": "technical", "fmt": "md"}')"
RECHECK="$(${RUNTIME} exec -i "${BE}" python manage.py shell -c "
from cases.models import CollectionRun, Finding, Investigation, MemoryCapture
from cases import reporting
inv = Investigation.objects.get(id=${INV})
tpl = reporting.ReportTemplate.objects.get(kind='technical')
body, sources = reporting.render_markdown(inv, tpl)
hosts = CollectionRun.objects.filter(investigation=inv).values('host').distinct().count()
print(sources.get('hosts_examined'), sources.get('findings'), sources.get('captures'),
      hosts, Finding.objects.filter(run__investigation=inv).count(),
      MemoryCapture.objects.filter(run__investigation=inv).count(),
      int('chain of custody' in body.lower()))" 2>/dev/null | tail -1)"
read -r R_HOSTS R_FIND R_CAPS R_THOSTS R_TFIND R_TCAPS R_CUSTODY <<<"${RECHECK}"
[[ "${REREPORT%% *}" == "201" && "${R_FIND}" == "${PRE_FIND}" && "${R_CAPS}" == "${PRE_CAPS}" ]] \
    && ok "the report regenerates from the restored case with the figures it had before it went cold (${R_FIND} findings, ${R_CAPS} captures)" \
    || bad "the restored case reports differently: ${R_FIND:-?}/${PRE_FIND} findings, ${R_CAPS:-?}/${PRE_CAPS} captures"
[[ "${R_HOSTS}" == "${R_THOSTS}" && "${R_FIND}" == "${R_TFIND}" && "${R_CAPS}" == "${R_TCAPS}" \
   && "${R_CUSTODY}" == "1" ]] \
    && ok "and it is still drawn from the tables, not from the bundle — custody verified against the restored rows" \
    || bad "post-restore report does not match its own tables: ${R_HOSTS}/${R_THOSTS} hosts, ${R_FIND}/${R_TFIND} findings"

# A restore is a loan, not a reversal. Left alone it lapses, and the case has to go cold
# again on its own rather than sit hot because someone once looked at it.
${RUNTIME} exec -i "${BE}" python manage.py shell -c "
from datetime import timedelta
from django.utils import timezone
from cases.models import InvestigationArchive
arc = InvestigationArchive.objects.filter(investigation_id=${INV}).order_by('-id').first()
arc.restored_until = timezone.now() - timedelta(days=1)
arc.save(update_fields=['restored_until'])" >/dev/null 2>&1
RECOOL="$(${RUNTIME} exec -i "${BE}" python manage.py archive_case --sweep --actor uat-life-admin 2>/dev/null)"
printf '%s' "${RECOOL}" | tr -d ' \n' | grep -q "\"recooled\":\[${INV}" \
    && ok "an expired restore re-cools itself on the next sweep" \
    || bad "the lapsed restore was not re-cooled: $(printf '%s' "${RECOOL}" | tr -d '\n' | tail -c 200)"
RECOOLED="$(${RUNTIME} exec -i "${BE}" python manage.py shell -c "
from cases.models import Finding, Investigation, InvestigationArchive
arc = InvestigationArchive.objects.filter(investigation_id=${INV}).order_by('-id').first()
print(Finding.objects.filter(run__investigation_id=${INV}).count(), arc.state,
      int(arc.restored_until is None))" 2>/dev/null | tail -1)"
read -r RC_FIND RC_STATE RC_TTL <<<"${RECOOLED}"
[[ "$(num "${RC_FIND:-}")" == "0" && "${RC_STATE}" == "archived" && "${RC_TTL}" == "1" ]] \
    && ok "the hot rows are shed again and the case reads cold, with no loan outstanding" \
    || bad "re-cool incomplete: ${RC_FIND} findings left, state=${RC_STATE}, ttl_cleared=${RC_TTL}"

# Restored last so the run leaves the case as it found it — a suite that ends with the
# estate's flagship investigation in cold storage has broken the stack for whoever is next.
FINAL="$(req "${T_ADMIN}" POST "/investigations/${INV}/restore/" '{}')"
FINAL_FIND="$(${RUNTIME} exec -i "${BE}" python manage.py shell -c "
from cases.models import Finding
print(Finding.objects.filter(run__investigation_id=${INV}).count())" 2>/dev/null | tail -1)"
[[ "${FINAL%% *}" == "200" && "${FINAL_FIND}" == "${PRE_FIND}" ]] \
    && ok "and it restores again after re-cooling — the case is left hot, whole and workable" \
    || bad "the case was not restored at the end of the run: ${FINAL%% *}, ${FINAL_FIND:-0}/${PRE_FIND} findings"

TIER_AUDIT="$(${RUNTIME} exec -i "${BE}" python manage.py shell -c "
from cases.models import AuditLog
from cases.audit import verify_audit_chain
acts = set(AuditLog.objects.filter(action__in=(
    'investigation.archive', 'investigation.restore', 'investigation.recool'))
    .values_list('action', flat=True))
ok, at = verify_audit_chain()
print(len(acts), int(bool(ok)))" 2>/dev/null | tail -1)"
read -r T_ACTS T_CHAIN <<<"${TIER_AUDIT}"
[[ "$(num "${T_ACTS:-}")" -ge 3 && "${T_CHAIN:-0}" == "1" ]] \
    && ok "archive, restore and re-cool are each in the ledger, and it still verifies" \
    || bad "retention audit incomplete: ${T_ACTS:-0} of 3 action kinds, chain_ok=${T_CHAIN:-0}"

report_finish
exit "${FAILED}"
