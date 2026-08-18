#!/usr/bin/env bash
# The case tree, the curated tag vocabulary and the task board, asserted against real rows:
# the tree's counts match the tables it summarizes, a tag outside the vocabulary is refused,
# every board move is audited, and all three respect case compartments. Ephemeral fixtures
# only; every trace removed on exit.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"
. "${HERE}/lib/report.sh"
report_begin 63 casework "Case tree, curated tags and the task board" \
    "The tree serves the hierarchy in one request with counts that match the underlying tables; tags come from an admin-curated vocabulary and free text is refused; task moves are audited; and all three are scoped by case membership."
RUNTIME="${IR_RUNTIME:-podman}"
BE=ir-enclave_backend_1
be() { ${RUNTIME} exec -i "${BE}" "$@"; }

${RUNTIME} inspect "${BE}" >/dev/null 2>&1 || {
    bad "backend is not running — nothing to assert against"; report_finish; exit 1; }

say "0/4  A case with two hosts, and two analyst identities"
SETUP="$(be python manage.py shell -c '
import hashlib
from django.contrib.auth.models import Group, User
from rest_framework.authtoken.models import Token
from cases.models import (Investigation, Host, CollectionRun, Finding, MemoryCapture,
                          CaseTag, CaseTask, CaseAssignment)
Investigation.objects.filter(incident_id__startswith="INC-UAT-WORK").delete()
User.objects.filter(username__in=("uat-work-analyst", "uat-work-outsider")).delete()
CaseTag.objects.filter(label__startswith="uat-work-").delete()
analysts, _ = Group.objects.get_or_create(name="analyst")
an = User.objects.create_user("uat-work-analyst"); an.groups.add(analysts)
out = User.objects.create_user("uat-work-outsider"); out.groups.add(analysts)
inv = Investigation.objects.create(name="uat-casework", incident_id="INC-UAT-WORK-A")
for i in (1, 2):
    host, _ = Host.objects.get_or_create(hostname=f"uat-work-host{i}",
        defaults={"machine_id": hashlib.sha256(f"uat-work{i}".encode()).hexdigest()[:32],
                  "platform": "linux"})
    run = CollectionRun.objects.create(investigation=inv, host=host,
                                       overall_status="COMPLETED", compromised=(i == 1))
    for j in range(i * 2):
        Finding.objects.create(run=run, finding_type="UAT Work Probe",
                               target=f"h{i}-f{j}", verdict="True Positive")
    MemoryCapture.objects.create(run=run, object_key=f"uat-work/h{i}.raw",
                                 size_bytes=1024 * i)
admin = User.objects.filter(is_superuser=True).first()
print("IDS", inv.id,
      Token.objects.get_or_create(user=an)[0].key,
      Token.objects.get_or_create(user=out)[0].key,
      Token.objects.get_or_create(user=admin)[0].key)' 2>/dev/null | sed -n 's/^IDS //p')"
read -r INV TOK_AN TOK_OUT TOK_ADM <<<"${SETUP}"
trap '${RUNTIME} exec "${BE}" python manage.py shell -c "
from django.contrib.auth.models import User
from cases.models import Investigation, Host, CaseTag
Investigation.objects.filter(incident_id__startswith=\"INC-UAT-WORK\").delete()
User.objects.filter(username__in=(\"uat-work-analyst\", \"uat-work-outsider\")).delete()
CaseTag.objects.filter(label__startswith=\"uat-work-\").delete()
Host.objects.filter(hostname__startswith=\"uat-work-host\", runs__isnull=True).delete()" >/dev/null 2>&1 || true' EXIT
[[ -n "${TOK_ADM:-}" ]] \
    && ok "case ${INV}: 2 hosts, 2 runs, 6 findings, 2 captures" \
    || { bad "could not seed the casework fixture"; report_finish; exit 1; }

# The JSON body is passed as an ARGUMENT, never interpolated into the Python source:
# a body containing quotes would otherwise terminate the string and the probe would fail
# with a syntax error that reads like a refusal.
req() { # token method path json
    be python -c "
import json, sys, urllib.request, urllib.error
tok, method, path, body = sys.argv[1:5]
data = body.encode() if body != 'None' else None
r = urllib.request.Request('http://127.0.0.1:8000/api' + path, method=method, data=data,
                           headers={'Authorization': 'Token ' + tok,
                                    'Content-Type': 'application/json'})
try:
    resp = urllib.request.urlopen(r, timeout=10)
    print(resp.getcode(), resp.read().decode().replace(chr(10), ' ')[:400000])
except urllib.error.HTTPError as e:
    print(e.code, e.read().decode().replace(chr(10), ' ')[:400])
except Exception as e:
    print(0, e)" "$1" "$2" "$3" "$4" 2>/dev/null | tail -1
}

say "1/4  The tree is one request, and its counts match the tables"
TREE="$(req "${TOK_AN}" GET "/investigations/${INV}/tree/" None)"
TREE_OK="$(printf '%s' "${TREE}" | python3 -c "
import json, sys
line = sys.stdin.read().split(' ', 1)
code = line[0]
d = json.loads(line[1]) if len(line) > 1 and line[1].strip().startswith('{') else {}
hosts = d.get('children', [])
runs = [r for h in hosts for r in h.get('children', [])]
caps = [c for r in runs for c in r.get('children', [])]
findings = sum(r.get('finding_count', 0) for r in runs)
print(code, len(hosts), len(runs), len(caps), findings)" 2>/dev/null)"
read -r TC TH TR TCAP TF <<<"${TREE_OK}"
[[ "${TC}" == "200" && "${TH}" == "2" && "${TR}" == "2" && "${TCAP}" == "2" ]] \
    && ok "tree returns 2 hosts, 2 runs, 2 captures in one request" \
    || bad "tree shape wrong: code=${TC} hosts=${TH} runs=${TR} captures=${TCAP}"
DB_F="$(be python manage.py shell -c "
from cases.models import Finding
print(Finding.objects.filter(run__investigation_id=${INV}).count())" 2>/dev/null | tail -1)"
[[ "${TF}" == "${DB_F}" ]] \
    && ok "the tree's finding counts sum to the finding table (${TF} == ${DB_F})" \
    || bad "tree counts disagree with the database: ${TF} vs ${DB_F}"

say "2/4  The tag vocabulary is curated, and free text is refused"
TAG_CREATE="$(req "${TOK_ADM}" POST "/tags/" '{"label": "uat-work-ransomware", "category": "threat"}')"
TAG_ID="$(printf '%s' "${TAG_CREATE}" | python3 -c "
import json, sys
p = sys.stdin.read().split(' ', 1)
print(json.loads(p[1])['id'] if len(p) > 1 and p[1].strip().startswith('{') else '')" 2>/dev/null)"
[[ -n "${TAG_ID}" ]] && ok "an admin adds 'uat-work-ransomware' to the vocabulary" \
                     || bad "the admin could not create a tag: ${TAG_CREATE}"
ANALYST_TAG="$(req "${TOK_AN}" POST "/tags/" '{"label": "uat-work-adhoc"}')"
[[ "${ANALYST_TAG%% *}" == "403" ]] \
    && ok "an analyst cannot invent a tag — the vocabulary stays curated" \
    || bad "an analyst created a vocabulary entry (${ANALYST_TAG%% *})"
APPLY="$(req "${TOK_AN}" POST "/investigations/${INV}/tags/" "{\"tag\": ${TAG_ID:-0}}")"
[[ "${APPLY%% *}" == "200" ]] && ok "the analyst applies a curated tag to the case" \
                             || bad "applying a curated tag failed: ${APPLY}"
BOGUS="$(req "${TOK_AN}" POST "/investigations/${INV}/tags/" '{"tag": 999999}')"
[[ "${BOGUS%% *}" == "400" ]] \
    && ok "a tag id outside the vocabulary is refused, not silently created" \
    || bad "an unknown tag was accepted (${BOGUS%% *})"

say "3/4  The board is the forensic lifecycle, and work moves BOTH ways"
BOARD="$(req "${TOK_AN}" GET "/investigations/${INV}/tasks/" None)"
STAGES="$(printf '%s' "${BOARD}" | python3 -c "
import json, sys
p = sys.stdin.read().split(' ', 1)
d = json.loads(p[1]) if len(p) > 1 and p[1].strip().startswith('{') else {}
print(','.join(c['state'] for c in d.get('columns', [])))" 2>/dev/null)"
[[ "${STAGES}" == "identification,preservation,analysis,documentation,presentation" ]] \
    && ok "the columns are the digital forensics process, in order: ${STAGES}" \
    || bad "board stages are not the forensic lifecycle: ${STAGES}"
INTENT="$(printf '%s' "${BOARD}" | python3 -c "
import json, sys
p = sys.stdin.read().split(' ', 1)
d = json.loads(p[1]) if len(p) > 1 and p[1].strip().startswith('{') else {}
print(sum(1 for c in d.get('columns', []) if c.get('intent')))" 2>/dev/null)"
[[ "${INTENT}" == "5" ]] && ok "every stage states what it is for — a column explains itself" \
                         || bad "only ${INTENT}/5 stages carry their intent"

AUD_BEFORE="$(be python manage.py shell -c "
from cases.models import AuditLog
print(AuditLog.objects.filter(action__startswith='task.').count())" 2>/dev/null | tail -1)"
NEW_TASK="$(req "${TOK_AN}" POST "/investigations/${INV}/tasks/" '{"title": "image uat-work-host1", "assignee": "uat-work-analyst"}')"
TASK_ID="$(printf '%s' "${NEW_TASK}" | python3 -c "
import json, sys
p = sys.stdin.read().split(' ', 1)
print(json.loads(p[1])['id'] if len(p) > 1 and p[1].strip().startswith('{') else '')" 2>/dev/null)"
[[ -n "${TASK_ID}" ]] && ok "a task opens in Identification" \
                     || bad "task creation failed: ${NEW_TASK}"
FWD="$(req "${TOK_AN}" POST "/investigations/${INV}/tasks/" "{\"id\": ${TASK_ID:-0}, \"state\": \"documentation\"}")"
[[ "${FWD%% *}" == "200" ]] && ok "it jumps forward to Documentation — stages are not a ratchet" \
                           || bad "the forward move failed: ${FWD}"
BACK="$(req "${TOK_AN}" POST "/investigations/${INV}/tasks/" "{\"id\": ${TASK_ID:-0}, \"state\": \"analysis\"}")"
BACK_STATE="$(printf '%s' "${BACK}" | python3 -c "
import json, sys
p = sys.stdin.read().split(' ', 1)
print(json.loads(p[1])['state'] if len(p) > 1 and p[1].strip().startswith('{') else '')" 2>/dev/null)"
[[ "${BACK_STATE}" == "analysis" ]] \
    && ok "and BACK to Analysis — late evidence reopens work, which a one-way board would hide" \
    || bad "the backward move did not take: ${BACK}"
BLOCK="$(req "${TOK_AN}" POST "/investigations/${INV}/tasks/" "{\"id\": ${TASK_ID:-0}, \"blocked\": true, \"blocked_reason\": \"awaiting legal sign-off\"}")"
BLOCKED="$(printf '%s' "${BLOCK}" | python3 -c "
import json, sys
p = sys.stdin.read().split(' ', 1)
d = json.loads(p[1]) if len(p) > 1 and p[1].strip().startswith('{') else {}
print(d.get('blocked'), d.get('state'))" 2>/dev/null)"
[[ "${BLOCKED}" == "True analysis" ]] \
    && ok "blocked is an attribute, not a column — the task stays in the stage it stalled in" \
    || bad "blocking moved or lost the task: ${BLOCKED}"
BADSTATE="$(req "${TOK_AN}" POST "/investigations/${INV}/tasks/" "{\"id\": ${TASK_ID:-0}, \"state\": \"invented\"}")"
[[ "${BADSTATE%% *}" == "400" ]] \
    && ok "a stage outside the process is refused — the board cannot invent columns" \
    || bad "an arbitrary stage was accepted (${BADSTATE%% *})"

NOTE="$(req "${TOK_AN}" POST "/tasks/${TASK_ID:-0}/notes/" '{"body": "verified the custody seal before staging"}')"
[[ "${NOTE%% *}" == "201" ]] && ok "an analyst records a working note on the task" \
                            || bad "adding a note failed: ${NOTE}"
FIND_ID="$(be python manage.py shell -c "
from cases.models import Finding
print(Finding.objects.filter(run__investigation_id=${INV}).order_by('id').first().id)" 2>/dev/null | tail -1)"
LINK="$(req "${TOK_AN}" POST "/tasks/${TASK_ID:-0}/attachments/" "{\"ref_type\": \"finding\", \"ref_id\": ${FIND_ID:-0}}")"
[[ "${LINK%% *}" == "201" ]] && ok "evidence the platform already holds is linked, never copied" \
                            || bad "linking evidence failed: ${LINK}"
BADREF="$(req "${TOK_AN}" POST "/tasks/${TASK_ID:-0}/attachments/" '{"ref_type": "auth_user", "ref_id": 1}')"
[[ "${BADREF%% *}" == "400" ]] \
    && ok "a reference to a table outside the evidence vocabulary is refused" \
    || bad "an arbitrary table was addressable as evidence (${BADREF%% *})"
DETAIL="$(req "${TOK_AN}" GET "/tasks/${TASK_ID:-0}/" None)"
COUNTS="$(printf '%s' "${DETAIL}" | python3 -c "
import json, sys
p = sys.stdin.read().split(' ', 1)
d = json.loads(p[1]) if len(p) > 1 and p[1].strip().startswith('{') else {}
print(len(d.get('notes', [])), len(d.get('attachments', [])), len(d.get('states', [])))" 2>/dev/null)"
[[ "${COUNTS}" == "1 1 5" ]] \
    && ok "the task carries its note, its attachment and the five stages it can move to" \
    || bad "task detail wrong (notes attachments stages): ${COUNTS}"
AUD_AFTER="$(be python manage.py shell -c "
from cases.models import AuditLog
print(AuditLog.objects.filter(action__startswith='task.').count())" 2>/dev/null | tail -1)"
[[ "${AUD_AFTER:-0}" -ge $(( ${AUD_BEFORE:-0} + 6 )) ]] \
    && ok "every action is audited (${AUD_BEFORE} -> ${AUD_AFTER}: create, 3 moves, note, attach)" \
    || bad "task actions are under-audited: ${AUD_BEFORE} -> ${AUD_AFTER}"

say "4/4  All three respect the compartment"
be python manage.py shell -c "
from cases.models import Investigation
Investigation.objects.filter(id=${INV}).update(compartment='restricted')" >/dev/null 2>&1
for path in "tree" "tags" "tasks"; do
    C="$(req "${TOK_OUT}" GET "/investigations/${INV}/${path}/" None)"
    [[ "${C%% *}" == "404" ]] \
        && ok "${path}: 404 for a non-member of the restricted case" \
        || bad "${path} answered ${C%% *} to a non-member — the compartment leaks"
done
# Asked OF THE CASE, not of the whole board: the answer stays exact however many tasks the
# deployment holds, and the count comes from the database rather than from how much of a
# response happened to fit.
BOARD="$(req "${TOK_OUT}" GET "/tasks/board/?investigation=${INV}" None)"
BOARD_N="$(printf '%s' "${BOARD}" | python3 -c "
import json, sys
p = sys.stdin.read().split(' ', 1)
try:
    d = json.loads(p[1]) if len(p) > 1 else {}
except ValueError:
    print('unreadable')
    raise SystemExit
# count is the database's answer for the whole filtered set; the rows are checked too, so a
# server that ignored the filter cannot pass on the count alone.
rows = [t for t in d.get('tasks', []) if t.get('investigation') == ${INV}]
print(max(int(d.get('count', 0)), len(rows)))" 2>/dev/null)"
# Three values, not two: a board this probe could not read is UNMEASURED, and reporting that
# as a leak sends the reader hunting a scoping bug that is not there.
if [[ "${BOARD_N}" == "0" ]]; then
    ok "the cross-case board shows a non-member none of this case's tasks"
elif [[ "${BOARD_N}" =~ ^[0-9]+$ ]]; then
    bad "the board leaked ${BOARD_N} task(s) of a restricted case"
else
    bad "the board could not be read (${BOARD_N:-no answer}) — the compartment is unmeasured, not proven"
fi

report_finish
exit "${FAILED}"
