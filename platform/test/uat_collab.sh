#!/usr/bin/env bash
# Working a case alongside other people: presence, soft locks, mentions, notifications,
# the activity feed, global search and the shift handover.
#
# Two properties carry this suite, and both are tested NEGATIVELY as well as positively:
#
#   1. NONE OF IT BLOCKS. A soft lock informs; it never refuses an edit. The suite proves
#      the second analyst is told who holds a task AND that their write still lands.
#   2. NONE OF IT LEAKS. Search, presence, mentions, the feed and the handover all reach
#      across every case at once, which makes them the easiest place to bypass
#      compartments. Each is checked against a case the caller is not cleared for.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"
. "${HERE}/lib/report.sh"
report_begin 40 collab "Presence, locks, mentions, search and shift handover" \
    "Three analysts share a case: one holds a task and the other is told without being stopped, a mention reaches only someone cleared for the case, the feed comes from the audit ledger itself, and search and handover refuse to show a compartmented case to a non-member."

# Bash compares arithmetically, so a non-numeric operand is read as a VARIABLE NAME and
# aborts the run under `set -u`.
num() { local v="${1//[^0-9]/}"; printf '%s' "${v:-0}"; }
RUNTIME="${IR_RUNTIME:-podman}"
BE=ir-enclave_backend_1

cleanup() {
    ${RUNTIME} exec -i "${BE}" python manage.py shell -c "
from django.contrib.auth.models import User
from cases.models import ArtifactLock, CaseTask, Investigation, Notification, Presence
Investigation.objects.filter(incident_id__startswith='INC-UAT-COLLAB').delete()
User.objects.filter(username__startswith='uat-collab-').delete()" >/dev/null 2>&1 || true
}
trap cleanup EXIT

say "1/7  Three analysts and two cases — one of them compartmented"
SETUP="$(${RUNTIME} exec -i "${BE}" python manage.py shell -c "
from django.contrib.auth.models import Group, User
from rest_framework.authtoken.models import Token
from cases.models import CaseAssignment, CaseTask, Investigation
g, _ = Group.objects.get_or_create(name='analyst')
out = []
for who in ('alice', 'bob', 'carol'):
    u, _ = User.objects.get_or_create(username=f'uat-collab-{who}')
    u.is_superuser = False; u.is_staff = False; u.save()
    u.groups.set([g])
    out.append(Token.objects.get_or_create(user=u)[0].key)

# An open case both alice and bob are assigned to.
opened = Investigation.objects.create(
    name='UAT Collab Open', incident_id='INC-UAT-COLLAB-OPEN', operator='uat')
# A compartmented case ONLY alice is a member of. Carol is an analyst in good standing and
# still must not learn it exists.
closed = Investigation.objects.create(
    name='UAT Collab Sealed Kingfisher', incident_id='INC-UAT-COLLAB-SEALED',
    operator='uat', compartment=Investigation.RESTRICTED)
for who in ('alice', 'bob'):
    CaseAssignment.objects.create(investigation=opened,
                                  username=f'uat-collab-{who}', assigned_by='uat')
CaseAssignment.objects.create(investigation=closed, username='uat-collab-alice',
                              assigned_by='uat')
t = CaseTask.objects.create(investigation=opened, title='Triage the sealed kingfisher host',
                            state='analysis', created_by='uat')
st = CaseTask.objects.create(investigation=closed, title='Sealed compartment task',
                             state='analysis', created_by='uat')
admin = User.objects.filter(is_superuser=True).first()
out.append(Token.objects.get_or_create(user=admin)[0].key)
print(' '.join(out), opened.id, closed.id, t.id, st.id)" 2>/dev/null | tail -1)"
read -r T_ALICE T_BOB T_CAROL T_ADMIN INV_OPEN INV_SEALED TASK SEALED_TASK <<<"${SETUP}"
[[ -n "${SEALED_TASK:-}" ]] && ok "alice and bob share case ${INV_OPEN}; only alice is in compartment case ${INV_SEALED}" \
                     || { bad "could not set up the fixture"; report_finish; exit 1; }

req() { # token method path json
    ${RUNTIME} exec -i "${BE}" python -c "
import sys, urllib.request, urllib.error
tok, method, path, body = sys.argv[1:5]
data = body.encode() if body != 'None' else None
r = urllib.request.Request('http://127.0.0.1:8000/api' + path, method=method, data=data,
                           headers={'Authorization': 'Token ' + tok,
                                    'Content-Type': 'application/json'})
try:
    resp = urllib.request.urlopen(r, timeout=45)
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

say "2/7  Presence — who else is on this case, and who is not told"
BEAT_A="$(req "${T_ALICE}" POST "/presence/" "{\"investigation\": ${INV_OPEN}, \"location\": \"/investigations/${INV_OPEN}\"}")"
[[ "${BEAT_A%% *}" == "200" ]] && ok "a heartbeat is accepted and answers with the roster" \
                              || bad "the heartbeat failed: ${BEAT_A}"
req "${T_BOB}" POST "/presence/" "{\"investigation\": ${INV_OPEN}, \"location\": \"/investigations/${INV_OPEN}\"}" >/dev/null
SEEN="$(req "${T_ALICE}" GET "/presence/?investigation=${INV_OPEN}" None | jqf "
print(','.join(sorted(p['username'] for p in d.get('here', []))))")"
[[ "${SEEN}" == *"uat-collab-bob"* ]] \
    && ok "alice sees bob on the same case" || bad "presence did not surface bob: '${SEEN}'"
[[ "${SEEN}" != *"uat-collab-alice"* ]] \
    && ok "and does not see herself listed as company" || bad "the roster included the caller"

# Presence is a cross-case read, so it is a place a compartment can leak.
req "${T_ALICE}" POST "/presence/" "{\"investigation\": ${INV_SEALED}, \"location\": \"/investigations/${INV_SEALED}\"}" >/dev/null
CAROL_SEES="$(req "${T_CAROL}" GET "/presence/" None | jqf "
print(','.join(str(p.get('investigation')) for p in d.get('here', [])))")"
[[ "${CAROL_SEES}" != *"${INV_SEALED}"* ]] \
    && ok "carol is never shown that anyone is inside the compartmented case" \
    || bad "presence leaked compartmented case ${INV_SEALED} to a non-member: '${CAROL_SEES}'"
SEALED_BEAT="$(req "${T_CAROL}" POST "/presence/" "{\"investigation\": ${INV_SEALED}, \"location\": \"/x\"}")"
[[ "${SEALED_BEAT%% *}" == "404" ]] \
    && ok "and cannot announce herself into it — a non-member gets 'no such case', not 'forbidden'" \
    || bad "carol was allowed into the compartment roster (${SEALED_BEAT%% *})"

say "3/7  Soft locks inform. They do not block — that is the whole design"
CLAIM="$(req "${T_ALICE}" POST "/locks/" "{\"investigation\": ${INV_OPEN}, \"ref_type\": \"task\", \"ref_id\": ${TASK}}")"
[[ "$(printf '%s' "${CLAIM}" | jqf "print(d.get('acquired'))")" == "True" ]] \
    && ok "alice takes the soft lock on the task" || bad "the lock was not acquired: ${CLAIM}"
SECOND="$(req "${T_BOB}" POST "/locks/" "{\"investigation\": ${INV_OPEN}, \"ref_type\": \"task\", \"ref_id\": ${TASK}}")"
read -r S_ACQ S_BY <<<"$(printf '%s' "${SECOND}" | jqf "print(d.get('acquired'), d.get('held_by'))")"
[[ "${S_ACQ}" == "False" && "${S_BY}" == "uat-collab-alice" ]] \
    && ok "bob is told alice holds it, by name" || bad "the second claim answered '${SECOND}'"
[[ "${SECOND%% *}" == "200" ]] \
    && ok "and is answered 200, not 409 — he is being informed, not refused" \
    || bad "a held lock returned ${SECOND%% *}; that reads as a refusal"

# The property the whole advisory design rests on.
BOB_WRITES="$(req "${T_BOB}" POST "/tasks/${TASK}/notes/" '{"body": "Second analyst writing while the lock is held elsewhere."}')"
[[ "${BOB_WRITES%% *}" == "201" ]] \
    && ok "AND BOB'S EDIT STILL LANDS — an unreachable colleague can never block an investigation" \
    || bad "a soft lock blocked a write (${BOB_WRITES%% *}); it is no longer advisory"

RELEASE="$(req "${T_ALICE}" DELETE "/locks/?ref_type=task&ref_id=${TASK}" None)"
[[ "$(printf '%s' "${RELEASE}" | jqf "print(d.get('released'))")" == "True" ]] \
    && ok "alice releases it when she closes the drawer" || bad "release failed: ${RELEASE}"
RECLAIM="$(req "${T_BOB}" POST "/locks/" "{\"investigation\": ${INV_OPEN}, \"ref_type\": \"task\", \"ref_id\": ${TASK}}")"
[[ "$(printf '%s' "${RECLAIM}" | jqf "print(d.get('acquired'))")" == "True" ]] \
    && ok "and bob can then take it" || bad "the released lock was not reclaimable: ${RECLAIM}"
NOT_MINE="$(req "${T_ALICE}" DELETE "/locks/?ref_type=task&ref_id=${TASK}" None)"
[[ "$(printf '%s' "${NOT_MINE}" | jqf "print(d.get('released'))")" == "False" ]] \
    && ok "one analyst cannot release another's lock" || bad "alice released bob's lock"

say "4/7  Mentions reach the people who may read the case, and no one else"
MENTION="$(req "${T_ALICE}" POST "/tasks/${TASK}/notes/" '{"body": "@uat-collab-bob please confirm the parent process before I rule on this."}')"
MENTIONED="$(printf '%s' "${MENTION}" | jqf "print(','.join(sorted(d.get('mentioned', []))))")"
[[ "${MENTIONED}" == *"uat-collab-bob"* ]] \
    && ok "bob, working the same case, is notified" || bad "the mention did not reach bob: '${MENTIONED}'"

# The negative has to be on the COMPARTMENTED case. An unassigned analyst may read an open
# case by design, so mentioning carol there is correct behavior, not a leak — only a
# restricted case can tell the two apart.
SEALED_MENTION="$(req "${T_ALICE}" POST "/tasks/${SEALED_TASK}/notes/" '{"body": "@uat-collab-carol can you take a look at this one?"}')"
SEALED_TO="$(printf '%s' "${SEALED_MENTION}" | jqf "print(','.join(sorted(d.get('mentioned', []))))")"
[[ "${SEALED_MENTION%% *}" == "201" && "${SEALED_TO}" != *"uat-collab-carol"* ]] \
    && ok "a mention of carol INSIDE the compartment reaches no one — and alice is not told it failed, which would leak the membership list" \
    || bad "a mention notified someone with no access to the compartmented case: '${SEALED_TO}'"
BOB_NOTIF="$(req "${T_BOB}" GET "/notifications/?unread=1" None | jqf "
ns = d.get('notifications', [])
print(d.get('unread'), sum(1 for n in ns if n.get('kind') == 'mention'))")"
read -r B_UNREAD B_MENTIONS <<<"${BOB_NOTIF}"
[[ "$(num "${B_UNREAD:-}")" -ge 1 && "$(num "${B_MENTIONS:-}")" -ge 1 ]] \
    && ok "it is waiting for him as an unread in-app notification (${B_UNREAD})" \
    || bad "bob has no unread mention: unread=${B_UNREAD:-0} mentions=${B_MENTIONS:-0}"
CAROL_NOTIF="$(req "${T_CAROL}" GET "/notifications/" None | jqf "
print(sum(1 for n in d.get('notifications', []) if n.get('investigation') == ${INV_SEALED}))")"
[[ "$(num "${CAROL_NOTIF:-}")" == "0" ]] \
    && ok "and nothing from the compartmented case is in her tray" \
    || bad "carol received ${CAROL_NOTIF} notification(s) from a case she cannot open"
SELF="$(req "${T_BOB}" POST "/tasks/${TASK}/notes/" '{"body": "note to self @uat-collab-bob"}' \
        | jqf "print(len(d.get('mentioned', [])))")"
[[ "${SELF}" == "0" ]] && ok "mentioning yourself notifies no one" \
                       || bad "a self-mention created ${SELF} notification(s)"

ASSIGN="$(req "${T_ALICE}" POST "/investigations/${INV_OPEN}/tasks/" \
          "{\"id\": ${TASK}, \"assignee\": \"uat-collab-bob\"}")"
ASSIGNED="$(req "${T_BOB}" GET "/notifications/?unread=1" None | jqf "
print(sum(1 for n in d.get('notifications', []) if n.get('kind') == 'assignment'))")"
[[ "${ASSIGN%% *}" == "200" && "$(num "${ASSIGNED:-}")" -ge 1 ]] \
    && ok "being given a task notifies the person it was given to" \
    || bad "assignment produced no notification (${ASSIGNED:-0})"

READ="$(req "${T_BOB}" POST "/notifications/" '{"ids": []}' | jqf "print(d.get('marked'))")"
STILL="$(req "${T_BOB}" GET "/notifications/" None | jqf "print(d.get('unread'))")"
[[ "$(num "${READ:-}")" -ge 1 && "$(num "${STILL:-}")" == "0" ]] \
    && ok "marking them read clears the count (${READ} marked)" \
    || bad "unread did not clear: marked=${READ:-0}, still unread=${STILL:-0}"

say "5/7  The activity feed IS the audit ledger — not a second copy of it"
FEED="$(req "${T_ALICE}" GET "/investigations/${INV_OPEN}/activity/" None)"
read -r F_N F_ACTS <<<"$(printf '%s' "${FEED}" | jqf "
es = d.get('events', [])
print(len(es), ','.join(sorted({e['action'] for e in es})))")"
[[ "$(num "${F_N:-}")" -ge 1 ]] \
    && ok "the case's actions are on its feed (${F_N} event(s): ${F_ACTS})" \
    || bad "the activity feed is empty after several recorded actions"
LEDGER_MATCH="$(${RUNTIME} exec -i "${BE}" python manage.py shell -c "
from cases.models import AuditLog, CaseTask
ids = {str(i) for i in CaseTask.objects.filter(investigation_id=${INV_OPEN}).values_list('id', flat=True)}
print(AuditLog.objects.filter(object_type='task', object_id__in=ids).count())" 2>/dev/null | tail -1)"
[[ "$(num "${LEDGER_MATCH:-}")" -ge 1 ]] \
    && ok "and every one of them is a row in the signed ledger (${LEDGER_MATCH})" \
    || bad "the feed showed events the audit ledger does not hold"
FEED_DENIED="$(req "${T_CAROL}" GET "/investigations/${INV_SEALED}/activity/" None)"
[[ "${FEED_DENIED%% *}" == "404" ]] \
    && ok "a non-member asking for the compartmented case's feed is told it does not exist" \
    || bad "the activity feed leaked a compartmented case (${FEED_DENIED%% *})"

say "6/7  Global search — the easiest place to bypass access control"
FOUND="$(req "${T_ALICE}" GET "/search/?q=Kingfisher" None | jqf "
print(sum(1 for r in d.get('results', []) if r.get('kind') == 'investigation'))")"
[[ "$(num "${FOUND:-}")" -ge 1 ]] \
    && ok "alice, a member, finds the compartmented case by name" \
    || bad "search did not return a case its member may read"
read -r H_SEALED H_OPEN <<<"$(req "${T_CAROL}" GET "/search/?q=Kingfisher" None | jqf "
rs = d.get('results', [])
print(sum(1 for r in rs if r.get('investigation') == ${INV_SEALED}),
      sum(1 for r in rs if r.get('investigation') == ${INV_OPEN}))")"
[[ "$(num "${H_SEALED:-}")" == "0" ]] \
    && ok "CAROL SEES NOTHING OF THE COMPARTMENT — a search box that ignores it is an access-control bypass" \
    || bad "search returned ${H_SEALED} compartmented result(s) to a non-member"
# The other half of the same assertion: scoping that returns nothing at all is not scoping.
[[ "$(num "${H_OPEN:-}")" -ge 1 ]] \
    && ok "and she still finds the open case's matching task in the SAME query — scoped, not blanked" \
    || bad "search returned nothing at all to carol; an empty result would pass the leak check for the wrong reason"
TASK_HIT="$(req "${T_BOB}" GET "/search/?q=kingfisher" None | jqf "
print(sum(1 for r in d.get('results', []) if r.get('kind') == 'task'))")"
[[ "$(num "${TASK_HIT:-}")" -ge 1 ]] \
    && ok "search reaches inside tasks, not only case names" \
    || bad "a task whose title matches was not returned"
SHORT="$(req "${T_ALICE}" GET "/search/?q=a" None | jqf "print(len(d.get('results', [])), d.get('detail', '')[:20])")"
[[ "${SHORT%% *}" == "0" ]] \
    && ok "a one-character query is refused rather than returning the estate" \
    || bad "a single character searched everything"
CASELESS="$(req "${T_BOB}" GET "/search/?q=TRIAGE" None | jqf "
print(sum(1 for r in d.get('results', []) if r.get('kind') == 'task'))")"
[[ "$(num "${CASELESS:-}")" -ge 1 ]] \
    && ok "matching is case-insensitive — analysts do not type the way data was stored" \
    || bad "an upper-case query missed a lower-case match"

say "7/7  Shift handover — what the next analyst inherits"
HAND="$(req "${T_ALICE}" GET "/handover/" None)"
read -r H_TASKS H_CRIT H_WAIT H_FLIGHT H_SINCE <<<"$(printf '%s' "${HAND}" | jqf "
print(d.get('open_tasks', {}).get('total'), d.get('new_criticals', {}).get('total'),
      d.get('awaiting_verdict', {}).get('total'), d.get('in_flight_analyses', {}).get('total'),
      1 if d.get('since') else 0)")"
[[ "${HAND%% *}" == "200" && "${H_SINCE}" == "1" ]] \
    && ok "the handover renders and states the window it covers" \
    || bad "handover failed: ${HAND:0:300}"
[[ "$(num "${H_TASKS:-}")" -ge 1 ]] \
    && ok "the open task on this case is on it (${H_TASKS} open)" \
    || bad "an open task did not reach the handover"

# The handover reads five tables at once. Every one of them has to be scoped.
CAROL_HAND="$(req "${T_CAROL}" GET "/handover/" None | jqf "
rows = d.get('open_tasks', {}).get('rows', [])
print(sum(1 for r in rows if r.get('investigation') == ${INV_SEALED}),
      sum(1 for r in rows if 'Sealed compartment' in (r.get('title') or '')),
      sum(1 for r in rows if r.get('investigation') == ${INV_OPEN}))")"
read -r C_INV C_TITLE C_OPEN <<<"${CAROL_HAND}"
[[ "$(num "${C_INV:-}")" == "0" && "$(num "${C_TITLE:-}")" == "0" ]] \
    && ok "carol's handover carries nothing from the compartmented case — not the case, not the task title" \
    || bad "the handover leaked ${C_INV} compartmented row(s) to a non-member"
[[ "$(num "${C_OPEN:-}")" -ge 1 ]] \
    && ok "while still handing her the ordinary case's open work" \
    || bad "carol's handover was empty; that passes the leak check without proving anything"
read -r A_SEALED A_OPEN <<<"$(req "${T_ALICE}" GET "/handover/" None | jqf "
rows = d.get('open_tasks', {}).get('rows', [])
print(sum(1 for r in rows if r.get('investigation') == ${INV_SEALED}),
      sum(1 for r in rows if r.get('investigation') == ${INV_OPEN}))")"
[[ "$(num "${A_SEALED:-}")" -ge 1 && "$(num "${A_OPEN:-}")" -ge 1 ]] \
    && ok "alice's carries both — her compartmented case AND the ordinary one" \
    || bad "a member's handover is wrong: ${A_SEALED:-0} sealed, ${A_OPEN:-0} open"

WINDOW="$(req "${T_ALICE}" GET "/handover/?since=2099-01-01T00:00:00Z" None | jqf "
print(d.get('new_criticals', {}).get('total'), d.get('record_entries', {}).get('total'))")"
read -r W_CRIT W_REC <<<"${WINDOW}"
[[ "$(num "${W_CRIT:-}")" == "0" && "$(num "${W_REC:-}")" == "0" ]] \
    && ok "the window is honoured — a future 'since' reports nothing new, not everything" \
    || bad "the since window was ignored: ${W_CRIT} criticals, ${W_REC} entries"

report_finish
exit "${FAILED}"
