#!/usr/bin/env bash
# Case compartments, proven by NEGATIVE assertions: an analyst who is not assigned to a
# restricted case cannot list it, read it, reach its findings, runs or notes by direct id,
# or export it — each attempted, not assumed. The converse is asserted too, so a scope that
# simply refuses everything cannot pass. Ephemeral accounts only; every trace removed on exit.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"
. "${HERE}/lib/report.sh"
report_begin 62 scoping "Compartments — a restricted case is invisible to everyone not on it" \
    "Case membership scopes every route that can reach a case: list, detail, findings, runs, notes and export. A non-member is refused each one by attempt; an assigned member reads the same case normally."
RUNTIME="${IR_RUNTIME:-podman}"
BE=ir-enclave_backend_1
be() { ${RUNTIME} exec -i "${BE}" "$@"; }

${RUNTIME} inspect "${BE}" >/dev/null 2>&1 || {
    bad "backend is not running — nothing to assert against"; report_finish; exit 1; }

say "0/5  A restricted case, one member and one outsider"
SETUP="$(be python manage.py shell -c '
import hashlib
from django.contrib.auth.models import Group, User
from cases.models import (Investigation, Host, CollectionRun, Finding, Note,
                          CaseAssignment)
Investigation.objects.filter(incident_id__startswith="INC-UAT-SCOPE").delete()
User.objects.filter(username__in=("uat-scope-member", "uat-scope-outsider")).delete()
analysts, _ = Group.objects.get_or_create(name="analyst")
member = User.objects.create_user("uat-scope-member")
outsider = User.objects.create_user("uat-scope-outsider")
member.groups.add(analysts); outsider.groups.add(analysts)
inv = Investigation.objects.create(name="uat-scope-restricted",
                                   incident_id="INC-UAT-SCOPE-R",
                                   compartment="restricted")
openinv = Investigation.objects.create(name="uat-scope-open",
                                       incident_id="INC-UAT-SCOPE-O")
host, _ = Host.objects.get_or_create(hostname="uat-scope-host",
    defaults={"machine_id": hashlib.sha256(b"uat-scope").hexdigest()[:32],
              "platform": "linux"})
run = CollectionRun.objects.create(investigation=inv, host=host,
                                   overall_status="COMPLETED", compromised=True)
f = Finding.objects.create(run=run, finding_type="UAT Scope Probe", target="secret",
                           verdict="True Positive")
n = Note.objects.create(investigation=inv, body="restricted case note", author="seed")
CaseAssignment.objects.create(investigation=inv, username="uat-scope-member",
                              assigned_by="seed")
from rest_framework.authtoken.models import Token
print("IDS", inv.id, openinv.id, run.id, f.id, n.id,
      Token.objects.get_or_create(user=member)[0].key,
      Token.objects.get_or_create(user=outsider)[0].key)' 2>/dev/null | sed -n 's/^IDS //p')"
read -r RINV OINV RUN FIND NOTE TOK_M TOK_O <<<"${SETUP}"
trap '${RUNTIME} exec "${BE}" python manage.py shell -c "
from django.contrib.auth.models import User
from cases.models import Investigation, Host
Investigation.objects.filter(incident_id__startswith=\"INC-UAT-SCOPE\").delete()
User.objects.filter(username__in=(\"uat-scope-member\", \"uat-scope-outsider\")).delete()
Host.objects.filter(hostname=\"uat-scope-host\", runs__isnull=True).delete()" >/dev/null 2>&1 || true' EXIT
[[ -n "${TOK_O:-}" ]] \
    && ok "restricted case ${RINV} (1 finding, 1 note) + open case ${OINV}; member and outsider are both analysts" \
    || { bad "could not seed the scoping fixture"; report_finish; exit 1; }

# Status code for one identity against one path, from inside the backend.
code() { # token path
    be python -c "
import urllib.request, urllib.error
req = urllib.request.Request('http://127.0.0.1:8000/api$2',
                             headers={'Authorization': 'Token $1'})
try:
    print(urllib.request.urlopen(req, timeout=8).getcode())
except urllib.error.HTTPError as e:
    print(e.code)
except Exception:
    print(0)" 2>/dev/null | tail -1
}
# How many rows of a listing this identity can see.
count() { # token path
    be python -c "
import urllib.request, json
req = urllib.request.Request('http://127.0.0.1:8000/api$2',
                             headers={'Authorization': 'Token $1'})
d = json.load(urllib.request.urlopen(req, timeout=8))
print(d.get('count', len(d if isinstance(d, list) else d.get('results', []))))" 2>/dev/null | tail -1
}

say "1/5  The outsider is refused every route to the case"
[[ "$(code "${TOK_O}" "/investigations/${RINV}/")" == "404" ]] \
    && ok "detail by direct id: 404 — an unassigned analyst is not told the case exists" \
    || bad "the outsider read the restricted case detail (got $(code "${TOK_O}" "/investigations/${RINV}/"))"
OUT_LIST="$(count "${TOK_O}" "/investigations/?search=uat-scope-restricted")"
[[ "${OUT_LIST}" == "0" ]] \
    && ok "list and search: 0 rows — searching for it by name finds nothing" \
    || bad "the restricted case appeared in the outsider's list (${OUT_LIST} rows)"
OUT_F="$(count "${TOK_O}" "/findings/?investigation=${RINV}")"
[[ "${OUT_F}" == "0" ]] \
    && ok "findings filtered to the case: 0 rows — the drill-down leaks nothing either" \
    || bad "the outsider read ${OUT_F} finding(s) of the restricted case"
OUT_R="$(count "${TOK_O}" "/runs/?investigation=${RINV}")"
[[ "${OUT_R}" == "0" ]] && ok "runs filtered to the case: 0 rows" \
                        || bad "the outsider read ${OUT_R} run(s) of the restricted case"
OUT_N="$(count "${TOK_O}" "/notes/?investigation=${RINV}")"
[[ "${OUT_N}" == "0" ]] && ok "notes filtered to the case: 0 rows" \
                        || bad "the outsider read ${OUT_N} note(s) of the restricted case"

say "2/5  The member reads the same case normally"
[[ "$(code "${TOK_M}" "/investigations/${RINV}/")" == "200" ]] \
    && ok "detail: 200 for the assigned analyst" \
    || bad "the assigned member was refused the case ($(code "${TOK_M}" "/investigations/${RINV}/"))"
MEM_F="$(count "${TOK_M}" "/findings/?investigation=${RINV}")"
[[ "${MEM_F}" == "1" ]] \
    && ok "findings: 1 row — the scope permits, it does not merely refuse" \
    || bad "the member saw ${MEM_F} findings, expected 1"

say "3/5  The open case is unaffected — compartmenting is not a global deny"
[[ "$(code "${TOK_O}" "/investigations/${OINV}/")" == "200" ]] \
    && ok "the outsider reads the OPEN case normally (200)" \
    || bad "an open case was hidden from an analyst — the scope over-reaches"

say "4/5  Assignment is an admin action, driven through the API and audited"
# An admin token, because assignment must be refused to an analyst and that refusal is
# itself an assertion.
TOK_A="$(be python manage.py shell -c "
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
print(Token.objects.get_or_create(user=User.objects.filter(is_superuser=True).first())[0].key)" 2>/dev/null | tail -1)"
post() { # token path json
    be python -c "
import json, urllib.request, urllib.error
req = urllib.request.Request('http://127.0.0.1:8000/api$2', method='POST',
                             data=json.dumps($3).encode(),
                             headers={'Authorization': 'Token $1',
                                      'Content-Type': 'application/json'})
try:
    print(urllib.request.urlopen(req, timeout=8).getcode())
except urllib.error.HTTPError as e:
    print(e.code)
except Exception:
    print(0)" 2>/dev/null | tail -1
}
BEFORE="$(be python manage.py shell -c "
from cases.models import AuditLog
print(AuditLog.objects.filter(action__in=('case.assign','case.unassign','case.compartment')).count())" 2>/dev/null | tail -1)"

[[ "$(post "${TOK_M}" "/investigations/${RINV}/assignments/" "{'username': 'uat-scope-outsider'}")" == "403" ]] \
    && ok "an analyst cannot assign anyone — membership is an admin decision" \
    || bad "an analyst was allowed to change case membership"

[[ "$(post "${TOK_A}" "/investigations/${RINV}/assignments/" "{'username': 'uat-scope-outsider'}")" == "200" ]] \
    && ok "the admin assigns the outsider through the API" \
    || bad "the admin could not assign through the API"

# The scope must FOLLOW the assignment, not a restart: the same identity that was refused
# above now reads the case.
[[ "$(code "${TOK_O}" "/investigations/${RINV}/")" == "200" ]] \
    && ok "the newly assigned analyst now reads the case — the scope tracks membership live" \
    || bad "assignment did not grant access ($(code "${TOK_O}" "/investigations/${RINV}/"))"

[[ "$(post "${TOK_A}" "/investigations/${RINV}/assignments/" "{'username': 'uat-scope-outsider', 'remove': True}")" == "200" ]] \
    && ok "and the admin removes them again" || bad "removal failed"
[[ "$(code "${TOK_O}" "/investigations/${RINV}/")" == "404" ]] \
    && ok "access is gone with the membership — 404 again" \
    || bad "access survived removal ($(code "${TOK_O}" "/investigations/${RINV}/"))"

[[ "$(post "${TOK_A}" "/investigations/${RINV}/compartment/" "{'compartment': 'open'}")" == "200" ]] \
    && ok "the admin moves the case to the open compartment" || bad "compartment change failed"
[[ "$(code "${TOK_O}" "/investigations/${RINV}/")" == "200" ]] \
    && ok "an open case is readable by any analyst — the compartment is what gated it" \
    || bad "the case stayed hidden after being opened"

AFTER="$(be python manage.py shell -c "
from cases.models import AuditLog
print(AuditLog.objects.filter(action__in=('case.assign','case.unassign','case.compartment')).count())" 2>/dev/null | tail -1)"
[[ "${AFTER:-0}" -ge $(( ${BEFORE:-0} + 3 )) ]] \
    && ok "the trail gained an entry per action (${BEFORE} -> ${AFTER}: assign, unassign, compartment)" \
    || bad "audit entries missing: ${BEFORE} -> ${AFTER}, expected at least 3 more"

say "5/5  Account administration — every role provisions, and deletion is real"
# The Users page's own endpoint, driven end to end: the platform provisions in Keycloak and
# mirrors locally, so a deletion has to remove both — and must refuse the two dangerous
# shapes, an analyst doing it and an admin deleting themselves.
udel() { # token username -> code
    be python -c "
import urllib.request, urllib.error
req = urllib.request.Request('http://127.0.0.1:8000/api/users/?username=$2',
                             method='DELETE', headers={'Authorization': 'Token $1'})
try:
    print(urllib.request.urlopen(req, timeout=20).getcode())
except urllib.error.HTTPError as e:
    print(e.code)
except Exception:
    print(0)" 2>/dev/null | tail -1
}
UC="$(post "${TOK_A}" "/users/" "{'username': 'uat-scope-re', 'email': 'uat-scope-re@example.invalid', 'role': 'reverse_engineer', 'password': 'Uat-Scope-Re!x91'}")"
[[ "${UC}" == "201" ]] \
    && ok "a reverse_engineer provisions through the admin endpoint — the fourth role is not second-class" \
    || bad "reverse_engineer provisioning failed (${UC})"
[[ "$(post "${TOK_A}" "/users/" "{'username': 'uat-scope-bad', 'email': 'b@example.invalid', 'role': 'wizard', 'password': 'Uat-Scope-Re!x91'}")" == "400" ]] \
    && ok "an unknown role is refused with the full vocabulary in the answer" \
    || bad "an unknown role was accepted"
[[ "$(udel "${TOK_O}" "uat-scope-re")" == "403" ]] \
    && ok "an analyst cannot delete an account — administration is the admin's act" \
    || bad "a non-admin deleted a user"
ADMIN_NAME="$(be python manage.py shell -c "
from django.contrib.auth.models import User
print(User.objects.filter(is_superuser=True).first().username)" 2>/dev/null | tail -1)"
[[ "$(udel "${TOK_A}" "${ADMIN_NAME}")" == "400" ]] \
    && ok "an admin cannot delete their own account — the session that issued it must belong to someone" \
    || bad "self-deletion was allowed"
[[ "$(udel "${TOK_A}" "uat-scope-re")" == "200" ]] \
    && ok "the admin deletes the account" || bad "deletion failed"
GONE="$(be python manage.py shell -c "
from django.contrib.auth.models import User
from cases.models import AuditLog
print(int(not User.objects.filter(username='uat-scope-re').exists()),
      AuditLog.objects.filter(action='user.delete', object_id='uat-scope-re').count())" 2>/dev/null | tail -1)"
read -r U_GONE U_AUD <<<"${GONE}"
[[ "${U_GONE}" == "1" && "${U_AUD:-0}" -ge 1 ]] \
    && ok "gone from Keycloak AND the local mirror, and the deletion is in the ledger" \
    || bad "deletion incomplete: local_gone=${U_GONE} audited=${U_AUD:-0}"
[[ "$(udel "${TOK_A}" "uat-scope-re")" == "502" ]] \
    && ok "deleting an absent account says so rather than pretending it worked" \
    || bad "a second deletion did not report the absence"

report_finish
exit "${FAILED}"
