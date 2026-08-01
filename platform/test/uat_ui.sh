#!/usr/bin/env bash
# UAT — analyst-facing capabilities, asserted against the seeded intrusion.
#
# Every check verifies REAL DATA, not reachability: correlation must identify the entry
# point the scenario encodes, paging must return distinct slices, filters must return the
# right rows, the diff must find the detections the newer ruleset adds, and adjudication
# must land in the tamper-proof ledger.
#
# The seed prints its ground truth, so this asserts against what the scenario encodes
# rather than against whatever the code happens to produce.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"
RUNTIME="${IR_RUNTIME:-podman}"
BE="${IR_BACKEND_CONTAINER:-ir-enclave_backend_1}"
FAILED=0

say()  { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
ok()   { printf '  \033[1;32mPASS\033[0m %s\n' "$*"; }
bad()  { printf '  \033[1;31mFAIL\033[0m %s\n' "$*"; FAILED=1; }

[[ $(${RUNTIME} ps --format '{{.Names}}' | grep -cx "${BE}") -gt 0 ]] || {
    printf '\033[1;31mbackend container %s is not running\033[0m\n' "${BE}"; exit 1; }

# The whole suite runs inside the backend: it holds the API, both databases and an admin
# identity, so no management port has to be opened to test.
run_in_backend() {
    ${RUNTIME} cp "$1" "${BE}:/tmp/_uat_ui.py" >/dev/null 2>&1 || return 1
    ${RUNTIME} exec -w /app -e PYTHONPATH=/app "${BE}" python /tmp/_uat_ui.py 2>&1
}

say "1/6  Seed the 20-host intrusion and correlate it"
SEED=$(${RUNTIME} exec -w /app "${BE}" python manage.py seed_campaign --reset 2>&1 | tail -40)
printf '%s' "$SEED" | grep -q '"patient_zero": "WS-007"' \
    && ok "scenario seeded (ground truth: WS-007 is the entry point)" \
    || bad "seed did not report the expected ground truth"
${RUNTIME} exec -w /app "${BE}" python manage.py correlate >/dev/null 2>&1 \
    && ok "correlation computed from collected evidence" \
    || bad "correlation failed"

cat > /tmp/_uat_ui.py <<'PYEOF'
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

import django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ir_platform.settings")
django.setup()

from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token

from cases.models import AuditLog, Finding, MemoryCapture
from correlation.models import Campaign, CampaignEdge, CampaignHost

admin = User.objects.filter(is_superuser=True).first()
TOKEN = Token.objects.get_or_create(user=admin)[0].key
BASE = "http://127.0.0.1:8000/api"

results = []
def check(cond, msg):
    results.append((bool(cond), msg))

def api(path, data=None, raw=False):
    req = urllib.request.Request(
        BASE + path,
        headers={"Authorization": "Token " + TOKEN, "Content-Type": "application/json"},
        data=json.dumps(data).encode() if data is not None else None,
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        body = r.read()
    return body if raw else json.loads(body)

# --- 2. Correlation identifies the intrusion the scenario encodes -------------------
ember = Campaign.objects.filter(label="Ember Fox", run__is_current=True).first()
miner = Campaign.objects.filter(label="Cryptominer Outbreak", run__is_current=True).first()

check(ember and ember.patient_zero == "WS-007",
      f"entry point identified as WS-007 (got {ember.patient_zero if ember else 'no campaign'})")
check(ember and ember.initial_vector == "T1566.001",
      f"initial vector T1566.001 (got {ember.initial_vector if ember else '-'})")
check(ember and ember.host_count == 10,
      f"blast radius is 10 hosts (got {ember.host_count if ember else 0})")
check(CampaignEdge.objects.filter(campaign=ember).count() == 9,
      "9 lateral-movement edges reconstructed")

# The negative control: a separate compromise must not be folded into the intrusion.
miner_hosts = set(CampaignHost.objects.filter(campaign=miner).values_list("hostname", flat=True))
ember_hosts = set(CampaignHost.objects.filter(campaign=ember).values_list("hostname", flat=True))
check(miner and miner.host_count == 2 and not (miner_hosts & ember_hosts),
      "unrelated compromise stays a separate campaign (no false linking)")
check(not (ember_hosts & {"WS-001", "WS-002", "WS-006", "WS-009"}),
      "clean hosts are excluded from the blast radius")

# Movement is reconstructed in the right direction, with the account that was used.
first_hop = CampaignEdge.objects.filter(campaign=ember, src_hostname="WS-007").first()
check(first_hop and first_hop.dst_hostname == "JUMP-01"
      and first_hop.account.endswith("j.okafor"),
      "first hop WS-007 -> JUMP-01 carries the harvested account")

# --- 3. Graph and timeline serve the same picture ------------------------------------
graph = api(f"/correlation/campaigns/{ember.id}/graph/")
roles = {n["role"] for n in graph["nodes"]}
check(len(graph["nodes"]) == 10 and len(graph["edges"]) == 9,
      "graph endpoint serves 10 nodes / 9 edges")
check("patient_zero" in roles and "pivot" in roles,
      "graph distinguishes the entry point from pivots")

timeline = api(f"/correlation/campaigns/{ember.id}/timeline/")
times = [e["at"] for e in timeline["events"]]
check(len(times) > 10 and times == sorted(times), "timeline is populated and ordered")
check(any(e["kind"] == "lateral_movement" for e in timeline["events"]),
      "timeline includes movement between hosts")

indicators = api("/correlation/indicators/")["indicators"]
c2 = next((i for i in indicators if i["value"] == "198.51.100.23"), None)
check(c2 and c2["host_count"] == 10, "shared C2 indicator spans all 10 intrusion hosts")

# --- 4. Paging, sorting and filtering happen at the database -------------------------
p1 = api("/findings/?page_size=5")
p2 = api("/findings/?page_size=5&page=2")
check(p1["count"] > 50 and p1["total_pages"] > 1, "findings are paged")
check({r["id"] for r in p1["results"]}.isdisjoint({r["id"] for r in p2["results"]}),
      "page 2 returns a different slice")
asc = [r["finding_type"] for r in api("/findings/?page_size=20&ordering=finding_type")["results"]]
check(asc == sorted(asc), "ordering is applied by the database")
tp = api("/findings/?verdict=" + urllib.parse.quote("True Positive") + "&page_size=1")
check(0 < tp["count"] < p1["count"], "verdict filter narrows the set")
tech = api("/findings/?technique=T1021.001&page_size=10")
check(tech["count"] == 1 and tech["results"][0]["hostname"] == "JUMP-01",
      "ATT&CK filter returns exactly the RDP movement (JUMP-01)")
hosts = api("/hosts/?page_size=3&ordering=-hostname")["results"]
check([h["hostname"] for h in hosts] == sorted([h["hostname"] for h in hosts], reverse=True),
      "host ordering is applied by the database")

# --- 5. Re-analysis diff surfaces what a newer ruleset adds --------------------------
cap = MemoryCapture.objects.filter(run__host__hostname="WS-007").first()
diff = api(f"/captures/{cap.id}/diff/")
added = {f["finding_type"] for f in diff["added"]}
check(diff["comparable"] and diff["base"]["ruleset_version"] == "2026.05"
      and diff["head"]["ruleset_version"] == "current",
      "diff compares oldest -> newest ruleset")
check("Known tool signature" in added and len(diff["added"]) == 3,
      f"diff finds the 3 detections the newer ruleset adds (got {sorted(added)})")
check(not diff["removed"], "nothing is lost between rulesets")

# --- 6. Adjudication and export are recorded in the tamper-proof ledger --------------
ids = list(Finding.objects.filter(verdict="Indeterminate").values_list("id", flat=True)[:3])
before = {f.id: f.verdict for f in Finding.objects.filter(id__in=ids)}
res = api("/findings/bulk-verdict/",
          {"ids": ids, "verdict": "False Positive", "reason": "uat"})
check(res["changed"] == len(ids), "bulk verdict applied to every selected finding")
check(all(f.verdict == "False Positive" for f in Finding.objects.filter(id__in=ids)),
      "verdicts persisted")

entry = AuditLog.objects.filter(action="finding.bulk_verdict").order_by("-id").first()
recorded = {c["id"]: c["from"] for c in (entry.detail or {}).get("changes", [])}
check(recorded == before,
      "ledger records each finding's prior verdict, not just an aggregate")

# Restore, so the suite is repeatable.
api("/findings/bulk-verdict/", {"ids": ids, "verdict": "Indeterminate", "reason": "uat revert"})

csv_body = api("/findings/export/?fmt=csv", raw=True).decode()
check(csv_body.startswith("host,investigation,finding_type") and csv_body.count("\n") > 50,
      "CSV export carries the findings with host attribution")
bundle = json.loads(api("/findings/export/?fmt=ioc", raw=True).decode())
values = {i["value"] for i in bundle["indicators"]}
check("198.51.100.23" in values and "203.0.113.77" in values,
      "IOC bundle contains indicators from both compromises")
check(AuditLog.objects.filter(action="finding.export").count() >= 2,
      "every export is written to the audit trail")

audit = api("/audit/?page_size=5")
check(audit["chain_intact"] is True, "audit hash chain verifies over the whole ledger")

print(json.dumps([{"ok": o, "msg": m} for o, m in results]))
PYEOF

say "2/6  Correlation identifies the seeded intrusion"
OUT=$(run_in_backend /tmp/_uat_ui.py)
JSON=$(printf '%s' "$OUT" | tail -1)

if ! printf '%s' "$JSON" | head -c1 | grep -q '\['; then
    bad "checks did not run — backend output follows"
    printf '%s\n' "$OUT" | tail -20
else
    # Section headers keep the output readable; the checks run as one batch so the
    # scenario is seeded and adjudicated exactly once.
    python3 - "$JSON" <<'PY'
import json, sys
sections = [
    (0, 7,  "2/6  Correlation identifies the seeded intrusion"),
    (7, 12, "3/6  Attack graph, timeline and shared indicators"),
    (12, 18, "4/6  Paging, sorting and filtering at the database"),
    (18, 21, "5/6  Re-analysis diff"),
    (21, 99, "6/6  Adjudication, export and the audit ledger"),
]
rows = json.loads(sys.argv[1])
failed = 0
for start, end, title in sections:
    chunk = rows[start:end]
    if not chunk:
        continue
    if start:
        print(f"\n\033[1;36m== {title}\033[0m")
    for r in chunk:
        if r["ok"]:
            print(f"  \033[1;32mPASS\033[0m {r['msg']}")
        else:
            print(f"  \033[1;31mFAIL\033[0m {r['msg']}")
            failed = 1
sys.exit(failed)
PY
    [[ $? -ne 0 ]] && FAILED=1
fi

echo
if [[ "${FAILED}" -eq 0 ]]; then
    printf '\033[1;32m  UI UAT PASSED\033[0m — analyst capabilities verified against real data.\n'
else
    printf '\033[1;31m  UI UAT FAILED\033[0m (see above)\n'
fi
exit "${FAILED}"
