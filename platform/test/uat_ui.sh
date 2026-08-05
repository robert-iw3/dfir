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
from django.db.models import Count
from rest_framework.authtoken.models import Token

from cases.models import AuditLog, Finding, FindingReclassification, MemoryCapture
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
# Found by PATIENT ZERO, not by label. A campaign's label is derived from its own evidence —
# the attributed family and the host the intrusion entered through — so it moves when the
# evidence does. A lookup pinned to a literal name breaks on a rename rather than on a
# behavior change, and then reports it as "correlation found nothing". Patient zero is what
# the scenario actually fixes.
ember = Campaign.objects.filter(patient_zero="WS-007", run__is_current=True).first()
miner = Campaign.objects.filter(
    run__is_current=True, host_count=2,
    hosts__hostname="WS-012").exclude(id=ember.id if ember else 0).distinct().first()

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

# This campaign's own row: the endpoint aggregates fleet-wide across investigations on
# purpose — that recurrence is the "seen before?" signal — so the row is selected by the
# campaign it belongs to rather than by value, which other cases legitimately share.
indicators = api("/correlation/indicators/")["indicators"]
c2 = next((i for i in indicators
           if i["value"] == "198.51.100.23" and ember.id in i["campaign_ids"]), None)
check(c2 and set(ember_hosts) <= set(c2["hostnames"]),
      "shared C2 indicator spans all 10 intrusion hosts")

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
# Scoped to this seed's investigation: the technique filter is global by design (searching
# across cases is the point), and the 25-endpoint corpus carries the same T1021.001 hop.
tech = api(f"/findings/?technique=T1021.001&investigation={ember.investigation_id}&page_size=10")
check(tech["count"] == 1 and tech["results"][0]["hostname"] == "JUMP-01",
      "ATT&CK filter returns exactly the RDP movement (JUMP-01)")
hosts = api("/hosts/?page_size=3&ordering=-hostname")["results"]
check([h["hostname"] for h in hosts] == sorted([h["hostname"] for h in hosts], reverse=True),
      "host ordering is applied by the database")

# --- 5. Re-analysis diff surfaces what a newer ruleset adds --------------------------
# Selected by the property under test — a capture carrying TWO analyses. Hostnames are not
# unique across investigations (the 25-endpoint corpus also has a WS-007), so picking by
# hostname alone lands on another case's capture, which has one analysis and nothing to diff.
cap = (MemoryCapture.objects
       .filter(run__host__hostname="WS-007", run__investigation_id=ember.investigation_id)
       .annotate(n_analyses=Count("analyses"))
       .filter(n_analyses__gte=2).first())
diff = api(f"/captures/{cap.id}/diff/")
added = {f["finding_type"] for f in diff["added"]}
check(diff["comparable"] and diff["base"]["ruleset_version"] == "2026.05"
      and diff["head"]["ruleset_version"] == "current",
      "diff compares oldest -> newest ruleset")
check("Known tool signature" in added and len(diff["added"]) == 3,
      f"diff finds the 3 detections the newer ruleset adds (got {sorted(added)})")
check(not diff["removed"], "nothing is lost between rulesets")

# The analysis summary is an OPEN map — an analyzer may add a key at any time, and some
# values are structured (`adjudication` carries a verdict and its reason). The run page
# rendered every value with String(), so those arrived as "[object Object]": a chip that
# takes the space of a fact while carrying none. Assert the shape the UI has to handle, so
# a newly structured key is a caught regression rather than a silent one.
# Across every analysis, not one capture: the structured keys are written by the adjudicator
# and appear on the captures it ran against, so scoping this to the diff's capture asserted
# the absence of a property rather than the property.
summaries = [a.summary for c in MemoryCapture.objects.all() for a in c.analyses.all()
             if isinstance(a.summary, dict)]
check(bool(summaries), f"analyses carry a summary for the run page to render ({len(summaries)})")
structured = sorted({k for s in summaries for k, v in s.items()
                     if isinstance(v, (dict, list))})
check(bool(structured),
      f"the summary carries structured values the chip row must render, not stringify ({structured})")
# Rendering rule asserted against the data: a structured value must expose either a scalar
# answer or named keys, or there is nothing for a chip to say about it.
empty = [k for s in summaries for k, v in s.items()
         if isinstance(v, (dict, list)) and not v]
check(not empty, f"every structured summary value has something to show ({empty})")

# --- 5b. A finding's recovered evidence reaches the analyst ---------------------------
# The graph reads Finding.raw; the findings table showed only type/target/verdict/ATT&CK, so
# a beacon's user-agent, mutex, JA3 and extracted C2 config were in the API and nowhere an
# analyst could see them. Assert the payload the detail panel renders is actually served.
beacon = (Finding.objects
          .filter(run__host__hostname="WS-007", finding_type="C2 Beacon",
                  raw__user_agent__isnull=False)
          .order_by("-id").first())
check(beacon is not None, "the enriched beacon finding exists to render")
if beacon:
    served = api(f"/findings/?run={beacon.run_id}&page_size=200")["results"]
    row = next((r for r in served if r["id"] == beacon.id), None)
    check(row is not None and isinstance(row.get("raw"), dict),
          "the findings API serves `raw` — the detail panel has something to render")
    raw = (row or {}).get("raw") or {}
    want = ["user_agent", "mutex", "pipe", "ja3", "registry_key", "certificate"]
    missing = [k for k in want if not raw.get(k)]
    check(not missing,
          f"every recovered indicator on the beacon is served to the UI (missing: {missing})")
    cfg = raw.get("config_extracted") or {}
    check(isinstance(cfg, dict) and {"campaign_id", "sleep", "address", "port"} <= set(cfg),
          f"the extracted C2 config reaches the UI with all its fields ({sorted(cfg)})")

    # The expander must DISCRIMINATE. Every finding's raw carries the collector's own record
    # (Type/Target/Verdict/MITRE), so a permissive rule puts the control on every row and it
    # stops meaning anything — a high-entropy region and an EDR agent inventory hold no
    # recovered intelligence. Mirrors hasEvidence() in components/FindingEvidence.jsx.
    INDICATORS = {"malware_family", "yara_rule", "user_agent", "useragent", "mutex", "pipe",
                  "ja3", "certificate", "registry_key", "domain", "ip", "url", "onion",
                  "sha256", "md5", "wallet", "account", "src_host", "dst_host", "protocol",
                  "technique", "yara_matches", "urls", "domains", "ips", "hashes",
                  "related_hashes", "mutexes", "pipes", "user_agents", "wallets", "xmr",
                  "aws_keys", "telegram_tokens", "discord_webhooks", "crypto_material",
                  "network_indicators", "indicators"}
    def has_evidence(r):
        r = r or {}
        for k in INDICATORS:
            v = r.get(k)
            if v not in (None, "", [], {}):
                return True
        c = r.get("config_extracted")
        return isinstance(c, dict) and bool(c)

    rows = api(f"/findings/?run={beacon.run_id}&page_size=200")["results"]
    withev = [r for r in rows if has_evidence(r.get("raw"))]
    check(has_evidence(raw), "the enriched beacon offers its evidence panel")
    # Memory-derived structural findings carry an offset and an entropy figure and nothing
    # else — no indicator to show. (An "Installed Agent" row DOES get a panel, and should:
    # its vendor domain and agent hash are the fleet-wide benign material rarity weighting
    # divides by. Listing it as noise was a wrong assumption, corrected here.)
    noise = [r["finding_type"] for r in rows
             if has_evidence(r.get("raw"))
             and r["finding_type"].startswith("High-entropy region")]
    check(not noise, f"structural memory rows carry no indicators and offer no panel ({sorted(set(noise))})")
    check(0 < len(withev) < len(rows),
          f"the panel is offered on some rows and not others ({len(withev)} of {len(rows)})")

# --- 6. Adjudication and export are recorded in the tamper-proof ledger --------------
ids = list(Finding.objects.filter(verdict="Indeterminate").values_list("id", flat=True)[:3])
before = {f.id: f.verdict for f in Finding.objects.filter(id__in=ids)}
owned = {f.id: f.adjudicated_by for f in Finding.objects.filter(id__in=ids)}
res = api("/findings/bulk-verdict/",
          {"ids": ids, "verdict": "False Positive", "reason": "uat"})
check(res["changed"] == len(ids), "bulk verdict applied to every selected finding")
check(all(f.verdict == "False Positive" for f in Finding.objects.filter(id__in=ids)),
      "verdicts persisted")
check(all(f.adjudicated_by == "analyst" for f in Finding.objects.filter(id__in=ids)),
      "a bulk verdict is the analyst's, so a later engine pass cannot silently replace it")
check(FindingReclassification.objects.filter(finding_id__in=ids, note="uat").count() == len(ids),
      "a bulk action leaves per-finding history, not only an aggregate audit entry")

entry = AuditLog.objects.filter(action="finding.bulk_verdict").order_by("-id").first()
recorded = {c["id"]: c["from"] for c in (entry.detail or {}).get("changes", [])}
check(recorded == before,
      "ledger records each finding's prior verdict, not just an aggregate")

# Restore, so the suite is repeatable. Ownership has to be restored explicitly: the revert
# goes through the same analyst path, which would otherwise leave these three findings
# marked as adjudicated by a human who never looked at them.
api("/findings/bulk-verdict/", {"ids": ids, "verdict": "Indeterminate", "reason": "uat revert"})
for _fid, _by in owned.items():
    Finding.objects.filter(id=_fid).update(adjudicated_by=_by)
FindingReclassification.objects.filter(finding_id__in=ids,
                                       note__in=("uat", "uat revert")).delete()

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
