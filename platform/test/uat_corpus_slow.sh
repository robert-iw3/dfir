#!/usr/bin/env bash
# ==============================================================================
# CORPUS S — 20 endpoints, "Glass Heron". Eight months of dwell.
#
# The fourth attack shape, and the one that finally makes the temporal factor decide
# something. The first three corpora fit inside a day, so coherence was 1.0 on every pair.
#
#   dwell        initial access to exfiltration spans 238 days, adjacent hosts are up to 56
#                days apart, and WINDOW_DAYS calls anything past thirty a separate intrusion.
#   no movement  the operator returns over the VPN rather than hopping — four of the seven
#                compromised endpoints have no movement record.
#   rotation     the C2 domain changes each quarter, so no indicator spans the campaign and
#                only tradecraft can hold it together.
#   aging        on the first host the delivery evidence rotated out of the logs, and the
#                collector says it could not determine whether it was there — a third answer.
#
# The benign baseline is planted EARLY on every endpoint, as in a real estate. A host's first
# activity is therefore its baseline, months before its compromise, so anything anchored to
# first activity is reading the estate's schedule rather than the intrusion.
#
# Two unrelated endpoints carry the same unsanctioned remote-access tool, installed 190 days
# apart by different people. They bound the answer: a window wide enough to hold Glass Heron
# together must still keep shadow IT apart.
#
# Seeds INC-CORPUS-S; re-running supersedes its correlation run.
# ==============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"

. "${HERE}/lib/report.sh"
report_begin 63 corpus_slow "Corpus S — 20 endpoints, eight months of dwell" \
    "A campaign that dwells for 238 days correlates as one, with four members carrying no movement record and every indicator rotated away — while two unrelated endpoints running the same unsanctioned tool 190 days apart stay separate, and the host whose delivery evidence aged out reports that it could not be established rather than that nothing was found."

CORPUS_PREFIX=INC-CORPUS-S
CORPUS_COUNT=20
CORPUS_MANIFEST=/tmp/corpus-slow-manifest.json
. "${HERE}/lib/corpus_pipeline.sh"

set -a; . "${PLATFORM}/deploy/.env" 2>/dev/null || true; set +a

corpus_preconditions

SCEN="$(mktemp -d)"
python3 "${HERE}/corpus/slow.py" "${SCEN}" >/dev/null \
    && ok "${CORPUS_COUNT} endpoint scenarios generated" \
    || { bad "scenario generation failed"; report_finish; exit 1; }

${RUNTIME} cp "${SCEN}/manifest.json" "${BE}:${CORPUS_MANIFEST}" 2>/dev/null \
    && ok "manifest published to the backend for comparison" \
    || { bad "could not publish the manifest to ${BE}"; report_finish; exit 1; }

corpus_reset
corpus_receiver_addr

say "Collection — ${CORPUS_COUNT} real collector runs, shipped from the edge"
corpus_collect_and_ship "${SCEN}"

say "Ingest — the puller delivers all ${CORPUS_COUNT} runs"
corpus_await_ingest

say "Analysis — every capture is analyzed and adjudicated before compromise is read"
corpus_await_analysis
corpus_assert_analysis_ran

say "Correlation"
corpus_correlate

# ---------------------------------------------------------------- classification
say "Classification — eight months of evidence, and the estate's own noise throughout"
corpus_checks <<'PYEOF'
from cases.models import CollectionRun

m = manifest()
runs = {r.host.hostname: r for r in CollectionRun.objects.filter(
    investigation__incident_id=PREFIX).select_related("host")}
got_comp = sorted(h for h, r in runs.items() if r.compromised)
got_clean = sorted(h for h, r in runs.items() if not r.compromised)

chk(got_comp == m["compromised"],
    f"{len(m['compromised'])} endpoints classify compromised across {m['campaign_span_days']} days"
    + ("" if got_comp == m["compromised"] else f" — got {got_comp}"))
chk(got_clean == m["clean"],
    f"{len(m['clean'])} endpoints classify clean" +
    ("" if got_clean == m["clean"] else f" — got {got_clean}"))
note(f"campaign span {m['campaign_span_days']}d, largest gap between hosts {m['largest_gap_days']}d, "
     f"shadow-IT installs {m['shadow_it_gap_days']}d apart")
PYEOF

# ---------------------------------------------------------------- the behavior graph
say "L0 — the habits span the campaign, the infrastructure does not"
corpus_checks <<'PYEOF'
from cases.models import Investigation
from correlation.models import BehaviorNode, CorrelationRun

m = manifest()
inv = Investigation.objects.filter(incident_id=PREFIX).first()
run = CorrelationRun.objects.filter(investigation_id=inv.id, is_current=True).first() if inv else None
n_camp = len(m["campaign_hosts"])

for subkind, frag, label, expect in (
        ("persistence_wmi", m["wmi_filter"], "the WMI subscription", n_camp),
        ("staging_name", m["staging"], "the staging file convention", 3),
        ("malware_family", m["family"], "the attributed family", n_camp)):
    n = BehaviorNode.objects.filter(run=run, kind="artifact", subkind=subkind,
                                    value__contains=frag).first() if run else None
    chk(bool(n) and n.host_count == expect,
        f"{label} is on {n.host_count if n else 0} of the {n_camp} compromised hosts")

# Rotation: three domains, none of them spanning the campaign. If any indicator did, the
# campaign could hold together on infrastructure and the tradecraft path would be untested.
widest = 0
for domain in m["c2_domains"]:
    n = BehaviorNode.objects.filter(run=run, kind="indicator", subkind="domain",
                                    value__contains=domain).first() if run else None
    widest = max(widest, n.host_count if n else 0)
chk(0 < widest < n_camp,
    f"no C2 domain reaches more than {widest} of {n_camp} hosts — the infrastructure rotated")

# The unsanctioned tool is an artifact, so two endpoints running it are comparable at all.
rmm = BehaviorNode.objects.filter(run=run, kind="artifact", subkind="rmm_tool",
                                  value__contains=m["shadow_tool"]).first() if run else None
chk(bool(rmm) and rmm.host_count == 2,
    f"the unsanctioned remote-access tool is an artifact on {rmm.host_count if rmm else 0} hosts")
PYEOF

# ---------------------------------------------------------------- campaign membership
say "L1/L2 — 238 days is one campaign, and 190 days apart is not"
corpus_checks <<'PYEOF'
from cases.models import Investigation
from correlation.models import Campaign, CampaignHost, CorrelationRun, HostLink

m = manifest()
inv = Investigation.objects.filter(incident_id=PREFIX).first()
run = CorrelationRun.objects.filter(investigation_id=inv.id, is_current=True).first() if inv else None
camps = list(Campaign.objects.filter(run=run).order_by("-host_count")) if run else []

if not camps:
    chk(False, "Glass Heron forms a campaign at all")
else:
    main = camps[0]
    members = sorted(CampaignHost.objects.filter(campaign=main).values_list("hostname", flat=True))
    expected = m["campaign_hosts"]
    missing = sorted(set(expected) - set(members))
    chk(members == expected,
        f"all {len(expected)} hosts touched over {m['campaign_span_days']} days are ONE campaign "
        f"({len(members)} found)" + (f" — missing {missing}" if missing else ""))

    absent = sorted(set(m["no_movement_record"]) - set(members))
    chk(not absent,
        f"the {len(m['no_movement_record'])} endpoints reached over the VPN — no movement "
        f"record — are members" + (f" — missing {absent}" if absent else ""))

    # The bound. Two people, two installs, 190 days apart, same tool: shadow IT, not a
    # campaign. A temporal window wide enough for Glass Heron must still refuse this.
    pulled = sorted(set(m["shadow_it_hosts"]) & set(members))
    chk(not pulled,
        f"the two shadow-IT endpoints {m['shadow_it_gap_days']} days apart are NOT in the "
        f"campaign" + (f" — {pulled} joined" if pulled else ""))

    shadow_pair = tuple(sorted(m["shadow_it_hosts"]))
    link = HostLink.objects.filter(run=run, host_a=shadow_pair[0], host_b=shadow_pair[1]).first()
    if link:
        top = (link.factors or {}).get("top") or {}
        chk(not link.linked,
            f"and the pair is DECLINED on its own merits (weight {link.weight}, "
            f"temporal {top.get('temporal')})")
    else:
        chk(True, "and the pair never became a candidate")

    chk(main.patient_zero == m["entry"],
        f"patient zero is the first host touched, 238 days before the last "
        f"({main.patient_zero})")

    strays = sorted(set(CampaignHost.objects.filter(campaign__run=run)
                        .values_list("hostname", flat=True)) & set(m["clean"]))
    chk(not strays, f"no clean endpoint appears in any campaign ({len(m['clean'])} clean)"
                    + (f" — strays: {strays}" if strays else ""))
PYEOF

# ---------------------------------------------------------------- temporal factor
say "L1 — coherence measures the shared evidence, not the estate's schedule"
corpus_checks <<'PYEOF'
from cases.models import Investigation
from correlation.models import CorrelationRun, HostLink

m = manifest()
inv = Investigation.objects.filter(incident_id=PREFIX).first()
run = CorrelationRun.objects.filter(investigation_id=inv.id, is_current=True).first() if inv else None
links = {(l.host_a, l.host_b): l for l in HostLink.objects.filter(run=run)}
days = m["campaign_days"]


def temporal_of(a, b):
    l = links.get((a, b)) or links.get((b, a))
    return ((l.factors or {}).get("top") or {}).get("temporal") if l else None


# The benign baseline is on day 0 for every endpoint, so a coherence anchored to each host's
# FIRST ACTIVITY is identical for a pair a week apart and a pair seven months apart. It has
# to separate them, or it is measuring the inventory agent's schedule.
near = ("RD-WS-04", "IT-WS-01")          # 38 days apart
far = ("RD-WS-04", "RD-SRV-01")          # 238 days apart
t_near, t_far = temporal_of(*near), temporal_of(*far)
chk(t_near is not None and t_far is not None and t_near > t_far,
    f"a pair {days[near[1]] - days[near[0]]}d apart reads MORE coherent than one "
    f"{days[far[1]] - days[far[0]]}d apart ({t_near} vs {t_far})")

# And it must not have collapsed to the floor for the whole campaign: a chain of weeks-apart
# hops is one intrusion, and scoring every pair at the minimum says the opposite.
internal = [((a, b), ((l.factors or {}).get("top") or {}).get("temporal"))
            for (a, b), l in links.items()
            if a in days and b in days and l.linked]
floored = [p for p, t in internal if t is not None and t <= 0.25]
chk(bool(internal) and not floored,
    f"no accepted link inside the campaign sits at the coherence floor "
    f"({len(internal)} links)" + (f" — {floored[:3]}" if floored else ""))

# The shadow-IT pair is the other side of the same measure.
t_shadow = temporal_of(*sorted(m["shadow_it_hosts"]))
chk(t_shadow is None or t_shadow < t_near,
    f"the {m['shadow_it_gap_days']}d shadow-IT pair reads less coherent than a campaign hop "
    f"({t_shadow} vs {t_near})")
PYEOF

# ---------------------------------------------------------------- aged-out evidence
say "L3 — evidence that aged out reads as undetermined, not as absent"
corpus_checks <<'PYEOF'
from cases.models import Finding, Investigation
from correlation.models import CampaignHost, CorrelationRun

m = manifest()
inv = Investigation.objects.filter(incident_id=PREFIX).first()
run = CorrelationRun.objects.filter(investigation_id=inv.id, is_current=True).first() if inv else None

# The collector could not establish whether the delivery artifact was ever present. That is a
# third answer, and it must survive ingest as its own finding rather than being dropped for
# carrying no verdict — an absent record and an unanswerable question read the same otherwise.
incomplete = Finding.objects.filter(run__investigation__incident_id=PREFIX,
                                    finding_type="Deleted File Scan Incomplete")
chk(incomplete.count() == 1,
    f"the host whose logs rotated carries its undetermined-scan finding ({incomplete.count()})")
f = incomplete.first()
chk(bool(f) and f.verdict == "Indeterminate",
    f"and it is adjudicated Indeterminate rather than treated as a clean result "
    f"({f.verdict if f else 'missing'})")

# It must not have made the host look compromised, nor kept it out of the campaign.
entry = CampaignHost.objects.filter(campaign__run=run, hostname=m["entry"]).first()
chk(bool(entry), f"{m['entry']} is still a campaign member despite its thinner evidence")
if entry:
    note(f"{m['entry']}: band={entry.confidence_band} "
         f"why={str((entry.confidence_factors or {}).get('why'))[:110]}")
PYEOF

# ---------------------------------------------------------------- fingerprint
say "L4 — the sequence is the operator's eight months, in order"
corpus_checks <<'PYEOF'
import urllib.request
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
from cases.models import Investigation
from correlation.models import Campaign, CorrelationRun

m = manifest()
admin = User.objects.filter(is_superuser=True).first()
TOKEN = Token.objects.get_or_create(user=admin)[0].key


def api(path):
    req = urllib.request.Request("http://127.0.0.1:8000/api" + path,
                                 headers={"Authorization": "Token " + TOKEN})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


inv = Investigation.objects.filter(incident_id=PREFIX).first()
run = CorrelationRun.objects.filter(investigation_id=inv.id, is_current=True).first() if inv else None
camp = Campaign.objects.filter(run=run).order_by("-host_count").first() if run else None

if not camp:
    chk(False, "the Glass Heron campaign is reachable for a fingerprint check")
else:
    fp = (api(f"/correlation/campaigns/{camp.id}/tradecraft/") or {}).get("fingerprint") or {}
    blob = json.dumps(fp)
    seq = fp.get("technique_sequence") or []
    conventions = fp.get("artifact_conventions") or []

    chk(bool(conventions), f"the campaign has naming conventions ({len(conventions)}): {conventions[:4]}")
    chk(m["fleet_task"] not in blob,
        "the estate's own scheduled task is not reported as this operator's tradecraft")
    chk(m["shadow_tool"] not in blob,
        "nor is the unsanctioned remote-access tool from an unrelated compromise")

    # Eight months of real ordering: credential access precedes the directory attack, which
    # precedes certificate theft and exfiltration. Anchored to when each technique was first
    # CONFIRMED, so a benign agent installed on day 0 cannot set the order.
    def before(x, y):
        return x in seq and y in seq and seq.index(x) < seq.index(y)

    chk(before("T1003", "T1649"),
        f"credential access precedes certificate theft in the sequence ({seq})")
    chk(before("T1546", "T1041"),
        "persistence precedes exfiltration")
    chk(bool(seq) and seq[-1] in ("T1041", "T1560"),
        f"and the sequence ends on the exfiltration it was all for ({seq[-3:]})")
PYEOF

# ---------------------------------------------------------------- cross-corpus
say "Population — a fourth fleet leaves the others alone"
corpus_checks <<'PYEOF'
from cases.models import CollectionRun, Host, Investigation
from correlation.models import CampaignHost, CorrelationRun

m = manifest()
note(f"deployment host population at correlation time: {Host.objects.count()}")

for incident, expect in (("INC-CORPUS-A", 12), ("INC-CORPUS-B", 4),
                         ("INC-CORPUS-L", 10), ("INC-CORPUS-R", 18)):
    i = Investigation.objects.filter(incident_id=incident).first()
    if not i:
        note(f"{incident} is not deployed — not applicable")
        continue
    n = CollectionRun.objects.filter(investigation=i, compromised=True).count()
    chk(n == expect, f"{incident} still classifies {n} compromised with a fourth fleet present")

    r = CorrelationRun.objects.filter(investigation_id=i.id, is_current=True).first()
    crossed = sorted(set(CampaignHost.objects.filter(campaign__run=r)
                         .values_list("hostname", flat=True)) & set(m["endpoints"]))
    chk(not crossed, f"no {incident} campaign reaches a Glass Heron endpoint"
                     + (f" — {crossed}" if crossed else ""))
PYEOF

rm -rf "${SCEN}"
report_finish
exit "${FAILED}"
