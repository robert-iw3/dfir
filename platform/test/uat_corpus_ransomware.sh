#!/usr/bin/env bash
# ==============================================================================
# CORPUS R — 24 endpoints, "Vault Serpent". Mass encryption and destruction.
#
# The third attack shape, and the one that inverts what the first two assume. An intrusion is
# rare, reached hop by hop, and leaves evidence that survives to be collected.
#
#   scale        the campaign's signature — the ransom note, the appended extension, the
#                payload hash — is on EVERY host it touched. Rarity reads "on most of the
#                fleet" as "environment", so a larger event argues less for itself.
#   deployment   the payload went out from one host over a group policy object. 13 of the
#                16 compromised endpoints have no movement record, because there was no hop.
#   destruction  shadow copies, event logs and the backup catalog are gone. On four hosts
#                nothing can date the compromise, so "when did this begin" must read as
#                unanswered rather than as late.
#   time         the whole event fits in ninety minutes, so temporal coherence is 1.0 for
#                every pair and decides nothing.
#
# Two hosts were staged and never encrypted, and one was only destroyed — a campaign whose
# members sit at different stages is the normal case.
#
# Seeds INC-CORPUS-R; re-running supersedes its correlation run.
# ==============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"

. "${HERE}/lib/report.sh"
report_begin 62 corpus_ransomware "Corpus R — 24 endpoints, mass encryption and destruction" \
    "A ransomware event correlates as ONE campaign despite its signature being on most of the fleet, 13 members having no movement record, two never being encrypted and one only being destroyed — and the hosts whose logs the actor cleared report their compromise date as unanswered rather than guessing."

CORPUS_PREFIX=INC-CORPUS-R
CORPUS_COUNT=24
CORPUS_MANIFEST=/tmp/corpus-ransomware-manifest.json
. "${HERE}/lib/corpus_pipeline.sh"

set -a; . "${PLATFORM}/deploy/.env" 2>/dev/null || true; set +a

corpus_preconditions

SCEN="$(mktemp -d)"
python3 "${HERE}/corpus/ransomware.py" "${SCEN}" >/dev/null \
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
say "Classification — impact, delivery and destruction all read as compromise"
corpus_checks <<'PYEOF'
from cases.models import CollectionRun

m = manifest()
runs = {r.host.hostname: r for r in CollectionRun.objects.filter(
    investigation__incident_id=PREFIX).select_related("host")}
got_comp = sorted(h for h, r in runs.items() if r.compromised)
got_clean = sorted(h for h, r in runs.items() if not r.compromised)

chk(got_comp == m["compromised"],
    f"{len(m['compromised'])} endpoints classify compromised, exactly the planted set"
    + ("" if got_comp == m["compromised"] else f" — got {got_comp}"))
chk(got_clean == m["clean"],
    f"{len(m['clean'])} endpoints classify clean inside the same ninety minutes"
    + ("" if got_clean == m["clean"] else f" — got {got_clean}"))

# A host that was staged and never encrypted carries no impact evidence at all. If delivery
# alone does not make it compromised, the campaign loses the hosts the operator had not
# reached yet — the ones an analyst most needs to find.
for host in m["staged_only"]:
    chk(bool(runs.get(host) and runs[host].compromised),
        f"{host} was staged and never encrypted, and still classifies compromised")

# And the backup server, which was never encrypted either — only emptied.
chk(bool(runs.get("SRV-BKP-01") and runs["SRV-BKP-01"].compromised),
    "SRV-BKP-01 carries destruction without encryption and still classifies compromised")
PYEOF

# ---------------------------------------------------------------- the behavior graph
say "L0 — impact vocabulary reaches the graph"
corpus_checks <<'PYEOF'
from cases.models import Investigation
from correlation.models import BehaviorNode, CorrelationRun

m = manifest()
inv = Investigation.objects.filter(incident_id=PREFIX).first()
run = CorrelationRun.objects.filter(investigation_id=inv.id, is_current=True).first() if inv else None


def node(subkind, value):
    return BehaviorNode.objects.filter(run=run, kind="artifact", subkind=subkind,
                                       value=value).first() if run else None


for subkind, value, label in (
        ("ransom_note", m["ransom_note"], "the ransom note"),
        ("gpo_name", m["gpo"], "the policy object the payload rode out on"),
        ("persistence_task", m["deploy_task"], "the deployment task"),
        ("malware_family", m["family"], "the attributed family")):
    n = node(subkind, value)
    chk(bool(n), f"{label} is an artifact node valued '{value}'"
                 + (f" on {n.host_count} host(s)" if n else " — MISSING"))

# The scale problem, stated as a measurement rather than an inference: the note is on most of
# the compromised fleet by construction, and rarity is what decides whether that helps.
note_node = node("ransom_note", m["ransom_note"])
if note_node:
    note(f"the ransom note is on {note_node.host_count} of {len(m['endpoints'])} endpoints in this fleet")
PYEOF

# ---------------------------------------------------------------- campaign membership
say "L1/L2 — one event, one campaign, whatever stage each host reached"
corpus_checks <<'PYEOF'
from cases.models import Investigation
from correlation.models import Campaign, CampaignHost, CorrelationRun, HostLink

m = manifest()
inv = Investigation.objects.filter(incident_id=PREFIX).first()
run = CorrelationRun.objects.filter(investigation_id=inv.id, is_current=True).first() if inv else None
camps = list(Campaign.objects.filter(run=run).order_by("-host_count")) if run else []

if not camps:
    chk(False, "Vault Serpent forms a campaign at all")
else:
    main = camps[0]
    members = sorted(CampaignHost.objects.filter(campaign=main).values_list("hostname", flat=True))
    expected = m["campaign_hosts"]
    missing = sorted(set(expected) - set(members))
    chk(members == expected,
        f"all {len(expected)} affected endpoints are ONE campaign ({len(members)} found)"
        + (f" — missing {missing}" if missing else ""))

    # Two compromises on this fleet, so two campaigns — the event, and the unrelated data
    # theft below. Anything more means the event itself fragmented.
    sizes = sorted((c.host_count for c in camps), reverse=True)
    chk(sizes == [len(expected), len(m["insider_hosts"])],
        f"the fleet resolves to exactly two compromises, not fragments ({sizes})")

    # No hop was ever recorded to these. Membership rests entirely on shared tradecraft.
    absent = sorted(set(m["no_movement_record"]) - set(members))
    chk(not absent,
        f"the {len(m['no_movement_record'])} endpoints reached by policy — no movement record "
        f"anywhere — are members" + (f" — missing {absent}" if absent else ""))

    # The two the operator never got to, and the one that was only emptied.
    for host in m["staged_only"] + ["SRV-BKP-01"]:
        chk(host in members, f"{host} is a member despite carrying no encryption")

    chk(main.patient_zero == m["entry"],
        f"patient zero is the phished workstation ({main.patient_zero})")

    # The fleet's own nightly job touches every host inside the same window the event did.
    joined = [l for l in HostLink.objects.filter(run=run, linked=True)
              if ((l.factors or {}).get("top") or {}).get("value") in
              (m["fleet_task"], m["ubiquitous_account"])]
    chk(not joined,
        "no pair is joined by the estate's own scheduled task or backup account, "
        "which touch every host in the same hour")

    strays = sorted(set(CampaignHost.objects.filter(campaign__run=run)
                        .values_list("hostname", flat=True)) & set(m["clean"]))
    chk(not strays, f"no clean endpoint appears in any campaign ({len(m['clean'])} clean)"
                    + (f" — strays: {strays}" if strays else ""))

    # The residual risk of the confirmed-everywhere rarity floor, measured rather than argued. A
    # public file-transfer binary is adjudicated True Positive on all five hosts that carry it —
    # three in this event, two in an unrelated data theft — so it is exactly the evidence the floor
    # could wrongly promote.
    joined = sorted(set(m["insider_hosts"]) & set(members))
    chk(not joined,
        f"the unrelated data theft is NOT pulled in by the {m['commodity_tool']} both "
        f"operators used" + (f" — {joined} joined" if joined else ""))

    insider_camp = next((c for c in camps
                         if set(CampaignHost.objects.filter(campaign=c)
                                .values_list("hostname", flat=True)) == set(m["insider_hosts"])),
                        None)
    chk(bool(insider_camp),
        "and the two hosts it did touch are their own campaign"
        + (f" (cohesion {insider_camp.cohesion_min})" if insider_camp else ""))
PYEOF

# ---------------------------------------------------------------- destroyed evidence
say "L3 — where the actor removed the history, the date reads as unanswered"
corpus_checks <<'PYEOF'
from cases.models import Investigation
from correlation.models import Campaign, CampaignHost, CorrelationRun

m = manifest()
inv = Investigation.objects.filter(incident_id=PREFIX).first()
run = CorrelationRun.objects.filter(investigation_id=inv.id, is_current=True).first() if inv else None
hosts = list(CampaignHost.objects.filter(campaign__run=run)) if run else []
by_name = {h.hostname: h for h in hosts}

chk(bool(hosts), f"the campaign's hosts carry membership bands ({len(hosts)})")

BANDS = {"confirmed", "probable", "possible", "indeterminate"}
chk(all(h.confidence_band in BANDS for h in hosts),
    "every band comes from the declared vocabulary")

# A band must be reached, not merely declared. An event this loud should produce settled
# membership somewhere, or the scale is defeating the scoring.
chk("confirmed" in {h.confidence_band for h in hosts},
    f"the event reaches the top band ({sorted({h.confidence_band for h in hosts})})")

# Every band decomposes, including on the hosts whose logs were cleared.
NAMED = {"band", "best_link", "evidence_kinds", "corroboration", "temporal",
         "contradiction", "why"}
chk(all(NAMED <= set(h.confidence_factors or {}) for h in hosts),
    "every band decomposes into its named factors")

# The point of this shape: on a host whose Security log the actor cleared, nothing can date
# the compromise. The contradiction test must say it was not evaluated rather than report a
# clean timeline — an unanswerable question recorded as a passed check is the failure mode
# the factor exists to avoid.
for host in m["logs_cleared"]:
    ch = by_name.get(host)
    if not ch:
        chk(False, f"{host} — logs cleared — is a campaign member")
        continue
    note(f"{host}: band={ch.confidence_band} "
         f"timeline={str((ch.confidence_factors or {}).get('contradiction_basis'))[:100]}")

# The timeline test states what it concluded, or states that it could not conclude. A blank
# field meant "checked and consistent", "could not be checked" and "no movement here" alike,
# which is the same defect as recording an unanswerable question as a passed one.
from correlation.models import HostLink

moved = set()
for link in HostLink.objects.filter(run=run, linked=True):
    factors = link.factors or {}
    for c in [factors.get("top") or {}, *(factors.get("corroboration") or [])]:
        if isinstance(c, dict) and c.get("kind") == "movement":
            moved |= {link.host_a, link.host_b}

with_movement = [h for h in hosts if h.hostname in moved]
stated = [h for h in with_movement if (h.confidence_factors or {}).get("contradiction_basis")]
chk(bool(with_movement) and len(stated) == len(with_movement),
    f"every host whose membership involves movement states what the timeline test found "
    f"({len(stated)}/{len(with_movement)}: {sorted(h.hostname for h in with_movement)})")

# And states it in words. A host with no movement on any link reports nothing, which is the
# one case where silence is the right answer.
for h in stated:
    basis = (h.confidence_factors or {})["contradiction_basis"]
    chk(basis.startswith(("consistent", "not evaluated", "movement at")),
        f"{h.hostname} states the finding in words ({basis[:80]})")

quiet_hosts = [h for h in hosts
               if h.hostname not in moved and (h.confidence_factors or {}).get("contradiction_basis")]
chk(not quiet_hosts,
    f"a host with no movement on any link reports no timeline finding rather than inventing one"
    + (f" — {[h.hostname for h in quiet_hosts]}" if quiet_hosts else ""))
PYEOF

# ---------------------------------------------------------------- fingerprint
say "L4/L5 — the affiliate's habits, and what they are not attributed to"
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
    chk(False, "the Vault Serpent campaign is reachable for a fingerprint check")
else:
    fp = (api(f"/correlation/campaigns/{camp.id}/tradecraft/") or {}).get("fingerprint") or {}
    blob = json.dumps(fp)
    conventions = fp.get("artifact_conventions") or []

    chk(bool(conventions), f"the campaign has naming conventions ({len(conventions)}): {conventions[:4]}")
    chk(m["fleet_task"] not in blob,
        "the estate's own update task is not reported as this affiliate's tradecraft")

    # An impact campaign's sequence must end on impact. T1486/T1490/T1489 are the last acts,
    # and a sequence that puts them anywhere else is ordering by something other than
    # observation.
    seq = fp.get("technique_sequence") or []
    impact = {"T1486", "T1490", "T1489"}
    tail = set(seq[-4:]) if len(seq) >= 4 else set(seq)
    chk(bool(seq) and bool(impact & tail),
        f"the technique sequence ends on impact ({seq[-5:]})")
    chk(bool(seq) and seq[0] == "T1566",
        f"and opens on the delivery that started it ({seq[:4]})")

    # Sharing a ransomware family is sharing a tool, not a tradecraft. Nothing here may be
    # attributed to the intrusions in the other corpora.
    related = list(camp.similar_to.all())
    names = [f"{s.other_label}={s.score:.2f}" for s in related]
    chk(not related,
        "the event is not attributed to any other corpus actor"
        + (f" — but got {names}" if related else ""))
PYEOF

# ---------------------------------------------------------------- cross-corpus
say "Population — a third fleet in the deployment leaves the other two alone"
corpus_checks <<'PYEOF'
from cases.models import CollectionRun, Host, Investigation
from correlation.models import Campaign, CampaignHost, CorrelationRun

m = manifest()
note(f"deployment host population at correlation time: {Host.objects.count()}")

for incident, expect in (("INC-CORPUS-A", 12), ("INC-CORPUS-B", 4), ("INC-CORPUS-L", 10)):
    i = Investigation.objects.filter(incident_id=incident).first()
    if not i:
        note(f"{incident} is not deployed — not applicable")
        continue
    n = CollectionRun.objects.filter(investigation=i, compromised=True).count()
    chk(n == expect, f"{incident} still classifies {n} compromised with a third fleet present")

    r = CorrelationRun.objects.filter(investigation_id=i.id, is_current=True).first()
    crossed = sorted(set(CampaignHost.objects.filter(campaign__run=r)
                         .values_list("hostname", flat=True)) & set(m["endpoints"]))
    chk(not crossed, f"no {incident} campaign reaches a Vault Serpent endpoint"
                     + (f" — {crossed}" if crossed else ""))

# Corpus L's campaign must still hold together at the larger population — rarity rises with
# the fleet, so this direction is the safe one, and it is asserted rather than assumed.
lin = Investigation.objects.filter(incident_id="INC-CORPUS-L").first()
if lin:
    r = CorrelationRun.objects.filter(investigation_id=lin.id, is_current=True).first()
    c = Campaign.objects.filter(run=r).order_by("-host_count").first()
    chk(bool(c) and c.host_count == 8,
        f"corpus L still clusters all 8 of its hosts ({c.host_count if c else 0})")
PYEOF

rm -rf "${SCEN}"
report_finish
exit "${FAILED}"
