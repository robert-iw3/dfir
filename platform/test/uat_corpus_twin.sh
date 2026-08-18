#!/usr/bin/env bash
# ==============================================================================
# CORPUS X — 26 collections, "Twin Adders". Two actors in one fleet at once.
#
# Every corpus before this contains a single intrusion, so the engine's job was to decide
# which hosts belong to THE campaign. This asks the harder question: given a fleet two
# unrelated actors are working simultaneously, does it find two campaigns or one blob?
#
#   concurrency   both intrusions run inside ninety-six hours, so temporal coherence is high
#                 for every cross-actor pair and argues for merging them.
#   shared tools  both actors use PsExec and Mimikatz — identical bytes — and so do two
#                 administrators neither actor touched. A link resting on shared tooling
#                 merges the campaigns and names an actor that does not exist.
#   shared victim SRV-X02 was compromised by both, four days apart. It belongs to two
#                 campaigns at once, which no earlier corpus contains.
#   rename        RELAY-01 is renamed RELAY-02 mid-campaign — one machine, two collections,
#                 which must stay one host and one campaign member.
#
# Seeds INC-CORPUS-X; re-running supersedes its correlation run.
# ==============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"

. "${HERE}/lib/report.sh"
report_begin 34 corpus_twin "Corpus X — two concurrent actors in one fleet" \
    "Two intrusions running at the same time, sharing commodity tooling and one victim host, separate into TWO campaigns rather than merging into one; the shared tools link nothing on their own; the shared victim belongs to both; and a host renamed mid-campaign stays one host."

CORPUS_PREFIX=INC-CORPUS-X
# 26 collections from 25 machines: RELAY-01 is collected, renamed, and collected again.
CORPUS_COUNT=26
CORPUS_HOSTS=25
CORPUS_MANIFEST=/tmp/corpus-twin-manifest.json
. "${HERE}/lib/corpus_pipeline.sh"

set -a; . "${PLATFORM}/deploy/.env" 2>/dev/null || true; set +a

corpus_preconditions

SCEN="$(mktemp -d)"
python3 "${HERE}/corpus/twin.py" "${SCEN}" >/dev/null \
    && ok "${CORPUS_COUNT} endpoint scenarios generated (two actors, one fleet)" \
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

# ---------------------------------------------------------------- identity
say "Identity — the renamed machine is ONE host, not two"
corpus_checks <<'PYEOF'
from cases.models import CollectionRun, Host, HostIdentityChange

m = manifest()
old, new = m["renamed_from"], m["renamed_to"]

host = Host.objects.filter(machine_id=m["renamed_machine_id"]).first()
chk(bool(host), f"the machine that was {old} resolves to a single host row"
                + (f" — now '{host.hostname}'" if host else " — MISSING"))
chk(bool(host) and host.hostname == new,
    f"it carries its CURRENT name '{new}'"
    + ("" if host and host.hostname == new else f" — got '{host.hostname if host else None}'"))
chk(not Host.objects.filter(hostname=old).exists(),
    f"no second host lingers under the old name '{old}' — a rename is history, not a new machine")

runs = CollectionRun.objects.filter(investigation__incident_id=PREFIX, host=host)
chk(runs.count() == 2,
    f"both collections attach to that one host ({runs.count()} of 2)")

changes = HostIdentityChange.objects.filter(host=host, field="hostname")
chk(changes.filter(from_value=old, to_value=new).exists(),
    f"the rename is recorded as history: {old} -> {new}")
PYEOF

# ---------------------------------------------------------------- classification
say "Classification — both actors' victims read as compromised, the fleet does not"
corpus_checks <<'PYEOF'
from cases.models import CollectionRun

m = manifest()
runs = {r.host.hostname: r for r in CollectionRun.objects.filter(
    investigation__incident_id=PREFIX).select_related("host")}
comp = {h for h, r in runs.items() if r.compromised}

for host in m["copper_hosts"]:
    chk(host in comp, f"{host} (Copper Adder) classifies compromised")
for host in m["iron_hosts"]:
    chk(host in comp, f"{host} (Iron Adder) classifies compromised")

# The administrators ran the same tools the actors did. They are not clean by luck — the
# platform cannot distinguish the bytes, so this is what an honest engine does with them.
admins = set(m["commodity_admin_hosts"])
chk(admins <= comp,
    f"the two administrators who ran the same commodity tools are flagged too ({sorted(admins)})"
    " — identical bytes cannot be told apart, and pretending otherwise would be the defect")
PYEOF

# ---------------------------------------------------------------- the crux
say "TWO campaigns — the property this corpus exists for"
corpus_checks <<'PYEOF'
from cases.models import Investigation
from correlation.models import Campaign, CampaignHost, CorrelationRun

m = manifest()
inv = Investigation.objects.filter(incident_id=PREFIX).first()
run = CorrelationRun.objects.filter(investigation_id=inv.id, is_current=True).first() if inv else None
camps = list(Campaign.objects.filter(run=run)) if run else []
members = {c.id: set(CampaignHost.objects.filter(campaign=c)
                     .values_list("hostname", flat=True)) for c in camps}

chk(len(camps) >= 2,
    f"the run produced {len(camps)} campaign(s) — two actors must not merge into one"
    + (f": {[sorted(v) for v in members.values()]}" if len(camps) < 2 else ""))

copper = set(m["copper_hosts"])
iron = set(m["iron_hosts"])
shared = m["shared_victim"]

# Identified by their entry points rather than by size, so the assertion does not depend on
# which campaign the engine happened to number first.
c_camp = next((c for c in camps if m["copper_entry"] in members[c.id]), None)
i_camp = next((c for c in camps if m["iron_entry"] in members[c.id]), None)
chk(bool(c_camp), f"a campaign contains Copper's entry point {m['copper_entry']}")
chk(bool(i_camp), f"a campaign contains Iron's entry point {m['iron_entry']}")
# The shared victim is an articulation point: remove it and the link graph falls into
# Copper's hosts and Iron's with nothing between them. Connected components cannot express
# a host belonging to two campaigns, so it fuses them and the report names one actor that
# does not exist.
chk(bool(c_camp) and bool(i_camp) and c_camp.id != i_camp.id,
    "they are DIFFERENT campaigns — the two intrusions are not one"
    + ("" if not (c_camp and i_camp and c_camp.id == i_camp.id) else
       f" — MERGED into '{c_camp.label}' via the doubly-compromised {shared}, which links to"
       " both sides and fuses them under connected components"))

if c_camp and i_camp and c_camp.id != i_camp.id:
    cm, im = members[c_camp.id], members[i_camp.id]
    # Copper's own hosts must not appear in Iron's campaign, and the reverse. The shared
    # victim is excluded from this: it legitimately belongs to both.
    chk(not (set(m["iron_only"]) & cm),
        f"no Iron-only host was pulled into Copper's campaign"
        + ("" if not (set(m["iron_only"]) & cm) else f" — {sorted(set(m['iron_only']) & cm)}"))
    chk(not (set(m["copper_only"]) & im),
        f"no Copper-only host was pulled into Iron's campaign"
        + ("" if not (set(m["copper_only"]) & im) else f" — {sorted(set(m['copper_only']) & im)}"))
    chk(set(m["copper_only"]) <= cm,
        f"Copper's campaign holds all of its own hosts ({sorted(cm)})")
    chk(set(m["iron_only"]) <= im,
        f"Iron's campaign holds all of its own hosts ({sorted(im)})")
    # The shared victim: compromised twice, by two actors, four days apart.
    chk(shared in cm and shared in im,
        f"the shared victim {shared} belongs to BOTH campaigns"
        f" — copper={shared in cm} iron={shared in im}")
    # An administrator's host must not be dragged in by tooling alone.
    for host in m["commodity_admin_hosts"]:
        chk(host not in cm and host not in im,
            f"{host} ran the same tools and joined NEITHER campaign — tooling is not membership")
PYEOF

# ---------------------------------------------------------------- shared tooling
say "Commodity tooling links nothing on its own"
corpus_checks <<'PYEOF'
from cases.models import Investigation
from correlation.models import CorrelationRun, HostLink

m = manifest()
inv = Investigation.objects.filter(incident_id=PREFIX).first()
run = CorrelationRun.objects.filter(investigation_id=inv.id, is_current=True).first() if inv else None
links = list(HostLink.objects.filter(run=run)) if run else []
copper_only, iron_only = set(m["copper_only"]), set(m["iron_only"])
commodity = set(m["commodity_hashes"])


def crosses(l):
    pair = {l.host_a, l.host_b}
    return bool(pair & copper_only) and bool(pair & iron_only)


cross = [l for l in links if crosses(l)]
linked_cross = [l for l in cross if l.linked]
chk(bool(cross), f"the engine considered {len(cross)} cross-actor pair(s) — it looked")
chk(not linked_cross,
    "no DIRECT cross-actor pair was linked — weighted linkage refuses them on the evidence"
    + ("" if not linked_cross
       else f" — {[(l.host_a, l.host_b, l.factors.get('top', {})) for l in linked_cross[:3]]}"))

# Declining is not enough: a pair declined with no recorded basis is right by accident. The
# strongest factor and its weight are what the report shows an analyst as the reason.
with_basis = [l for l in cross if (l.factors or {}).get("top") and l.weight is not None]
chk(bool(cross) and len(with_basis) == len(cross),
    f"every considered cross-actor pair records its strongest factor and weight "
    f"({len(with_basis)}/{len(cross)}) — a decline with no basis is an accident, not a judgement")

# And the specific hazard: no ACCEPTED link anywhere may rest on the commodity hashes.
def top_value(l):
    return str((l.factors or {}).get("top", {}).get("value", ""))


bad_top = [l for l in links if l.linked and top_value(l) in commodity]
chk(not bad_top,
    "no accepted link anywhere rests on PsExec or Mimikatz as its strongest factor"
    + ("" if not bad_top else f" — {[(l.host_a, l.host_b) for l in bad_top[:3]]}"))
PYEOF

# ---------------------------------------------------------------- attribution restraint
say "Attribution — two families, neither claimed as one actor"
corpus_checks <<'PYEOF'
from cases.models import Investigation
from correlation.models import BehaviorNode, CorrelationRun

m = manifest()
inv = Investigation.objects.filter(incident_id=PREFIX).first()
run = CorrelationRun.objects.filter(investigation_id=inv.id, is_current=True).first() if inv else None

fams = set(BehaviorNode.objects.filter(run=run, kind="artifact", subkind="malware_family")
           .values_list("value", flat=True)) if run else set()
chk(m["copper_family"] in fams and m["iron_family"] in fams,
    f"both families reach the graph as distinct artifacts ({sorted(fams)})")

# Each C2 domain belongs to one campaign's hosts only — rotation is not what separates these
# two, their infrastructure never overlapped in the first place.
for key, hosts_key in (("copper_c2", "copper_hosts"), ("iron_c2", "iron_hosts")):
    # An address is an INDICATOR, not an artifact: artifacts are what the actor brought
    # (family, mutex, persistence), indicators are what it reached.
    n = BehaviorNode.objects.filter(run=run, kind="indicator", subkind="domain",
                                    value=m[key]).first() if run else None
    chk(bool(n), f"{m[key]} is an artifact node"
                 + (f" ({n.subkind}, {n.host_count} host(s))" if n else " — MISSING"))
PYEOF

report_finish
exit "${FAILED}"
