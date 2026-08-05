"""
L1 — weighted linkage. Scores candidate host-host links instead of asserting them.

v1.0 joined two hosts on any shared artifact, transitively and irreversibly: one account
legitimately present fleet-wide fused every compromise it touched into a single campaign.
The corpus demonstrates it — the cryptominer merges into Ember Fox through `svc_helpdesk`.

    link_weight = type_weight x rarity x verdict_weight x temporal_coherence

Each factor answers a question v1.0 never asked:

  type       is this observed movement, shared tradecraft, an account, or a bare indicator?
  rarity     how much of the FLEET carries this? IDF over the deployment's own population,
             so software on 20 of 25 hosts is environment and an artifact on 2 is signal.
  verdict    was the evidence adjudicated True Positive, or is it an Indeterminate note?
  temporal   did these hosts see this within one intrusion window, and does the movement's
             direction agree with when each side was first compromised?

Clustering becomes thresholded connected components over the weighted graph. Still
deterministic, still explainable: every link keeps its per-factor contributions and the
findings behind it, so a merge can be defended and a refusal can be shown.

Nothing here infers. A weight is a product of four stated numbers, each derived from a
recorded observation, and `HostLink.factors` holds all of them.
"""
from collections import defaultdict
from math import log

from .models import BehaviorEvent, BehaviorNode, HostLink

# What KIND of shared thing this is. Observed movement is direct evidence one host reached
# another; a rare named artifact is tradecraft; an account is weaker (accounts are shared by
# policy as often as by intrusion); a bare indicator is weakest, since fleet software and
# actor infrastructure look identical at this level and only rarity separates them.
TYPE_WEIGHT = {
    "movement": 1.00,
    "artifact": 0.85,
    "account": 0.45,
    "indicator": 0.55,
    "technique": 0.15,
}

# The verdict ladder, mirrored. An Indeterminate observation is a lead, not a link — it
# contributes, but it cannot on its own carry a pair over the threshold.
VERDICT_WEIGHT = {
    "True Positive": 1.00,
    "Likely True Positive": 0.75,
    "Indeterminate": 0.25,
    "": 0.25,
}

# Verdicts that assert compromise rather than raise a question. Read off the ladder above so
# there is one vocabulary: anything ranked above Indeterminate says something happened.
CONFIRMING_VERDICTS = frozenset(
    v for v, w in VERDICT_WEIGHT.items() if w > VERDICT_WEIGHT["Indeterminate"]
)

# A pair joins a campaign when its strongest link reaches this. Set so that a single
# Indeterminate indicator (0.55 x 0.25 = 0.1375 before rarity) cannot merge anything, while
# one True Positive movement (1.00) or a rare shared artifact always does.
LINK_THRESHOLD = 0.35

# Beyond this many days apart, two observations are not one intrusion window. Inside it the
# penalty scales smoothly rather than cliff-edging, because intrusions dwell.
WINDOW_DAYS = 30.0


def rarity(host_count, population):
    """Inverse document frequency over the DEPLOYMENT's host population.

    An artifact on every host carries no linkage information however suspicious it looks;
    one on two hosts out of forty is the reason those two are being compared. Normalized to
    (0, 1] so it scales the other factors rather than dominating them.

    The denominator is the whole deployment, not the investigation being correlated. Measured
    against the case's own host count, a two-host intrusion has its shared C2 on 100% of the
    population and scores zero — "common, therefore environment" — so the same evidence linked
    or did not depending on how the case happened to be scoped. Rarity is a statement about
    the environment, and the environment does not change size with the case.

    Smoothed (`+1`/`+0.5`) so a small population cannot drive the numerator to log(1) = 0 and
    silently zero out every shared artifact.
    """
    if population <= 1 or host_count <= 0:
        return 1.0
    return max(0.0, min(1.0, log((population + 1) / (host_count + 0.5)) / log(population + 1)))


def temporal_coherence(a_time, b_time):
    """1.0 for co-occurrence, decaying to 0.2 across the intrusion window."""
    if not a_time or not b_time:
        return 0.6            # unknown timing neither confirms nor refutes
    days = abs((a_time - b_time).total_seconds()) / 86400.0
    if days >= WINDOW_DAYS:
        return 0.2
    return 1.0 - 0.8 * (days / WINDOW_DAYS)


# A movement recorded before its source shows any compromise cannot be right. Discounted to
# this rather than dropped: a contradictory record is itself something an analyst should see.
CONTRADICTION_DISCOUNT = 0.35


def contradiction_for(src, moved_at, src_first):
    """(multiplier, basis) for one movement edge. Returns 1.0 when nothing contradicts it.

    `src_first` is the source host's first STANDALONE CONFIRMING evidence. The claim under
    test is "used to move onward before anything showed it compromised", so that baseline may
    include neither this movement — recorded on the source, it would set the very baseline it
    is compared against — nor Indeterminate fleet noise, which is present on every host at
    every hour and says nothing about compromise.

    With no such evidence the check is UNANSWERED, and the basis says so. An unevaluated test
    recorded as a passed one is the failure mode this whole factor exists to avoid.
    """
    if not src_first or not moved_at:
        return 1.0, f"not evaluated — no standalone confirming evidence on {src}"
    if moved_at < src_first:
        return CONTRADICTION_DISCOUNT, (
            f"movement at {moved_at.isoformat()} precedes {src}'s first compromise evidence "
            f"at {src_first.isoformat()}")
    return 1.0, (f"consistent — {src} shows compromise from {src_first.isoformat()}, "
                 f"movement at {moved_at.isoformat()}")


def build_links(crun, compromised, host_first, edges, population=None, first_standalone=None):
    """Score every candidate pair from the behavior graph. Returns {(a,b): HostLink}.

    Only compromised hosts can be campaign members, but rarity is measured against the whole
    DEPLOYMENT — `population` — not against this investigation. Falls back to the graph's own
    host count when no deployment figure is supplied, which is only correct for a case that
    happens to span the fleet.

    `first_standalone` is `host_first` computed over evidence that is not itself a movement
    record, and only the contradiction test uses it — see there for why the two must differ.
    """
    first_standalone = first_standalone or {}
    nodes = list(BehaviorNode.objects.filter(run=crun))
    population = max(1, population or sum(1 for n in nodes if n.kind == "host"))

    # Best verdict seen per (node, host): a node shared through a True Positive on one host
    # and an Indeterminate mention on the other is only as strong as its weaker end.
    best_verdict = defaultdict(str)
    for ev in BehaviorEvent.objects.filter(run=crun).only("node_id", "hostname", "verdict"):
        key = (ev.node_id, ev.hostname)
        if VERDICT_WEIGHT.get(ev.verdict, 0.25) > VERDICT_WEIGHT.get(best_verdict[key], 0.0):
            best_verdict[key] = ev.verdict

    pairs = defaultdict(list)   # (a, b) -> [contribution, ...]

    for node in nodes:
        if node.kind == "host":
            continue
        carriers = sorted(h for h in node.hostnames if h in compromised)
        if len(carriers) < 2:
            continue
        r = rarity(node.host_count, population)
        tw = TYPE_WEIGHT.get(node.kind, 0.3)
        for i, a in enumerate(carriers):
            for b in carriers[i + 1:]:
                vw = min(VERDICT_WEIGHT.get(best_verdict[(node.id, a)], 0.25),
                         VERDICT_WEIGHT.get(best_verdict[(node.id, b)], 0.25))
                tc = temporal_coherence(host_first.get(a), host_first.get(b))
                pairs[(a, b)].append({
                    "kind": node.kind, "subkind": node.subkind, "value": node.value[:200],
                    "type_weight": round(tw, 3), "rarity": round(r, 3),
                    "verdict_weight": round(vw, 3), "temporal": round(tc, 3),
                    "weight": round(tw * r * vw * tc, 4),
                    "host_count": node.host_count,
                })

    # Observed movement, scored separately: it is the one link type that is direct evidence
    # of one host reaching another, and it carries its own contradiction check.
    for e in edges:
        a, b = e["src"], e["dst"]
        if a not in compromised or b not in compromised:
            continue
        key = (a, b) if a < b else (b, a)
        vw = VERDICT_WEIGHT.get("True Positive", 1.0)
        tc = temporal_coherence(host_first.get(a), host_first.get(b))
        contradiction, basis = contradiction_for(
            a, e.get("observed_dt"), first_standalone.get(a))
        pairs[key].append({
            "kind": "movement", "subkind": e.get("technique", ""),
            "value": f"{a} -> {b} via {e.get('protocol','')}",
            "type_weight": TYPE_WEIGHT["movement"], "rarity": 1.0,
            "verdict_weight": vw, "temporal": round(tc, 3),
            "contradiction": contradiction,
            "contradiction_basis": basis,
            "weight": round(TYPE_WEIGHT["movement"] * vw * tc * contradiction, 4),
            "host_count": 2,
        })

    links = {}
    for (a, b), contributions in pairs.items():
        contributions.sort(key=lambda c: -c["weight"])
        top = contributions[0]["weight"]
        # The strongest link decides membership; the rest are corroboration. Summing instead
        # would let a pile of fleet-wide noise out-vote one piece of real evidence.
        links[(a, b)] = HostLink(
            run=crun, host_a=a, host_b=b,
            weight=top,
            linked=top >= LINK_THRESHOLD,
            factors={
                "top": contributions[0],
                "corroboration": contributions[1:6],
                "contribution_count": len(contributions),
                # Every evidence type that contributed, not only the five strongest kept in
                # full. Truncating the detail is a size decision; letting a shared user-agent
                # or mutex vanish from the record entirely is an evidentiary one, and an
                # analyst asking what tied two hosts together must see all of it named.
                "evidence_kinds": sorted({(c.get("subkind") or c["kind"]) for c in contributions}),
            },
        )
    HostLink.objects.bulk_create(links.values(), batch_size=500)
    return links


def cluster(compromised, links):
    """Connected components over links at or above the threshold.

    A pair below the threshold is not merged, however many weak things it shares — which is
    what stops one fleet-wide account from fusing unrelated compromises.
    """
    adjacency = defaultdict(set)
    for (a, b), link in links.items():
        if link.linked:
            adjacency[a].add(b)
            adjacency[b].add(a)

    seen, clusters = set(), []
    for host in sorted(compromised):
        if host in seen:
            continue
        stack, group = [host], set()
        while stack:
            cur = stack.pop()
            if cur in group:
                continue
            group.add(cur)
            stack.extend(adjacency[cur] - group)
        seen |= group
        clusters.append(group)
    return clusters


def cohesion(group, links):
    """(min, mean) of the links holding a campaign together.

    The MINIMUM is reported alongside the mean because it is what an opposing analyst
    attacks: a campaign is only as defensible as its weakest internal link.
    """
    inside = [l.weight for (a, b), l in links.items()
              if a in group and b in group and l.linked]
    if not inside:
        return 0.0, 0.0
    return round(min(inside), 4), round(sum(inside) / len(inside), 4)
