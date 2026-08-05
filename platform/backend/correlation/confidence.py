"""L3 — membership confidence bands.

How confident the engine is that a host belongs to **this** campaign, as a band rather than a
float. Floats invite false precision: a UI given 0.62 and 0.67 will invent a threshold between
them, and nobody can defend that threshold in a report. Three bands can be defended, and the
fourth says the question was not answerable.

Nothing new is computed. Every input is already in `HostLink.factors`, written for every
candidate pair including the ones the engine declined — this reads that record and names what
it found, so a band decomposes back into the evidence that produced it.

The vocabulary tracks the verdict ladder deliberately, `indeterminate` included: a host with no
link to any other host in its campaign has no cross-host evidence to be confident *or*
doubtful about, and recording that as the lowest band would report an absence of evidence as
evidence of weakness.
"""
from __future__ import annotations

from .linkage import LINK_THRESHOLD
from .models import CampaignHost

CONFIRMED = CampaignHost.BAND_CONFIRMED
PROBABLE = CampaignHost.BAND_PROBABLE
POSSIBLE = CampaignHost.BAND_POSSIBLE
INDETERMINATE = CampaignHost.BAND_INDETERMINATE

# A link at LINK_THRESHOLD was strong enough to merge and no more. STRONG_LINK is where one
# piece of evidence carries the membership on its own — a True Positive movement, or a rare
# shared artifact — rather than needing the corroboration to hold it up.
STRONG_LINK = 0.70

# Two DISTINCT kinds, not two contributions: forty sightings of one shared account are one
# kind of evidence repeated, and treating the count as corroboration would let fleet-wide
# noise band a host as confirmed.
MIN_KINDS_FOR_CONFIRMED = 2

# Below this the two hosts' first activity sits far enough apart that the link is carried by
# the indicator alone, with the timeline arguing against it.
TEMPORAL_OK = 0.50


def _contradiction_in(link):
    """The contradicted contribution on this link, top or corroborating — None if clean."""
    factors = link.factors or {}
    for c in [factors.get("top") or {}, *(factors.get("corroboration") or [])]:
        if isinstance(c, dict) and (c.get("contradiction") or 1.0) < 1.0:
            return c
    return None


def _links_for(host, links):
    """Every accepted link touching `host`, strongest first."""
    out = [link for (a, b), link in links.items()
           if link.linked and (a == host or b == host)]
    return sorted(out, key=lambda link: -link.weight)


def band_for(host, links):
    """(band, factors) for one host, from the links already scored for this run."""
    accepted = _links_for(host, links)
    if not accepted:
        return INDETERMINATE, {
            "band": INDETERMINATE,
            "best_link": None,
            "evidence_kinds": [],
            "corroboration": 0,
            "temporal": None,
            "contradiction": None,
            "why": ("no link to another host in this campaign, so membership rests on no "
                    "cross-host evidence — not weak evidence, none of that kind"),
        }

    best = accepted[0]
    top = (best.factors or {}).get("top") or {}
    kinds = sorted({k for link in accepted
                    for k in (link.factors or {}).get("evidence_kinds", [])})
    temporal = top.get("temporal")
    peer = best.host_b if best.host_a == host else best.host_a

    # ANY accepted link, and any CONTRIBUTION within it — not just the strongest of either.
    #
    # A host can be tied in by a clean artifact at 1.00 and also by a movement whose sequence
    # cannot be right. Reading only the top link hides the contradiction behind the
    # corroboration, which is backwards: the corroboration is why the host is not merely
    # `possible`, and the contradiction is why it is not settled.
    #
    # Reading only each link's top contribution hides it a second way, and this one is caused
    # by the discount itself — discounting the movement drops it below the pair's clean
    # artifact evidence, so the contradicted contribution sorts into `corroboration` and the
    # link presents as ordinary. The record is right there; only the reader was wrong.
    contradicted = next(
        ((link, c) for link in accepted if (c := _contradiction_in(link))), None)

    strong = best.weight >= STRONG_LINK
    corroborated = len(kinds) >= MIN_KINDS_FOR_CONFIRMED
    coherent = temporal is None or temporal >= TEMPORAL_OK

    if contradicted:
        link, ctop = contradicted
        other = link.host_b if link.host_a == host else link.host_a
        # Held one band below whatever the rest of the evidence would have earned, never
        # above `probable`. A membership the timeline argues against must not read as
        # settled; a host with real independent corroboration is not merely `possible`.
        band = PROBABLE if (strong or corroborated) else POSSIBLE
        why = (f"movement with {other} is recorded before that host shows any compromise "
               f"(discounted x{ctop.get('contradiction')}) — the sequence contradicts itself, "
               f"so membership is held below what the other evidence would carry")
    elif strong and corroborated and coherent:
        band = CONFIRMED
        why = (f"link to {peer} at {best.weight:.2f} carries membership on its own, "
               f"corroborated by {len(kinds)} kinds of evidence, timeline consistent")
    elif strong or (corroborated and coherent):
        band = PROBABLE
        why = (f"link to {peer} at {best.weight:.2f} with {len(kinds)} evidence kind(s)"
               + ("" if coherent else "; first activity far apart"))
    else:
        band = POSSIBLE
        why = (f"link to {peer} at {best.weight:.2f}, just past the {LINK_THRESHOLD} "
               f"threshold, with {len(kinds)} evidence kind(s)"
               + ("" if coherent else " and a timeline that argues against it"))

    return band, {
        "band": band,
        "best_link": {
            "with": peer,
            "weight": round(best.weight, 4),
            "kind": top.get("subkind") or top.get("kind", ""),
            "value": top.get("value", ""),
        },
        "evidence_kinds": kinds,
        "corroboration": len(kinds),
        "temporal": temporal,
        "contradiction": (contradicted[1].get("contradiction") if contradicted else None),
        # The instants the discount was decided from, so the arithmetic can be checked
        # without rerunning correlation.
        "contradiction_basis": (contradicted[1].get("contradiction_basis")
                                if contradicted else None),
        "link_count": len(accepted),
        "why": why,
    }
