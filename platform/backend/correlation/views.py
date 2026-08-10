"""
Read APIs over the derived correlation store, plus the recompute trigger.

Everything served here is derived and rebuildable; the authoritative per-host record
stays in `cases`. Responses carry the algorithm version and the time the correlation was
computed, so a view is never mistaken for live evidence.
"""
from django.db.models import Sum
from django.utils import timezone
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from cases.audit import audit
from cases.models import Finding, Investigation
from cases.rbac import IsAnalystOrAdmin, role_of

from .engine import correlate_all, correlate_investigation
from .linkage import LINK_THRESHOLD
from .models import (AttributionCandidate, Campaign, CampaignEdge, CampaignFingerprint,
                     CampaignHost, CampaignSimilarity, CorrelationRun, HostLink,
                     SharedIndicator)


def _as_dt(value):
    """An ISO timestamp string as an aware datetime, or None.

    Timeline events arrive from two places: campaign rows hold real datetimes, a finding's
    time is an ISO string inside `raw`. They have to become one type before the events can
    be ordered against each other.
    """
    if not value:
        return None
    try:
        parsed = timezone.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return parsed if timezone.is_aware(parsed) else timezone.make_aware(parsed)


def _campaign_payload(campaign):
    return {
        "id": campaign.id,
        "label": campaign.label,
        "investigation_id": campaign.investigation_id,
        "patient_zero": campaign.patient_zero,
        "initial_vector": campaign.initial_vector,
        "first_activity": campaign.first_activity,
        "last_activity": campaign.last_activity,
        "host_count": campaign.host_count,
        "confidence": campaign.confidence,
        "linking_evidence": campaign.linking_evidence,
    }


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def investigation_correlation(request, investigation_id):
    """Current campaigns for one investigation."""
    crun = CorrelationRun.objects.filter(
        investigation_id=investigation_id, is_current=True
    ).first()
    if not crun:
        return Response({"correlated": False, "campaigns": []})

    # The id alone does not prove this correlation belongs to this investigation. The two
    # stores are separate databases with no cross-database foreign key, so a deleted
    # investigation leaves its correlation behind and PostgreSQL hands the id to the next
    # one created — which then reads as another incident's campaigns. The name recorded at
    # correlation time is the check: when it no longer matches, the row describes something
    # else and is not served.
    from cases.models import Investigation

    current_name = (Investigation.objects.filter(id=investigation_id)
                    .values_list("name", flat=True).first())
    if crun.investigation_name and current_name and crun.investigation_name != current_name:
        return Response({
            "correlated": False,
            "campaigns": [],
            "stale": True,
            "detail": (f"the stored correlation was computed for "
                       f"{crun.investigation_name!r} — recompute to correlate this "
                       f"investigation"),
        })

    campaigns = Campaign.objects.filter(run=crun)
    return Response({
        "correlated": True,
        "computed_at": crun.created_at,
        "algorithm_version": crun.algorithm_version,
        "input_summary": crun.input_summary,
        "campaigns": [_campaign_payload(c) for c in campaigns],
    })


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def campaign_graph(request, campaign_id):
    """Nodes and edges for the attack graph.

    Node order is the order the intrusion reached each host, so a renderer can lay the
    graph out chronologically without re-deriving timing.
    """
    campaign = Campaign.objects.filter(id=campaign_id).first()
    if not campaign:
        return Response({"detail": "not found"}, status=404)

    hosts = list(CampaignHost.objects.filter(campaign=campaign))
    edges = list(CampaignEdge.objects.filter(campaign=campaign))
    names = {h.hostname for h in hosts}
    # Every candidate pair this run scored that touches the campaign, accepted or not.
    links = [l for l in HostLink.objects.filter(run_id=campaign.run_id)
             if l.host_a in names or l.host_b in names]

    reached = {e.dst_hostname for e in edges}
    return Response({
        "campaign": _campaign_payload(campaign),
        "nodes": [{
            "hostname": h.hostname, "host_id": h.host_id, "role": h.role,
            "first_activity": h.first_activity, "entry_technique": h.entry_technique,
            "entry_account": h.entry_account, "tp_count": h.tp_count,
            "techniques": h.techniques,
            # The band and what it decomposes into. Serving the label alone would leave the
            # UI explaining a judgment it cannot see the basis for.
            "confidence_band": h.confidence_band,
            "confidence_factors": h.confidence_factors,
            # A node nothing moved to, that is not the entry point, was reached by a
            # means the evidence does not show — surfaced rather than hidden.
            "entry_observed": h.hostname in reached or h.role == "patient_zero",
        } for h in hosts],
        "edges": [{
            "src": e.src_hostname, "dst": e.dst_hostname, "technique": e.technique,
            "protocol": e.protocol, "account": e.account, "observed_at": e.observed_at,
            "source_finding_id": e.source_finding_id,
            "kind": "movement",
            # Movement is direct evidence of one host reaching another; weight lets the
            # renderer draw it at the same scale as a behavioral link without conflating
            # the two, which `kind` keeps apart.
            "weight": _weight_between(links, e.src_hostname, e.dst_hostname),
        } for e in edges],
        # Behavioral links: hosts tied by shared tradecraft with no movement recorded
        # between them. Drawn as a distinct overlay, not as movement that was observed.
        "behavioral_edges": [{
            "src": l.host_a, "dst": l.host_b, "kind": "behavioral",
            "weight": round(l.weight, 4),
            "top_factor": (l.factors or {}).get("top", {}),
            "evidence_kinds": (l.factors or {}).get("evidence_kinds", []),
        } for l in links
            if l.linked and {l.host_a, l.host_b} <= names
            and not _has_movement(edges, l.host_a, l.host_b)],
        # What ALMOST linked. A link the engine declined is as informative as one it
        # accepted, and an analyst asking "why aren't these two the same intrusion?"
        # deserves the answer rather than an absence.
        "declined_edges": [{
            "src": l.host_a, "dst": l.host_b, "kind": "declined",
            "weight": round(l.weight, 4),
            "top_factor": (l.factors or {}).get("top", {}),
            "why": _decline_reason(l),
        } for l in links
            if not l.linked and (l.host_a in names or l.host_b in names)][:60],
        "thresholds": {"link": LINK_THRESHOLD},
    })


def _weight_between(links, a, b):
    for l in links:
        if {l.host_a, l.host_b} == {a, b}:
            return round(l.weight, 4)
    return None


def _has_movement(edges, a, b):
    return any({e.src_hostname, e.dst_hostname} == {a, b} for e in edges)


def _decline_reason(link):
    """Why this pair was not merged, in the terms the weighting actually used."""
    top = (link.factors or {}).get("top") or {}
    if not top:
        return "no shared evidence scored above zero"
    if top.get("rarity", 1.0) < 0.35:
        return (f"the strongest shared thing is common across the fleet "
                f"(rarity {top.get('rarity')}) — it reads as environment, not intrusion")
    if top.get("verdict_weight", 1.0) <= 0.25:
        return "the shared evidence is only Indeterminate — a lead, not a link"
    if top.get("temporal", 1.0) < 0.35:
        return "the two hosts' activity is too far apart to be one intrusion window"
    return f"strongest link {link.weight:.3f} did not reach the {LINK_THRESHOLD} threshold"


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def campaign_timeline(request, campaign_id):
    """Chronological reconstruction: host compromise, movement, and notable findings."""
    campaign = Campaign.objects.filter(id=campaign_id).first()
    if not campaign:
        return Response({"detail": "not found"}, status=404)

    hosts = list(CampaignHost.objects.filter(campaign=campaign))
    hostnames = [h.hostname for h in hosts]
    events = []

    for h in hosts:
        if h.first_activity:
            events.append({
                "at": h.first_activity, "kind": "host_compromised",
                "host": h.hostname, "role": h.role,
                "detail": f"first observed activity on {h.hostname}",
            })
    for e in CampaignEdge.objects.filter(campaign=campaign):
        if e.observed_at:
            events.append({
                "at": e.observed_at, "kind": "lateral_movement",
                "host": e.dst_hostname,
                "detail": f"{e.src_hostname} → {e.dst_hostname} via {e.protocol} as {e.account}",
                "technique": e.technique,
            })

    # Notable collected findings, read from the evidence store for detail the derived
    # store deliberately does not duplicate.
    findings = Finding.objects.filter(
        run__investigation_id=campaign.investigation_id,
        run__host__hostname__in=hostnames,
        verdict__in=("True Positive", "Likely True Positive"),
    ).select_related("run__host")
    for f in findings:
        observed = _as_dt((f.raw or {}).get("observed_at"))
        if observed and f.finding_type != "Lateral Movement":
            events.append({
                "at": observed, "kind": "finding", "host": f.run.host.hostname,
                "detail": f"{f.finding_type}: {f.target}",
                "technique": (f.mitre or [""])[0], "verdict": f.verdict,
                "finding_id": f.id,
            })

    # Ordered as instants, not as text. Campaign rows carry datetimes while a finding's time
    # arrives as an ISO string; `str()` renders the two differently and a space sorts before
    # "T", which orders every finding after every movement regardless of when it happened.
    events.sort(key=lambda e: e["at"])
    return Response({"campaign": _campaign_payload(campaign), "events": events})


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def shared_indicators(request):
    """Fleet-wide indicators seen on more than one host, across investigations.

    This is the 'seen before?' anchor: an indicator recurring in a later engagement is
    the signal that two incidents are the same actor.
    """
    current = CorrelationRun.objects.filter(is_current=True).values_list("id", flat=True)
    rows = (
        SharedIndicator.objects.filter(run_id__in=list(current))
        .values("kind", "value")
        .annotate(hosts=Sum("host_count"))
        .order_by("-hosts", "kind", "value")[:200]
    )
    detail = {}
    for ind in SharedIndicator.objects.filter(run_id__in=list(current)):
        key = (ind.kind, ind.value)
        entry = detail.setdefault(key, {"hostnames": set(), "campaigns": set()})
        entry["hostnames"].update(ind.hostnames)
        if ind.campaign_id:
            entry["campaigns"].add(ind.campaign_id)

    return Response({"indicators": [{
        "kind": r["kind"], "value": r["value"],
        "hostnames": sorted(detail.get((r["kind"], r["value"]), {}).get("hostnames", [])),
        "host_count": len(detail.get((r["kind"], r["value"]), {}).get("hostnames", [])),
        "campaign_ids": sorted(detail.get((r["kind"], r["value"]), {}).get("campaigns", [])),
    } for r in rows]})


class RecomputeView(APIView):
    """Rebuild correlation. Derived data only — collected evidence is untouched."""

    permission_classes = [IsAnalystOrAdmin]

    def post(self, request):
        investigation_id = request.data.get("investigation_id")
        if investigation_id:
            inv = Investigation.objects.filter(id=investigation_id).first()
            if not inv:
                return Response({"detail": "no such investigation"}, status=404)
            runs = [correlate_investigation(inv.id, inv.name)]
        else:
            runs = correlate_all()

        audit(request.user, "correlation.recompute",
              role=role_of(request.user), method="POST", path=request.path,
              object_type="CorrelationRun",
              detail={"investigations": len(runs)})
        return Response({
            "recomputed": len(runs),
            "campaigns": Campaign.objects.filter(run_id__in=[r.id for r in runs]).count(),
        })


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def campaign_tradecraft(request, campaign_id):
    """L4/L5 — the campaign's fingerprint, its advisory actor candidates, and lookalikes.

    Attribution is served as *candidates* and nothing here writes an actor onto the case.
    A platform that assigns attribution has turned a similarity score into a claim nobody
    made; this ranks, explains, and leaves the judgment where it belongs.
    """
    campaign = Campaign.objects.filter(id=campaign_id).first()
    if not campaign:
        return Response({"detail": "not found"}, status=404)

    fp = CampaignFingerprint.objects.filter(campaign=campaign).first()
    return Response({
        "campaign_id": campaign.id,
        "fingerprint": None if not fp else {
            "techniques": fp.techniques,
            # The order, and the collected values the conventions were abstracted from. Both
            # exist so a reader can check the fingerprint rather than take it on trust — a
            # field stored but never served is, to them, a field never computed.
            "technique_sequence": fp.technique_sequence,
            "technique_ngrams": fp.technique_ngrams,
            "artifact_conventions": fp.artifact_conventions,
            "convention_examples": fp.convention_examples,
            "c2_pattern": fp.c2_pattern,
            "account_chain": fp.account_chain,
            # Names what the vector was computed over, so a thin fingerprint reads as thin
            # evidence rather than as an actor with little tradecraft.
            "basis": fp.basis,
        },
        "attribution_candidates": [{
            "actor_key": a.actor_key, "actor_name": a.actor_name,
            "score": round(a.score, 4), "source": a.source, "rationale": a.rationale,
            "advisory": True,
        } for a in AttributionCandidate.objects.filter(campaign=campaign)[:10]],
        "similar_campaigns": [{
            "campaign_id": s.other_campaign_id,
            "investigation_id": s.other_investigation_id,
            "label": s.other_label, "score": round(s.score, 4), "rationale": s.rationale,
        } for s in CampaignSimilarity.objects.filter(campaign=campaign)[:10]],
    })


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def correlation_links(request, run_id):
    """V-API — every scored pair for a run, accepted and declined, with its factors.

    Serves the whole candidate set rather than a page: a chart built over one page of links
    draws a picture of that page, which is the failure this endpoint exists to prevent.
    """
    crun = CorrelationRun.objects.filter(id=run_id).first()
    if not crun:
        return Response({"detail": "not found"}, status=404)
    links = HostLink.objects.filter(run=crun)
    bands = {h.hostname: h.confidence_band
             for h in CampaignHost.objects.filter(campaign__run=crun)}
    return Response({
        "run_id": crun.id,
        "algorithm_version": crun.algorithm_version,
        "threshold": LINK_THRESHOLD,
        "links": [{
            "src": l.host_a, "dst": l.host_b,
            "weight": round(l.weight, 4), "linked": l.linked,
            "src_band": bands.get(l.host_a), "dst_band": bands.get(l.host_b),
            "evidence_kinds": (l.factors or {}).get("evidence_kinds", []),
            "top_factor": (l.factors or {}).get("top", {}),
        } for l in links],
    })
