"""
Read APIs over the derived correlation store, plus the recompute trigger.

Everything served here is derived and rebuildable; the authoritative per-host record
stays in `cases`. Responses carry the algorithm version and the time the correlation was
computed, so a view is never mistaken for live evidence.
"""
from django.db.models import Sum
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from cases.audit import audit
from cases.models import Finding, Investigation
from cases.rbac import IsAnalystOrAdmin, role_of

from .engine import correlate_all, correlate_investigation
from .models import Campaign, CampaignEdge, CampaignHost, CorrelationRun, SharedIndicator


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

    reached = {e.dst_hostname for e in edges}
    return Response({
        "campaign": _campaign_payload(campaign),
        "nodes": [{
            "hostname": h.hostname, "host_id": h.host_id, "role": h.role,
            "first_activity": h.first_activity, "entry_technique": h.entry_technique,
            "entry_account": h.entry_account, "tp_count": h.tp_count,
            "techniques": h.techniques,
            # A node nothing moved to, that is not the entry point, was reached by a
            # means the evidence does not show — surfaced rather than hidden.
            "entry_observed": h.hostname in reached or h.role == "patient_zero",
        } for h in hosts],
        "edges": [{
            "src": e.src_hostname, "dst": e.dst_hostname, "technique": e.technique,
            "protocol": e.protocol, "account": e.account, "observed_at": e.observed_at,
            "source_finding_id": e.source_finding_id,
        } for e in edges],
    })


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
        observed = (f.raw or {}).get("observed_at")
        if observed and f.finding_type != "Lateral Movement":
            events.append({
                "at": observed, "kind": "finding", "host": f.run.host.hostname,
                "detail": f"{f.finding_type}: {f.target}",
                "technique": (f.mitre or [""])[0], "verdict": f.verdict,
                "finding_id": f.id,
            })

    events.sort(key=lambda e: str(e["at"]))
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
