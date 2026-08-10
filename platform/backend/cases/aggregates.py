"""Server-side aggregates for visualizations, plus the lifecycle and custody reads.

**Charts must never aggregate over paged data.** A client that sums what it was handed draws
a picture of one page and labels it the investigation. Every figure here is computed over the
full underlying set in the database, and each endpoint's totals are meant to equal the sum of
the rows behind them — that equality is what `uat_ui.sh` asserts.

The verdict rule that runs through all of it: `Indeterminate` is never folded into a
confirmed count. It is the ladder's word for "not decided", and a chart that quietly counts
it as a true positive reports certainty the evidence does not carry.
"""
from collections import Counter, defaultdict

from django.db.models import Count, Min
from django.utils import timezone
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .audit import audit
from .models import (CollectionRun, CustodyEvent, Finding, IndicatorSighting,
                     Investigation, InvalidTransition, MemoryAnalysisRun, MemoryCapture)
from .rbac import IsAnalystOrAdmin, role_of

# The verdicts that assert something happened. Everything else — Indeterminate, the false
# positives, the unset — is counted separately and never merged in.
CONFIRMING = ("True Positive", "Likely True Positive")


def _verdict_of(finding):
    raw = finding.raw or {}
    return (finding.verdict or raw.get("Verdict") or raw.get("adjudication", {}).get("Verdict")
            or "")


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def investigation_stats(request, investigation_id):
    """V1/V2/V4 — counts by tactic, verdict, source and day, over every finding."""
    inv = Investigation.objects.filter(id=investigation_id).first()
    if not inv:
        return Response({"detail": "not found"}, status=404)

    findings = Finding.objects.filter(run__investigation=inv).select_related("run__host")
    total = findings.count()

    by_verdict = Counter()
    by_tactic = Counter()
    by_source = Counter()
    by_day = Counter()
    # V2 marks. Bucketed technique x day x host rather than one row per finding: the shape
    # is bounded by what happened instead of by how much was collected, and each bucket
    # drills to the findings table with params it accepts today (?technique=&host=&
    # investigation=) — so the chart can never claim a set the table cannot reproduce.
    killchain = {}
    hosts = {}
    # Every field named here must exist on Finding: `.only()` resolves them against the model
    # and raises for one that does not, so a stray name takes the whole endpoint down rather
    # than being ignored. Severity is not a Finding field — it lives on the analysis rows.
    for f in findings.only("verdict", "raw", "created_at", "finding_type",
                           "run__host__id", "run__host__hostname"):
        verdict = _verdict_of(f) or "unset"
        confirmed_one = verdict in CONFIRMING
        by_verdict[verdict] += 1
        raw = f.raw or {}
        mitre = str(raw.get("MITRE") or "")
        technique = mitre.split(" ")[0] if mitre else "unmapped"
        by_tactic[technique] += 1
        by_source[str(raw.get("Source") or "collection")] += 1
        when = raw.get("Timestamp") or (f.created_at.isoformat() if f.created_at else "")
        day = str(when)[:10] or "unknown"
        by_day[day] += 1

        host = f.run.host
        kc = killchain.setdefault((technique, day, host.id), {
            "technique": technique, "day": day,
            "host_id": host.id, "host": host.hostname,
            "count": 0, "confirmed": 0,
        })
        kc["count"] += 1
        kc["confirmed"] += 1 if confirmed_one else 0

        h = hosts.setdefault(host.id, {
            "host_id": host.id, "host": host.hostname,
            "first_seen": day, "findings": 0, "confirmed": 0,
        })
        h["findings"] += 1
        h["confirmed"] += 1 if confirmed_one else 0
        # "unknown" sorts after every date, so a real day always wins it.
        if day != "unknown" and (h["first_seen"] == "unknown" or day < h["first_seen"]):
            h["first_seen"] = day

    # Membership bands from the current correlation, joined by hostname because the
    # correlation layer stores hostnames, not host rows. A host outside every campaign
    # simply carries no band — absence of a claim, not a low one.
    from correlation.models import CampaignHost, CorrelationRun
    crun = CorrelationRun.objects.filter(investigation_id=inv.id, is_current=True).first()
    bands = ({ch.hostname: ch.confidence_band
              for ch in CampaignHost.objects.filter(campaign__run=crun)} if crun else {})
    for h in hosts.values():
        h["confidence_band"] = bands.get(h["host"], "")

    confirmed = sum(n for v, n in by_verdict.items() if v in CONFIRMING)
    return Response({
        "investigation_id": inv.id,
        "status": inv.status,
        "total_findings": total,
        # Named apart so a caller cannot accidentally present "not decided" as "confirmed".
        "confirmed_findings": confirmed,
        "indeterminate_findings": by_verdict.get("Indeterminate", 0),
        "by_verdict": dict(by_verdict),
        "by_tactic": dict(by_tactic.most_common(20)),
        "by_source": dict(by_source),
        "by_day": dict(sorted(by_day.items())),
        "killchain": sorted(killchain.values(),
                            key=lambda k: (k["day"], k["technique"], k["host"])),
        "hosts": sorted(hosts.values(), key=lambda h: (h["first_seen"], h["host"])),
        "computed_over": total,      # the equality uat_ui.sh checks
    })


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def investigation_coverage(request, investigation_id):
    """V2 — hosts collected versus hosts the evidence implicates.

    The gap is the point: a host named in someone else's movement evidence that was never
    collected is the next collection, and it is invisible in any per-host view.
    """
    inv = Investigation.objects.filter(id=investigation_id).first()
    if not inv:
        return Response({"detail": "not found"}, status=404)

    runs = CollectionRun.objects.filter(investigation=inv).select_related("host")
    collected = {r.host.hostname for r in runs}
    with_findings = set(
        Finding.objects.filter(run__investigation=inv)
        .values_list("run__host__hostname", flat=True).distinct())

    implicated = set()
    from correlation.models import CampaignEdge, CampaignHost, CorrelationRun
    crun = CorrelationRun.objects.filter(investigation_id=inv.id, is_current=True).first()
    if crun:
        implicated |= set(CampaignHost.objects.filter(campaign__run=crun)
                          .values_list("hostname", flat=True))
        for e in CampaignEdge.objects.filter(campaign__run=crun):
            implicated.add(e.src_hostname)
            implicated.add(e.dst_hostname)

    return Response({
        "investigation_id": inv.id,
        "collected": sorted(collected),
        "collected_count": len(collected),
        "with_findings_count": len(with_findings),
        "implicated": sorted(implicated),
        "implicated_count": len(implicated),
        # Named in evidence, never collected. The actionable half of coverage.
        "implicated_not_collected": sorted(implicated - collected),
        "collected_clean": sorted(collected - with_findings),
    })


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def run_timeline(request, run_id):
    """V3 — one run's findings in time order, each carrying the source that produced it."""
    run = CollectionRun.objects.filter(id=run_id).select_related("host").first()
    if not run:
        return Response({"detail": "not found"}, status=404)

    events = []
    for f in Finding.objects.filter(run=run):
        raw = f.raw or {}
        events.append({
            "at": raw.get("Timestamp") or (f.created_at.isoformat() if f.created_at else None),
            "finding_id": f.id,
            "type": f.finding_type,
            # Severity is not a Finding column — the analysis rows carry it, and the
            # collector records it in `raw`. Reading it as an attribute raised on every
            # request and took the whole timeline down.
            "severity": str(raw.get("Severity") or raw.get("severity") or ""),
            "verdict": _verdict_of(f) or "unset",
            "source": str(raw.get("Source") or "collection"),
            "target": str(raw.get("Target") or "")[:200],
        })
    events.sort(key=lambda e: (e["at"] or ""))
    return Response({
        "run_id": run.id, "hostname": run.host.hostname,
        "collected_at": run.collected_at, "events": events, "event_count": len(events),
    })


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def ioc_spread(request, ioc_type, value):
    """V6 — everywhere an indicator has been seen, across investigations.

    Reads `IndicatorSighting`, not `IOC`: the rollup is what survives archival of the runs,
    and this is the question that has to keep answering afterwards.
    """
    sightings = IndicatorSighting.objects.filter(ioc_type=ioc_type, value=value)
    by_inv = defaultdict(list)
    for s in sightings:
        by_inv[s.investigation_id].append(s)

    investigations = []
    for inv_id, rows in sorted(by_inv.items()):
        firsts = [r.first_seen for r in rows if r.first_seen]
        investigations.append({
            "investigation_id": inv_id,
            "incident_id": rows[0].incident_id,
            "hosts": sorted({r.hostname for r in rows}),
            "host_count": len({r.host_id for r in rows}),
            "first_seen": min(firsts) if firsts else None,
            "sightings": sum(r.sighting_count for r in rows),
        })
    return Response({
        "ioc_type": ioc_type, "value": value,
        "investigation_count": len(investigations),
        "host_count": len({s.host_id for s in sightings}),
        "total_sightings": sum(s.sighting_count for s in sightings),
        "investigations": investigations,
    })


class QueueDepthView(APIView):
    """V7 — the analysis backlog, as depth by state plus the oldest waiting item.

    Depth alone hides a stuck queue: ten queued items that arrived a minute ago and ten that
    have waited six hours are the same number and not the same situation.
    """

    permission_classes = [IsAnalystOrAdmin]

    def get(self, request):
        by_state = dict(MemoryAnalysisRun.objects.values_list("status")
                        .annotate(n=Count("id")).values_list("status", "n"))
        waiting = (MemoryAnalysisRun.objects.filter(status__in=("queued", "running"))
                   .aggregate(oldest=Min("created_at")))
        oldest = waiting.get("oldest")
        return Response({
            "sampled_at": timezone.now(),
            "by_state": by_state,
            "queued": by_state.get("queued", 0),
            "running": by_state.get("running", 0),
            "oldest_waiting_at": oldest,
            "oldest_waiting_seconds": (
                int((timezone.now() - oldest).total_seconds()) if oldest else 0),
            "captures_awaiting_analysis": MemoryCapture.objects.filter(
                analyses__isnull=True).count(),
        })


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def run_custody(request, run_id):
    """B1.2 — the custody chain for one run, and whether it still verifies.

    These guarantees already held; they were readable only in the receiver's log. A refusal
    an analyst cannot see is a control that protects the record without informing the person
    relying on it.
    """
    run = CollectionRun.objects.filter(id=run_id).select_related("host").first()
    if not run:
        return Response({"detail": "not found"}, status=404)

    events = list(CustodyEvent.objects.filter(run=run))
    # Recompute the chain rather than trusting the stored flag: the ledger is append-only and
    # hash-linked, so a break is detectable here and saying "verified" without checking would
    # be repeating a claim instead of testing it.
    broken_at, prev = None, ""
    for i, e in enumerate(events):
        if e.prev_hash and prev and e.prev_hash != prev:
            broken_at = i
            break
        prev = e.entry_hash or prev

    captures = MemoryCapture.objects.filter(run=run)
    return Response({
        "run_id": run.id, "hostname": run.host.hostname,
        "collected_at": run.collected_at,
        "chain": [{
            "at": e.created_at, "action": e.action, "actor": e.actor,
            "detail": e.detail, "entry_hash": e.entry_hash, "prev_hash": e.prev_hash,
        } for e in events],
        "event_count": len(events),
        "chain_intact": broken_at is None,
        "chain_broken_at_index": broken_at,
        "verification": {
            "verified_events": [e.action for e in events if e.action == "verify"],
            "verified_by": sorted({e.actor for e in events if e.action == "verify" and e.actor}),
            # An unverified bundle is not a failed one, and the difference has to be legible.
            "state": ("broken" if broken_at is not None else
                      "verified" if any(e.action == "verify" for e in events) else
                      "unverified"),
        },
        "captures": [{
            "id": c.id, "sha256": c.sha256, "size_bytes": c.size_bytes,
            "retention_status": c.retention_status,
        } for c in captures],
    })


class InvestigationTransitionView(APIView):
    """T1 — move an investigation through its lifecycle, or refuse and say why."""

    permission_classes = [IsAnalystOrAdmin]

    def post(self, request, investigation_id):
        inv = Investigation.objects.filter(id=investigation_id).first()
        if not inv:
            return Response({"detail": "not found"}, status=404)
        target = str(request.data.get("status", "")).strip()
        if not target:
            return Response({"detail": "status is required"}, status=400)

        previous = inv.status
        try:
            inv.transition_to(target)
        except InvalidTransition as exc:
            # 409, not 400: the request is well formed and the state refuses it. The legal
            # moves are named so a caller does not have to guess at the machine.
            return Response({
                "detail": str(exc),
                "current": inv.status,
                "allowed": sorted(Investigation.TRANSITIONS.get(inv.status, set())),
            }, status=409)

        audit(request.user, "investigation.transition", role=role_of(request.user),
              method="POST", path=request.path, object_type="Investigation",
              object_id=str(inv.id), detail={"from": previous, "to": inv.status})
        return Response({
            "investigation_id": inv.id, "status": inv.status,
            "previous": previous, "concluded_at": inv.concluded_at,
            "allowed_next": sorted(Investigation.TRANSITIONS.get(inv.status, set())),
        })


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def stalled_investigations(request):
    """T1 — open cases past an age ceiling, and concluded ones never archived."""
    days = int(request.query_params.get("days", 30))
    cutoff = timezone.now() - timezone.timedelta(days=days)
    active = Investigation.objects.filter(
        status__in=(Investigation.OPEN, Investigation.CONTAINED), updated_at__lt=cutoff)
    unarchived = Investigation.objects.filter(
        status=Investigation.CONCLUDED, concluded_at__lt=cutoff)
    return Response({
        "age_ceiling_days": days,
        "stalled": [{
            "id": i.id, "name": i.name, "incident_id": i.incident_id,
            "status": i.status, "last_activity": i.updated_at,
        } for i in active],
        "concluded_not_archived": [{
            "id": i.id, "name": i.name, "incident_id": i.incident_id,
            "concluded_at": i.concluded_at,
        } for i in unarchived],
    })
