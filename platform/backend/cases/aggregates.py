"""Server-side aggregates for visualizations, plus the lifecycle and custody reads.

**Charts must never aggregate over paged data.** A client that sums what it was handed draws
a picture of one page and labels it the investigation. Every figure here is computed over the
full underlying set in the database, and each endpoint's totals are meant to equal the sum of
the rows behind them — that equality is what `uat_ui.sh` asserts.

The verdict rule that runs through all of it: `Indeterminate` is never folded into a
confirmed count. It is the ladder's word for "not decided", and a chart that quietly counts
it as a true positive reports certainty the evidence does not carry.
"""
import os

from collections import Counter, defaultdict
from datetime import timedelta

from django.db.models import Count, Min, Q
from django.utils import timezone
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .audit import audit
from .killchain import TACTIC_NAMES, TACTIC_ORDER, tactics_for
from .models import (CollectionRun, CustodyEvent, Finding, FindingReclassification,
                     IndicatorSighting, Investigation, InvalidTransition, MemoryAnalysisRun,
                     MemoryCapture)
from .rbac import IsAdmin, IsAnalystOrAdmin, role_of

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
    techniques = {}
    stages = {}
    pairs = {}
    # Every field named here must exist on Finding: `.only()` resolves them against the model
    # and raises for one that does not, so a stray name takes the whole endpoint down rather
    # than being ignored. Severity is not a Finding field — it lives on the analysis rows.
    for f in findings.only("verdict", "raw", "mitre", "created_at", "finding_type",
                           "run__host__id", "run__host__hostname"):
        verdict = _verdict_of(f) or "unset"
        confirmed_one = verdict in CONFIRMING
        by_verdict[verdict] += 1
        raw = f.raw or {}
        # Techniques come from the STORED `mitre` list — the field the findings table
        # filters by — never from the raw payload's string, which disagrees with it on
        # promoted findings. A finding carrying several techniques counts under EACH:
        # that is what makes a bar's drill (`mitre__contains`) return exactly its rows,
        # and it means the per-technique counts cover the findings rather than
        # partitioning them.
        f_techniques = [str(t) for t in (f.mitre or [])] or ["unmapped"]
        technique = f_techniques[0]
        for tq in f_techniques:
            by_tactic[tq] += 1
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

        for tac in {t for tq in f_techniques for t in tactics_for(tq)}:
            # The host x tactic pair the chord diagram's ribbons are drawn from: which
            # machine exhibited which stage, and how much. Two hosts sharing a tactic set is
            # what the correlation engine links them on, so the picture and the engine are
            # looking at the same evidence.
            pair = pairs.setdefault((host.hostname, tac), {
                "host": host.hostname, "host_id": host.id, "tactic": tac,
                "name": TACTIC_NAMES.get(tac, "No ATT&CK mapping"),
                "count": 0, "confirmed": 0,
            })
            pair["count"] += 1
            pair["confirmed"] += 1 if confirmed_one else 0

            st = stages.setdefault(tac, {
                "tactic": tac, "name": TACTIC_NAMES.get(tac, "Unmapped"),
                "count": 0, "confirmed": 0, "hosts": set(), "techniques": set(),
                "first_day": day, "last_day": day,
            })
            st["count"] += 1
            st["confirmed"] += 1 if confirmed_one else 0
            st["hosts"].add(host.hostname)
            st["techniques"].update(t for t in f_techniques if t != "unmapped")
            if day != "unknown":
                if st["first_day"] == "unknown" or day < st["first_day"]:
                    st["first_day"] = day
                if st["last_day"] == "unknown" or day > st["last_day"]:
                    st["last_day"] = day

        for tq in f_techniques:
            t = techniques.setdefault(tq, {
                "technique": tq, "count": 0, "confirmed": 0,
                "hosts": set(), "first_day": day, "last_day": day,
            })
            t["count"] += 1
            t["confirmed"] += 1 if confirmed_one else 0
            t["hosts"].add(host.hostname)
            if day != "unknown":
                if t["first_day"] == "unknown" or day < t["first_day"]:
                    t["first_day"] = day
                if t["last_day"] == "unknown" or day > t["last_day"]:
                    t["last_day"] = day
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
        # One row per technique, biggest first — the bars the kill-chain panel renders. "unmapped" is a
        # real row: findings carrying no ATT&CK mapping are a fact about the evidence, and the findings
        # table accepts technique=unmapped to show them.
        "host_tactics": sorted(
            [{**v,
              "pct_of_host": round(100.0 * v["count"] / max(hosts[v["host_id"]]["findings"], 1), 1)}
             for v in pairs.values()],
            key=lambda v: (-v["count"], v["host"], v["tactic"])),
        # The kill chain as a PROGRESSION: every canonical stage in order, evidenced or not.
        # A stage with no findings is rendered as a gap rather than omitted — which stages
        # carry no evidence is the question this answers, and dropping them hides it.
        "killchain_stages": [
            {**stages.get(key, {"tactic": key, "name": name, "count": 0, "confirmed": 0,
                                "hosts": set(), "techniques": set(),
                                "first_day": "", "last_day": ""}),
             "hosts": len(stages.get(key, {}).get("hosts", ())),
             "techniques": sorted(stages.get(key, {}).get("techniques", ()))}
            for key, name in TACTIC_ORDER
        ] + ([{**stages["unmapped"],
               "hosts": len(stages["unmapped"]["hosts"]),
               "techniques": sorted(stages["unmapped"]["techniques"]),
               "name": "No ATT&CK mapping"}] if "unmapped" in stages else []),
        "techniques": sorted(
            [{**t, "hosts": len(t["hosts"])} for t in techniques.values()],
            key=lambda t: -t["count"]),
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


QUEUE_SAMPLE_KEEP_DAYS = 7


def record_queue_sample():
    """One backlog reading, on the backend's health-report beat; prunes as it writes.

    The same derivations QueueDepthView serves live, so the line and the instant figures can
    never disagree about what "queued" means.
    """
    from .models import QueueSample
    by_state = dict(MemoryAnalysisRun.objects.values_list("status")
                    .annotate(n=Count("id")).values_list("status", "n"))
    oldest = (MemoryAnalysisRun.objects.filter(status__in=("queued", "running"))
              .aggregate(oldest=Min("created_at")).get("oldest"))
    QueueSample.objects.create(
        queued=by_state.get("queued", 0),
        running=by_state.get("running", 0),
        awaiting=MemoryCapture.objects.filter(analyses__isnull=True).count(),
        oldest_waiting_seconds=(
            int((timezone.now() - oldest).total_seconds()) if oldest else 0),
    )
    QueueSample.objects.filter(
        sampled_at__lt=timezone.now() - timedelta(days=QUEUE_SAMPLE_KEEP_DAYS)).delete()


class QueueDepthView(APIView):
    """V7 — the analysis backlog, as depth by state plus the oldest waiting item.

    Depth alone hides a stuck queue: ten queued items that arrived a minute ago and ten that
    have waited six hours are the same number and not the same situation. The `samples`
    series — written on the health-report beat, not on page views, so it keeps recording
    while nobody watches — is what says whether the backlog is being worked down or growing.
    """

    permission_classes = [IsAnalystOrAdmin]

    def get(self, request):
        from .models import QueueSample
        by_state = dict(MemoryAnalysisRun.objects.values_list("status")
                        .annotate(n=Count("id")).values_list("status", "n"))
        waiting = (MemoryAnalysisRun.objects.filter(status__in=("queued", "running"))
                   .aggregate(oldest=Min("created_at")))
        oldest = waiting.get("oldest")
        samples = list(
            QueueSample.objects.order_by("sampled_at")
            .values("sampled_at", "queued", "running", "awaiting",
                    "oldest_waiting_seconds"))
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
            "samples": samples,
            "sample_interval_seconds": int(
                os.environ.get("IR_HEALTH_REPORT_INTERVAL", "900")),
            "computed_over": len(samples),
        })


class StorageAllocationView(APIView):
    """V7 — what the object store holds, per bucket, with the retention state visible.

    Sizes come from the platform's own records (every capture and carved region stores its
    size at write time), not from listing MinIO: the panel answers "what does the platform
    account for", and a listing would silently blend in anything else living in the bucket.
    The two answers differing is a finding, not a display choice.
    """

    permission_classes = [IsAdmin]

    def get(self, request):
        from django.db.models import Sum
        from .models import CarvedRegion

        evidence = [
            {"retention_status": row["retention_status"] or "pending",
             "count": row["n"], "bytes": row["b"] or 0}
            for row in (MemoryCapture.objects.values("retention_status")
                        .annotate(n=Count("id"), b=Sum("size_bytes"))
                        .order_by("retention_status"))
        ]
        carved = [
            {"bucket": row["bucket"], "count": row["n"], "bytes": row["b"] or 0}
            for row in (CarvedRegion.objects.values("bucket")
                        .annotate(n=Count("id"), b=Sum("size_bytes"))
                        .order_by("-b"))
        ]
        return Response({
            "evidence_bucket": {
                "states": evidence,
                "bytes": sum(s["bytes"] for s in evidence),
                "count": sum(s["count"] for s in evidence),
            },
            "carved_buckets": carved,
            "computed_over": (sum(s["count"] for s in evidence)
                              + sum(c["count"] for c in carved)),
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


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def investigations_activity(request):
    """V1 — findings per day per open investigation, with the confirmed subset.

    The heat strip reads the rows; the fleet trend reads the totals. Both series are served
    so neither chart sums the other's data client-side. Days derive from the same source the
    findings table's `day` filter matches, so a cell's drill returns exactly its rows.
    """
    try:
        window = min(int(request.query_params.get("days", 30)), 120)
    except ValueError:
        window = 30
    since = (timezone.now() - timedelta(days=window)).date().isoformat()

    rows = {}
    fleet = {}
    qs = (Finding.objects.filter(run__investigation__status__in=["open", "contained"])
          .select_related("run__investigation")
          .only("verdict", "raw", "created_at", "run__investigation__id",
                "run__investigation__name"))
    for f in qs:
        raw = f.raw or {}
        when = raw.get("Timestamp") or (f.created_at.isoformat() if f.created_at else "")
        day = str(when)[:10] or "unknown"
        if day == "unknown" or day < since:
            continue
        confirmed_one = (_verdict_of(f) or "") in CONFIRMING
        inv = f.run.investigation
        r = rows.setdefault(inv.id, {"investigation_id": inv.id, "name": inv.name,
                                     "days": {}})
        d = r["days"].setdefault(day, {"count": 0, "confirmed": 0})
        d["count"] += 1
        d["confirmed"] += 1 if confirmed_one else 0
        fd = fleet.setdefault(day, {"count": 0, "confirmed": 0})
        fd["count"] += 1
        fd["confirmed"] += 1 if confirmed_one else 0

    return Response({
        "window_days": window,
        "investigations": sorted(rows.values(), key=lambda r: r["name"]),
        "fleet": [{"day": d, **v} for d, v in sorted(fleet.items())],
        "computed_over": sum(v["count"] for v in fleet.values()),
    })


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def findings_backlog(request):
    """Is the queue being worked down or falling behind — open backlog over time.

    Findings per day answers "how much arrived", which is a property of the intrusion rather
    than of the response: a quiet week reads as progress and a fresh collection reads as
    regress. What moves with the team's work is the BACKLOG — arrived and not yet decided.

    Both series are on the WALL CLOCK (when the finding landed, when a decision was recorded),
    never the evidence timestamp the activity strip uses. An arrival dated to the intrusion
    and a decision dated to today cannot be differenced, and a cumulative series built across
    the two clocks would drift without ever reading as wrong.

    A finding the engine settled on arrival is decided the day it arrived, so what this
    reports is the queue waiting on a PERSON.
    """
    try:
        window = min(int(request.query_params.get("days", 30)), 120)
    except ValueError:
        window = 30
    start = (timezone.now() - timedelta(days=window)).date()

    qs = Finding.objects.all()
    inv = request.query_params.get("investigation")
    if inv:
        qs = qs.filter(run__investigation_id=inv)

    # When a person recorded a decision. Ordered so the LAST one wins: a finding reclassified
    # twice left the queue once, on the day it was first taken out of the entry state.
    decided_on = dict(FindingReclassification.objects.filter(finding__in=qs)
                      .order_by("finding_id", "-created_at")
                      .values_list("finding_id", "created_at"))

    arrived, decided, opening = {}, {}, 0
    for fid, created, adj_by, verdict in qs.values_list(
            "id", "created_at", "adjudicated_by", "verdict").iterator():
        if not created:
            continue
        a_day = created.date()
        still_open = not adj_by and verdict in ("", "Indeterminate")
        when = decided_on.get(fid)
        d_day = when.date() if when else (None if still_open else a_day)
        if a_day < start:
            # Already in the queue when the window opened, unless it was settled by then.
            # Without this the running total goes negative the first time an older finding
            # is decided inside the window.
            if d_day is None or d_day >= start:
                opening += 1
        else:
            arrived[a_day.isoformat()] = arrived.get(a_day.isoformat(), 0) + 1
        if d_day is not None and d_day >= start:
            decided[d_day.isoformat()] = decided.get(d_day.isoformat(), 0) + 1

    # EVERY day in the window, not only the days something happened. A backlog has a value on
    # a quiet day — the same value as the day before — and emitting only event days draws the
    # gaps as slopes, so a queue that sat untouched for a week reads as steady progress.
    today = timezone.now().date()
    series, running = [], opening
    for i in range((today - start).days + 1):
        day = (start + timedelta(days=i)).isoformat()
        running += arrived.get(day, 0) - decided.get(day, 0)
        series.append({"day": day, "arrived": arrived.get(day, 0),
                       "decided": decided.get(day, 0), "open": max(0, running)})

    entry_state = Q(adjudicated_by="") & Q(verdict__in=["", "Indeterminate"])
    return Response({
        "window_days": window,
        "days": series,
        "opening_backlog": opening,
        "open_now": qs.filter(entry_state).count(),
        "decided_total": qs.exclude(entry_state).count(),
        "total": qs.count(),
        # Days on which anything actually moved. The series is filled to every day in the
        # window, so its length says nothing about whether there is a shape to read — this
        # does, and the client refuses to draw a direction below two.
        "activity_days": len(set(arrived) | set(decided)),
        "decision_days": len([d for d in series if d["decided"]]),
        "computed_over": qs.count(),
    })


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def findings_funnel(request):
    """V1 — where the backlog actually is: collected → promoted → adjudicated → confirmed.

    Each stage is a COUNT OVER THE SAME ROWS narrowed further, with the filter the findings
    table uses to reproduce it — a stage nobody can open is a number taken on trust.
    """
    qs = Finding.objects.all()
    inv = request.query_params.get("investigation")
    if inv:
        qs = qs.filter(run__investigation_id=inv)
    collected = qs.count()
    # Past the entry state — the same composite the findings table's `adjudicated` filter applies,
    # so the stage stays reproducible. An engine marker OR a verdict beyond the Indeterminate every
    # lead enters at; either one is a decision having been made.
    entry_state = Q(adjudicated_by="") & Q(verdict__in=["", "Indeterminate"])
    adjudicated = qs.exclude(entry_state).count()
    confirmed = qs.filter(verdict__in=CONFIRMING).count()
    return Response({
        # Three NARROWING stages. Promotion from memory is a source split rather than a
        # stage: a case with no memory findings would otherwise render as a collapse.
        "stages": [
            {"stage": "collected", "count": collected, "params": {}},
            {"stage": "adjudicated", "count": adjudicated, "params": {"adjudicated": "yes"}},
            {"stage": "confirmed", "count": confirmed,
             "params": {"verdict": ",".join(CONFIRMING)}},
        ],
        "memory_share": {"count": qs.filter(source="memory").count(),
                         "params": {"source": "memory"}},
        "computed_over": collected,
    })


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def findings_matrix(request):
    """V4 — finding type x verdict counts, and per-type triage standing.

    `types` is what the progress rings read: how much of each type a person has decided. It
    replaced a per-type source-agreement rollup that could never report anything — the
    collector and the memory analyzer emit disjoint type vocabularies and memory findings are
    identified only by byte offsets, so no (host, type) pair can ever carry both sources and
    the chart was a permanent 0/N. Each entry drills with the table's own filters.
    """
    qs = Finding.objects.all()
    inv = request.query_params.get("investigation")
    if inv:
        qs = qs.filter(run__investigation_id=inv)

    cells = Counter()
    types = {}
    for ftype, verdict, adj_by in qs.values_list("finding_type", "verdict", "adjudicated_by"):
        ftype = ftype or "unknown"
        cells[(ftype, verdict or "unset")] += 1
        t = types.setdefault(ftype, {"finding_type": ftype, "total": 0, "open": 0})
        t["total"] += 1
        # The same entry-state composite the funnel and the table's `adjudicated` filter use.
        if not adj_by and verdict in ("", "Indeterminate"):
            t["open"] += 1

    for t in types.values():
        t["params"] = {"finding_type": t["finding_type"], "adjudicated": "no"}

    return Response({
        "cells": [{"finding_type": t, "verdict": v, "count": n}
                  for (t, v), n in sorted(cells.items())],
        "types": sorted(types.values(), key=lambda t: -t["open"]),
        "computed_over": sum(cells.values()),
    })
