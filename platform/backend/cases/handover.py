"""Shift handover — what the next analyst on needs to know.

Answers one question: since the last handover, what changed and what is still open? It
reads existing rows and stores nothing of its own, so it can never disagree with the pages
it summarizes.

The `since` window is explicit rather than "your last login". An analyst coming back from
leave wants the shift boundary, not their own absence, and a window derived from the
viewer would give two people looking at the same screen two different answers.
"""
from datetime import timedelta

from django.db.models import Q
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import (CaseTask, Finding, MemoryAnalysisRun, MemoryFinding, Notification,
                     Note)
from .rbac import IsAnalystOrAdmin, scope_by_investigation

DEFAULT_WINDOW = timedelta(hours=12)
# What counts as "wake someone up". Severity is carried on the memory finding, not on the
# collector finding, which records a verdict instead.
CRITICAL_SEVERITIES = ("Critical", "High")
UNADJUDICATED = Q(adjudicated_by="") & Q(verdict__in=["", "Indeterminate"])


class HandoverView(APIView):
    """Open work, what landed during the window, and what is still running."""

    permission_classes = [IsAnalystOrAdmin]

    def get(self, request):
        raw = request.query_params.get("since")
        since = parse_datetime(raw) if raw else None
        if since and timezone.is_naive(since):
            since = timezone.make_aware(since)
        if not since:
            since = timezone.now() - DEFAULT_WINDOW

        # Every open case plus the restricted ones this identity belongs to — not the
        # restricted set alone, which would leave an analyst a handover of nothing.
        def within(qs, path="investigation_id"):
            return scope_by_investigation(qs, request.user, path)

        open_tasks = within(CaseTask.objects.select_related("investigation")).exclude(
            state=CaseTask.PRESENTATION)
        blocked = [t for t in open_tasks if t.blocked]
        overdue = [t for t in open_tasks
                   if t.due_at and t.due_at < timezone.now() and not t.blocked]

        # An analysis reaches its case through the capture it ran on. MemoryAnalysisRun
        # also has an `investigation` field, but it holds the engine's narrative output —
        # same name, unrelated thing.
        new_criticals = within(
            MemoryFinding.objects.select_related(
                "analysis__capture__run__host", "analysis__capture__run__investigation"),
            "analysis__capture__run__investigation_id").filter(
            created_at__gte=since, severity__in=CRITICAL_SEVERITIES)

        # The queue the next shift actually inherits: evidence that arrived and has not been
        # ruled on. A finding nobody decided is the one that goes stale over a handover.
        #
        # UNADJUDICATED is the same composite the dashboard funnel and the findings table
        # use — no engine marker AND no verdict past the Indeterminate every lead enters
        # at. Written fresh here it would be a second definition of "decided", and the two
        # would drift until the handover and the dashboard disagreed about the same rows.
        undecided = within(
            Finding.objects.select_related("run__host", "run__investigation"),
            "run__investigation_id").filter(UNADJUDICATED)

        in_flight = within(
            MemoryAnalysisRun.objects.select_related("capture__run__host"),
            "capture__run__investigation_id").filter(status__in=("queued", "running"))

        entries = within(Note.objects.all()).filter(created_at__gte=since, retracted=False)

        return Response({
            "since": since.isoformat(),
            "generated_at": timezone.now().isoformat(),
            "open_tasks": {
                "total": open_tasks.count(),
                "blocked": len(blocked),
                "overdue": len(overdue),
                "by_stage": {s: open_tasks.filter(state=s).count()
                             for s, _ in CaseTask.STATES},
                "rows": [{"id": t.id, "title": t.title, "state": t.state,
                          "assignee": t.assignee, "blocked": t.blocked,
                          "blocked_reason": t.blocked_reason,
                          "due_at": t.due_at.isoformat() if t.due_at else None,
                          "investigation": t.investigation_id,
                          "case": t.investigation.name}
                         for t in open_tasks.order_by("-blocked", "due_at")[:50]],
            },
            "new_criticals": {
                "total": new_criticals.count(),
                "rows": [{"id": f.id, "finding_type": f.finding_type,
                          "severity": f.severity, "detail": (f.detail or "")[:200],
                          "host": f.analysis.capture.run.host.hostname,
                          "investigation": f.analysis.capture.run.investigation_id,
                          "case": f.analysis.capture.run.investigation.name,
                          "at": f.created_at.isoformat()}
                         for f in new_criticals.order_by("-created_at")[:50]],
            },
            "awaiting_verdict": {
                "total": undecided.count(),
                "rows": [{"id": f.id, "finding_type": f.finding_type, "target": f.target,
                          "confidence": f.confidence, "host": f.run.host.hostname,
                          "investigation": f.run.investigation_id,
                          "case": f.run.investigation.name,
                          "at": f.created_at.isoformat()}
                         for f in undecided.order_by("-created_at")[:50]],
            },
            "in_flight_analyses": {
                "total": in_flight.count(),
                "rows": [{"id": a.id, "status": a.status, "engine": a.engine,
                          "host": a.capture.run.host.hostname,
                          "investigation": a.capture.run.investigation_id,
                          "started_at": a.started_at.isoformat() if a.started_at else None}
                         for a in in_flight.order_by("-created_at")[:50]],
            },
            "record_entries": {
                "total": entries.count(),
                "rows": [{"id": n.id, "kind": n.kind, "author": n.author,
                          "summary": (n.summary or n.body)[:200],
                          "investigation": n.investigation_id,
                          "at": n.created_at.isoformat()}
                         for n in entries.order_by("-created_at")[:50]],
            },
            "unacknowledged": Notification.objects.filter(
                user=request.user, read_at__isnull=True).count(),
            "cases_touched": sorted(set(
                list(entries.values_list("investigation_id", flat=True))
                + list(new_criticals.values_list(
                    "analysis__capture__run__investigation_id", flat=True)))),
        })
