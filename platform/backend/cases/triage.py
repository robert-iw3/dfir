"""
Analyst throughput: re-analysis diffing, bulk adjudication, and export.

Adjudication is a recorded act. Bulk verdict changes go through the same hash-chained
audit ledger as single ones, with the prior verdict captured per finding — a bulk action
must be as reconstructable afterwards as an individual one, not a single opaque entry.
"""
import csv
import io
import json

from django.db import transaction
from django.db.models import F
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .audit import audit
from .models import (Finding, FindingReclassification, IOC, MemoryAnalysisRun,
                     MemoryCapture)
from .rbac import IsAnalystOrAdmin, role_of

VALID_VERDICTS = {
    "True Positive", "Likely True Positive", "Indeterminate",
    "Likely False Positive", "False Positive",
}


def _fingerprint(f):
    """Identity of a memory finding across analysis runs.

    Offset is deliberately excluded: the same artifact lands at a different address in a
    later capture, and including it would report every finding as both removed and added.
    """
    return (f.finding_type, f.detail)


class AnalysisDiffView(APIView):
    """Compare two analyses of one capture — what a newer ruleset catches that an older
    one did not.

    This is the payoff for retaining captures and versioning rulesets: without it, a
    re-analysis produces a second opaque result list and the gain is invisible.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request, capture_id):
        capture = MemoryCapture.objects.filter(id=capture_id).first()
        if not capture:
            return Response({"detail": "no such capture"}, status=404)

        # Ordered by when the analysis ran, not when its row was written: re-analysis of
        # an old capture can be recorded after a newer pass, and insertion order would
        # then present the comparison backwards.
        runs = list(
            MemoryAnalysisRun.objects.filter(capture=capture)
            .order_by(F("started_at").asc(nulls_last=True), "created_at")
        )
        if len(runs) < 2:
            return Response({
                "capture_id": capture.id, "comparable": False,
                "reason": "one analysis run — nothing to compare against",
                "runs": [{"id": r.id, "ruleset_version": r.ruleset_version,
                          "status": r.status} for r in runs],
            })

        def pick(param, default):
            raw = request.query_params.get(param)
            if raw:
                match = next((r for r in runs if str(r.id) == str(raw)), None)
                if match:
                    return match
            return default

        # Default to the oldest and newest: the comparison an analyst actually wants.
        base = pick("a", runs[0])
        head = pick("b", runs[-1])

        base_map = {_fingerprint(f): f for f in base.findings.all()}
        head_map = {_fingerprint(f): f for f in head.findings.all()}

        def payload(f):
            return {"finding_type": f.finding_type, "severity": f.severity,
                    "detail": f.detail, "offset": f.offset}

        added = [payload(f) for k, f in head_map.items() if k not in base_map]
        removed = [payload(f) for k, f in base_map.items() if k not in head_map]
        changed = [
            {"finding_type": k[0], "detail": k[1],
             "from_severity": base_map[k].severity, "to_severity": head_map[k].severity}
            for k in head_map.keys() & base_map.keys()
            if base_map[k].severity != head_map[k].severity
        ]

        return Response({
            "capture_id": capture.id,
            "comparable": True,
            "object_key": capture.object_key,
            "base": {"id": base.id, "ruleset_version": base.ruleset_version,
                     "engine": base.engine, "finished_at": base.finished_at,
                     "finding_count": len(base_map)},
            "head": {"id": head.id, "ruleset_version": head.ruleset_version,
                     "engine": head.engine, "finished_at": head.finished_at,
                     "finding_count": len(head_map)},
            "runs": [{"id": r.id, "ruleset_version": r.ruleset_version,
                      "finished_at": r.finished_at} for r in runs],
            "added": added, "removed": removed, "changed": changed,
            "unchanged": len(head_map.keys() & base_map.keys()) - len(changed),
        })


class BulkVerdictView(APIView):
    """Apply one verdict to many findings.

    Each finding's prior verdict is recorded individually, so a bulk action can be undone
    or explained finding-by-finding rather than only in aggregate.
    """

    permission_classes = [IsAnalystOrAdmin]

    def post(self, request):
        ids = request.data.get("ids") or []
        verdict = request.data.get("verdict") or ""
        reason = (request.data.get("reason") or "").strip()

        if not isinstance(ids, list) or not ids:
            return Response({"detail": "ids must be a non-empty list"}, status=400)
        if verdict not in VALID_VERDICTS:
            return Response({"detail": f"verdict must be one of {sorted(VALID_VERDICTS)}"},
                            status=400)

        findings = list(Finding.objects.filter(id__in=ids).select_related("run__host"))
        if not findings:
            return Response({"detail": "no matching findings"}, status=404)

        changes = [{"id": f.id, "host": f.run.host.hostname, "type": f.finding_type,
                    "from": f.verdict, "to": verdict}
                   for f in findings if f.verdict != verdict]

        changed_ids = [c["id"] for c in changes]
        with transaction.atomic():
            # A bulk action is still an analyst determination per finding, so it leaves the
            # same history a single reclassification does. The audit entry alone was not
            # enough: it truncates its `changes` list, so past 200 findings the per-finding
            # record this class promises did not exist.
            FindingReclassification.objects.bulk_create([
                FindingReclassification(
                    finding_id=f.id, investigation_id=f.run.investigation_id,
                    actor=getattr(request.user, "username", "?"),
                    role=role_of(request.user) or "",
                    from_verdict=f.verdict, to_verdict=verdict,
                    from_confidence=f.confidence, to_confidence=f.confidence,
                    note=reason or f"bulk verdict applied to {len(changes)} findings",
                )
                for f in findings if f.id in set(changed_ids)
            ], batch_size=500)
            # Marked as the analyst's, so a later engine pass records disagreement rather
            # than overwriting it — the same protection the single-finding path gives.
            Finding.objects.filter(id__in=changed_ids).update(
                verdict=verdict, adjudicated_by="analyst", adjudication_conflict={})
            # Compromise state is derived from verdicts, so runs whose findings changed
            # are re-evaluated rather than left stale.
            for run in {f.run for f in findings}:
                run.tp_count = run.findings.filter(verdict="True Positive").count()
                run.evaluate_compromise()
                run.save(update_fields=["tp_count", "compromised"])

            audit(getattr(request.user, "username", "?"), "finding.bulk_verdict",
                  role=role_of(request.user), method="POST", path=request.path,
                  object_type="Finding", object_id=",".join(str(c["id"]) for c in changes[:50]),
                  detail={"verdict": verdict, "reason": reason,
                          "changed": len(changes), "requested": len(ids),
                          "changes": changes[:200]})

        return Response({"requested": len(ids), "changed": len(changes),
                         "verdict": verdict, "changes": changes})


class ReclassifyView(APIView):
    """Change one finding's verdict, with a required note.

    Downgrading a noisy automated hit is routine analytic work, and so is promoting one
    that was underrated. Either way it changes what the incident asserts, so the reason is
    mandatory and the previous verdict is preserved — a verdict that moved for no stated
    reason cannot be evaluated by whoever reads the case next.
    """

    permission_classes = [IsAnalystOrAdmin]

    def post(self, request, finding_id):
        finding = Finding.objects.filter(id=finding_id).select_related("run").first()
        if not finding:
            return Response({"detail": "no such finding"}, status=404)

        data = request.data or {}
        verdict = data.get("verdict", "")
        note = str(data.get("note", "")).strip()
        confidence = str(data.get("confidence", "") or finding.confidence)

        if verdict not in VALID_VERDICTS:
            return Response({"detail": f"verdict must be one of {sorted(VALID_VERDICTS)}"},
                            status=400)
        if len(note) < 10:
            return Response({
                "detail": "a note explaining the reclassification is required",
                "hint": "state what the evidence actually shows — a rule name alone is not a finding",
            }, status=400)

        actor = getattr(request.user, "username", "?")
        previous, prev_conf = finding.verdict, finding.confidence

        with transaction.atomic():
            record = FindingReclassification.objects.create(
                finding=finding, actor=actor, role=role_of(request.user) or "",
                from_verdict=previous, to_verdict=verdict,
                from_confidence=prev_conf, to_confidence=confidence, note=note,
            )
            finding.verdict = verdict
            finding.confidence = confidence
            # The verdict is now the analyst's, and a later engine pass may not replace it.
            # Any standing engine disagreement is cleared: the analyst has seen the finding
            # and ruled, so leaving the flag up would send them back to a question they
            # just answered.
            finding.adjudicated_by = "analyst"
            finding.adjudication_conflict = {}
            finding.save(update_fields=["verdict", "confidence",
                                        "adjudicated_by", "adjudication_conflict"])

            run = finding.run
            run.tp_count = run.findings.filter(verdict="True Positive").count()
            run.evaluate_compromise()
            run.save(update_fields=["tp_count", "compromised"])

            audit(actor, "finding.reclassify", role=role_of(request.user),
                  method="POST", path=request.path, object_type="Finding",
                  object_id=finding.id,
                  detail={"from": previous, "to": verdict,
                          "from_confidence": prev_conf, "to_confidence": confidence,
                          "note": note, "source": finding.source})

        return Response({
            "finding": finding.id,
            "from": previous, "to": verdict,
            "confidence": confidence,
            "note": note,
            "reclassification_id": record.id,
            "run_compromised": run.compromised,
        })


class FindingExportView(APIView):
    """Export findings as CSV or JSON, or the IOC set as a shareable bundle.

    Export is a handoff, so it records who took what: the export itself is audited.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Not "format": DRF reserves that query parameter for content negotiation and
        # answers 404 for a renderer it does not have.
        fmt = request.query_params.get("fmt", "csv")
        qs = Finding.objects.select_related("run__host", "run__investigation")

        investigation = request.query_params.get("investigation")
        verdict = request.query_params.get("verdict")
        run = request.query_params.get("run")
        if investigation:
            qs = qs.filter(run__investigation_id=investigation)
        if verdict:
            qs = qs.filter(verdict__in=verdict.split(","))
        if run:
            qs = qs.filter(run_id=run)
        qs = qs.order_by("run__host__hostname", "finding_type")[:10000]

        rows = [{
            "host": f.run.host.hostname,
            "investigation": f.run.investigation.name,
            "finding_type": f.finding_type,
            "target": f.target,
            "verdict": f.verdict,
            "confidence": f.confidence,
            "mitre": ";".join(f.mitre or []),
            "source": f.source,
        } for f in qs]

        audit(getattr(request.user, "username", "?"), "finding.export",
              role=role_of(request.user), method="GET", path=request.path,
              object_type="Finding",
              detail={"fmt": fmt, "rows": len(rows),
                      "filters": {"investigation": investigation, "verdict": verdict,
                                  "run": run}})

        if fmt == "ioc":
            iocs = IOC.objects.select_related("run__host")
            if investigation:
                iocs = iocs.filter(run__investigation_id=investigation)
            bundle = {}
            for i in iocs:
                key = f"{i.ioc_type}:{i.value}"
                entry = bundle.setdefault(
                    key, {"type": i.ioc_type, "value": i.value, "hosts": set()})
                entry["hosts"].add(i.run.host.hostname)
            payload = {
                "generated_by": getattr(request.user, "username", "?"),
                "indicators": [{"type": v["type"], "value": v["value"],
                                "hosts": sorted(v["hosts"])}
                               for v in bundle.values()],
            }
            return _attachment(json.dumps(payload, indent=2), "application/json",
                               "ioc-bundle.json")

        if fmt == "json":
            return _attachment(json.dumps(rows, indent=2), "application/json",
                               "findings.json")

        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()) if rows else
                                ["host", "investigation", "finding_type", "target",
                                 "verdict", "confidence", "mitre", "source"])
        writer.writeheader()
        writer.writerows(rows)
        return _attachment(buf.getvalue(), "text/csv", "findings.csv")


def _attachment(body, content_type, filename):
    from django.http import HttpResponse

    response = HttpResponse(body, content_type=content_type)
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response
