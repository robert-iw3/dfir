"""
Case bundle archive and restore.

The unit of archival is the CASE. A bundle holds everything FK-reachable from the
investigation as gzipped newline-delimited Django-fixture rows plus a manifest, sealed with
the platform's custody HMAC and stored in a dedicated bucket — inspectable with ordinary
tools and restorable without the platform if it ever came to that.

Only the COLD set is deleted after the upload verifies: findings (their reclassifications
cascade), memory findings, process verdicts, IOCs and principals. Run, host and capture
metadata stay hot as the index of what exists; the correlation store and indicator sightings
stay hot because they are what answers "have we seen this before?"; the audit ledger is
never touched here.

A restore replays rows with their ORIGINAL ids — the uniqueness constraints make a second
restore a no-op rather than a duplicate — marks the archive `restored` with an expiry, and a
sweep re-cools it. The seal is verified before a single row is inserted: a tampered archive
must not enter the evidence store.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import os
import shutil
import tarfile
import tempfile
from datetime import timedelta

from django.core import serializers as dj_serializers
from django.db import transaction
from django.utils import timezone

import custody as custody_seal

from . import audit, storage
from .models import (IOC, CollectionRun, CustodyEvent, Finding,
                     FindingReclassification, Host, Investigation,
                     InvestigationArchive, MemoryAnalysisRun, MemoryCapture,
                     MemoryFinding, Note, Principal, ProcessVerdict,
                     RestoreRequest)

ARCHIVE_BUCKET = os.environ.get("IR_ARCHIVE_BUCKET", "ir-archive")
GRACE_DAYS = int(os.environ.get("IR_ARCHIVE_GRACE_DAYS", "120"))
CEILING_DAYS = int(os.environ.get("IR_ARCHIVE_CEILING_DAYS", "180"))
WARNING_DAYS = int(os.environ.get("IR_ARCHIVE_WARNING_DAYS", "14"))
RESTORE_TTL_DAYS = int(os.environ.get("IR_RESTORE_TTL_DAYS", "14"))


def _correlation_models():
    from correlation.models import (BehaviorEvent, BehaviorNode, CorrelationRun,
                                    HostLink)
    return CorrelationRun, HostLink, BehaviorNode, BehaviorEvent


def _tables(inv):
    """(name, queryset) in dependency order, parents first, so a restore can replay it."""
    CorrelationRun, HostLink, BehaviorNode, BehaviorEvent = _correlation_models()
    crun_ids = list(CorrelationRun.objects.filter(
        investigation_id=inv.id).values_list("id", flat=True))
    return [
        ("investigation", Investigation.objects.filter(id=inv.id)),
        # Hosts are SHARED across investigations: bundled for reference, never deleted.
        ("hosts", Host.objects.filter(runs__investigation=inv).distinct()),
        ("runs", CollectionRun.objects.filter(investigation=inv)),
        ("captures", MemoryCapture.objects.filter(run__investigation=inv)),
        ("analyses", MemoryAnalysisRun.objects.filter(capture__run__investigation=inv)),
        ("findings", Finding.objects.filter(run__investigation=inv)),
        ("reclassifications",
         FindingReclassification.objects.filter(finding__run__investigation=inv)),
        ("memory_findings",
         MemoryFinding.objects.filter(analysis__capture__run__investigation=inv)),
        ("process_verdicts", ProcessVerdict.objects.filter(run__investigation=inv)),
        ("iocs", IOC.objects.filter(run__investigation=inv)),
        ("principals", Principal.objects.filter(run__investigation=inv)),
        ("custody_events", CustodyEvent.objects.filter(run__investigation=inv)),
        ("notes", Note.objects.filter(investigation=inv)),
        ("correlation_runs", CorrelationRun.objects.filter(investigation_id=inv.id)),
        ("correlation_links", HostLink.objects.filter(run_id__in=crun_ids)),
        ("correlation_nodes", BehaviorNode.objects.filter(run_id__in=crun_ids)),
        ("correlation_events", BehaviorEvent.objects.filter(run_id__in=crun_ids)),
    ]


# Deleted only after the upload has been read back and verified. Findings cascade their
# reclassifications; everything else here is the bulk the hot tier exists to shed.
COLD_DELETE = ("memory_findings", "process_verdicts", "reclassifications",
               "findings", "iocs", "principals")


def _schema_version():
    from django.db.migrations.recorder import MigrationRecorder
    row = (MigrationRecorder.Migration.objects.filter(app="cases")
           .order_by("-id").first())
    return f"cases.{row.name}" if row else ""


def legal_hold(inv):
    return MemoryCapture.objects.filter(
        run__investigation=inv, retention_status="legal_hold").exists()


def stage_bundle(inv, stagedir):
    """Write the NDJSON tables and the manifest into `stagedir`; returns the manifest."""
    counts, object_keys = {}, []
    for name, qs in _tables(inv):
        rows = 0
        with gzip.open(os.path.join(stagedir, f"{name}.ndjson.gz"), "wt") as fh:
            for obj in qs.iterator():
                for item in dj_serializers.serialize("python", [obj]):
                    fh.write(json.dumps(item, default=str) + "\n")
                rows += 1
        counts[name] = rows
    for cap in MemoryCapture.objects.filter(run__investigation=inv):
        if cap.object_key:
            object_keys.append(cap.object_key)
    manifest = {
        "investigation": {"id": inv.id, "incident_id": inv.incident_id,
                          "name": inv.name, "status_before": inv.status},
        "schema_version": _schema_version(),
        "row_counts": counts,
        # Recorded, not duplicated: the images already live in object storage under
        # their own retention.
        "object_keys": object_keys,
        "created_at": timezone.now().isoformat(),
    }
    with open(os.path.join(stagedir, "manifest.json"), "w") as fh:
        json.dump(manifest, fh, indent=1, sort_keys=True)
    return manifest


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def archive_case(inv, actor="system", force_open=False):
    """The full archival flow: stage -> seal -> upload -> verify -> scoped delete -> record.

    Refuses a legal hold absolutely. `force_open` is the hard-ceiling path only — it
    archives an OPEN case and flags the anomaly rather than negotiating with case state.
    """
    if legal_hold(inv):
        raise ValueError("legal hold: archival refused")
    if inv.status == Investigation.ARCHIVED:
        raise ValueError("already archived")
    if inv.status != Investigation.CONCLUDED and not force_open:
        raise ValueError(f"case is {inv.status}; only concluded cases archive on the "
                         "grace path")

    workdir = tempfile.mkdtemp(prefix="ir-archive-")
    try:
        stage = os.path.join(workdir, f"case-{inv.id}")
        os.makedirs(stage)
        manifest = stage_bundle(inv, stage)
        custody_seal.seal(stage, incident_id=inv.incident_id, operator=actor)

        bundle = os.path.join(workdir, f"case-{inv.id}.tar.gz")
        with tarfile.open(bundle, "w:gz") as tar:
            tar.add(stage, arcname=os.path.basename(stage))
        sha = _sha256(bundle)
        key = f"cases/{inv.id}/{sha[:16]}.tar.gz"

        storage.ensure_bucket_named(ARCHIVE_BUCKET)
        storage.put_file_to(ARCHIVE_BUCKET, bundle, key)

        # Read back and verify BEFORE anything is deleted: the copy in cold storage is
        # the one that must be good, not the one still on local disk.
        check = os.path.join(workdir, "readback.tar.gz")
        storage.download_from(ARCHIVE_BUCKET, key, check)
        if _sha256(check) != sha:
            raise RuntimeError("readback hash mismatch — nothing was deleted")
        with tarfile.open(check) as tar:
            tar.extractall(os.path.join(workdir, "rb"), filter="data")
        ok, why, _ = custody_seal.verify(os.path.join(workdir, "rb", f"case-{inv.id}"))
        if not ok:
            raise RuntimeError(f"readback seal failed ({why}) — nothing was deleted")

        archived_open = inv.status != Investigation.CONCLUDED
        with transaction.atomic():
            for name, qs in reversed(_tables(inv)):
                if name in COLD_DELETE:
                    qs.delete()
            # The ceiling path bypasses TRANSITIONS deliberately: the state machine
            # refuses OPEN->ARCHIVED for people, and the sweep flags it instead.
            inv.status = Investigation.ARCHIVED
            inv.save(update_fields=["status", "updated_at"])
            rec = InvestigationArchive.objects.create(
                investigation=inv, object_key=key, bundle_sha256=sha,
                schema_version=manifest["schema_version"],
                row_counts=manifest["row_counts"],
                size_bytes=os.path.getsize(bundle),
                archived_while_open=archived_open, created_by=actor)
        audit.audit(actor, "investigation.archive", object_type="investigation",
                    object_id=str(inv.id),
                    detail={"object_key": key, "sha256": sha,
                            "archived_while_open": archived_open,
                            "rows": manifest["row_counts"]})
        for run in CollectionRun.objects.filter(investigation=inv):
            audit.custody(run, "archive", actor, {"object_key": key, "sha256": sha})
        return rec
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def restore_case(archive, actor="system"):
    """Verify the seal, replay rows with their original ids, mark and audit."""
    req = RestoreRequest.objects.create(archive=archive, requested_by=actor)
    workdir = tempfile.mkdtemp(prefix="ir-restore-")
    try:
        bundle = os.path.join(workdir, "bundle.tar.gz")
        storage.download_from(ARCHIVE_BUCKET, archive.object_key, bundle)
        if _sha256(bundle) != archive.bundle_sha256:
            raise RuntimeError("bundle hash does not match the archive record")
        with tarfile.open(bundle) as tar:
            tar.extractall(workdir, filter="data")
        stage = os.path.join(workdir, f"case-{archive.investigation_id}")
        ok, why, _ = custody_seal.verify(stage)
        if not ok:
            raise RuntimeError(f"custody seal failed: {why}")

        restored = skipped = 0
        order = [n for n, _ in _tables(archive.investigation)]
        for name in order:
            path = os.path.join(stage, f"{name}.ndjson.gz")
            if not os.path.exists(path):
                continue
            with gzip.open(path, "rt") as fh:
                for line in fh:
                    item = json.loads(line)
                    for obj in dj_serializers.deserialize("python", [item]):
                        model = obj.object.__class__
                        if model.objects.filter(pk=obj.object.pk).exists():
                            skipped += 1
                        else:
                            obj.save()
                            restored += 1
        archive.state = "restored"
        archive.restored_until = timezone.now() + timedelta(days=RESTORE_TTL_DAYS)
        archive.save(update_fields=["state", "restored_until", "updated_at"])
        req.state = "completed" if restored else "noop"
        req.detail = f"restored {restored} rows, {skipped} already present"
        req.completed_at = timezone.now()
        req.expires_at = archive.restored_until
        req.save(update_fields=["state", "detail", "completed_at", "expires_at",
                                "updated_at"])
        audit.audit(actor, "investigation.restore", object_type="investigation",
                    object_id=str(archive.investigation_id),
                    detail={"object_key": archive.object_key,
                            "restored": restored, "skipped": skipped,
                            "expires_at": archive.restored_until.isoformat()})
        return req
    except Exception as exc:
        req.state = "failed"
        req.detail = str(exc)[:2000]
        req.completed_at = timezone.now()
        req.save(update_fields=["state", "detail", "completed_at", "updated_at"])
        raise
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def due_for_archival(now=None):
    """(due, warning) querysets: past the grace/ceiling, and inside the warning window."""
    now = now or timezone.now()
    grace = now - timedelta(days=GRACE_DAYS)
    ceiling = now - timedelta(days=CEILING_DAYS)
    warn_g = grace + timedelta(days=WARNING_DAYS)
    warn_c = ceiling + timedelta(days=WARNING_DAYS)
    live = Investigation.objects.exclude(status=Investigation.ARCHIVED)
    due = (live.filter(status=Investigation.CONCLUDED, concluded_at__lt=grace)
           | live.filter(created_at__lt=ceiling))
    warning = (live.filter(status=Investigation.CONCLUDED, concluded_at__lt=warn_g)
               | live.filter(created_at__lt=warn_c)).exclude(
        id__in=due.values_list("id", flat=True))
    return due.distinct(), warning.distinct()


def sweep(actor="system", dry_run=False):
    """Archive everything due; re-cool expired restores. Returns a report dict."""
    done, held, errors = [], [], []
    due, warning = due_for_archival()
    for inv in due:
        if legal_hold(inv):
            held.append(inv.id)
            continue
        if dry_run:
            done.append(inv.id)
            continue
        try:
            archive_case(inv, actor=actor, force_open=inv.status != Investigation.CONCLUDED)
            done.append(inv.id)
        except Exception as exc:            # noqa: BLE001 — one failure must not stop the sweep
            errors.append({"id": inv.id, "error": str(exc)[:500]})
    recooled = []
    for arc in InvestigationArchive.objects.filter(
            state="restored", restored_until__lt=timezone.now()):
        if dry_run:
            recooled.append(arc.investigation_id)
            continue
        with transaction.atomic():
            for name, qs in reversed(_tables(arc.investigation)):
                if name in COLD_DELETE:
                    qs.delete()
            arc.state = "archived"
            arc.restored_until = None
            arc.save(update_fields=["state", "restored_until", "updated_at"])
        audit.audit(actor, "investigation.recool", object_type="investigation",
                    object_id=str(arc.investigation_id), detail={})
        recooled.append(arc.investigation_id)
    return {"archived": done, "legal_hold": held, "errors": errors,
            "warning": [i.id for i in warning], "recooled": recooled,
            "dry_run": dry_run}


# --- API ----------------------------------------------------------------------------
from rest_framework.response import Response      # noqa: E402
from rest_framework.views import APIView          # noqa: E402

from .rbac import IsAdmin                         # noqa: E402


class ArchiveDueView(APIView):
    """Cases due for archival and those inside the warning window, for the admin page."""

    permission_classes = [IsAdmin]

    def get(self, request):
        def rows(qs):
            return [{"id": i.id, "name": i.name, "incident_id": i.incident_id,
                     "status": i.status,
                     "concluded_at": i.concluded_at.isoformat() if i.concluded_at else None,
                     "created_at": i.created_at.isoformat(),
                     "legal_hold": legal_hold(i)} for i in qs]
        due, warning = due_for_archival()
        return Response({"due": rows(due), "warning": rows(warning),
                         "grace_days": GRACE_DAYS, "ceiling_days": CEILING_DAYS,
                         "warning_days": WARNING_DAYS})


class RestoreView(APIView):
    """Bring an archived case back to the hot tier. Synchronous: a bundle is metadata
    rows, kilobytes to low megabytes, well inside the request budget."""

    permission_classes = [IsAdmin]

    def post(self, request, investigation_id):
        arc = (InvestigationArchive.objects
               .filter(investigation_id=investigation_id).order_by("-id").first())
        if not arc:
            return Response({"detail": "no archive for this case"}, status=404)
        try:
            req = restore_case(arc, actor=getattr(request.user, "username", "") or "admin")
        except Exception as exc:                  # noqa: BLE001
            return Response({"detail": str(exc)[:500]}, status=502)
        return Response({"state": req.state, "detail": req.detail,
                         "expires_at": req.expires_at.isoformat() if req.expires_at
                         else None})
