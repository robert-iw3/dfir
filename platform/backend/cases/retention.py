"""
Object-storage retention lifecycle.

Policy: once a capture's analysis is complete, a *clean* host's capture is purged from
object storage (only metadata + analysis results stay in PostgreSQL). A *compromised*
host's capture is retained as evidence and never auto-purged. Purge is itself a custody
event that records the pre-purge sha256, so lawful deletion stays provable.
"""
from django.utils import timezone

from . import audit, storage
from .models import MemoryCapture


def apply_retention_after_analysis(capture, actor="system"):
    """Called after a capture's analysis completes. Returns the new retention_status."""
    run = capture.run
    run.evaluate_compromise()
    run.save(update_fields=["compromised"])

    if capture.retention_status == "legal_hold":
        return "legal_hold"  # admin hold overrides automatic purge

    if run.compromised:
        capture.retention_status = "retained"
        capture.retention_reason = "host assessed compromised — retained as evidence"
        capture.save(update_fields=["retention_status", "retention_reason"])
        audit.custody(run, "retain", actor,
                      {"capture_id": capture.id, "reason": capture.retention_reason,
                       "sha256": capture.sha256})
        return "retained"

    return purge_capture(capture, actor=actor,
                         reason="host assessed clean — capture purged post-analysis")


def purge_capture(capture, actor="system", reason=""):
    """Delete the object from storage; keep the row + results. Records custody."""
    if capture.retention_status == "purged":
        return "purged"
    pre_purge_sha = capture.sha256
    try:
        storage.client().delete_object(Bucket=capture.bucket, Key=capture.object_key)
    except Exception as exc:  # noqa: BLE001 — record the failure, don't crash the pipeline
        audit.custody(capture.run, "purge_failed", actor,
                      {"capture_id": capture.id, "error": str(exc)})
        raise
    capture.retention_status = "purged"
    capture.retention_reason = reason or capture.retention_reason
    capture.purged_at = timezone.now()
    capture.save(update_fields=["retention_status", "retention_reason", "purged_at"])
    audit.custody(capture.run, "purge", actor,
                  {"capture_id": capture.id, "object_key": capture.object_key,
                   "pre_purge_sha256": pre_purge_sha, "reason": capture.retention_reason})
    audit.audit(actor, "capture.purge", object_type="MemoryCapture",
                object_id=capture.id,
                detail={"pre_purge_sha256": pre_purge_sha, "reason": capture.retention_reason})
    return "purged"


def sweep_purgeable(max_age_days=0, actor="maintenance"):
    """Maintenance sweep: purge captures on clean hosts whose analysis is complete.
    max_age_days>0 restricts to captures older than that. Returns count purged."""
    from datetime import timedelta

    qs = MemoryCapture.objects.filter(retention_status="retained", run__compromised=False)
    if max_age_days > 0:
        cutoff = timezone.now() - timedelta(days=max_age_days)
        qs = qs.filter(created_at__lt=cutoff)
    count = 0
    for cap in qs.iterator():
        purge_capture(cap, actor=actor, reason="maintenance sweep (clean host)")
        count += 1
    return count
