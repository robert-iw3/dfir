"""Record an acknowledged discontinuity in the audit chain.

A broken hash chain is never repaired by rewriting rows — that is the act the chain exists to
detect. It is DECLARED: this command finds unacknowledged breaks, and records each with the
hashes on both sides and a stated reason, signed under the audit key.

    manage.py audit_checkpoint --list
    manage.py audit_checkpoint --record-all --reason "..." --actor "..."
    manage.py audit_checkpoint --record 2024 --reason "..." --actor "..."

Verification afterwards reports acknowledged discontinuities separately from unexplained ones.
Only an unexplained break is evidence of tampering, and it still fails.
"""
from django.core.management.base import BaseCommand, CommandError

from cases import audit as audit_mod
from cases.models import AuditCheckpoint, AuditLog


def _walk_breaks():
    """Every break in id order, with the hashes on both sides of each gap."""
    prev_hash = ""
    breaks = []
    known = {c.at_entry_id for c in AuditCheckpoint.objects.all()}
    for row in AuditLog.objects.order_by("id").iterator():
        payload = {
            "actor": row.actor, "role": row.role, "action": row.action,
            "method": row.method, "path": row.path, "object_type": row.object_type,
            "object_id": row.object_id, "detail": row.detail,
        }
        if audit_mod._chain_hash(prev_hash, payload) != row.entry_hash or row.prev_hash != prev_hash:
            breaks.append({
                "id": row.id, "action": row.action, "at": row.created_at,
                "observed_prev_hash": prev_hash, "declared_prev_hash": row.prev_hash,
                "acknowledged": row.id in known,
            })
        prev_hash = row.entry_hash
    return breaks


class Command(BaseCommand):
    help = "List or record acknowledged discontinuities in the audit chain."

    def add_arguments(self, parser):
        parser.add_argument("--list", action="store_true")
        parser.add_argument("--record", type=int, help="entry id where the chain restarts")
        parser.add_argument("--record-all", action="store_true")
        parser.add_argument("--reason", default="")
        parser.add_argument("--actor", default="")

    def handle(self, *args, **opts):
        breaks = _walk_breaks()

        if opts["list"] or not (opts["record"] or opts["record_all"]):
            if not breaks:
                self.stdout.write("audit chain: no breaks")
                return
            self.stdout.write(f"{len(breaks)} break(s):")
            for b in breaks:
                mark = "acknowledged" if b["acknowledged"] else "UNEXPLAINED"
                self.stdout.write(
                    f"  entry {b['id']:>6}  {b['action']:<24} {b['at']:%Y-%m-%d %H:%M:%S}  {mark}")
            return

        # A checkpoint without a stated reason is worse than no checkpoint: it clears the
        # verdict and records nothing about why, which is the outcome this design refuses.
        reason = (opts["reason"] or "").strip()
        actor = (opts["actor"] or "").strip()
        if not reason:
            raise CommandError("--reason is required: an unexplained acknowledgement explains nothing")
        if not actor:
            raise CommandError("--actor is required: who is accepting this discontinuity")

        targets = [b for b in breaks if not b["acknowledged"]]
        if opts["record"]:
            targets = [b for b in targets if b["id"] == opts["record"]]
            if not targets:
                raise CommandError(f"entry {opts['record']} is not an unacknowledged break")

        for b in targets:
            sig = audit_mod.checkpoint_signature(
                b["id"], b["observed_prev_hash"], b["declared_prev_hash"], reason)
            AuditCheckpoint.objects.create(
                at_entry_id=b["id"],
                observed_prev_hash=b["observed_prev_hash"],
                declared_prev_hash=b["declared_prev_hash"],
                reason=reason, recorded_by=actor,
                signature=sig, sig_key_id=audit_mod._key_id(),
            )
            # Recording an acknowledgement is itself a privileged act on the audit trail, so
            # it lands in the trail.
            audit_mod.audit(actor, "audit.checkpoint", role="admin",
                            object_type="AuditLog", object_id=str(b["id"]),
                            detail={"reason": reason, "observed_prev_hash": b["observed_prev_hash"],
                                    "declared_prev_hash": b["declared_prev_hash"]})
            self.stdout.write(f"recorded checkpoint at entry {b['id']}")

        ok, first_bad, sigs = audit_mod.verify_audit_detail()
        self.stdout.write(
            f"chain_ok={ok} first_unexplained_break={first_bad} "
            f"acknowledged_discontinuities={len(sigs.get('discontinuities', []))}")
