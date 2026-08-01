"""
Tamper-evident audit + custody logging.

Every entry is hash-chained to the previous one: entry_hash = SHA256(prev_hash ||
canonical(payload)). Removing or editing any historical row breaks every subsequent
hash, so tampering is detectable by re-walking the chain (verify_audit_chain). When
IR_AUDIT_HMAC_KEY is set, each entry is additionally HMAC-signed so an attacker who can
write the table still can't forge a consistent chain without the key.
"""
import hashlib
import hmac
import json
import os

from django.db import transaction

from .models import AuditLog, CustodyEvent


def _canonical(payload):
    return json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))


def _chain_hash(prev_hash, payload):
    h = hashlib.sha256()
    h.update((prev_hash or "").encode())
    h.update(_canonical(payload).encode())
    return h.hexdigest()


def _sign(entry_hash):
    key = os.environ.get("IR_AUDIT_HMAC_KEY")
    if not key:
        return ""
    return hmac.new(key.encode(), entry_hash.encode(), hashlib.sha256).hexdigest()


@transaction.atomic
def audit(actor, action, *, role="", method="", path="", object_type="",
          object_id="", detail=None):
    """Append one hash-chained audit entry. Serialized so the chain stays linear."""
    detail = detail or {}
    prev = AuditLog.objects.select_for_update().order_by("-id").first()
    prev_hash = prev.entry_hash if prev else ""
    payload = {
        "actor": actor, "role": role, "action": action, "method": method,
        "path": path, "object_type": object_type, "object_id": str(object_id),
        "detail": detail,
    }
    entry_hash = _chain_hash(prev_hash, payload)
    return AuditLog.objects.create(
        actor=actor, role=role, action=action, method=method, path=path,
        object_type=object_type, object_id=str(object_id), detail=detail,
        prev_hash=prev_hash, entry_hash=entry_hash, signature=_sign(entry_hash),
    )


def verify_audit_chain():
    """Re-walk the chain; return (ok, first_broken_id_or_None)."""
    prev_hash = ""
    for row in AuditLog.objects.order_by("id").iterator():
        payload = {
            "actor": row.actor, "role": row.role, "action": row.action,
            "method": row.method, "path": row.path, "object_type": row.object_type,
            "object_id": row.object_id, "detail": row.detail,
        }
        expect = _chain_hash(prev_hash, payload)
        if expect != row.entry_hash or row.prev_hash != prev_hash:
            return False, row.id
        if row.signature and _sign(row.entry_hash) != row.signature:
            return False, row.id
        prev_hash = row.entry_hash
    return True, None


@transaction.atomic
def custody(run, action, actor, detail=None):
    """Append one hash-chained custody event for a run's evidence chain."""
    detail = detail or {}
    prev = (CustodyEvent.objects.select_for_update()
            .filter(run=run).order_by("-id").first())
    prev_hash = prev.entry_hash if prev else ""
    entry_hash = _chain_hash(prev_hash, {"action": action, "detail": detail})
    return CustodyEvent.objects.create(
        run=run, action=action, actor=actor, detail=detail,
        prev_hash=prev_hash, entry_hash=entry_hash,
    )
