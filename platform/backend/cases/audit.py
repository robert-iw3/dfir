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
import threading

from django.db import connection, transaction

from .models import AuditLog, CustodyEvent

# Set when a call site audits an action itself, so the catch-all write middleware records only
# what nothing else did. Thread-local because gunicorn serves one request per thread.
_current = threading.local()


def mark_written():
    _current.written = True


def was_written():
    return getattr(_current, "written", False)


def reset_marker():
    _current.written = False


def _canonical(payload):
    return json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))


def _chain_hash(prev_hash, payload):
    h = hashlib.sha256()
    h.update((prev_hash or "").encode())
    h.update(_canonical(payload).encode())
    return h.hexdigest()


# Where Vault Agent renders the running secrets. The application's entrypoint sources this, so
# the server process holds the real keys while its environment still carries the compose-time
# placeholders.
_VAULT_ENV = "/vault/secrets/app.env"


def _secret(name):
    """One key, whichever way the process was started.

    A management command reached through `podman exec` inherits the container's environment —
    the placeholder — and never the file the entrypoint sourced. It would then sign with a
    different key than the server verifies with, and every signature it wrote would read as a
    forgery. The rendered file is authoritative when it exists.
    """
    try:
        with open(_VAULT_ENV) as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("export "):
                    line = line[7:]
                if line.startswith(f"{name}="):
                    value = line.split("=", 1)[1].strip().strip('"').strip("'")
                    if value:
                        return value
    except OSError:
        pass
    return os.environ.get(name, "")


def _sign(entry_hash):
    key = _secret("IR_AUDIT_HMAC_KEY")
    if not key:
        return ""
    return hmac.new(key.encode(), entry_hash.encode(), hashlib.sha256).hexdigest()


def _key_id(key=None):
    """A stable, non-secret identifier for the signing key in force — a digest, never the key.

    Every signed row carries one. Without it a signature written under a PREVIOUS key is
    indistinguishable from a forged one, so a key rotation reads as a tampered trail — and,
    worse, teaches a reader to wave away a real break as "probably a key change".
    """
    key = key if key is not None else _secret("IR_AUDIT_HMAC_KEY")
    return hashlib.sha256(key.encode()).hexdigest()[:16] if key else ""


# One lock for the whole audit chain, and a second family for custody chains. Arbitrary
# constants; only their uniqueness matters.
_AUDIT_LOCK = 4_242_001
_CUSTODY_LOCK_NS = 4_242_002


def _serialize_chain(lock_id, key=0):
    """Take a transaction-scoped advisory lock so exactly one appender chains at a time.

    `select_for_update()` on `ORDER BY id DESC LIMIT 1` is not enough: FOR UPDATE locks the
    rows a query RETURNED and cannot lock a row that does not exist yet. Under READ COMMITTED
    the second transaction blocks, re-reads, and still sees the old maximum because the
    competing insert is a phantom to it — so both compute the same prev_hash and the chain
    forks.

    An advisory lock has no such gap: it is held on a name, not on rows, so the second writer
    waits until the first has COMMITTED its insert and then reads a chain that includes it.
    Transaction-scoped (`_xact_`), so it is released by commit or rollback and a crashed
    writer cannot wedge the trail.
    """
    with connection.cursor() as cur:
        cur.execute("SELECT pg_advisory_xact_lock(%s, %s)", [lock_id, key])


@transaction.atomic
def audit(actor, action, *, role="", method="", path="", object_type="",
          object_id="", detail=None, covers_request=True):
    """Append one hash-chained audit entry. Serialized so the chain stays linear.

    `covers_request` says whether this entry describes the action the current request
    performed. It does for a call site auditing its own write, and it does not for session
    bookkeeping such as a login recorded while authenticating some other request — which
    would otherwise suppress the catch-all entry for the write that request carried.
    """
    detail = detail or {}
    if covers_request:
        mark_written()
    _serialize_chain(_AUDIT_LOCK)
    prev = AuditLog.objects.order_by("-id").first()
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
        sig_key_id=_key_id(),
    )


def verify_audit_chain():
    """Re-walk the chain. Returns (ok, first_broken_id_or_None) — the CHAIN's verdict.

    The chain is the tamper-evidence: content that changed, or a row removed, breaks every
    hash after it and is detected here regardless of any key.
    """
    ok, broken, _ = verify_audit_detail()
    return ok, broken


def _checkpoint_map():
    """Acknowledged discontinuities, by the entry id where the chain restarts."""
    from .models import AuditCheckpoint
    return {c.at_entry_id: c for c in AuditCheckpoint.objects.all()}


def checkpoint_signature(at_entry_id, observed, declared, reason):
    """Bind a checkpoint to the exact gap it acknowledges.

    Unsigned, an acknowledgement is just a row anyone able to write the table could add to
    cover a real break. Signed under the audit key, forging one costs what forging the trail
    costs.
    """
    key = _secret("IR_AUDIT_HMAC_KEY")
    if not key:
        return ""
    msg = f"{at_entry_id}|{observed}|{declared}|{reason}"
    return hmac.new(key.encode(), msg.encode(), hashlib.sha256).hexdigest()


def verify_audit_detail():
    """(chain_ok, first_broken_id, signatures) — chain and signatures reported APART.

    They answer different questions and collapsing them lost the distinction that matters:

      chain      does the content still hash to what was recorded? A break here is tampering
                 or loss, always, and no key rotation can cause it.
      signature  was this row signed by the key we hold? A row signed under a SUPERSEDED key
                 cannot be verified and has not been contradicted — it is unverifiable, which
                 is a third answer and not a failure.

    Only rows carrying the CURRENT key id are signature-checked. A mismatch there is a real
    forgery signal, because the row claims this key and does not satisfy it.

    A break at a row covered by a signed AuditCheckpoint is an ACKNOWLEDGED discontinuity: the
    walk records it, resumes from that row, and keeps going. An unacknowledged break still
    stops the walk and returns the row. The distinction is the point — a ledger that is
    silently re-chained to pass verification proves nothing, and one that can never record a
    known historical break can never be verified again after a single defect.
    """
    prev_hash = ""
    sigs = {"current": 0, "superseded": 0, "unsigned": 0, "invalid": []}
    sigs["discontinuities"] = []
    current = _key_id()
    checkpoints = _checkpoint_map()
    for row in AuditLog.objects.order_by("id").iterator():
        payload = {
            "actor": row.actor, "role": row.role, "action": row.action,
            "method": row.method, "path": row.path, "object_type": row.object_type,
            "object_id": row.object_id, "detail": row.detail,
        }
        expect = _chain_hash(prev_hash, payload)
        if expect != row.entry_hash or row.prev_hash != prev_hash:
            cp = checkpoints.get(row.id)
            # The acknowledgement has to match THIS gap and carry a valid signature. A
            # checkpoint that names other hashes, or that anyone could have written, is not an
            # explanation — accepting it would hand an attacker the way to clear a real break.
            expected_sig = checkpoint_signature(
                row.id, cp.observed_prev_hash, cp.declared_prev_hash, cp.reason) if cp else ""
            if (cp and cp.observed_prev_hash == prev_hash
                    and cp.declared_prev_hash == row.prev_hash
                    and (not expected_sig or expected_sig == cp.signature)):
                sigs["discontinuities"].append(
                    {"at": row.id, "reason": cp.reason, "recorded_by": cp.recorded_by})
                prev_hash = row.entry_hash
                continue
            return False, row.id, sigs
        if not row.signature:
            sigs["unsigned"] += 1
        elif row.sig_key_id and row.sig_key_id == current:
            if _sign(row.entry_hash) == row.signature:
                sigs["current"] += 1
            else:
                # Claims the key we hold and fails it. Not a rotation.
                sigs["invalid"].append(row.id)
        else:
            # Written under a key this deployment no longer holds — or before key ids were
            # recorded at all. Unverifiable, and NOT evidence of tampering.
            sigs["superseded"] += 1
        # Advance. Without this every row after the first is checked against an empty
        # previous hash and the whole ledger reports broken at row 2 — the false accusation
        # this function exists to prevent, reintroduced by the function itself.
        prev_hash = row.entry_hash
    return True, None, sigs


@transaction.atomic
def custody(run, action, actor, detail=None):
    """Append one hash-chained custody event for a run's evidence chain."""
    detail = detail or {}
    _serialize_chain(_CUSTODY_LOCK_NS, run.id)
    prev = CustodyEvent.objects.filter(run=run).order_by("-id").first()
    prev_hash = prev.entry_hash if prev else ""
    entry_hash = _chain_hash(prev_hash, {"action": action, "detail": detail})
    return CustodyEvent.objects.create(
        run=run, action=action, actor=actor, detail=detail,
        prev_hash=prev_hash, entry_hash=entry_hash,
        # The custody seal is the evidentiary chain for collected material. Same reasoning as
        # the audit trail: a seal seals under a key, and which key has to travel with it.
        sig_key_id=_custody_key_id(),
    )


def _custody_key_id():
    key = _secret("IR_CUSTODY_HMAC_KEY")
    return hashlib.sha256(key.encode()).hexdigest()[:16] if key else ""
