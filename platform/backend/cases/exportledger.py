"""
The export ledger — one place that records what left the platform.

Every export writes here AND to the audit chain. They answer different questions and neither
replaces the other: the chain proves nothing was removed from the history, the ledger says
what to look at. Reconstructing "what has already gone out of this platform" by filtering a
hash-chained log on an action name and unpacking a free-form detail blob was possible and is
not the same as answerable.

Written through one function so no call site invents its own shape. A ledger whose rows mean
slightly different things per endpoint is a report nobody can total.
"""
import logging

from .audit import audit
from .models import ExportLedger
from .rbac import role_of

logger = logging.getLogger(__name__)

# Where an export goes, as the platform can honestly describe it. Every export today is a
# download over the brokered session onto the analyst workstation's fixed download directory
# (D-010); what the analyst does with the file afterwards is outside what this can claim.
DESTINATION_DOWNLOAD = "browser download (brokered session)"


def record_export(request, *, kind, fmt="", filters=None, row_count=0,
                  destination=DESTINATION_DOWNLOAD, outcome="completed", denied_reason=""):
    """Record one export attempt — completed or denied — and audit it.

    Returns the ledger row. Never raises: an export that succeeded and a ledger that failed
    to record it is bad, but refusing the analyst their evidence because the bookkeeping
    stumbled is worse, and the audit call below is the tamper-evident half either way.
    """
    actor = getattr(request.user, "username", "?") or "?"
    role = role_of(request.user) or ""
    filters = {k: v for k, v in (filters or {}).items() if v not in (None, "")}

    row = None
    try:
        row = ExportLedger.objects.create(
            actor=actor, role=role, kind=kind, fmt=fmt or "",
            filters=filters, row_count=row_count or 0,
            destination=destination, outcome=outcome,
            denied_reason=denied_reason or "", path=request.path[:512],
        )
    except Exception:
        # Logged rather than swallowed: a ledger that silently stops recording reads exactly
        # like a platform nobody exported from.
        logger.exception("export ledger write failed for %s %s", actor, kind)

    audit(actor, f"export.{outcome}", role=role, method=request.method,
          path=request.path, object_type="ExportLedger",
          object_id=str(getattr(row, "id", "") or ""),
          detail={"kind": kind, "fmt": fmt, "rows": row_count,
                  "filters": filters, "destination": destination,
                  **({"denied_reason": denied_reason} if denied_reason else {})})
    return row
