"""
Enforcement actions are recorded — SRG-APP-000805-WSR-000140.

RBAC returned 403 and told nobody. The refusal was correct and invisible: an analyst probing
what they cannot reach produced exactly the same evidence as an analyst who never tried, which
is the wrong way round for a platform whose own users are sometimes the subject.

Recorded HERE rather than in each permission class, for the reason every "remember to log it"
convention eventually fails: the next permission class added would not log, and the gap would
be discovered by needing the record and not having it. DRF routes every refusal through one
exception handler, so this catches the ones nobody thought about.

Wired via REST_FRAMEWORK["EXCEPTION_HANDLER"].
"""
import logging

from rest_framework.exceptions import NotAuthenticated, PermissionDenied
from rest_framework.views import exception_handler as drf_exception_handler

logger = logging.getLogger(__name__)

# Paths whose refusal is not an enforcement event worth chaining. An unauthenticated poll of
# the health endpoint is background noise, and a chain full of it is a chain nobody reads.
QUIET_PREFIXES = ("/api/health",)


def audited_exception_handler(exc, context):
    """DRF's handler, plus an audit row for every access refusal."""
    response = drf_exception_handler(exc, context)

    if not isinstance(exc, (PermissionDenied, NotAuthenticated)):
        return response

    request = context.get("request")
    path = getattr(request, "path", "") or ""
    if any(path.startswith(p) for p in QUIET_PREFIXES):
        return response

    try:
        # Imported here: this module is loaded from settings, and importing models at that
        # point runs before the app registry is ready.
        from .audit import audit
        from .rbac import role_of

        view = context.get("view")
        # A refused export belongs in the export ledger, beside the ones that succeeded. A ledger
        # showing only successes answers "what left" and cannot answer "what was tried", and during an
        # investigation into a responder those are one question.
        kind = getattr(view, "export_kind", None)
        if kind and isinstance(exc, PermissionDenied):
            from .exportledger import record_export
            record_export(request, kind=kind,
                          fmt=request.query_params.get("fmt", "") if hasattr(
                              request, "query_params") else "",
                          outcome="denied",
                          denied_reason=str(getattr(exc, "detail", "") or exc)[:255])
            return response

        user = getattr(request, "user", None)
        actor = getattr(user, "username", "") or "anonymous"
        # An unauthenticated refusal and an authorized-but-insufficient one are different
        # events. Collapsing them loses the distinction between someone who has no session and
        # someone who has one and reached past it.
        kind = "access.unauthenticated" if isinstance(exc, NotAuthenticated) else "access.denied"

        audit(actor, kind,
              role=role_of(user) or "",
              method=getattr(request, "method", ""),
              path=path,
              object_type="",
              detail={
                  # The permission class that refused, so a pattern is legible without
                  # re-deriving it from role and path.
                  "reason": str(getattr(exc, "detail", "") or exc)[:300],
                  "view": context.get("view").__class__.__name__ if context.get("view") else "",
                  "status": getattr(response, "status_code", None),
              })
    except Exception:
        # A failure to record must never convert a 403 into a 500: the refusal itself is the
        # security-relevant outcome and has to reach the client either way.
        logger.exception("failed to audit access denial for %s", path)

    return response
