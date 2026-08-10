"""
Catch-all write auditing.

Explicit ``audit()`` calls describe an action in the vocabulary of the case — `finding.reclassify`
carries the old and new verdict, `export.completed` carries what left the platform. They are the
better record, and they stay.

What they cannot do is cover everything: they are added by hand at each call site, so any write
path nobody instrumented leaves no trace at all, and a viewset added later is unaudited until
someone remembers. This records every successful mutating API request, so coverage follows from
the request itself rather than from a developer's memory. Where an explicit call already fired
for the request, that entry stands alone — the same action is not recorded twice.
"""
from . import audit as audit_mod
from .rbac import role_of

WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

VERBS = {"POST": "create", "PUT": "replace", "PATCH": "modify", "DELETE": "delete"}

# Paths whose writes are recorded by their own call site with far better detail, or which are
# not user actions at all. Listed by prefix under /api/.
SKIP_PREFIXES = (
    "ingest/",          # service token, already audited with run and host detail
    "auth/logout/",     # records user.logout itself
    "health",
    "opslog/",
)

# The token exchange. A login, recorded as one rather than as a create — see _token_login().
TOKEN_PATH = "auth/token/"


def _resource(path):
    """The resource a path acts on: /api/findings/12/verdict/ -> findings.

    Falls back to the whole path when it does not look like a collection, so an unrecognized
    route is still recorded under something searchable rather than dropped.
    """
    parts = [p for p in path.split("/") if p]
    if parts and parts[0] == "api":
        parts = parts[1:]
    return parts[0] if parts else "api"


def _object_id(path):
    """The id segment when the path addresses one object, else blank."""
    parts = [p for p in path.split("/") if p]
    for part in parts[1:]:
        if part.isdigit():
            return part
    return ""


class AuditWriteMiddleware:
    """Record every successful write that no call site recorded itself."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Cleared per request: the marker is thread-local and a worker thread is reused, so a
        # leftover from the previous request would suppress this one's entry.
        audit_mod.reset_marker()
        response = self.get_response(request)
        try:
            self._record(request, response)
        except Exception:
            # A failure to audit must not fail the request that was already served. The gap
            # is visible in the trail as a missing entry, which is the honest outcome.
            pass
        return response

    def _record(self, request, response):
        if request.method not in WRITE_METHODS:
            return
        if not request.path.startswith("/api/"):
            return
        if not (200 <= getattr(response, "status_code", 500) < 300):
            # Denials are recorded by the permission layer with the reason for the denial,
            # which is the part that matters; a failed write changed nothing.
            return
        if audit_mod.was_written():
            return

        user = getattr(request, "user", None)
        actor = getattr(user, "username", "") or "anonymous"
        rest = request.path[len("/api/"):]
        if any(rest.startswith(p) for p in SKIP_PREFIXES):
            return

        if rest.startswith(TOKEN_PATH):
            self._token_login(request)
            return

        resource = _resource(request.path)
        audit_mod.audit(
            actor, f"{resource}.{VERBS[request.method]}",
            role=role_of(user) if user and user.is_authenticated else "",
            method=request.method, path=request.path[:512],
            object_type=resource, object_id=_object_id(request.path),
            detail={"status": response.status_code, "fields": _fields(request)},
        )


    def _token_login(self, request):
        """A successful token exchange is a login, and is recorded as one.

        The view authenticates through a serializer and never populates `request.user`, so the
        generic path would file this under `anonymous` as though nobody had signed in — the
        exact gap this middleware exists to close. The username comes from the request body;
        nothing else from it is read, and the password is neither logged nor referenced.
        """
        data = getattr(request, "data", None)
        username = ""
        if isinstance(data, dict):
            username = str(data.get("username", ""))[:150]
        audit_mod.audit(
            username or "unknown", "user.login", role="",
            method=request.method, path=request.path[:512],
            object_type="AuthToken",
            detail={"key_source": "token", "client_address": _client(request)},
        )


def _client(request):
    fwd = request.META.get("HTTP_X_FORWARDED_FOR", "")
    return fwd.split(",")[0].strip() if fwd else request.META.get("REMOTE_ADDR", "")


def _fields(request):
    """Which fields a write touched — names only.

    Values are deliberately excluded: the body of a note or an analyst's justification is
    already stored as the record itself, and copying it into the audit trail would put case
    content in a table that is exported to auditors who are not cleared for it.
    """
    data = getattr(request, "data", None)
    if isinstance(data, dict):
        return sorted(str(k) for k in data)[:40]
    if isinstance(data, list):
        return [f"<{len(data)} items>"]
    return []
