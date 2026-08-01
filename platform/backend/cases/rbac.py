"""
Role-based access control.

Three roles, enforced by Django groups + DRF permission classes:

  admin    full control, including deletion of information
  analyst  work cases end-to-end: read everything, write notes, initiate rescans;
           may NOT delete
  auditor  read investigations AND the audit trail (see everything analysts did);
           may not mutate anything
  reverse_engineer
           analyze carved memory regions and record what they are. Scoped deliberately
           narrowly: a reverse engineer works on extracted malware, not on cases, so the
           role reads region context and writes region analyses — and nothing else. Its
           conclusions reach the incident as findings raised on the owning run.

The store-and-forward broker authenticates with a separate *service* token and is the
only identity allowed to hit the ingest endpoint — it is not one of the roles.
"""
from rest_framework.permissions import BasePermission, SAFE_METHODS

ROLES = ("admin", "analyst", "auditor", "reverse_engineer")
SERVICE_GROUP = "service"  # broker / ingest


def role_of(user):
    if not user or not user.is_authenticated:
        return None
    if user.is_superuser:
        return "admin"
    names = set(user.groups.values_list("name", flat=True))
    for r in ROLES:
        if r in names:
            return r
    if SERVICE_GROUP in names:
        return "service"
    return None


class IsAdmin(BasePermission):
    def has_permission(self, request, view):
        return role_of(request.user) == "admin"


class IsAnalystOrAdmin(BasePermission):
    """Analysts and admins can act on cases/notes/rescans; auditors cannot mutate."""

    def has_permission(self, request, view):
        return role_of(request.user) in ("analyst", "admin")


class ReadAnyRoleWriteAnalyst(BasePermission):
    """Any authenticated role may read; only analyst/admin may write; delete is
    reserved to admin (checked separately in the view)."""

    def has_permission(self, request, view):
        role = role_of(request.user)
        if role is None:
            return False
        if request.method in SAFE_METHODS:
            return role in ("admin", "analyst", "auditor")
        if request.method == "DELETE":
            return role == "admin"
        return role in ("admin", "analyst")


class IsReverseEngineerOrAdmin(BasePermission):
    """Carved-region workflow: reverse engineers and admins.

    Analysts are deliberately excluded from *writing* region analyses — the point of the
    role split is that malware attribution is recorded by the person who did it. Analysts
    still see the resulting findings on the incident.
    """

    def has_permission(self, request, view):
        role = role_of(request.user)
        if role == "admin":
            return True
        if role == "reverse_engineer":
            return True
        # Analysts and auditors may read the region list, not write to it.
        return request.method in SAFE_METHODS and role in ("analyst", "auditor")


class IsAuditorOrAdmin(BasePermission):
    """The audit trail is visible to auditors and admins."""

    def has_permission(self, request, view):
        return role_of(request.user) in ("auditor", "admin")


class IsService(BasePermission):
    """Ingest endpoint: the broker service account only (admins also allowed for ops)."""

    def has_permission(self, request, view):
        return role_of(request.user) in ("service", "admin")
