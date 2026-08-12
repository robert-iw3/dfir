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

# Export is a RIGHT, not a consequence of being able to read. Reading a finding inside the
# enclave and carrying ten thousand of them out of it are different acts with different blast
# radii, and until now anyone who could do the first could do the second.
EXPORT_GROUP = "export"

# Groups that grant a right ALONGSIDE a role rather than being one. The SSO layer reconciles
# these from the same Keycloak claim as the role (cases/authentication.py), and only these:
# a group invented in Keycloak cannot quietly become a permission on this side.
GRANT_GROUPS = (EXPORT_GROUP,)


def may_export(user):
    """Whether this identity may take evidence out of the platform.

    Admins always may — the role already implies deletion, so withholding export from it
    would be theatre. Everyone else needs the group, INCLUDING auditors: an auditor's remit is
    to see everything, which is a strictly separate question from removing it.
    """
    if not user or not user.is_authenticated:
        return False
    if role_of(user) == "admin":
        return True
    return user.groups.filter(name=EXPORT_GROUP).exists()


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


class CanExport(BasePermission):
    """Gate on the export right, not merely on being authenticated.

    The refusal is recorded by the exception handler in `cases.denials`, so a pattern of
    attempts is legible without anyone having thought to log it here.
    """

    message = "export requires the export right; read access does not imply it"

    def has_permission(self, request, view):
        return may_export(request.user)
