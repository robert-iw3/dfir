"""
Case membership and compartments.

Assignment is the scoping unit: an analyst works the cases they are assigned to, and a
restricted case is visible only to its members and to admins. Auditors see everything by
remit — an audit that compartmenting can hide from is not an audit.

Every assign, remove and compartment change is audited, because "who could see this case,
and from when" is a question a review will ask long after the fact.
"""
from django.utils import timezone
from rest_framework.response import Response
from rest_framework.views import APIView

from . import audit
from .models import CaseAssignment, Investigation
from .rbac import IsAdmin, IsAnalystOrAdmin, may_see_investigation, role_of


def _rows(inv):
    return [{"username": a.username, "assigned_by": a.assigned_by,
             "assigned_at": a.created_at.isoformat()}
            for a in inv.assignments.filter(removed_at__isnull=True).order_by("username")]


class CaseAssignmentView(APIView):
    """Who is on a case. Analysts read their own cases' membership; admins write it."""

    permission_classes = [IsAnalystOrAdmin]

    def get(self, request, investigation_id):
        inv = Investigation.objects.filter(id=investigation_id).first()
        if not inv or not may_see_investigation(request.user, inv):
            return Response({"detail": "not found"}, status=404)
        return Response({"investigation": inv.id, "compartment": inv.compartment,
                         "members": _rows(inv)})

    def post(self, request, investigation_id):
        if role_of(request.user) != "admin":
            return Response({"detail": "assignment is an admin action"}, status=403)
        inv = Investigation.objects.filter(id=investigation_id).first()
        if not inv:
            return Response({"detail": "not found"}, status=404)
        username = (request.data.get("username") or "").strip()
        if not username:
            return Response({"detail": "username is required"}, status=400)
        actor = getattr(request.user, "username", "") or "admin"
        if request.data.get("remove"):
            CaseAssignment.objects.filter(
                investigation=inv, username=username, removed_at__isnull=True
            ).update(removed_at=timezone.now())
            action = "case.unassign"
        else:
            CaseAssignment.objects.get_or_create(
                investigation=inv, username=username, removed_at=None,
                defaults={"assigned_by": actor})
            action = "case.assign"
        audit.audit(actor, action, object_type="investigation", object_id=str(inv.id),
                    detail={"username": username})
        return Response({"investigation": inv.id, "compartment": inv.compartment,
                         "members": _rows(inv)})


class CaseCompartmentView(APIView):
    """Move a case between open and restricted. Admin-only, and audited both ways."""

    permission_classes = [IsAdmin]

    def post(self, request, investigation_id):
        inv = Investigation.objects.filter(id=investigation_id).first()
        if not inv:
            return Response({"detail": "not found"}, status=404)
        target = (request.data.get("compartment") or "").strip()
        if target not in dict(Investigation.COMPARTMENTS):
            return Response({"detail": f"compartment must be one of "
                                       f"{[c for c, _ in Investigation.COMPARTMENTS]}"},
                            status=400)
        before, inv.compartment = inv.compartment, target
        inv.save(update_fields=["compartment", "updated_at"])
        actor = getattr(request.user, "username", "") or "admin"
        audit.audit(actor, "case.compartment", object_type="investigation",
                    object_id=str(inv.id), detail={"from": before, "to": target})
        return Response({"investigation": inv.id, "compartment": inv.compartment,
                         "members": _rows(inv)})
