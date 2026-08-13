"""Working alongside other analysts on the same case.

Everything here is ADVISORY. Presence, soft locks and concurrence warnings tell an analyst
what someone else is doing; none of them can stop a write. An incident-response platform
that lets one person block another's work has chosen the wrong failure mode — the analyst
who is unreachable is exactly the one whose lock will not be released.

The activity feed reads the audit ledger rather than keeping a second record of its own.
A feed that could disagree with the ledger would be worse than no feed.

Everything is scoped: presence, notifications, locks and the feed are all filtered by the
same case visibility rules as the evidence, so none of them can tell you a case exists that
you are not cleared to see.
"""
import re
from datetime import timedelta

from django.contrib.auth.models import User
from django.utils import timezone
from rest_framework.response import Response
from rest_framework.views import APIView

from . import audit
from .models import ArtifactLock, AuditLog, CaseTask, Investigation, Notification, Presence
from .rbac import IsAnalystOrAdmin, may_see_investigation, scope_by_investigation

# How long a heartbeat vouches for someone. Two missed beats at the UI's 30s interval:
# short enough that a closed tab clears quickly, long enough that one dropped request does
# not blink an analyst out of the room.
PRESENCE_TTL = timedelta(seconds=75)
LOCK_TTL = timedelta(minutes=15)

# A mention is a username, so it is matched as one. Anchoring on a leading non-word
# character keeps an email address in a note from reading as a mention of its local part.
MENTION_RE = re.compile(r"(?:^|(?<=[^\w@]))@([A-Za-z0-9][A-Za-z0-9._-]{1,149})")


def _live(qs):
    return qs.filter(last_seen__gte=timezone.now() - PRESENCE_TTL)


def notify_mentions(body, actor, investigation, ref_type="", ref_id=None):
    """Create a notification for every @user named in `body` who may see the case.

    Returns the usernames actually notified. A mention of someone without access is
    silently not delivered: telling them a case exists is the leak that scoping prevents,
    and telling the author who is cleared would leak it the other way.
    """
    names = {m.group(1) for m in MENTION_RE.finditer(body or "")}
    if not names:
        return []
    notified = []
    for user in User.objects.filter(username__in=names):
        if user.username == actor or not may_see_investigation(user, investigation):
            continue
        Notification.objects.create(
            user=user, kind=Notification.MENTION, actor=actor or "",
            investigation=investigation, ref_type=ref_type, ref_id=ref_id,
            body=(body or "")[:1000])
        notified.append(user.username)
    return notified


def notify_assignment(assignee, actor, task):
    """Tell someone a task became theirs. Self-assignment notifies no one."""
    if not assignee or assignee == actor:
        return False
    user = User.objects.filter(username=assignee).first()
    if not user or not may_see_investigation(user, task.investigation):
        return False
    Notification.objects.create(
        user=user, kind=Notification.ASSIGNMENT, actor=actor or "",
        investigation=task.investigation, ref_type="task", ref_id=task.id,
        body=f"assigned to you: {task.title}"[:1000])
    return True


class PresenceView(APIView):
    """POST a heartbeat, GET who else is here. One endpoint serves presence, the
    concurrence warning and the roster."""

    permission_classes = [IsAnalystOrAdmin]

    def post(self, request):
        inv = None
        inv_id = request.data.get("investigation")
        if inv_id:
            inv = Investigation.objects.filter(id=inv_id).first()
            if inv and not may_see_investigation(request.user, inv):
                return Response({"detail": "not found"}, status=404)
        Presence.objects.update_or_create(
            user=request.user,
            defaults={"investigation": inv,
                      "location": str(request.data.get("location", ""))[:255]})
        return Response(self._roster(request, inv))

    def get(self, request):
        inv = None
        inv_id = request.query_params.get("investigation")
        if inv_id:
            inv = Investigation.objects.filter(id=inv_id).first()
            if inv and not may_see_investigation(request.user, inv):
                return Response({"detail": "not found"}, status=404)
        return Response(self._roster(request, inv))

    def _roster(self, request, inv):
        rows = _live(Presence.objects.select_related("user", "investigation"))
        rows = scope_by_investigation(rows, request.user, "investigation_id")
        if inv:
            rows = rows.filter(investigation=inv)
        here = [{"username": p.user.username, "location": p.location,
                 "investigation": p.investigation_id,
                 "last_seen": p.last_seen.isoformat()}
                for p in rows if p.user_id != request.user.id]
        return {"here": here, "ttl_seconds": int(PRESENCE_TTL.total_seconds())}


class LockView(APIView):
    """Claim, release and list soft locks. A refused claim names the holder; it never
    refuses the underlying edit."""

    permission_classes = [IsAnalystOrAdmin]

    def get(self, request):
        rows = ArtifactLock.objects.select_related("user").filter(
            expires_at__gt=timezone.now())
        rows = scope_by_investigation(rows, request.user, "investigation_id")
        if request.query_params.get("investigation"):
            rows = rows.filter(investigation_id=request.query_params["investigation"])
        return Response({"locks": [{
            "ref_type": l.ref_type, "ref_id": l.ref_id, "held_by": l.user.username,
            "investigation": l.investigation_id, "since": l.created_at.isoformat(),
            "expires_at": l.expires_at.isoformat(),
        } for l in rows]})

    def post(self, request):
        inv = Investigation.objects.filter(id=request.data.get("investigation")).first()
        if not inv or not may_see_investigation(request.user, inv):
            return Response({"detail": "not found"}, status=404)
        ref_type = str(request.data.get("ref_type", ""))[:32]
        try:
            ref_id = int(request.data.get("ref_id"))
        except (TypeError, ValueError):
            return Response({"detail": "ref_id is required"}, status=400)
        if not ref_type:
            return Response({"detail": "ref_type is required"}, status=400)

        now = timezone.now()
        ArtifactLock.objects.filter(ref_type=ref_type, ref_id=ref_id,
                                    expires_at__lte=now).delete()
        held = ArtifactLock.objects.select_related("user").filter(
            ref_type=ref_type, ref_id=ref_id).first()
        if held and held.user_id != request.user.id:
            # 200, not 409: the caller is being informed, not refused. The UI shows a
            # warning and lets the analyst proceed.
            return Response({"acquired": False, "held_by": held.user.username,
                             "since": held.created_at.isoformat(),
                             "advisory": "Locks never block an edit."})
        lock, _ = ArtifactLock.objects.update_or_create(
            ref_type=ref_type, ref_id=ref_id,
            defaults={"user": request.user, "investigation": inv,
                      "expires_at": now + LOCK_TTL})
        return Response({"acquired": True, "held_by": request.user.username,
                         "expires_at": lock.expires_at.isoformat()})

    def delete(self, request):
        ref_type = str(request.query_params.get("ref_type", ""))[:32]
        ref_id = request.query_params.get("ref_id")
        deleted, _ = ArtifactLock.objects.filter(
            ref_type=ref_type, ref_id=ref_id, user=request.user).delete()
        return Response({"released": bool(deleted)})


class NotificationView(APIView):
    """Unread first, and marking them read. In-app only; nothing leaves the enclave."""

    permission_classes = [IsAnalystOrAdmin]

    def get(self, request):
        rows = Notification.objects.filter(user=request.user)
        if request.query_params.get("unread") == "1":
            rows = rows.filter(read_at__isnull=True)
        rows = list(rows[:200])
        return Response({
            "unread": Notification.objects.filter(
                user=request.user, read_at__isnull=True).count(),
            "notifications": [{
                "id": n.id, "kind": n.kind, "actor": n.actor, "body": n.body,
                "investigation": n.investigation_id, "ref_type": n.ref_type,
                "ref_id": n.ref_id, "created_at": n.created_at.isoformat(),
                "read_at": n.read_at.isoformat() if n.read_at else None,
            } for n in rows]})

    def post(self, request):
        ids = request.data.get("ids") or []
        qs = Notification.objects.filter(user=request.user, read_at__isnull=True)
        if ids:
            qs = qs.filter(id__in=[i for i in ids if isinstance(i, int)])
        return Response({"marked": qs.update(read_at=timezone.now())})


class ActivityFeedView(APIView):
    """What has happened on a case, newest first — read from the audit ledger itself.

    Keeping no separate feed table is the point: there is one record of what happened, and
    it is the signed one.
    """

    permission_classes = [IsAnalystOrAdmin]

    def get(self, request, investigation_id):
        inv = Investigation.objects.filter(id=investigation_id).first()
        if not inv or not may_see_investigation(request.user, inv):
            return Response({"detail": "not found"}, status=404)
        try:
            limit = min(int(request.query_params.get("limit", 100)), 500)
        except ValueError:
            limit = 100

        # The ledger records an object's type and id, not its case, so the case's own rows
        # are gathered by the ids it owns rather than by a column that does not exist.
        task_ids = {str(i) for i in
                    CaseTask.objects.filter(investigation=inv).values_list("id", flat=True)}
        rows = AuditLog.objects.order_by("-id")[:4000]
        events = []
        for r in rows:
            hit = (r.object_type == "investigation" and r.object_id == str(inv.id)) or \
                  (r.object_type == "task" and r.object_id in task_ids) or \
                  (isinstance(r.detail, dict)
                   and str(r.detail.get("investigation", "")) == str(inv.id))
            if not hit:
                continue
            events.append({"id": r.id, "at": r.created_at.isoformat(), "actor": r.actor,
                           "action": r.action, "object_type": r.object_type,
                           "object_id": r.object_id, "detail": r.detail})
            if len(events) >= limit:
                break
        return Response({"investigation": inv.id, "events": events})


class WhoAmIHereView(APIView):
    """The unread count and the live roster in one call, for the app chrome."""

    permission_classes = [IsAnalystOrAdmin]

    def get(self, request):
        # Presence rows with no case attached belong to nobody's compartment, so they are
        # kept alongside the scoped ones rather than filtered out with them.
        rows = _live(Presence.objects.select_related("user"))
        rows = (scope_by_investigation(rows, request.user, "investigation_id")
                | rows.filter(investigation__isnull=True)).distinct()
        return Response({
            "unread": Notification.objects.filter(
                user=request.user, read_at__isnull=True).count(),
            "online": sorted({p.user.username for p in rows} - {request.user.username}),
        })


def record_read(request, inv, what):
    """Audit a privileged read of a restricted case. Reads of an open case are not
    recorded — a log nobody can find anything in is not an audit trail."""
    if not inv or not inv.compartment:
        return
    audit.audit(getattr(request.user, "username", "") or "anonymous",
                "investigation.read", object_type="investigation",
                object_id=str(inv.id), detail={"what": what,
                                               "compartment": inv.compartment})
