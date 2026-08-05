"""Reading the operational log, and the endpoint the browser reports its own failures to."""
from django.utils import timezone
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from cases.rbac import IsAnalystOrAdmin

from .models import ClientError, RequestLog


class ClientErrorView(APIView):
    """The browser reporting a render crash or a request that never reached the API.

    Authenticated but analyst-open: any signed-in user's session can fail, and a report that
    required elevated rights would go unwritten exactly when the UI is broken for the person
    who has none.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        d = request.data if isinstance(request.data, dict) else {}
        try:
            ClientError.objects.create(
                request_id=str(d.get("request_id", ""))[:36],
                username=(getattr(request.user, "username", "") or "")[:150],
                where=str(d.get("where", ""))[:256],
                url=str(d.get("url", ""))[:1024],
                message=str(d.get("message", ""))[:4000],
                stack=str(d.get("stack", ""))[:8000],
                component_stack=str(d.get("component_stack", ""))[:8000],
                user_agent=request.META.get("HTTP_USER_AGENT", "")[:256],
            )
        except Exception:                               # noqa: BLE001
            # A failed report must not itself surface as an error in a UI that is already
            # showing one.
            return Response({"recorded": False}, status=202)
        return Response({"recorded": True}, status=201)


class RequestLogView(APIView):
    """Recent API calls. Defaults to failures, because that is what a person comes here for."""

    permission_classes = [IsAnalystOrAdmin]

    def get(self, request):
        q = request.query_params
        rows = RequestLog.objects.all()
        if q.get("failed", "1") != "0":
            rows = rows.filter(status__gte=400)
        if q.get("path"):
            rows = rows.filter(path__icontains=q["path"])
        if q.get("username"):
            rows = rows.filter(username=q["username"])
        if q.get("request_id"):
            rows = rows.filter(request_id=q["request_id"])
        if q.get("minutes"):
            try:
                since = timezone.now() - timezone.timedelta(minutes=int(q["minutes"]))
                rows = rows.filter(at__gte=since)
            except (TypeError, ValueError):
                pass
        limit = min(int(q.get("limit", 100) or 100), 500)
        return Response({
            "count": rows.count(),
            "results": [{
                "request_id": r.request_id, "at": r.at, "method": r.method, "path": r.path,
                "query": r.query, "status": r.status, "duration_ms": r.duration_ms,
                "username": r.username, "source": r.source,
                "response_bytes": r.response_bytes,
                "error_type": r.error_type, "error_detail": r.error_detail[:2000],
            } for r in rows[:limit]],
        })


@api_view(["GET"])
@permission_classes([IsAnalystOrAdmin])
def client_errors(request):
    """Failures the browser saw — the ones no server-side log can contain."""
    limit = min(int(request.query_params.get("limit", 50) or 50), 200)
    rows = ClientError.objects.all()[:limit]
    return Response({"results": [{
        "at": e.at, "where": e.where, "url": e.url, "username": e.username,
        "message": e.message, "stack": e.stack[:2000],
        "component_stack": e.component_stack[:2000], "request_id": e.request_id,
    } for e in rows]})
