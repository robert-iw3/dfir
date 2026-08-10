"""
Sign-on endpoints: ending a session, and reading who is signed on.
"""
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from . import authevents
from .models import SsoSession
from .rbac import IsAuditorOrAdmin

# Where the browser is sent to end the OIDC session. The gate clears its cookie and forwards
# to Keycloak, which ends the session there too — a local sign-out that skipped this would
# leave a session the next request silently reuses.
SIGN_OUT_PATH = "/oauth2/sign_out"


class SignOutView(APIView):
    """Record the sign-out, then tell the browser where to go to complete it.

    The audit entry is written here rather than left to the gate: oauth2-proxy logs a sign-out
    to container stdout, which is not the platform's trail and is not what an auditor reads.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        session = authevents.sign_out(request, request.user)
        return Response({
            "signed_out": session is not None,
            # False means no open sign-on was found to close, not that sign-out failed. The
            # browser still has to visit the gate either way.
            "redirect": SIGN_OUT_PATH,   # same origin as the app; the gate sits in front of it
            "session_id": session.id if session else None,
        })


class SessionsView(APIView):
    """Who is signed on, and who was. Auditors and admins only."""

    permission_classes = [IsAuditorOrAdmin]

    def get(self, request):
        # Idle sessions are closed on read, so the active list reflects what is still valid
        # rather than everything that ever signed on. Most sessions end by expiry.
        expired = authevents.expire_idle()

        limit = min(int(request.query_params.get("limit", 100)), 500)
        rows = SsoSession.objects.all()[:limit]
        return Response({
            "expired_on_read": expired,
            "active": SsoSession.objects.filter(ended_at__isnull=True).count(),
            "results": [_shape(s) for s in rows],
        })


def _shape(session):
    return {
        "id": session.id,
        "username": session.username,
        "role": session.role,
        "active": session.active,
        "started_at": session.started_at,
        "last_seen_at": session.last_seen_at,
        "ended_at": session.ended_at,
        "end_reason": session.end_reason,
        "client_address": session.client_address,
        "user_agent": session.user_agent,
        "workstation": session.workstation,
        "request_count": session.request_count,
        # How the sign-on was identified. "derived" means requests were grouped by caller
        # rather than by the identity provider's session id, so two sign-ons from one browser
        # would appear as one.
        "key_source": session.key_source,
    }
