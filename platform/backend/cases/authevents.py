"""
Sign-on lifecycle: login, continued activity, and sign-out.

SSO authentication here is stateless. oauth2-proxy validates the OIDC session and forwards the
identity on every request, and each request is authenticated on its own — so there is no login
call to hook and no logout to observe. A sign-on is therefore reconstructed from the session
identity the gate forwards, and `SsoSession` is that reconstruction.

Session identity comes from the access token's `sid` claim (Keycloak's own session id). The
token is read for correlation ONLY: authorization is decided by the verified headers in
``authentication.py``, so nothing here can grant a right. When no token is present the key is
derived from the caller instead, and `key_source` records which of the two happened.
"""
import base64
import hashlib
import json
import re
from datetime import timedelta

from django.db.models import F
from django.utils import timezone

from . import audit as audit_mod
from .models import SsoSession

# Request counts not yet written, per sign-on. Held in the worker process and flushed on the
# touch interval or at sign-out; see _touch().
_pending = {}

# How long a session with no requests is considered still open. Matches the gate's
# --cookie-expire: past it the browser's cookie is gone, so the sign-on is over whether or
# not anyone told us.
IDLE_EXPIRY = 8 * 3600
# Activity is recorded on the session at most this often. A write per request would put a
# row update in front of every API call to save a timestamp nobody reads at that resolution.
TOUCH_INTERVAL = 60


def _header(request, name):
    return request.META.get("HTTP_" + name.upper().replace("-", "_"), "")


def _jwt_claims(token):
    """Claims from a JWT payload, or {} if it is not one.

    Unverified by design — see the module docstring. The gate has already validated this
    token; re-verifying it here would need the JWKS and would still not make the result
    authoritative for anything this module does with it.
    """
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}


def _client_address(request):
    fwd = _header(request, "X-Forwarded-For")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "")


def session_identity(request, username):
    """(key, source) for the sign-on this request belongs to.

    `--pass-access-token` delivers the token upstream as X-Forwarded-Access-Token. The
    X-Auth-Request-* form belongs to `--set-xauthrequest`, which sets RESPONSE headers for
    nginx auth_request mode, so it is a fallback rather than the expected source.
    """
    claims = _jwt_claims(_header(request, "X-Forwarded-Access-Token")
                         or _header(request, "X-Auth-Request-Access-Token"))
    sid = claims.get("sid") or claims.get("session_state")
    if sid:
        return sid, "oidc"

    # No token: coalesce by who and from where. This cannot separate two sign-ons from one
    # browser, which is why it is labeled rather than presented as the session id.
    seed = "|".join([username, _client_address(request), _header(request, "User-Agent")])
    return hashlib.sha256(seed.encode()).hexdigest()[:32], "derived"


def note_request(request, user, role=""):
    """Attribute this request to a sign-on, opening one if it is the first.

    Returns the SsoSession, or None if the sign-on could not be established — a failure here
    must never block the request that carried it.
    """
    try:
        username = getattr(user, "username", "") or ""
        if not username:
            return None
        key, source = session_identity(request, username)

        session = SsoSession.objects.filter(session_key=key).first()
        if session is None:
            session = _open(request, user, username, role, key, source)
        elif session.ended_at is not None:
            # The same session key seen again after sign-out: the browser still holds a valid
            # cookie, so this is a resumption rather than a new sign-on. Reopened under the
            # same key, and recorded, because a resumed session that silently reappears in the
            # active list with no entry explaining it reads as a gap in the trail.
            session.ended_at = None
            session.end_reason = ""
            session.save(update_fields=["ended_at", "end_reason"])
            _record(user, "user.login.resume", request, session)
        _touch(session, role)
        return session
    except Exception:
        return None


def _open(request, user, username, role, key, source):
    session = SsoSession.objects.create(
        session_key=key, key_source=source, user=user, username=username, role=role,
        client_address=_client_address(request),
        user_agent=_header(request, "User-Agent")[:256],
        workstation=_workstation(request),
    )
    _record(user, "user.login", request, session)
    return session


def _workstation(request):
    """Which workstation this came from, when the kiosk says so.

    The kiosk appends `IR-WS/<id>` to its User-Agent — the only place on an end-to-end-TLS
    path where the workstation can be named, since every hop between browser and ingress is
    L4. Blank rather than a guess: an empty value reads as "not established", and a wrong
    one would attribute a person's actions to a machine they never touched.
    """
    m = re.search(r"\bIR-WS/([A-Za-z0-9_.-]{1,64})\b", _header(request, "User-Agent"))
    if m:
        return m.group(1)
    return (_header(request, "X-Workstation-Id")
            or _header(request, "X-Tailnet-Node") or "")[:64]


def _record(user, action, request, session):
    audit_mod.audit(
        session.username, action,
        role=session.role,
        method=request.method if request else "",
        path=getattr(request, "path", "")[:512],
        object_type="SsoSession", object_id=session.id,
        detail={
            "session_key": session.session_key,
            "key_source": session.key_source,
            "client_address": session.client_address,
            "user_agent": session.user_agent,
            "workstation": session.workstation,
        },
        covers_request=False,
    )


def _touch(session, role=""):
    """Record activity without putting a write in front of every request.

    Counting on each request would mean one UPDATE per authenticated call, on a row a busy
    analyst contends with themselves for. Increments accumulate per worker process and flush
    with the timestamp at most once per TOUCH_INTERVAL. A worker restart drops whatever had
    not flushed, so the count is a measure of activity rather than an exact tally — which is
    what it is used for. The audit trail, not this counter, is the record of what was done.
    """
    now = timezone.now()
    _pending[session.id] = _pending.get(session.id, 0) + 1

    fields = []
    if role and session.role != role:
        # A role change mid-session is a privilege change; the trail has to carry it.
        session.role = role
        fields.append("role")
    if (now - session.last_seen_at).total_seconds() >= TOUCH_INTERVAL:
        session.last_seen_at = now
        fields.append("last_seen_at")
        # F(), not a read-modify-write: several workers touch the same sign-on and a
        # Python-side increment would lose whichever flush lands second.
        session.request_count = F("request_count") + _pending.pop(session.id, 0)
        fields.append("request_count")
    if fields:
        session.save(update_fields=fields)
        session.refresh_from_db(fields=["request_count"])


def sign_out(request, user, reason="signout"):
    """Close the sign-on this request belongs to and record it. Returns the session or None."""
    username = getattr(user, "username", "") or ""
    if not username:
        return None
    key, _ = session_identity(request, username)
    session = SsoSession.objects.filter(session_key=key, ended_at__isnull=True).first()
    if session is None:
        return None
    session.ended_at = timezone.now()
    session.end_reason = reason
    # Flush the unwritten count: a closed sign-on is read as a final record, and one showing
    # fewer requests than it served is wrong in a way nothing later corrects.
    session.request_count = F("request_count") + _pending.pop(session.id, 0)
    session.save(update_fields=["ended_at", "end_reason", "request_count"])
    session.refresh_from_db(fields=["request_count"])
    _record(user, "user.logout", request, session)
    return session


def expire_idle(now=None):
    """Close sign-ons whose cookie can no longer be valid. Returns how many were closed.

    Most sessions end this way. A browser closed at the end of a shift sends no sign-out, and
    without this every one of them stays open forever and the active list becomes meaningless.
    """
    now = now or timezone.now()
    cutoff = now - timedelta(seconds=IDLE_EXPIRY)
    closed = 0
    for session in SsoSession.objects.filter(ended_at__isnull=True, last_seen_at__lt=cutoff):
        session.ended_at = session.last_seen_at
        session.end_reason = "expired"
        session.save(update_fields=["ended_at", "end_reason"])
        audit_mod.audit(
            session.username, "user.session.expired", role=session.role,
            object_type="SsoSession", object_id=session.id,
            detail={"session_key": session.session_key,
                    "last_seen_at": session.last_seen_at.isoformat(),
                    "idle_seconds": IDLE_EXPIRY},
            covers_request=False,
        )
        closed += 1
    return closed
