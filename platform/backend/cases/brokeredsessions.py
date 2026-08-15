"""
Brokered analyst sessions, read from Boundary.

Every analyst reaches this platform through a Boundary session and no other way — that is the
enclave's whole ingress design. So this list IS the access record: who connected, from where,
to what, when, and whether it is still open. Nothing else in the platform can answer it,
because the connection terminates before the application sees a request.

Read with a principal that can `list` and `read` sessions and nothing else. It cannot
authorize a session, cancel one, or read a target — watching access must never be a way to
obtain it. The recovery key would make all of this trivial and is exactly why it is not used.

Boundary is the authority. A session recorded here and absent there is a session that was
canceled or expired, and showing a stale row as live is the failure that matters most on an
audit page.
"""
from __future__ import annotations

import json
import os
import re
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timedelta

from django.db.models import Q

from .models import SsoSession

BOUNDARY_ADDR = os.environ.get("IR_BOUNDARY_ADDR", "https://boundary:9200")
BOUNDARY_CACERT = os.environ.get("IR_BOUNDARY_CACERT") or None
LOGIN = os.environ.get("IR_BOUNDARY_SESSION_AUDITOR_LOGIN", "session-auditor")
PASSWORD = os.environ.get("IR_BOUNDARY_SESSION_AUDITOR_PASSWORD", "")
AUTH_METHOD_ID = os.environ.get("BOUNDARY_AUTH_METHOD_ID", "")
SCOPE_ID = os.environ.get("BOUNDARY_PROJECT_ID", "")
# How many recent sign-ons are considered when attributing a session to a person. Bounded so
# an audit page reading a long history does not walk the whole table.
# How long an un-ended sign-on still counts as the person being there. A sign-on ends when
# the analyst signs off; one that stops without saying so is bounded by this instead, which
# is the platform's own idle timeout. Never a row count: a count-based window silently drops
# attribution for older sessions once the deployment is busy enough to fill it.
SIGNON_IDLE_GRACE = timedelta(seconds=int(os.environ.get("IR_SIGNON_IDLE_GRACE", "3600")))
# The configured workstation set, in the order the distributor's pinning map is rendered
# from: the Nth workstation's connections land on session principal analyst-sN. One variable
# on both sides, so the pairing cannot drift.
WS_IDS = os.environ.get("IR_WS_IDS", "").split()


def _principal_workstation(principal):
    """Which workstation a pool principal carries, by configuration; '' when unpinned."""
    m = re.match(r"analyst-s(\d+)$", principal or "")
    if not m:
        return ""
    idx = int(m.group(1)) - 1
    return WS_IDS[idx] if 0 <= idx < len(WS_IDS) else ""

# Boundary's own vocabulary, kept rather than renamed: an operator reading this page and then
# running `boundary sessions list` should see the same words.
ACTIVE_STATES = {"active", "pending"}
ORG_ID = os.environ.get("BOUNDARY_ORG_ID", "")

# How many sessions get a detail read. `connections` and the state timeline come only from a
# session READ, never the list — and an access record grows without limit, so a page that fans
# out over all of it stops loading exactly when an incident makes it busy.
DETAIL_LIMIT = int(os.environ.get("IR_BOUNDARY_SESSION_DETAIL_LIMIT", "25"))
# How many sessions one read returns. Every session the deployment has ever opened is kept —
# an access record that forgets is not an access record — but returning all of them grows
# without bound, so the read is a window over the record and `total` still reports the whole.
PAGE_LIMIT = int(os.environ.get("IR_BOUNDARY_SESSION_PAGE", "200"))
MAX_PAGE_LIMIT = 1000


def _ctx():
    return ssl.create_default_context(cafile=BOUNDARY_CACERT) if BOUNDARY_CACERT else None


def _call(path, method="GET", body=None, token=None, timeout=6):
    req = urllib.request.Request(
        f"{BOUNDARY_ADDR}/v1/{path}", method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json",
                 **({"Authorization": f"Bearer {token}"} if token else {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ctx()) as r:
            return json.loads(r.read() or "null")
    except (urllib.error.HTTPError, urllib.error.URLError, OSError, ValueError):
        return None


def _token():
    if not (AUTH_METHOD_ID and PASSWORD):
        return None
    out = _call(f"auth-methods/{AUTH_METHOD_ID}:authenticate", "POST",
                {"attributes": {"login_name": LOGIN, "password": PASSWORD}})
    if not out:
        return None
    return (out.get("attributes") or {}).get("token") or out.get("token")


def _names(token):
    """Resolve the opaque ids Boundary records into the names an auditor reads.

    `u_rAOgVpmcyW reached ttcp_wRSYiGwYZD` is not an audit record — it is a lookup exercise
    handed to whoever is trying to establish what happened. Boundary stores ids because they
    are stable; a page that shows them raw makes the reader do the join by hand, usually
    against a system they do not have access to.

    Fetched once per request and passed down, rather than per session.
    """
    users, targets = {}, {}
    if ORG_ID:
        for u in (_call(f"users?scope_id={ORG_ID}", token=token) or {}).get("items") or []:
            # The login name is what appears in the identity provider and on the incident
            # report; the full name is decoration when there is one.
            users[u.get("id")] = u.get("name") or u.get("id")
    if SCOPE_ID:
        for t in (_call(f"targets?scope_id={SCOPE_ID}", token=token) or {}).get("items") or []:
            targets[t.get("id")] = {
                "name": t.get("name") or t.get("id"),
                "port": t.get("attributes", {}).get("default_port") or t.get("default_port"),
            }
    return users, targets


def _total(conns, field):
    """Sum a byte counter across a session's connections, or None if none were retrieved."""
    if not conns:
        return None
    out = 0
    for c in conns:
        try:
            out += int(c.get(field) or 0)
        except (TypeError, ValueError):
            pass
    return out


def _shape(item, users, targets):
    """One session, as an access record rather than a status line.

    Every field here answers a question an auditor asks of a session: who, from where, to what,
    when, for how long, how much moved, and why it ended.
    """
    conns = item.get("connections") or []
    tgt = targets.get(item.get("target_id")) or {}
    states = item.get("states") or []

    # The states list carries the transition timestamps; the newest is first.
    ended = next((st.get("start_time") for st in states
                  if st.get("status") in ("terminated", "canceling")), None)

    return {
        "id": item.get("id"),
        "status": item.get("status"),
        "active": item.get("status") in ACTIVE_STATES,

        # WHO — resolved, with the id kept so it can still be correlated with Boundary's logs.
        "principal": users.get(item.get("user_id")) or item.get("user_id"),
        "user_id": item.get("user_id"),

        # WHAT they were authorized to reach, and where that actually went.
        "target": tgt.get("name") or item.get("target_id"),
        "target_id": item.get("target_id"),
        "endpoint": item.get("endpoint"),

        # FROM WHERE. Present only on a detail read; None means not retrieved, not "no client".
        "client_address": (conns[0].get("client_tcp_address") if conns else None),

        # WHEN, and for how long.
        "created_time": item.get("created_time"),
        "expiration_time": item.get("expiration_time"),
        "ended_time": ended,
        "updated_time": item.get("updated_time"),

        # HOW MUCH moved — the measure of what a session could have carried out.
        "connection_count": len(conns),
        # Coerced: Boundary returns these as STRINGS in JSON (64-bit counters), so summing
        # them raw raises rather than adding.
        "bytes_up": _total(conns, "bytes_up"),
        "bytes_down": _total(conns, "bytes_down"),

        # WHY it ended, and what authenticated it — the link back to the login event.
        "termination_reason": item.get("termination_reason"),
        "auth_token_id": item.get("auth_token_id"),
        "detailed": bool(conns or states),
    }


def _parse(ts):
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None


def _attribute(items):
    """Name the people who were signed on while each session was open.

    Boundary authenticates a POOL principal (analyst-s1..sN) and sees every connection arriving
    from the distributor, so its own record cannot say which analyst used which session. The
    person is known on the platform side instead, from the sign-on record.

    The join is a time overlap, which does not produce a unique answer when several analysts
    are working at once. `attribution` says which case each row is, so a session is never
    presented as belonging to one person on evidence that cannot support it.
    """
    # Bounded by the window the sessions on this page actually span, not by a row count.
    opens = [o for o in (_parse(i.get("created_time")) for i in items) if o]
    earliest = min(opens) - SIGNON_IDLE_GRACE if opens else None
    signons = SsoSession.objects.filter(started_at__isnull=False)
    if earliest:
        # A sign-on matters here only if it could still have been open when the earliest
        # session on the page started.
        signons = signons.filter(Q(ended_at__isnull=True) | Q(ended_at__gte=earliest),
                                 last_seen_at__gte=earliest - SIGNON_IDLE_GRACE)
    windows = [
        # An un-ended sign-on is an OPEN interval. Collapsing it to last_seen_at ended the
        # analyst's window at their last request, so the moment the broker re-established
        # their session — routine, and invisible to them — the new session opened after that
        # instant and the page reported that nobody was using it.
        (s.started_at,
         s.ended_at or (s.last_seen_at + SIGNON_IDLE_GRACE if s.last_seen_at else None),
         s.username, s.workstation)
        for s in signons.order_by("-started_at")
    ]
    for item in items:
        opened = _parse(item.get("created_time"))
        closed = _parse(item.get("ended_time"))
        pinned_ws = _principal_workstation(item.get("principal"))
        item["pinned_workstation"] = pinned_ws
        if opened is None:
            # No start time to compare against. Reported as unknown rather than as nobody:
            # an empty analyst list would read as "no one used this session".
            item["analysts"] = []
            item["workstations"] = []
            item["attribution"] = "unknown"
            continue
        matched = [w for w in windows if _overlaps(w, opened, closed)]
        # The session's principal names a workstation by configuration (the distributor pins that
        # workstation's connections to it), and a sign-on names its workstation from the kiosk's own
        # statement. When both sides speak, the join narrows to the sign-ons from THAT workstation.
        if pinned_ws:
            narrowed = [w for w in matched if w[3] == pinned_ws]
            if narrowed:
                matched = narrowed
        item["analysts"] = sorted({user for (_s, _e, user, _ws) in matched})
        item["workstations"] = sorted({ws for (_s, _e, _u, ws) in matched if ws})
        item["attribution"] = ("none" if not matched
                               else "exact" if len(item["analysts"]) == 1
                               else "overlapping")


def _overlaps(window, opened, closed):
    """Whether a sign-on window overlaps a session window.

    A session still open has no end, which is an open interval rather than a zero-length one —
    treating a missing end as the start would exclude every session currently in use.
    """
    start, end, _user, _ws = window
    if closed is not None and start > closed:
        return False
    return end is None or end >= opened


def overview(include_terminated=True, limit=None, offset=0):
    """Brokered sessions Boundary knows about, newest first, one bounded window at a time."""
    if not AUTH_METHOD_ID:
        return {"reachable": False,
                "error": "Boundary is not provisioned for this deployment (no auth method id)",
                "sessions": [], "active": 0, "total": 0}

    token = _token()
    if not token:
        return {"reachable": False,
                "error": "could not authenticate to Boundary as the session auditor — check its account and the controller certificate",
                "sessions": [], "active": 0, "total": 0}

    q = f"sessions?scope_id={SCOPE_ID}" if SCOPE_ID else "sessions"
    if include_terminated:
        # Boundary lists only active sessions unless asked; an access record that silently
        # drops everything already closed is not an access record.
        q += ("&" if "?" in q else "?") + "include_terminated=true"
    out = _call(q, token=token)
    if out is None:
        return {"reachable": False,
                "error": "Boundary did not answer the session list",
                "sessions": [], "active": 0, "total": 0}

    raw = out.get("items") or []
    raw.sort(key=lambda s: s.get("created_time") or "", reverse=True)
    total = len(raw)

    # A live session is never paged out of the answer: the running fleet is what an operator
    # acts on, and it must not fall off the end as closed sessions accumulate in front of it.
    size = PAGE_LIMIT if limit is None else max(1, min(int(limit), MAX_PAGE_LIMIT))
    start = max(0, int(offset or 0))
    live = [i for i in raw if (i.get("status") or "") in ACTIVE_STATES]
    live_ids = {i.get("id") for i in live}
    rest = [i for i in raw if i.get("id") not in live_ids]
    window = (live + rest[start:start + size]) if start == 0 else rest[start:start + size]

    # Detail for the newest of the window — the recent ones are what an incident asks about.
    for i, item in enumerate(window[:DETAIL_LIMIT]):
        detail = _call(f"sessions/{item.get('id')}", token=token)
        if detail:
            window[i] = detail.get("item", detail)

    users, targets = _names(token)
    items = [_shape(i, users, targets) for i in window]
    _attribute(items)
    return {
        "reachable": True,
        "sessions": items,
        "active": sum(1 for s in items if s["active"]),
        "shown": len(items),
        "offset": start,
        "truncated": len(items) < total,
        # The whole record, not the size of this window: a page that reported its own length
        # as the total would say the deployment had fewer sessions than it has.
        "total": total,
    }
