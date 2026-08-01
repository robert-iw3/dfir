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
cancelled or expired, and showing a stale row as live is the failure that matters most on an
audit page.
"""
from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request

BOUNDARY_ADDR = os.environ.get("IR_BOUNDARY_ADDR", "https://boundary:9200")
BOUNDARY_CACERT = os.environ.get("IR_BOUNDARY_CACERT") or None
LOGIN = os.environ.get("IR_BOUNDARY_SESSION_AUDITOR_LOGIN", "session-auditor")
PASSWORD = os.environ.get("IR_BOUNDARY_SESSION_AUDITOR_PASSWORD", "")
AUTH_METHOD_ID = os.environ.get("BOUNDARY_AUTH_METHOD_ID", "")
SCOPE_ID = os.environ.get("BOUNDARY_PROJECT_ID", "")

# Boundary's own vocabulary, kept rather than renamed: an operator reading this page and then
# running `boundary sessions list` should see the same words.
ACTIVE_STATES = {"active", "pending"}
ORG_ID = os.environ.get("BOUNDARY_ORG_ID", "")

# How many sessions get a detail read. `connections` and the state timeline come only from a
# session READ, never the list — and an access record grows without limit, so a page that fans
# out over all of it stops loading exactly when an incident makes it busy.
DETAIL_LIMIT = int(os.environ.get("IR_BOUNDARY_SESSION_DETAIL_LIMIT", "25"))


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


def overview(include_terminated=True):
    """Every brokered session Boundary knows about, newest first."""
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
    # Newest first, then detail for those — the recent ones are what an incident asks about.
    for i, item in enumerate(raw[:DETAIL_LIMIT]):
        detail = _call(f"sessions/{item.get('id')}", token=token)
        if detail:
            raw[i] = detail.get("item", detail)

    users, targets = _names(token)
    items = [_shape(i, users, targets) for i in raw]
    return {
        "reachable": True,
        "sessions": items,
        "active": sum(1 for s in items if s["active"]),
        "total": len(items),
    }
