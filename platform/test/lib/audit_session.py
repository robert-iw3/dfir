#!/usr/bin/env python3
"""
Drives one analyst sign-on all the way through, so the audit trail can be asserted against
what a session actually did rather than against a synthetic API call.

The sequence is a shift in miniature: sign in through the real OIDC flow, read, write, then
sign out. Each step prints one `KEY=value` line, and the UAT compares those against the audit
entries the platform recorded for the same window.

The whole run uses ONE cookie jar. That is the point: login must be recorded once for the
session and not once per request, and only a client that keeps its session can tell the
difference.

Usage: audit_session.py <sso_base> <app_url> <username> <password> [rotate_to]
"""
import json
import sys
import urllib.error
import urllib.request

sys.path.insert(0, "/uatlib")
import oidc_login   # noqa: E402  (mounted alongside this file)


def call(op, url, method="GET", body=None):
    """(status, parsed_body). A non-2xx is returned, not raised — the status IS the result."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with op.open(req, timeout=25) as r:
            raw = r.read().decode("utf-8", "replace")
            status = r.getcode()
    except urllib.error.HTTPError as exc:
        raw, status = exc.read().decode("utf-8", "replace"), exc.code
    except Exception as exc:
        return 0, {"error": str(exc)}
    try:
        return status, json.loads(raw)
    except ValueError:
        return status, {}


def main(sso_base, app_url, user, password, rotate_to=None, ws_id=None):
    code, message, op, _jar = oidc_login.login(sso_base, app_url, user, password, rotate_to,
                                               ws_id=ws_id)
    if code != 0:
        print(f"LOGIN={code}")
        print(f"MESSAGE={message}")
        return 1
    base = app_url.rstrip("/")
    print("LOGIN=0")

    status, me = call(op, f"{base}/api/me/")
    print(f"ME={status}")
    print(f"USERNAME={me.get('username', '')}")
    print(f"ROLE={me.get('role', '')}")

    # Several reads. None of them may add a sign-on: a login recorded per request would make
    # the trail unreadable and the session count meaningless.
    for _ in range(3):
        call(op, f"{base}/api/investigations/")

    # A write that IS audited by its call site — recorded as `note.create` with case detail.
    status, created = call(op, f"{base}/api/notes/", "POST",
                           {"body": "uat audit-trail probe", "investigation": 1})
    print(f"AUDITED_WRITE={status}")
    note_id = created.get("id", "")
    print(f"AUDITED_WRITE_ID={note_id}")

    # The same resource, edited. Nothing audits the viewset's update, so this is the case the
    # catch-all exists for — and doing both on one resource shows the two paths producing one
    # entry each rather than two for the same action.
    if note_id:
        status, _ = call(op, f"{base}/api/notes/{note_id}/", "PATCH",
                         {"body": "uat audit-trail probe, edited"})
    else:
        status = 0
    print(f"WRITE={status}")
    print(f"WRITE_ID={note_id}")

    status, out = call(op, f"{base}/api/auth/logout/", "POST", {})
    print(f"LOGOUT={status}")
    print(f"LOGOUT_RECORDED={out.get('signed_out')}")
    print(f"LOGOUT_SESSION={out.get('session_id', '')}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) not in (5, 6, 7):
        print(__doc__)
        sys.exit(2)
    sys.exit(main(*sys.argv[1:]))
