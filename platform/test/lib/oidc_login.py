#!/usr/bin/env python3
"""
Headless OIDC browser-flow driver — exercises the REAL authorization-code flow the way a
browser does, so the callback path is actually validated (a ROPC token request does NOT
exercise it, which is how an issuer/host bug hid behind a "green" SSO UAT once already).

It performs, per role:
  1. GET the oauth2-proxy login URL   → the Keycloak authorize redirect
  2. POST the Keycloak login form → the auth code
  3. follow the redirect to oauth2-proxy's /api/oauth/callback/generic → session cookie
  4. GET the protected app with that cookie → must be authenticated (not 401)

Usage: oidc_login.py <sso_base> <app_url> <username> <password> [rotate_to]
Exit 0 = the role logged in end to end. Prints one summary line.

Accounts are provisioned with a forced password update at first login. When Keycloak
presents that form, `rotate_to` completes it (the login then ends on the NEW password);
without it, the driver reports the demand distinctly so a test can assert enforcement.
"""
import http.cookiejar
import json
import re
import ssl
import sys
import urllib.parse
import urllib.request

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE   # platform CA is self-signed; this is a test client


def build_opener():
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=ctx),
    ), jar


def login(sso_base, app_url, user, password, rotate_to=None, ws_id=None):
    """Walk the flow. Returns (code, message, opener, jar).

    The opener is returned still holding the session, so a caller can keep going as the same
    signed-in analyst — a test that has to observe what a session DOES cannot start over,
    because a second login is a second session.

    `ws_id` appends the kiosk's workstation token to the UA, the same way launch.sh does, so
    a test can present as a specific workstation for attribution assertions.
    """
    op, jar = build_opener()
    ua = "Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0"
    if ws_id:
        ua += f" IR-WS/{ws_id}"
    op.addheaders = [("User-Agent", ua)]

    # 1. Ask oauth2-proxy where to send the browser (the Keycloak authorize URL).

    # 2. Load the Keycloak login page and extract its form action.
    with op.open(app_url, timeout=25) as r:
        page = r.read().decode("utf-8", "replace")
    m = re.search(r'action="([^"]+)"', page)
    if not m:
        return 1, "FAIL: no login form on the Keycloak page", op, jar
    action = m.group(1).replace("&amp;", "&")

    # 3. Submit credentials.
    data = urllib.parse.urlencode({"username": user, "password": password,
                                   "credentialId": ""}).encode()
    try:
        with op.open(urllib.request.Request(action, data=data), timeout=25) as r:
            final_url, body = r.geturl(), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return 1, f"FAIL: login POST -> HTTP {exc.code}", op, jar

    if "/error" in final_url:
        return 1, f"FAIL: callback errored (landed on {final_url})", op, jar
    if "Invalid username or password" in body:
        return 1, "FAIL: credentials rejected by Keycloak", op, jar

    # Forced first-login password update. The form's field names are Keycloak's own
    # (password-new / password-confirm); its presence IS the enforcement.
    if "password-new" in body:
        if not rotate_to:
            return 3, "UPDATE_REQUIRED: Keycloak demands a password change before any session", op, jar
        m = re.search(r'action="([^"]+)"', body)
        if not m:
            return 1, "FAIL: update-password page carries no form action", op, jar
        data = urllib.parse.urlencode({"password-new": rotate_to,
                                       "password-confirm": rotate_to}).encode()
        try:
            with op.open(urllib.request.Request(m.group(1).replace("&amp;", "&"), data=data),
                         timeout=25) as r:
                final_url, body = r.geturl(), r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            return 1, f"FAIL: password update POST -> HTTP {exc.code}", op, jar
        if "password-new" in body or "/error" in final_url:
            return 1, "FAIL: the new password was refused (policy?) — still on the update form", op, jar

    # 4. The session must now authenticate against the protected app.
    try:
        with op.open(app_url, timeout=20) as r:
            code = r.getcode()
    except urllib.error.HTTPError as exc:
        code = exc.code
    if code != 200:
        return 1, f"FAIL: app returned {code} after login (session not accepted)", op, jar

    cookies = ",".join(sorted({c.name for c in jar}))
    return 0, f"OK: {user} completed the browser OIDC flow (app 200; cookies: {cookies})", op, jar


def main(sso_base, app_url, user, password, rotate_to=None):
    code, message, _op, _jar = login(sso_base, app_url, user, password, rotate_to)
    print(message)
    return code


if __name__ == "__main__":
    if len(sys.argv) not in (5, 6):
        print(__doc__)
        sys.exit(2)
    sys.exit(main(*sys.argv[1:]))
