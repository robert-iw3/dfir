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

Usage: oidc_login.py <sso_base> <app_url> <username> <password>
Exit 0 = the role logged in end to end. Prints one summary line.
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


def main(sso_base, app_url, user, password):
    op, jar = build_opener()
    op.addheaders = [("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0")]

    # 1. Ask oauth2-proxy where to send the browser (the Keycloak authorize URL).

    # 2. Load the Keycloak login page and extract its form action.
    # Hit the app; unauthenticated, the SSO gate redirects through to the Keycloak
    # login page. urllib follows the chain for us.
    with op.open(app_url, timeout=25) as r:
        page = r.read().decode("utf-8", "replace")
    m = re.search(r'action="([^"]+)"', page)
    if not m:
        print("FAIL: no login form on the Keycloak page")
        return 1
    action = m.group(1).replace("&amp;", "&")

    # 3. Submit credentials. The resulting redirect chain runs the callback.
    data = urllib.parse.urlencode({"username": user, "password": password,
                                   "credentialId": ""}).encode()
    try:
        with op.open(urllib.request.Request(action, data=data), timeout=25) as r:
            final_url, body = r.geturl(), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        print(f"FAIL: login POST -> HTTP {exc.code}")
        return 1

    if "/error" in final_url:
        print(f"FAIL: callback errored (landed on {final_url})")
        return 1
    if "Invalid username or password" in body:
        print("FAIL: credentials rejected by Keycloak")
        return 1

    # 4. The session must now authenticate against the protected app.
    try:
        with op.open(app_url, timeout=20) as r:
            code = r.getcode()
    except urllib.error.HTTPError as exc:
        code = exc.code
    if code != 200:
        print(f"FAIL: app returned {code} after login (session not accepted)")
        return 1

    cookies = ",".join(sorted({c.name for c in jar}))
    print(f"OK: {user} completed the browser OIDC flow (app 200; cookies: {cookies})")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 5:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(*sys.argv[1:]))
