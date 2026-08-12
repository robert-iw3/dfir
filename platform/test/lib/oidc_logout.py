#!/usr/bin/env python3
"""
Headless sign-out driver — proves the logout chain ends BOTH sessions.

Sign-out has to tear down three things in order: the local token, the oauth2-proxy
cookie, and the Keycloak session. Dropping only the first two leaves the IdP session
alive, so the next request re-authenticates silently and the user is never signed out.
That failure is invisible to a check that only looks for a 200 after logout — the app
returns 200 either way. This driver distinguishes them by asserting the browser lands
on the Keycloak *login form*, not on the app.

It performs:
  1. full authorization-code login (must reach the app authenticated)
  2. GET /oauth2/sign_out?rd=<Keycloak end-session endpoint>
  3. GET the app again with the same cookie jar → must land on the login form

Usage: oidc_logout.py <sso_base> <app_url> <username> <password>
Exit 0 = both sessions ended. Prints one summary line.
"""
import http.cookiejar
import re
import ssl
import sys
import urllib.parse
import urllib.request

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE   # platform CA is self-signed; this is a test client

UA = "Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0"


def opener():
    jar = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=ctx),
    )
    op.addheaders = [("User-Agent", UA)]
    return op, jar


def is_login_form(html):
    return "kc-form-login" in html or re.search(r'action="[^"]*openid-connect/auth', html)


def main(sso_base, app_url, user, password):
    op, jar = opener()

    # 1. Log in through the real authorization-code flow.
    with op.open(app_url, timeout=25) as r:
        page = r.read().decode("utf-8", "replace")
    m = re.search(r'action="([^"]+)"', page)
    if not m:
        print("FAIL: no login form on the Keycloak page")
        return 1
    action = m.group(1).replace("&amp;", "&")
    body = urllib.parse.urlencode({"username": user, "password": password}).encode()
    with op.open(urllib.request.Request(action, data=body), timeout=25) as r:
        after = r.read().decode("utf-8", "replace")
        landed = r.geturl()
    if is_login_form(after):
        print(f"FAIL: {user} was not authenticated (still on the login form)")
        return 1

    names = sorted(c.name for c in jar)
    if "_oauth2_proxy" not in names:
        print(f"FAIL: no gate session cookie after login (got: {','.join(names) or 'none'})")
        return 1

    # 2. Sign out: the gate drops its cookie, then hands off to Keycloak's end-session
    #    endpoint, which ends the IdP session and returns the browser to the app.
    origin = "{0.scheme}://{0.netloc}".format(urllib.parse.urlsplit(app_url))
    end_session = (
        origin + "/realms/irplatform/protocol/openid-connect/logout"
        "?client_id=ir-platform"
        "&post_logout_redirect_uri=" + urllib.parse.quote(origin + "/", safe="")
    )
    sign_out = origin + "/oauth2/sign_out?rd=" + urllib.parse.quote(end_session, safe="")
    with op.open(sign_out, timeout=25) as r:
        r.read()

    # 3. Revisit the app.
    #    prompt and serve the app; a properly ended one must show the login form again.
    with op.open(app_url, timeout=25) as r:
        final = r.read().decode("utf-8", "replace")
        final_url = r.geturl()

    if not is_login_form(final):
        print(f"FAIL: {user} still authenticated after sign-out — "
              f"the IdP session survived (landed on {final_url})")
        return 1

    left = sorted(c.name for c in jar)
    print(f"OK: {user} signed out of app and IdP; re-entry hits the Keycloak login form "
          f"(cookies left: {','.join(left) or 'none'})")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 5:
        print(__doc__.strip())
        sys.exit(2)
    sys.exit(main(*sys.argv[1:]))
