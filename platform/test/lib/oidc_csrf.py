#!/usr/bin/env python3
"""
CSRF-cookie eviction driver — proves a page load's worth of API calls cannot destroy the
login flow the analyst is standing in.

The gate mints a CSRF cookie PER authentication attempt and caps how many it will keep.
Eviction is oldest-first, and the oldest is the navigation already in progress: the flow the
analyst started is exactly the one that gets discarded. With `--skip-provider-button` every
unauthenticated request 302s straight to the IdP and mints one, so the SPA's parallel data
calls each start an attempt of their own — a single page view produced four in one second
against a ceiling of three, and the callback then came back to a cookie that was gone:
"403 Forbidden ... CSRF cookie was not found", with Go Back as the only way out.

Reproduced the way it actually happens, which is why the flow is held OPEN across the data
calls: a forced password change is the reliable trigger because it keeps the attempt alive
long enough for the rest of the shell to pile up behind it.

  oidc_csrf.py <app_url> <username> <initial_password> <rotate_to> [api_path ...]

The account must be in its forced-change state — that is the state that holds the flow open,
and a run that finds the flow already complete proves nothing and says so.

Emits one KEY VALUE line per observation and exits 0 only when the flow survived:

  NAV_MINTED n          CSRF cookies the navigation minted (one attempt = one cookie)
  PROBE_ACCEPT hdr      the Accept the probes sent — the gate 401s AJAX on this header alone
  API_STATUS path code  what each data call answered — 401 is the fix, 302 is the defect
  API_MINTED n          CSRF cookies the data calls minted (0 is the fix)
  POLL_MINTED n         and what six polling cycles minted while the flow stayed open
  NAV_SURVIVED 0|1      the navigation's own cookie still present when the callback ran
  FLOW OK|FAIL: ...     the held-open flow completed through the callback
"""
import http.cookiejar
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE   # platform CA is self-signed; this is a test client

UA = "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"

# What the app shell actually issues on load — taken from what the SPA requests, NOT from
# what the gate was configured to answer. Listing only the paths already covered is how a
# test comes to agree with the fix instead of checking it: `/index.html` is polled every 30
# seconds by DeployWatch, is not under /api/, and was minting an attempt each time.
DEFAULT_API = ["/api/me/", "/api/stats/", "/api/facets/", "/api/investigations/",
               "/index.html?_=1", "/api/version/"]

# Exactly what the SPA's fetch wrapper sends (frontend/src/api.js) — and specifically NOT
# `Accept: application/json`. The gate answers 401 for anything that looks like AJAX, by the
# Accept header alone and whatever the path: sending one here would produce a 401 attributable
# to two mechanisms at once, and the test would pass with --api-route removed. The SPA sets
# Content-Type and no Accept, so fetch's own `*/*` is what actually arrives.
PROBE_HEADERS = {"Accept": "*/*", "Content-Type": "application/json"}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """A data call must be judged on what the gate ANSWERED, not where it ended up.

    Followed, a 302 to the IdP arrives as a 200 carrying a login page — indistinguishable
    from success unless the body is inspected, and the mint has already happened by then.
    """
    def redirect_request(self, *_a, **_kw):
        return None


def csrf_names(jar):
    return {c.name for c in jar if c.name.startswith("_oauth2_proxy") and c.name.endswith("_csrf")}


def form_action(page):
    m = re.search(r'action="([^"]+)"', page)
    return m.group(1).replace("&amp;", "&") if m else None


def main(app_url, user, password, rotate_to, api_paths):
    jar = http.cookiejar.CookieJar()
    browser = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=ctx))
    # Shares the jar, so a mint by a data call is visible to the flow it would evict.
    fetcher = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=ctx),
        NoRedirect())
    for op in (browser, fetcher):
        op.addheaders = [("User-Agent", UA)]

    origin = "{0.scheme}://{0.netloc}".format(urllib.parse.urlsplit(app_url))

    # 1. The navigation. One attempt, therefore one cookie.
    try:
        with browser.open(app_url, timeout=25) as r:
            page = r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        print(f"FLOW FAIL: navigation returned HTTP {exc.code}")
        return 1
    nav = csrf_names(jar)
    print(f"NAV_MINTED {len(nav)}")
    action = form_action(page)
    if not action:
        print("FLOW FAIL: no login form — the navigation did not reach the identity provider")
        return 1

    # 2. Credentials. The forced change leaves the attempt open, mid-flow, callback not yet run.
    data = urllib.parse.urlencode({"username": user, "password": password,
                                   "credentialId": ""}).encode()
    try:
        with browser.open(urllib.request.Request(action, data=data), timeout=25) as r:
            page = r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        print(f"FLOW FAIL: login POST returned HTTP {exc.code}")
        return 1
    if "Invalid username or password" in page:
        print("FLOW FAIL: credentials rejected")
        return 1
    if "password-new" not in page:
        # Not a pass. Without a held-open flow there is no window for the data calls to
        # evict anything, so the run would agree with itself whether the gate were fixed
        # or not — the shape of green result this whole test exists to distrust.
        print("FLOW FAIL: no forced password change — re-provision the account first, "
              "an already-rotated account cannot hold the flow open")
        return 2

    held = csrf_names(jar)

    # 3. The page load lands ON TOP of the open flow. Each of these would start an attempt
    #    of its own were API paths not answered directly.
    minted_by_api = set()
    print("PROBE_ACCEPT " + PROBE_HEADERS["Accept"])
    for path in api_paths:
        try:
            with fetcher.open(urllib.request.Request(
                    origin + path, headers=PROBE_HEADERS), timeout=20) as r:
                code, where = r.getcode(), ""
        except urllib.error.HTTPError as exc:
            code = exc.code
            where = exc.headers.get("Location", "") or ""
        except Exception as exc:
            print(f"API_STATUS {path} error:{type(exc).__name__}")
            continue
        # The destination is reported as IdP-or-not rather than verbatim: these reports are
        # published, and the redirect target carries the deployment's own address.
        dest = " ->idp" if "openid-connect" in where or "/realms/" in where else ""
        print(f"API_STATUS {path} {code}{dest}")
        minted_by_api |= (csrf_names(jar) - held - minted_by_api)

    print(f"API_MINTED {len(minted_by_api)}")

    # A page load is one burst; a login takes MINUTES. DeployWatch polls every 30 seconds for
    # as long as the tab is open, so the question is not whether one page load fits under the
    # ceiling but whether an idle unauthenticated tab exhausts it while someone types a new
    # password. Six polls is three minutes of waiting — less than a forced change takes.
    minted_by_poll = set()
    for _ in range(6):
        try:
            with fetcher.open(urllib.request.Request(
                    origin + "/index.html?_=poll", headers=PROBE_HEADERS), timeout=20):
                pass
        except urllib.error.HTTPError:
            pass
        except Exception:
            break
        minted_by_poll |= (csrf_names(jar) - held - minted_by_api - minted_by_poll)
    print(f"POLL_MINTED {len(minted_by_poll)}")

    survived = 1 if held and held <= csrf_names(jar) else 0
    print(f"NAV_SURVIVED {survived}")

    # 4. Complete the held-open flow. This is the callback that returned 403.
    action = form_action(page)
    if not action:
        print("FLOW FAIL: update-password page carries no form action")
        return 1
    data = urllib.parse.urlencode({"password-new": rotate_to,
                                   "password-confirm": rotate_to}).encode()
    try:
        with browser.open(urllib.request.Request(action, data=data), timeout=25) as r:
            final, page = r.geturl(), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        detail = "CSRF cookie missing at the callback" if exc.code == 403 else ""
        print(f"FLOW FAIL: callback returned HTTP {exc.code} {detail}".rstrip())
        return 1
    if "CSRF" in page or "/error" in final:
        print("FLOW FAIL: the callback refused the returning flow")
        return 1

    try:
        with browser.open(app_url, timeout=20) as r:
            code = r.getcode()
    except urllib.error.HTTPError as exc:
        code = exc.code
    if code != 200:
        print(f"FLOW FAIL: app returned {code} after the flow completed")
        return 1

    print("FLOW OK")
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 5:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4],
                  sys.argv[5:] or DEFAULT_API))
