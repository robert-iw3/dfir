#!/usr/bin/env python3
"""
Concurrent analyst agents — the driver behind test/uat_load.sh.

Each agent is one simulated analyst: its own credentials, its own cookie jar, its own
server-side session, driving the REAL path — the platform name, the brokered port, the SSO
gate, a full OIDC login with the forced password change — with a real browser User-Agent.
Nothing talks to a backend port directly; a load test beside the ingress measures a
platform nobody deploys.

Phases, run in one process because the sessions live in it:

  storm     every agent logs in at once (the 09:00 problem). Per-login timing.
  activity  a sustained window of SPA-shaped work. Reads, the 30-second poll pair, and
            WRITES that deliberately collide: every writer appends notes to the same
            investigation, and re-adjudicates the same small finding set, because lock
            contention and lost updates only exist where writers overlap.
  ramp      concurrency steps up until latency crosses the ceiling or errors appear.
            The knee — the largest step that held — is the measured capacity of the
            design, and finding it is this phase's success condition.

Throughout, every agent re-asserts its own identity (`/api/me/` must answer with ITS
username — a session-bleed check that only means something under concurrency), and every
write the driver believes succeeded goes into a client-side ledger the UAT reconciles
against the database EXACTLY. `>=` is not accounting.

Usage: load_agents.py <config.json>
Emits one JSON document on stdout; everything else goes to stderr.
"""
import http.client
import json
import re
import ssl
import sys
import random
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE   # platform CA is self-signed; this is a test client

UA = "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"

# The verdict pair the contention writers alternate between. Both are non-terminal working
# verdicts, so churning them stresses the precedence machinery without asserting anything
# false about the corpus — and the UAT restores the originals afterwards.
CHURN_VERDICTS = ("Likely True Positive", "Indeterminate")


def pct(sorted_ms, p):
    if not sorted_ms:
        return None
    return sorted_ms[min(len(sorted_ms) - 1, int(len(sorted_ms) * p / 100))]


class Session:
    """ONE persistent connection per agent — the shape a workstation actually presents.

    urllib opens a fresh TCP connection per request. Fifty agents doing that manufacture
    hundreds of simultaneous connections through the brokered session, which no browser
    would: the ingress negotiates h2, so a real analyst drives a whole page over ONE
    connection. Measuring the platform against a client it never serves reports a limit that
    does not exist — and did, until this replaced it.

    Keep-alive over HTTP/1.1 is the closest honest model available here: one connection per
    agent, reused for every request including the login flow (Keycloak is same-origin, so it
    needs no second connection).
    """

    def __init__(self, base):
        u = urllib.parse.urlsplit(base)
        self.host, self.port = u.hostname, u.port or 443
        self.origin = f"{u.scheme}://{u.netloc}"
        self.cookies = {}
        self._lock = threading.Lock()
        # Requests re-sent after reaching the server. A GET is safe to repeat at the transport
        # layer but not always at the application's: an endpoint that RECORDS the attempt sees
        # two, so anything reconciling a server-side ledger needs this count.
        self.resent = 0
        # One connection PER THREAD, not per Session: http.client is not thread-safe, and two threads on
        # one socket interleave requests and corrupt the TLS stream.
        self._tl = threading.local()

    @property
    def conn(self):
        return getattr(self._tl, "conn", None)

    @conn.setter
    def conn(self, value):
        self._tl.conn = value

    def _connect(self):
        self.conn = http.client.HTTPSConnection(self.host, self.port, context=ctx, timeout=30)

    def _cookie_header(self):
        with self._lock:
            return "; ".join(f"{k}={v}" for k, v in self.cookies.items())

    def _absorb(self, headers):
      with self._lock:
        for value in headers.get_all("Set-Cookie") or []:
            pair = value.split(";", 1)[0].strip()
            if "=" not in pair:
                continue
            name, _, val = pair.partition("=")
            # An expiry in the past is a deletion; keeping it would resend a cookie the
            # server has just retired — which is how a stale CSRF cookie outlives its flow.
            if "expires=Thu, 01 Jan 1970" in value or "Max-Age=0" in value:
                self.cookies.pop(name, None)
            else:
                self.cookies[name] = val

    def request(self, method, path, body=None, headers=None, follow=8):
        """Send one request on the persistent connection, following same-origin redirects."""
        url = path if path.startswith("http") else self.origin + path
        for _ in range(follow + 1):
            u = urllib.parse.urlsplit(url)
            target = u.path + (("?" + u.query) if u.query else "")
            h = {"User-Agent": UA, "Accept": "*/*", "Connection": "keep-alive"}
            h.update(headers or {})
            if self.cookies:
                h["Cookie"] = self._cookie_header()
            for attempt in (1, 2, 3, 4):
                # Whether the request was PUT ON THE WIRE decides if retrying is safe. A POST
                # that committed and then lost its response would be applied twice, and the
                # database ends up ahead of the agent's own ledger — which the fidelity
                # assertions correctly report as a lost or doubled write.
                sent = False
                # Bytes may reach the server from here on. `sent` is stricter — it means the
                # write COMPLETED — and a write that failed part way may still have delivered
                # a whole request, so retrying it can double a row the agent counts once.
                wrote = False
                try:
                    if self.conn is None:
                        self._connect()
                    wrote = True
                    self.conn.request(method, target, body=body, headers=h)
                    sent = True
                    resp = self.conn.getresponse()
                    payload = resp.read()
                    break
                except Exception:
                    # Two normal client behaviors, not platform errors: a kept-alive
                    # connection the server has since closed fails on first use, and a cold
                    # connection setup can be dropped while the distributor paces a burst —
                    # every real browser retries both. Backoff spreads the retry out of the
                    # burst window; the retry COUNT is what the storm records as evidence.
                    try:
                        self.conn.close()
                    except Exception:
                        pass
                    self.conn = None
                    # Idempotent, or never sent: safe to retry. A mutation already on the wire
                    # is not, so it surfaces as the failure it was.
                    if attempt == 4 or (sent and method not in ("GET", "HEAD")):
                        raise
                    if wrote:
                        with self._lock:
                            self.resent += 1
                    # NO backoff on the first retry: the common case is a kept-alive connection the server closed mid-
                    # idle, where an immediate reconnect succeeds.
                    if attempt > 1:
                        time.sleep(0.4 * (attempt - 1) + random.random() * 0.4)
            self._absorb(resp.headers)
            if resp.status in (301, 302, 303, 307, 308) and follow:
                loc = resp.headers.get("Location")
                if not loc:
                    return resp.status, payload
                url = urllib.parse.urljoin(url, loc)
                # A redirect chain after a POST continues as GET, as a browser does.
                method, body = "GET", None
                headers = {k: v for k, v in (headers or {}).items()
                           if k.lower() != "content-type"}
                continue
            return resp.status, payload
        return resp.status, payload

    def close(self):
        try:
            if self.conn:
                self.conn.close()
        except Exception:
            pass


class Agent:
    def __init__(self, cfg, spec):
        self.base = cfg["base_url"].rstrip("/")
        self.username = spec["username"]
        self.password = spec["password"]
        self.rotated = spec["password"] + "-R1!"
        self.role = spec["role"]
        self.may_export = spec.get("export", False)
        self.s = Session(self.base)
        self.authenticated = False

    # ---- transport ----------------------------------------------------------------
    def req(self, method, path, body=None, timeout=30):
        """One timed request on this agent's own connection.

        Returns (status, ms, parsed-or-None, error-or-''). A 0 status means the transport
        failed, which is an availability event and is counted apart from a slow answer.
        """
        data = json.dumps(body).encode() if body is not None else None
        # Content-Type only, no Accept override: the SPA's fetch sends exactly this, and an
        # `Accept: application/json` would earn a 401 from the gate's AJAX shortcut rather
        # than from the path classification actually under test.
        headers = {"Content-Type": "application/json"} if data is not None else {}
        t0 = time.monotonic()
        try:
            status, payload = self.s.request(method, path, body=data, headers=headers)
            ms = (time.monotonic() - t0) * 1000
            try:
                return status, ms, json.loads(payload), ""
            except Exception:
                return status, ms, None, ""
        except Exception as exc:
            return 0, (time.monotonic() - t0) * 1000, None, f"{type(exc).__name__}: {exc}"[:160]

    # ---- the full OIDC browser flow ----------------------------------------------
    def login(self, attempts=10):
        """Log in, retrying only TRANSPORT failures — never an authentication refusal.

        The brokered session turns over periodically, and for the few seconds it takes to
        re-establish, every connection is refused. A real client retries that; aborting the
        whole run on it measures the moment rather than the platform. The retries are
        counted and returned so the outage still shows up rather than being smoothed away —
        the independent sampler records the same window from outside.
        """
        transport = ("ConnectionRefused", "ConnectionReset", "SSLEOFError",
                     "RemoteDisconnected", "TimeoutError", "SSLError", "socket")
        retried = 0
        for attempt in range(attempts):
            ms, err = self._login_once()
            if ms is not None or not any(t in err for t in transport):
                return ms, err, retried
            retried += 1
            self.s.close()
            # The brokered session's recovery is tens of seconds, not a few: cancel,
            # re-authenticate, reconnect, rebind. A retry budget shorter than that
            # measures the outage window rather than the platform.
            time.sleep(8)
        return None, err, retried

    def _login_once(self):
        """Navigate, credentials, forced change if demanded, callback, authenticated 200.

        All of it on ONE connection — Keycloak is served from the same origin, so a browser
        would not open a second one either.
        """
        t0 = time.monotonic()
        try:
            status, page = self.s.request("GET", "/")
            body = page.decode("utf-8", "replace")
            m = re.search(r'action="([^"]+)"', body)
            if not m:
                if "login" not in body.lower():
                    self.authenticated = True
                    return (time.monotonic() - t0) * 1000, ""
                return None, f"no login form (HTTP {status})"

            form = urllib.parse.urlencode({"username": self.username,
                                           "password": self.password,
                                           "credentialId": ""}).encode()
            hdr = {"Content-Type": "application/x-www-form-urlencoded"}
            status, page = self.s.request("POST", m.group(1).replace("&amp;", "&"),
                                          body=form, headers=hdr)
            body = page.decode("utf-8", "replace")

            if "Invalid username or password" in body:
                # The rotated credential, from an earlier phase of this same run.
                status, page = self.s.request("GET", "/")
                m0 = re.search(r'action="([^"]+)"', page.decode("utf-8", "replace"))
                if not m0:
                    self.authenticated = True
                    return (time.monotonic() - t0) * 1000, ""
                form = urllib.parse.urlencode({"username": self.username,
                                               "password": self.rotated,
                                               "credentialId": ""}).encode()
                status, page = self.s.request("POST", m0.group(1).replace("&amp;", "&"),
                                              body=form, headers=hdr)
                body = page.decode("utf-8", "replace")

            if "password-new" in body:
                m2 = re.search(r'action="([^"]+)"', body)
                if not m2:
                    return None, "update form carries no action"
                upd = urllib.parse.urlencode({"password-new": self.rotated,
                                              "password-confirm": self.rotated}).encode()
                status, page = self.s.request("POST", m2.group(1).replace("&amp;", "&"),
                                              body=upd, headers=hdr)
                if "password-new" in page.decode("utf-8", "replace"):
                    return None, "the new password was refused"

            code, _, _, err = self.req("GET", "/api/me/")
            if code != 200:
                return None, f"post-login me/ answered {code} {err}".strip()
            self.authenticated = True
            return (time.monotonic() - t0) * 1000, ""
        except Exception as exc:
            return None, f"{type(exc).__name__}: {exc}"[:200]


class Run:
    """Shared state across agents: results, the write ledger, violation counters."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.lock = threading.Lock()
        self.ops = []                      # (phase, cls, status, ms, error)
        self.ledger = {"notes": 0, "reclassify": [], "export_ok": 0, "export_denied": 0}
        self.violations = []               # confidentiality — must stay empty
        # How many identity/privilege checks actually RAN. Zero violations over zero checks
        # is not confidentiality held — it is confidentiality unmeasured, and the UAT treats
        # the two differently.
        self.conf_checks = 0
        # Requests that never reached an authorization decision. Kept apart so a server
        # error is never reported as a permission failure.
        self.rbac_unserved = 0
        self.export_unserved = 0
        # Export attempts the transport re-sent after they had already arrived: the platform
        # ledgers each arrival, so these are decisions the agent cannot account for.
        self.export_resent = 0
        self.expected_403 = 0              # RBAC refusals that are CORRECT under load
        self.marker = cfg["marker"]

    def record(self, phase, cls, status, ms, error="", resent=0):
        with self.lock:
            self.ops.append((phase, cls, status, round(ms, 1), error, resent))

    # ---- one activity iteration per agent -----------------------------------------
    def step(self, agent, phase, i):
        cfg = self.cfg
        inv = cfg["investigation_id"]

        # Identity, every iteration. Under concurrency this is the check that a session
        # store or a header path is not crossing streams — the only time it can fail.
        code, ms, body, err = agent.req("GET", "/api/me/")
        self.record(phase, "me", code, ms, err)
        if code == 200 and body:
            with self.lock:
                self.conf_checks += 1
                if body.get("username") != agent.username:
                    self.violations.append(
                        f"{agent.username} received identity {body.get('username')}")

        code, ms, _, err = agent.req("GET", f"/api/investigations/{inv}/stats/")
        self.record(phase, "read_stats", code, ms, err)
        code, ms, _, err = agent.req("GET", f"/api/findings/?investigation={inv}&page_size=25")
        self.record(phase, "read_findings", code, ms, err)
        code, ms, _, err = agent.req("GET", "/api/version/")
        self.record(phase, "poll", code, ms, err)

        if agent.role in ("analyst", "admin"):
            note = {"investigation": inv, "kind": "observation",
                    "summary": f"{self.marker} {agent.username} {phase} {i}",
                    "body": "load harness entry — removed by teardown"}
            r0 = agent.s.resent
            code, ms, body, err = agent.req("POST", "/api/notes/", note)
            self.record(phase, "write_note", code, ms, err, agent.s.resent - r0)
            if code == 201:
                with self.lock:
                    self.ledger["notes"] += 1
            # Contention on purpose: everyone re-adjudicates the same few findings.
            fid = cfg["finding_ids"][i % len(cfg["finding_ids"])]
            verdict = CHURN_VERDICTS[i % 2]
            r0 = agent.s.resent
            code, ms, body, err = agent.req(
                "POST", f"/api/findings/{fid}/reclassify/",
                {"verdict": verdict, "note": f"{self.marker} churn by {agent.username}"})
            self.record(phase, "write_verdict", code, ms, err, agent.s.resent - r0)
            if code == 200 and body:
                with self.lock:
                    self.ledger["reclassify"].append(
                        {"finding": fid, "id": body.get("reclassification_id")})
        else:
            # An auditor writing is a refusal, and the refusal is the passing outcome.
            note = {"investigation": inv, "kind": "observation",
                    "summary": f"{self.marker} {agent.username} must-fail"}
            code, ms, _, err = agent.req("POST", "/api/notes/", note)
            self.record(phase, "rbac_refusal", code, ms, err)
            with self.lock:
                # A 5xx is NOT an authorization decision — the request never reached the check, and counting it as
                # a failure-to-refuse reports a server error as a permission slip.
                if code >= 500 or code == 0 or code == 429:
                    self.rbac_unserved += 1
                else:
                    self.conf_checks += 1
                    if code == 403:
                        self.expected_403 += 1
                    else:
                        self.violations.append(
                            f"auditor {agent.username} write answered {code}")

        # The export right, exercised under load on a subset — completions and denials
        # both belong in the export ledger (B1.4), which the UAT reconciles.
        if i % 7 == 0:
            resent_before = agent.s.resent
            code, ms, _, err = agent.req(
                "GET", f"/api/findings/export/?fmt=csv&investigation={inv}", timeout=120)
            self.record(phase, "export", code, ms, err, agent.s.resent - resent_before)
            with self.lock:
                # An export the transport re-sent reached the platform twice and was ledgered
                # twice, while the agent can only count the answer it got.
                self.export_resent += agent.s.resent - resent_before
                # Same rule as RBAC above: an export that was never served says nothing about
                # the export boundary, in either direction.
                if code >= 500 or code == 0 or code == 429:
                    self.export_unserved += 1
                else:
                    self.conf_checks += 1
                    if agent.may_export or agent.role == "admin":
                        if code == 200:
                            self.ledger["export_ok"] += 1
                        else:
                            self.violations.append(
                                f"export-holder {agent.username} refused ({code})")
                    else:
                        if code == 403:
                            self.ledger["export_denied"] += 1
                        else:
                            self.violations.append(
                                f"non-holder {agent.username} export answered {code}")

    # ---- summaries -----------------------------------------------------------------
    def summarize(self, phase):
        rows = [o for o in self.ops if o[0] == phase]
        out = {}
        for cls in sorted({r[1] for r in rows}):
            sub = [r for r in rows if r[1] == cls]
            ok = [r for r in sub if 200 <= r[2] < 400 or (cls == "rbac_refusal" and r[2] == 403)
                  or (cls == "export" and r[2] in (200, 403))]
            ms = sorted(r[3] for r in ok)
            out[cls] = {
                "n": len(sub), "ok": len(ok),
                "errors_5xx": sum(1 for r in sub if r[2] >= 500),
                "resets": sum(1 for r in sub if r[2] == 0),
                # Requests the transport re-sent after bytes had already gone out. The
                # platform may have applied each one twice while the agent counted the one
                # answer it got, so this is what bounds a fidelity comparison.
                "resent": sum(r[5] for r in sub if len(r) > 5),
                # The ingress refusing on purpose. Not a server error and not a failure of
                # the application — it is the fleet meeting the rate limit, which is a
                # capacity finding and is reported as one.
                "throttled_429": sum(1 for r in sub if r[2] == 429),
                "p50": pct(ms, 50), "p95": pct(ms, 95), "p99": pct(ms, 99),
            }
            # WHAT failed, not only that something did. A knee that says "errors" without
            # naming them cannot be diagnosed after the run has exited.
            kinds = {}
            for r in sub:
                if r[2] == 0 or r[2] >= 500:
                    key = (r[4] or f"HTTP {r[2]}")[:80]
                    kinds[key] = kinds.get(key, 0) + 1
            if kinds:
                out[cls]["error_kinds"] = kinds
        return out



def paced(items, fn, rate, workers=None):
    """Run fn over items with arrivals PACED at `rate` per second.

    A fleet does not cold-start in one instant. Analysts arrive over minutes and a browser
    holds one HTTP/2 connection, so `rate` is what models it; `rate <= 0` releases everything
    at once, which models a thundering herd after a network blip. The two are different
    questions and this harness asks both rather than reporting the herd as the fleet.
    """
    out = []
    with ThreadPoolExecutor(max_workers=workers or max(len(items), 1)) as ex:
        futures = []
        for it in items:
            futures.append(ex.submit(fn, it))
            if rate and rate > 0:
                time.sleep(1.0 / rate)
        for f in futures:
            out.append(f.result())
    return out


def provision(cfg):
    """Phase K — create the fleet through the platform's own admin API, concurrently.

    As the logged-in admin over the ingress: `POST /api/users/` provisions Keycloak AND
    mirrors the Django account and group in one call, so this measures the deployed
    provisioning path under concurrency — not a kcadm side door beside it.
    """
    admin = Agent(cfg, {"username": cfg["admin_user"], "password": cfg["admin_password"],
                        "role": "admin"})
    ms, err, _ = admin.login()
    if not admin.authenticated:
        print(json.dumps({"provision": {"fatal": f"admin login failed: {err}"}}))
        return 1

    n = cfg["n_users"]
    stamp = cfg["marker"].replace("loadtest-", "")
    specs = []
    for i in range(n):
        # 4 analysts to 1 auditor — write pressure with a read-only minority whose
        # refusals prove RBAC under load.
        role = "auditor" if i % 5 == 4 else "analyst"
        specs.append({"username": f"loadtest-{stamp}-{i:03d}", "role": role,
                      "password": f"Lt-{stamp}-{i:03d}-Pw1!"})

    results = []
    lock = threading.Lock()

    made = []

    def create(spec):
        code, ms, _, err = admin.req("POST", "/api/users/", {
            "username": spec["username"], "email": f"{spec['username']}@ir-platform.local",
            "role": spec["role"], "password": spec["password"], "temporary": True,
        }, timeout=60)
        with lock:
            results.append((code, ms, err))
            if code == 201:
                made.append(spec)
        return code == 201

    created = sum(1 for ok in paced(specs, create, cfg.get("arrival_rate", 0),
                                   workers=cfg.get("provision_concurrency", 10)) if ok)

    ok_ms = sorted(r[1] for r in results if r[0] == 201)
    print(json.dumps({
        "provision": {
            "attempted": n, "created": created,
            "failed": [{"code": r[0], "error": r[2]} for r in results if r[0] != 201][:10],
            "p50": pct(ok_ms, 50), "p95": pct(ok_ms, 95),
            "admin_login_ms": round(ms or 0),
        },
        # The accounts that WERE created, never all-or-nothing: emptying this on a partial result throws
        # away existing accounts and takes the later phases with it.
        "users": made,
    }))
    return 0 if created == n else 1


def main():
    cfg = json.load(open(sys.argv[1]))
    if cfg.get("phase") == "provision":
        return provision(cfg)
    agents = [Agent(cfg, s) for s in cfg["users"]]
    run = Run(cfg)
    n = len(agents)
    out = {"agents": n}

    # ---- storm ---------------------------------------------------------------------
    rate = cfg.get("arrival_rate", 0)
    shape = f"{rate}/s arrivals" if rate and rate > 0 else "all at once"
    print(f"[load] storm: {n} logins, {shape}", file=sys.stderr)
    login_ms, login_err, login_retries = [], [], 0
    for ms, err, retried in paced(agents, lambda a: a.login(), rate):
        login_retries += retried
        (login_ms.append(ms) if ms is not None else login_err.append(err))
    login_ms.sort()
    out["storm"] = {
        "attempted": n, "completed": len(login_ms), "failed": len(login_err),
        "failures": login_err[:10], "transport_retries": login_retries,
        "p50": pct(login_ms, 50), "p95": pct(login_ms, 95), "max": login_ms[-1] if login_ms else None,
    }

    live = [a for a in agents if a.authenticated]

    # ---- activity ------------------------------------------------------------------
    window = cfg.get("activity_seconds", 60)
    print(f"[load] activity: {len(live)} agents for {window}s", file=sys.stderr)

    # THINK TIME: without it each agent loops as fast as the platform answers, and the run measures
    # the harness rather than an analyst workload.
    think = cfg.get("think_seconds", 3.0)

    def loop(agent):
        # Staggered start: otherwise iteration zero is a synchronized fleet-wide burst and its latency is
        # an artifact of the harness.
        if think > 0:
            time.sleep(random.random() * think)
        i, end = 0, time.monotonic() + window
        while time.monotonic() < end:
            run.step(agent, "activity", i)
            i += 1
            if think > 0:
                # Jittered, so fifty agents do not synchronize into a wave the ingress sees
                # as one burst — which is the herd shape again, inside the activity phase.
                time.sleep(think * (0.5 + random.random()))

    with ThreadPoolExecutor(max_workers=max(len(live), 1)) as ex:
        list(ex.map(loop, live))
    out["activity"] = run.summarize("activity")

    # ---- ramp ----------------------------------------------------------------------
    # Fresh mixed work at each step, over the first K live agents, until the knee. The
    # ceiling judges READ latency: reads are what an analyst feels first, and a knee
    # defined over the heaviest write would flatter the design.
    ceiling = cfg.get("knee_p95_ms", 3000)
    steps = [s for s in cfg.get("ramp_steps", [10, 20, 30, 40, 50, 60, 75]) if s <= len(live)]
    knee, degraded = None, None
    for s in steps:
        tag = f"ramp{s}"
        print(f"[load] ramp step {s}", file=sys.stderr)

        def burst(agent):
            # The ramp measures how many CONCURRENT analysts the platform carries, not how it
            # answers a synchronized thundering herd of them — that question is the arrival
            # rate, asked separately. The stagger spans at least the window the ingress needs
            # to ADMIT this many fresh dials at its configured accept rate: agents idle since
            # an earlier step all reconnect on first use, and a spread narrower than the
            # admit window manufactures the herd this phase exists not to measure.
            stagger = max(think, s / max(cfg.get("accept_rate", 8), 1))
            if stagger > 0:
                time.sleep(random.random() * stagger)
            for i in range(cfg.get("ramp_iterations", 3)):
                run.step(agent, tag, i)
                if think > 0:
                    time.sleep(think * (0.5 + random.random()))

        with ThreadPoolExecutor(max_workers=s) as ex:
            list(ex.map(burst, live[:s]))
        summary = run.summarize(tag)
        reads = [c for c in ("read_stats", "read_findings") if c in summary]
        worst = max((summary[c]["p95"] or 0) for c in reads) if reads else 0
        errs = sum(summary[c]["errors_5xx"] + summary[c]["resets"] for c in summary)
        total = sum(summary[c]["n"] for c in summary) or 1
        err_pct = 100.0 * errs / total
        out[tag] = summary
        # The knee is where the platform stops meeting its service level, not where a single request
        # failed — any-error-ends-the-ramp reported 'capacity: none' over healthy latencies.
        budget = cfg.get("ramp_error_budget_pct", 1.0)
        if err_pct > budget or worst > ceiling:
            degraded = {"step": s, "read_p95": worst, "errors": errs,
                        "error_pct": round(err_pct, 2), "budget_pct": budget,
                        "reason": "latency" if worst > ceiling else "errors",
                        # The failing step's own evidence, carried in the verdict: which
                        # categories failed and with what error, so the knee is diagnosable
                        # from the report alone.
                        "failing_categories": {c: v for c, v in summary.items()
                                               if v.get("errors_5xx") or v.get("resets")}}
            break
        knee = s
    out["ramp"] = {"knee": knee, "ceiling_ms": ceiling, "degraded_at": degraded,
                   "steps_run": steps}

    # Attempts the platform may have applied without the agent counting an answer, per class,
    # over EVERY phase. The database counts a fidelity check reads are not phase-scoped, so a
    # bound taken from one phase misses the ramp's own dropped and re-sent writes.
    out["uncounted"] = {}
    for cls in sorted({o[1] for o in run.ops}):
        rows = [o for o in run.ops if o[1] == cls]
        out["uncounted"][cls] = (sum(1 for r in rows if r[2] == 0)
                                 + sum(r[5] for r in rows if len(r) > 5))

    out["ledger"] = run.ledger
    out["confidentiality"] = {"violations": run.violations, "checks": run.conf_checks,
                              "expected_403": run.expected_403,
                              "rbac_unserved": run.rbac_unserved,
                              "export_unserved": run.export_unserved,
                              "export_resent": run.export_resent}
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
