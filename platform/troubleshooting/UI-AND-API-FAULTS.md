# A page is blank, empty, or wrong — where to look

Three failures look alike in a browser and have nothing in common underneath. Separate them
first; each section below says which evidence proves which, and where the fix goes.

| What you see | What it means | Section |
|---|---|---|
| Black window, no chrome | render crash — the app unmounted | §1 |
| Page renders, panel says "no data" | the API answered, with nothing in it | §2 |
| Page renders, values look wrong | the API answered with the wrong thing | §3 |
| Spinner that never resolves | the request never came back | §4 |

## 0. The capability

Two stores, and neither is evidence:

- **`opslog.RequestLog`** — every API call: method, path, status, duration, user, response
  size, and the traceback on a 5xx. Written by `opslog/middleware.py`, which wraps the view
  so the duration is what the caller waited for.
- **`opslog.ClientError`** — what the *browser* saw: a render crash, or a request that never
  reached the server. Posted by `components/ErrorBoundary.jsx`.

Both live in the `ir_opslog` database, apart from `cases` and `correlation`. They are
operational telemetry and may never be cited in a report.

Every response carries **`X-Request-Id`**. That value is the join between what somebody saw
and what the server did — quote it rather than a timestamp.

    # what failed in the last 15 minutes
    curl -s "$API/api/opslog/requests/?minutes=15" | jq '.results[] | {path, status, error_type}'

    # one specific request, end to end
    curl -s "$API/api/opslog/requests/?request_id=<X-Request-Id>" | jq .

    # what the browser could not render
    curl -s "$API/api/opslog/client-errors/list/" | jq '.results[] | {where, message}'

From a shell on the backend, with the Vault-issued credential:

    podman exec -it ir-enclave_backend_1 sh -c '. /vault/secrets/app.env; python3 manage.py shell'

> `podman exec` gets the **compose** environment, not PID 1's. Without sourcing `app.env`
> the settings fall back to the static defaults and you will be reading a different database
> user than the running application uses. Sourcing it is not optional.

## 1. Black window — a render crash

React unmounts the whole tree on an unhandled render error. `ErrorBoundary` now catches this
and shows the message and stack, so a black window means the boundary itself was bypassed —
check that the route is inside it in `App.jsx`.

**Where the fix goes: the component, and usually the shape it assumed.**

The failure mode to expect first is a **type contract that is not uniform**. Correlation
supersedes rather than migrates: rows written by an earlier `ALGORITHM_VERSION` stay readable
in the table. A renderer that assumes today's shape crashes on yesterday's row and takes the
whole page with it — one stale record hides every campaign.

  * Reproduce against the data, not the UI: `CampaignSimilarity.objects.filter(run__is_current=False)`
    is where old shapes live.
  * Fix the renderer to tolerate both (`sharedSummary()` in `pages/Correlation.jsx` is the
    pattern), *and* make the producer uniform going forward.
  * Recomputing correlation does **not** clean history. It writes new rows beside the old.

## 2. Renders, but empty

Ask whether the API returned nothing, or returned something the page could not read.

    curl -s -D- "$API/api/correlation/investigations/<id>/" | head -20

**Empty and correct** — the derived store has not been built. Recompute correlation. Check
`is_current`: `investigation_correlation` refuses to serve a run whose recorded
`investigation_name` no longer matches, and answers `stale: true` rather than another
incident's campaigns.

**Empty and wrong** — the read path is filtering it out. Confirm the rows exist first:

    CampaignHost.objects.filter(campaign__run__is_current=True).count()

**Where the fix goes: `correlation/views.py` for a read, `correlation/engine.py` for a build.**

> Calling a DRF view directly from a shell without `force_authenticate` returns **403**, and
> `.data.get("nodes", [])` on that error body is `[]`. That reads exactly like "no hosts".
> Use `rest_framework.test.APIRequestFactory` with `force_authenticate`.

## 3. Renders, values wrong

Check the **stored** value before reading any code — most of these are a derived field that
was never written, not a display fault.

    # a band, and what it decomposes into
    CampaignHost.objects.filter(campaign__run__is_current=True).values(
        "hostname", "confidence_band", "confidence_factors")

Every judgment carries its own reasoning. `confidence_factors.why`, `HostLink.factors.top`
and `AttributionCandidate.rationale.components` each say what produced the result; if the
reasoning is empty the input was missing, not the logic.

**Where the fix goes:**

| Wrong thing | File |
|---|---|
| membership band | `correlation/confidence.py` |
| link weight, or a pair not linking | `correlation/linkage.py` |
| campaign shape, patient zero, edges | `correlation/engine.py` |
| fingerprint, attribution, similarity | `correlation/fingerprint.py` |
| counts on a chart | `cases/aggregates.py` |

A signal that is computed but never fires is the recurring defect here, and it looks
identical to a signal with nothing to report. **Confirm the branch is reachable before tuning
it**, and check the baseline it compares against as carefully as the comparison.

The L1 contradiction discount has been unreachable twice, each time for a different reason:

* the baseline was the source host's first activity — but movement out of a host is recorded
  *on* that host, so the edge under test defined the baseline it was measured against;
* the baseline then counted **Indeterminate** findings. Fleet-wide benign noise (an inventory
  scan, an agent install) sits on every host in the small hours, so nothing could precede
  "first evidence" and the check was disarmed for the whole fleet.

Neither failed anywhere visible. Both read as a clean timeline.

A unit test over the *consumer* cannot catch this — the banding truth table feeds links that
already carry a contradiction factor, so it proves what banding does with the finding and
nothing about whether the finding is made. Test the producer separately:
`correlation.engine.sets_compromise_baseline` decides what may set the baseline,
`correlation.linkage.contradiction_for` compares against it, and where the baseline is absent
the factor records `not evaluated` rather than a silent pass.

## 4. Spinner that never resolves

The request did not come back. In order:

    curl -s "$API/api/opslog/requests/?minutes=5&failed=0&path=<fragment>"

- **No row at all** — it never reached the backend. Look at the edge: `oauth2-proxy` and
  `traefik` logs, and an SSO redirect answering a `fetch` with HTML instead of JSON.
- **A row with a 5xx** — `error_detail` holds the traceback.
- **A row with 200 and `response_bytes` near zero** — the server answered emptily; that is §2.

## 5. When the log itself is missing

`RequestLogMiddleware` swallows every failure of its own writes, so the application can never
be taken down by its telemetry — but it logs a warning to stderr when it does. **No rows at
all is a finding, not a quiet system:**

    podman logs ir-enclave_backend_1 2>&1 | grep "request log not written"

The usual cause is the `ir_opslog` database missing. It is created by
`hashicorp/db-bootstrap.py`, which holds the one static admin credential — the app tier has
no `CREATEDB` attribute and must not. The entrypoint *requires* the database and names it
when absent; it does not create it. Re-run the data-tier stage of `deploy.sh` rather than
granting the application the right to create databases.

## 6. Rebuilt code that is not running

Backend code is baked into the image, not mounted. After changing anything under `backend/`,
redeploy — `deploy.sh` builds and then `recreate_if_stale` replaces containers still serving
a superseded image. A change that appears to have no effect is usually this.

The same trap in reverse: `manage.py` invoked in an old container reports pre-change
behavior convincingly. Check what is actually running:

    podman inspect ir-enclave_backend_1 --format '{{.Image}}'
    podman image inspect localhost/ir-backend:latest --format '{{.Id}}'
