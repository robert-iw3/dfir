# Troubleshooting runbook — symptom → cause → where to fix

Every entry here is a failure actually hit while building and validating this platform,
with the real root cause and the file to change. Start with
[`diagnose.sh`](diagnose.sh) — it walks the data flow and the segmentation boundaries and
usually names the broken hop for you:

```bash
troubleshooting/diagnose.sh              # all running tiers
troubleshooting/diagnose.sh --flow       # data-flow trace only
troubleshooting/diagnose.sh --net        # segmentation assertions only
troubleshooting/diagnose.sh -p ir-enclave
```

---

## 1. Analyst browser / SSO

### "The connection was reset" right after the login page appears
**Cause.** The OIDC redirect goes to Keycloak, which had not finished starting (Keycloak takes
30–60s). Traefik logs a 502 for the realm path while it is down.
**Fix.** Not a config error — wait for Keycloak; `deploy.sh enclave` gates on it.
**Verify.** `podman exec ir-enclave_keycloak_1 curl -s -o /dev/null -w '%{http_code}'
http://127.0.0.1:8080/realms/irplatform` → `200`.

### "Secure Connection Failed" / PR_END_OF_FILE_ERROR on the platform name
**Cause.** The brokered listener accepted the TCP connection but the Boundary session behind it
is down — the enclave is mid-redeploy, or the session just ended. The broker supervises its
session and re-establishes within seconds of the controller answering.
**Fix.** Reload. If it persists: `podman logs ir-dmz_broker_1 | tail` — a broker waiting on the
controller says so; an exited broker container means the DMZ tier needs `deploy.sh dmz`.
**Verify.** `podman logs ir-dmz_broker_1 | grep 'authenticated as' | tail -1`.

### A bare "Forbidden" page, even signed in as an admin
**Cause.** The ingress denies `PathPrefix(/admin)` outright — that is how Keycloak's admin
console and master realm are kept off the analyst origin
([`traefik/dynamic-sso/dynamic.yml`](../traefik/dynamic-sso/dynamic.yml), router `idp-deny`).
The deny happens at traefik, before oauth2-proxy or the application see the request, so being
an admin makes no difference; roles are never consulted. Any *application* route under
`/admin` collides with it and is unreachable.
**Fix.** Move the application route, not the deny rule. Keycloak's admin console lives under
`/admin/...` and narrowing the rule to carve out an app path risks exposing it. Platform
Health was moved to `/platform-health` for exactly this reason.
**Verify.** `podman logs ir-enclave_traefik_1 | grep idp-deny` shows the denied path and the
router that refused it. API paths under `/api/admin/...` are unaffected — they do not match
the prefix.

### Browser shows only a "blocked page"
**Cause.** The Firefox `WebsiteFilter` exception was invalid. **Match patterns must not contain
a port** — `https://host:8443/*` is invalid, so *everything* (including the platform) is blocked.
The **scheme is matched**, so `https://` alone won't permit the `http://` brokered IdP.
**Fix.** [`workstation/policies.json`](../workstation/policies.json) → `WebsiteFilter.Exceptions`
= `["https://ir-platform.local/*", "http://ir-platform.local/*"]`. The image's build-time smoke
test now rejects port-bearing patterns.

### `Error: cannot open display: :0`
**Cause.** Under **rootless podman**, a non-root container UID maps into the subuid range and
cannot open the host's X socket. (Container *root* maps to the invoking host user, which can.)
**Fix.** [`workstation/Dockerfile`](../workstation/Dockerfile) runs as container-root, and the
run needs: `--security-opt label=type:container_runtime_t`, `-v /tmp/.X11-unix:/tmp/.X11-unix`
(**not** `:ro`), `-e DISPLAY -e XDG_RUNTIME_DIR`, and `xhost +local:` on the host once.
Privilege is still stripped with `cap_drop: ALL` + `no-new-privileges`.

### Browser window opens but pages never render; logs show `Sandbox: writing /proc/self/uid_map: EPERM` and `exited on signal 11`
**Cause.** Firefox's *internal* content-process sandbox needs user-namespace privileges that
`cap_drop: ALL` removes, so content processes crash.
**Fix.** [`workstation/launch.sh`](../workstation/launch.sh) exports
`MOZ_DISABLE_CONTENT_SANDBOX=1` / `MOZ_DISABLE_GMP_SANDBOX=1`. The *container* is the isolation
boundary (no caps, no-new-privs, no internet), so Firefox's inner sandbox is redundant here.

### TLS interstitial on the platform
**Cause.** The self-signed platform CA isn't trusted; Firefox does **not** use the system store
by default.
**Fix.** `launch.sh` installs the mounted CA and `policies.json` sets
`Certificates.ImportEnterpriseRoots` + `Install`. Mount `traefik/certs` into the browser
container. Analysts must never be trained to click through cert warnings.

---

## 2. Evidence flow (collector → DMZ → enclave)

### Bundle rejected with HTTP 400 at the receiver
**Cause (expected).** Custody verification failed — the bundle was modified after sealing. This
is the control working; the bundle is quarantined and never pulled inward.
**Cause (misconfig).** The `IR_CUSTODY_HMAC_KEY` used to *seal* differs from the one used to
*verify*. A signed seal cannot be validated with a different key.
**Fix.** Same `IR_CUSTODY_HMAC_KEY` on the collector and in
[`deploy/.env`](../deploy/.env.example). Check with
`podman logs ir-dmz_receiver_1 | grep QUARANTINE`.

### Bundles pile up in the DMZ ("held" count grows; nothing appears in the web app)
**Cause.** The enclave **puller** is not running or cannot reach the receiver. Evidence is only
ever *pulled*, so a stopped puller stalls the whole flow silently.
**Fix.** `diagnose.sh --flow` reports the held count and both puller reachability checks.
Check `RECEIVER_URL` in [`deploy/.env`](../deploy/.env.example) and
`podman logs ir-enclave_puller_1`.

### Puller exits immediately with `unrecognized arguments`
**Cause.** The image `ENTRYPOINT` is already `["python","puller.py"]`, so a compose `command:`
repeating the program name duplicates the args.
**Fix.** Pass **flags only** in `command:` — see the puller service in
[`deploy/enclave/docker-compose.yml`](../deploy/enclave/docker-compose.yml).

### Receiver 500s on upload: `OSError: [Errno 18] Cross-device link`
**Cause.** `os.replace()` cannot move a file across filesystems (temp dir → holding volume).
**Fix.** Already fixed in [`dmz/receiver.py`](../dmz/receiver.py) (`shutil.move`). If you add
new file handoffs, use `shutil.move`.

### Runs appear but `captures = 0`
**Cause.** The object-store upload failed, so metadata landed without a capture pointer.
**Fix.** Check `S3_ENDPOINT_URL` / credentials / bucket in [`deploy/.env`](../deploy/.env.example)
and that MinIO is reachable *from the enclave* (`diagnose.sh --flow` asserts this).

### Nothing is adjudicated, no host reads compromised, and correlation links nothing
**Symptom.** Captures analyze and go terminal, but every run reads clean and the corpus UAT's
linkage section fails with `0 pairs` / `0 at or above threshold`. It presents as a correlation
defect, several layers from its cause.

**Cause.** The analysis worker embeds the **whole backend application** — it runs the same
Django code as the API. The worker image used to be built only when *absent*, so a migration
that added a column left the worker inserting rows without it:

```
MemoryAnalysisRun.status = 'failed'
error = IntegrityError: null value in column "<new column>" of relation
        "cases_finding" violates not-null constraint
```

`recreate_if_stale` cannot catch this. It compares the running container against
`localhost/ir-worker:latest`, and that image was never rebuilt — so nothing looked stale.

**Why it stayed hidden.** `adjudicate()` never raises, because losing a completed memory pass
over a failed verdict step is the worse outcome. It recorded the reason in
`MemoryAnalysisRun.summary["adjudication"]["reason"]` and returned. The corpus settle gate then
counted `status in ('completed','failed')` as terminal, so 25 failed analyses satisfied it.

**Fix.** `ensure_build_images` rebuilds the worker whenever anything under `backend/` or
`shared/` is newer than the image; `IR_REBUILD_WORKER=1` forces it for a toolkit change it
cannot see. `uat_corpus.sh` asserts every analysis completed *and* was adjudicated, printing
the recorded error — which names the real cause.

**Ask the store directly:**

```bash
podman exec -i ir-enclave_backend_1 python3 -c "import os,django;os.environ.setdefault('DJANGO_SETTINGS_MODULE','ir_platform.settings');django.setup();from cases.models import MemoryAnalysisRun as M;print([(r.status, (r.error or '')[:120]) for r in M.objects.order_by('-id')[:3]])"
```

---

## 3. Database / secrets (Vault)

### Backend can't start; `POSTGRES_USER` looks like `${POSTGRES_USER:-...}`
**Cause.** **podman-compose does not interpolate `${VAR:-default}`** in `environment:` — it
passes the literal string. This has bitten this project twice (once it wrote a literal
`${...}` into an nginx config and broke the frontend).
**Fix.** Use `env_file:` or plain literals in compose. Never `KEY: ${KEY:-default}`.

### Vault mode: app waits forever for `/vault/secrets/app.env`
**Cause.** The Vault Agent could not write the shared volume. The Vault image entrypoint
`su-exec`s `vault …` back to the `vault` user, which cannot write root-owned volumes.
**Fix.** In [`deploy/enclave/docker-compose.yml`](../deploy/enclave/docker-compose.yml) the
agent uses `user: root` **and** `entrypoint: ["vault"]` (bypassing the wrapper); `vault-setup`
also needs `user: root` to write `/vault/state`.

### Vault is sealed after a restart, and the application tier gets no credentials
**Cause.** Vault comes back sealed by design; every dynamic credential is unavailable until it
is unsealed.
**Fix.** Request the **Unseal Vault** repair from the Enclave Repairs page, or run
`deploy.sh enclave`, which unseals as part of its sequence.
**Verify.** `podman exec ir-enclave_vault_1 vault status | grep Sealed` → `false`.

### Backend loops on `still waiting for postgres`, and the role in `app.env` does not exist
**Symptom.** `deploy.sh` reports the app tier was issued a credential, then the API never
becomes healthy. The backend logs only `still waiting for postgres — is this service's sidecar
up?`, but the sidecar is up and a TCP connect to `127.0.0.1:5432` succeeds.
**Cause.** The AppRole `secret_id` the Vault Agent authenticates with carries a TTL (72h by
default) while the file holding it does not expire. Past that, the agent fails auth
(`invalid role or secret ID`), stops rendering, and the leased Postgres role it last wrote is
revoked — leaving a stale `app.env` naming a role Postgres has dropped. The entrypoint's probe
discards the exception, so an authentication failure is reported as a connectivity problem.
**Fix.** `vault-setup` reissues both agents' secret_ids on every run and restarts them, and the
deploy gate now proves the credential authenticates instead of grepping the file. Run
`deploy.sh enclave`. On a deployment whose stored `ir-provisioner` policy predates the
secret-id paths the run converges it through break-glass once and says so.
**Verify.** `podman logs ir-enclave_vault-setup_1 | grep 'fresh secret_id issued'` → both roles;
the deploy prints `…and it authenticates`.
**Diagnose it directly** — the probe's own error, which the entrypoint hides:
```
podman exec ir-enclave_backend_1 sh -c '. /vault/secrets/app.env; python -c "
import os,psycopg; psycopg.connect(host=os.environ[\"POSTGRES_HOST\"],
  dbname=os.environ[\"POSTGRES_DB\"], user=os.environ[\"POSTGRES_USER\"],
  password=os.environ[\"POSTGRES_PASSWORD\"])"'
```
`podman exec` gets the compose environment, not PID 1's — without sourcing `app.env` you read a
different user than the running app.

### A service reports Postgres or MinIO unreachable while both are healthy
**Cause.** The service's Connect sidecar is no longer in its network namespace — a recreated
service gets a fresh namespace and the proxy keeps serving the dead one. The data tier listens
on loopback only, so without its sidecar a service has no route at all.
**Fix.** Request the **mesh-reattach** repair from the Enclave Repairs page, or run
`deploy.sh enclave` (its `mesh_orphan_check` converges every sidecar).
**Verify.** The Service Mesh page shows every service `proxied`; `test/uat_consul.sh` passes.

### Migrations succeed but later objects are owned by a rotating user
**Cause.** Dynamic DB credentials rotate; objects created by a short-lived user become
orphaned.
**Fix.** Dynamic users are created `IN ROLE ir_app` with `SET role = 'ir_app'`, so all objects
are owned by the stable `ir_app`. See
[`hashicorp/vault/vault-setup-ir.sh`](../hashicorp/vault/vault-setup-ir.sh) and
[`hashicorp/db-bootstrap.py`](../hashicorp/db-bootstrap.py).
**Verify.** `select session_user, current_user;` → login is `v-…`, acting-as is `ir_app`.

---

## 4. Identity (Keycloak + oauth2-proxy)

### 403 "Login Failed: Unable to find a valid CSRF token"
**Cause.** Stale oauth2-proxy cookies in the browser (from an earlier SSO configuration or a
changed `--cookie-secret`), so the CSRF cookie set at `/oauth2/start` no longer matches the one
presented at `/oauth2/callback`.
**Distinguish it fast:** run `test/lib/oidc_login.py` — it uses a clean cookie jar. If the
headless flow passes and only the browser fails, it is browser state, not configuration.
**Fix.** Clear the site's cookies, or recreate the kiosk container for a fresh profile
(the policy sets `SanitizeOnShutdown`, so a restart clears it). `--cookie-samesite=lax` is set
so the cookie survives the top-level redirect back from Keycloak.

### Callback 500: `audience claims [aud] do not exist in claims`
**Cause.** oauth2-proxy validates the token's `aud`. A Keycloak client emits `azp` but no
`aud` unless an audience mapper is configured.
**Fix.** Add an `oidc-audience-mapper` to the client in
[`hashicorp/keycloak/realm-irplatform.json`](../hashicorp/keycloak/realm-irplatform.json)
with `included.client.audience` = the client id and `access.token.claim=true`.
**Verify.** All roles pass `test/lib/oidc_login.py`.

### Callback 403: `invalid_scope: openid email profile groups`
**Cause.** `groups` is a *claim* from the client's group-membership mapper, not a Keycloak
*scope*. Requesting it as a scope is rejected.
**Fix.** Request `--scope=openid email profile` only; groups still arrive in the token via
the mapper.

### App returns 401 with no redirect to login
**Cause.** oauth2-proxy's `/oauth2/auth` is an auth-check endpoint that answers 401; used as
a Traefik `forwardAuth` target it propagates that 401 rather than redirecting.
**Fix.** oauth2-proxy fronts the app directly (`--upstream=http://frontend:8080`) and Traefik
routes `/` to it, so unauthenticated users get a 302 into the Keycloak flow.

### oauth2-proxy exits at start: `failed to discover OIDC configuration ... no such host`
**Cause.** OIDC discovery against the public ingress name at start-up, before the ingress is
up (and the name only resolves via it).
**Fix.** `--skip-oidc-discovery=true` with explicit `--login-url` (public, browser-facing) and
`--redeem-url` / `--profile-url` / `--oidc-jwks-url` (internal, back-channel).

### Sign-out appears to do nothing — the app reloads still logged in
**Cause.** Only the gate cookie was dropped; the Keycloak session survived, so the redirect
back through `/oauth2/sign_out?rd=/` re-authenticates silently. The app answers 200 either
way, which is why a status-code check does not catch this.
**Check the gate's own log** — the back-channel call fails loudly there:
```bash
podman logs ir-enclave_oauth2-proxy_1 2>&1 | grep -i 'backend logout'
```
`connection refused` means `--backend-logout-url` is pointed at the **public** URL. oauth2-proxy
makes that call itself from inside the enclave, where the public name resolves to the edge
listener and is unreachable — it must use `http://keycloak:8080/...` like the other
back-channel URLs.
**Verify:** [`../test/lib/oidc_logout.py`](../test/lib/oidc_logout.py) asserts re-entry lands on
the Keycloak login form, and that `KEYCLOAK_IDENTITY` / `KEYCLOAK_SESSION` are gone.

### Postgres container exits: "There appears to be PostgreSQL data in /var/lib/postgresql/data"
**Cause.** Postgres 18+ images expect the volume at `/var/lib/postgresql`, not the
`/data` subdirectory used by earlier majors.
**Fix.** Mount `pgdata:/var/lib/postgresql` and recreate the volume.



### Token request 400s; `groups` claim missing
**Cause.** A top-level `clientScopes` array in the realm JSON **replaces** Keycloak's standard
scopes, so `email`/`profile` stop existing and requesting them fails.
**Fix.** Put the group-membership mapper on the **client** (`protocolMappers`), not as a
clientScopes override — see
[`hashicorp/keycloak/realm-irplatform.json`](../hashicorp/keycloak/realm-irplatform.json).

### SSO user authenticates but has no platform role
**Cause.** The Keycloak group name doesn't match a platform role, or `X-Forwarded-Groups` isn't
being forwarded.
**Fix.** Groups must be exactly `admin` / `analyst` / `auditor`; Traefik must list
identity headers forwarded by nginx to the backend
([`traefik/dynamic-sso/dynamic.yml`](../traefik/dynamic-sso/dynamic.yml)).

### API returns 401/403 for a browser session that is logged in
**Cause.** The backend only trusts forwarded identity when the shared proxy secret matches —
by design, so identity headers can't be spoofed by a client reaching the API directly.
**Fix.** `IR_SSO_PROXY_SECRET` must be identical for the frontend (nginx sets the header) and
the backend (validates it). See [`backend/cases/authentication.py`](../backend/cases/authentication.py).

---

## 5. Networking / segmentation

### A "blocked" assertion unexpectedly passes (false confidence)
**Cause.** Probing with `nc`/`curl` in a minimal image where the tool doesn't exist: the command
fails for the wrong reason and looks like a successful block.
**Fix.** Probe with Python (present in every tier image) — see the `tcp()` helper in
[`../test/uat_full_stack.sh`](../test/uat_full_stack.sh) and `diagnose.sh`.

### Workstation can't resolve the platform name
**Cause.** The analyst side deliberately has **no** general DNS. Only the DMZ CoreDNS answers,
and only for the platform name.
**Fix.** The workstation/browser must set `dns: [<DNS_EDGE_IP>]`
([`deploy/workstation/docker-compose.yml`](../deploy/workstation/docker-compose.yml)). If the
name must change, update [`hashicorp/access/Corefile`](../hashicorp/access/Corefile) — it
answers with the **broker's** address, never an internal one.
**Expected:** any other name returns `REFUSED`. That is the anti-exfil control, not a bug.

### `dig` resolves the platform name but clients fail with `[Errno -3] Try again`
**Cause.** `EAI_AGAIN` from `getaddrinfo(3)`, which queries **A and AAAA together** and fails the
whole lookup if either is `SERVFAIL`. `dig +short` and `getent hosts` ask only for A, so they
report success while every Python/curl client fails — the two disagree, and the resolver looks
healthy when it is not.
**Fix.** The platform-name server block in
[`hashicorp/access/Corefile.tmpl`](../hashicorp/access/Corefile.tmpl) templates `AAAA` (and any
other qtype) to `NOERROR` — NODATA, the correct answer for an IPv4-only name. A qtype with no
handler returns `SERVFAIL` instead.
**Check both records, not just A:**
```bash
podman run --rm --network ir-edge localhost/ir-workstation:latest sh -c \
  'for t in A AAAA; do dig @<DNS_EDGE_IP> ir-platform.local $t +noall +comment | grep -o "status: [A-Z]*"; done'
```
Expect `NOERROR` twice. Other names must still return `REFUSED`.

### Memory analysis reports YARA matches but carves no regions
**Cause.** The analyzer has two YARA engines and only one of them carves. `native` scans the
whole image and reports matches without attributing them to a process, so there is nothing
to extract; `vol` runs per-process and can carve the matching region. Passing `--carve`
with the native engine silently produces zero regions — no error anywhere, and the
reverse-engineering queue simply stays empty.
**Fix.** `cases/analysis/vol3.py` passes `--yara-engine vol` (override with
`IR_YARA_ENGINE`). Expect it to be slower than the native sweep: it is per-PID.
**Scope of carving.** Only injected regions — anonymous and executable — are carved by
default, which is what warrants reverse engineering. `IR_CARVE_ANY=1` carves every hit
including file-backed matches; far more volume, useful for exercising the workflow.

### Analysis silently runs at reduced depth
**Cause.** The worker falls back to the structural scan whenever the Volatility pass raises,
and the run still completes "successfully". Two configuration faults cause it without any
obvious symptom:
  * a symbol table present in the store under a different name than the capture recorded —
    the lookup now tries build-id, distro-qualified, bare release and a release suffix;
  * `IR_VOL3_TIMEOUT` arriving unparseable. A compose entry of the form
    `KEY: "${KEY:-default}"` self-references, which podman-compose does not resolve, so the
    literal string is passed through and `int()` raises.
**Check.** The engine recorded on the analysis run, and its error field:
```bash
podman exec ir-enclave_backend_1 python -c "
import os,django; os.environ.setdefault('DJANGO_SETTINGS_MODULE','ir_platform.settings'); django.setup()
from cases.models import MemoryAnalysisRun
r=MemoryAnalysisRun.objects.latest('id'); print(r.engine, r.status, r.error[:200])"
```
`engine=native-scan` with a symbol table present means the deep pass was attempted and
failed. The error is now saved as soon as the fallback happens rather than at completion.

### Capture analysis dies with `OSError: [Errno 28] No space left on device`
**Cause.** Volatility needs a seekable local file, so the capture is staged before analysis.
Staging into a tmpfs stages into RAM, and a real capture does not fit.
**Fix.** The worker mounts a disk-backed `worker-scratch` volume with `TMPDIR=/scratch`.
Size the host filesystem for the capture again on top of the object store's copy; a
preflight check now refuses the run with a clear message rather than failing mid-transfer.

### `apk add` fails inside a workstation/edge container
**Cause (expected).** The edge network has no internet gateway. Nothing on the analyst side may
egress.
**Fix.** Bake tools into the image — see
[`workstation/Dockerfile.tools`](../workstation/Dockerfile.tools).

### Tiers can't see each other after splitting onto separate hardware
**Cause.** The two inter-tier segments are shared/external networks; each tier is its own
compose project.
**Fix.** `deploy.sh` creates `ir-edge` (no gateway) and `ir-dmzlink`. Across real hardware, set
`RECEIVER_URL` (enclave→DMZ) and `ENCLAVE_INGRESS` (DMZ→enclave) to routed addresses per
[`deploy/NETWORKING.md`](../deploy/NETWORKING.md).

---

## 6. podman / compose mechanics

| Symptom | Cause | Fix |
|---|---|---|
| `up` hangs forever on a one-shot service | podman-compose runs `podman wait --condition=running`; a service that exits 0 never satisfies it | don't `depends_on:` one-shot services — use runtime waits/retries |
| `container name is already in use` / dependency-graph errors | partial recreate with stale containers | full `deploy.sh down all`, then up; force `podman ps -aq --filter name=<proj> \| xargs podman rm -f` |
| `short-name "x" did not resolve` | podman won't resolve an unqualified compose-generated image name | give the service an explicit `image: localhost/<name>:latest` |
| `HEALTHCHECK is not supported for OCI` warning | podman's default image format | harmless; build-time smoke tests cover it |
| code change deploys cleanly but the old behavior persists | compose will not recreate a container that is already running, so `up -d --build` builds a new image and leaves the old one serving | `deploy.sh` now compares each app container's image against `:latest` and replaces the drifted ones; confirm with the check below |
| the worker runs old code and the container/image comparison says nothing is stale | the worker image is built outside compose, and was built only when absent — the container matched `:latest` because `:latest` itself was never rebuilt | `deploy.sh` rebuilds it when `backend/` or `shared/` is newer; `IR_REBUILD_WORKER=1` forces it. See §2, "Nothing is adjudicated" |
| `container has dependent containers which must be removed before it` | compose turns `depends_on` into podman container dependencies, and `podman rm` refuses while dependents exist | remove with `--depend`; the staged bring-up restores the dependents in order |

Confirming a container is running the image you just built — worth doing after any change
to backend, frontend or worker, because the failure mode is silent:

```bash
for s in backend frontend worker; do
  printf '%-9s running=%s  latest=%s\n' "$s" \
    "$(podman inspect ir-enclave_${s}_1 --format '{{slice .Image 0 12}}')" \
    "$(podman image inspect localhost/ir-${s}:latest --format '{{slice .Id 0 12}}')"
done
```

The two columns must match. When they do not, the deploy built an image nothing is running.

### A background thread that never does its job, with nothing in the logs

Seen as: a Component Health row that never appears while the process looks healthy. Diagnosis
order that works when the thread's own errors are invisible:

1. **Count the threads** — `ls /proc/1/task` and `cat /proc/1/task/*/comm` inside the
   container. A missing thread means start-up raised; a present one means it runs and fails.
2. **Check what identity it runs under.** `backend/entrypoint.sh` derives
   `IR_HEALTH_REPORT_ROLE` from `$1`; only `web`/`worker` may export it. A compose `command:`
   starting with anything else (e.g. `python`) must NOT set a role, or `apps.py` claims the
   reporter under the wrong component name and later `start()` calls are no-ops behind the
   `_started` guard — the work happens under a name nobody is watching, and can overwrite
   another component's row.
3. **boto3 in threads**: never `boto3.client(...)` — the lazily-built default session is not
   thread-safe and two threads first-using it deadlock inside botocore (`futex_do_wait`
   forever, zero log output). `cases/storage.py` builds `boto3.session.Session().client(...)`
   per call for this reason.
4. **Make first failures visible.** `healthreporter` prints `[health] reporting as <name>` at
   thread start and each failure to stderr until the first success, then retries every 30s
   until one lands. `[health] first report recorded` in the container log is the all-clear;
   its absence plus repeated failure lines names the actual exception.

---

## 7. When you change something, re-validate

```bash
test/uat_e2e.sh            # capstone: collect → ship → analyze → carve → reverse engineer
test/uat_full_stack.sh     # evidence pipeline, all tiers
test/uat_dns.sh            # resolvers answer in-zone only; egress refused
test/uat_tailnet.sh        # analyst tunnel, and its bounds
test/uat_boundary.sh       # brokered session: authority placement, healing, truthful record
test/uat_baseline.sh       # identity and the SSO gate
test/uat_consul.sh         # mesh: hardened control plane, default-deny intentions
test/uat_vault.sh          # dynamic secrets
test/uat_repairs.sh        # admin-requested repairs, isolated executor
troubleshooting/diagnose.sh
```

Each UAT asserts **real data flow** (evidence ingested and renderable), not just reachability —
so a green run means the pipeline actually works, not merely that ports are open.
