# Component schematic — configs, network path, and how to probe each hop

A hop-by-hop reference for isolating faults. Every component lists **where it runs**, **what
configures it**, **who it talks to**, and **the exact command to prove it is healthy** — so a
failure can be bisected to one hop instead of guessed at.

Companion docs: [`RUNBOOK.md`](RUNBOOK.md) (symptom → cause → fix),
[`diagnose.sh`](diagnose.sh) (automated sweep), [`../deploy/NETWORKING.md`](../deploy/NETWORKING.md)
(VLANs / firewall / IDPS).

---

## The two end-to-end paths

```
EVIDENCE PATH  (data in, pull-based)
  collector ──▶ receiver ──▶│ puller ──▶ MinIO ──▶ worker ──▶ Postgres ──▶ web app
  (endpoint)     (DMZ)      │ (enclave)
                     the enclave PULLS across this boundary; nothing initiates inward

ANALYST PATH  (brokered, single origin)
  kiosk browser ──▶ CoreDNS (name→bastion) ──▶ tailnet ──▶ broker (Boundary session)
      ──▶ egress worker ──▶ Traefik ──▶ oauth2-proxy ──┬─▶ Keycloak
                                                       └─▶ frontend ──▶ backend
```

Both cross exactly one boundary each, and both are deny-by-default everywhere else. Inside the
enclave, Postgres and MinIO bind loopback only and are reached exclusively through their
Connect sidecars — intentions in
[`../hashicorp/consul/config-entries/`](../hashicorp/consul/config-entries/) decide which
service may reach which, default-deny ([`../test/uat_consul.sh`](../test/uat_consul.sh)).

---

## Analyst path, hop by hop

### 1. Kiosk browser — `workstation` tier
- **Config:** [`workstation/policies.json`](../workstation/policies.json) (STIG policy, kiosk
  allow-list, clipboard denied), [`workstation/launch.sh`](../workstation/launch.sh) (CA trust,
  sandbox flags), [`deploy/workstation/docker-compose.yml`](../deploy/workstation/docker-compose.yml).
- **Talks to:** CoreDNS (`${DNS_EDGE_IP}:53`) and the broker (`:8443`). Nothing else — the
  `ir-edge` network has no gateway.
- **Probe:**
  ```bash
  podman logs ir-workstation_browser_1 | head -5          # CA installed? policy present?
  podman exec ir-workstation_browser_1 getent hosts ir-platform.local
  ```

### 2. CoreDNS — DMZ
- **Config:** [`hashicorp/access/Corefile`](../hashicorp/access/Corefile) — answers the platform
  name with the **broker's** address; REFUSES everything else (no recursion → no DNS exfil).
- **Probe:**
  ```bash
  podman run --rm --network ir-edge localhost/ir-workstation:latest \
    sh -c 'dig +short @10.89.30.53 ir-platform.local; dig @10.89.30.53 evil.example | grep -c REFUSED'
  ```
  Expect the broker IP, then `1`.

### 3. Session broker — DMZ
- **Config:** [`hashicorp/access/boundary_session.sh`](../hashicorp/access/boundary_session.sh)
  + the `broker` service in [`deploy/dmz/docker-compose.yml`](../deploy/dmz/docker-compose.yml).
  Target and auth-method ids arrive via `deploy/.env.boundary`, written by the controller's
  bootstrap. **The Boundary target is the allow-list** — one target, the SSO gate, authorized
  per session and per principal.
- The session is **supervised**: when it ends — controller rebuilt, worker recreated, expiry, a
  fatal proxy error — the broker re-authenticates and re-establishes within seconds, and it
  cancels the sessions it abandons so the access record stays truthful.
- **Probe:**
  ```bash
  podman logs ir-dmz_broker_1 | grep -E 'authenticated as|Session ID' | tail -2
  podman exec ir-dmz_bastion_1 sh -c 'netstat -ltn 2>/dev/null | grep 8443 || ss -ltn | grep 8443'
  ```

### 4. Traefik — enclave ingress
- **Config:** [`traefik/traefik.yml`](../traefik/traefik.yml) (entrypoints, TLS) +
  [`traefik/dynamic-sso/dynamic.yml`](../traefik/dynamic-sso/dynamic.yml) (path routing).
  Routes on one origin: `/realms/irplatform*`→Keycloak, `/oauth2/*` and `/`→oauth2-proxy,
  `/admin` + `/realms/master`→denied.
- **Probe:**
  ```bash
  podman logs ir-enclave_traefik_1 | grep -E ' 50[0-9] | 403 ' | tail   # 502 = upstream down
  ```

### 5. oauth2-proxy — SSO gate
- **Config:** the `oauth2-proxy` service in
  [`deploy/enclave/docker-compose.yml`](../deploy/enclave/docker-compose.yml). Fronts the app
  (`--upstream=http://frontend:8080`), redirects unauthenticated users to Keycloak, and attaches
  identity headers upstream.
- **Key flags:** `--skip-oidc-discovery` with explicit login/redeem/profile/JWKS URLs (browser-facing
  login, internal back-channel); `--scope=openid email profile`; `--cookie-samesite=lax`;
  `--backend-logout-url` (internal address) so sign-out ends the Keycloak session too.
- **Probe:**
  ```bash
  podman logs ir-enclave_oauth2-proxy_1 | tail -5     # "Initiating login" = working
  ```

### 6. Keycloak — identity
- **Config:** [`hashicorp/keycloak/realm-irplatform.json`](../hashicorp/keycloak/realm-irplatform.json)
  — realm, role groups, the **groups** mapper and the **audience** mapper (both required),
  and the per-role break-glass logins. `KC_HOSTNAME` pins the public issuer.
- **Probe:**
  ```bash
  podman exec ir-enclave_keycloak_1 sh -c \
    'curl -s http://127.0.0.1:8080/realms/irplatform/.well-known/openid-configuration' | head -c 120
  ```
  The `issuer` must equal `PLATFORM_PUBLIC_URL/realms/irplatform`.

### 7. Frontend / backend
- **Config:** [`frontend/nginx.conf.template`](../frontend/nginx.conf.template) sets
  `X-Proxy-Auth` and forwards the identity headers;
  [`backend/cases/authentication.py`](../backend/cases/authentication.py) trusts them **only**
  when the shared secret matches, then maps the Keycloak group → RBAC role.
- **Probe (whole chain, all roles):**
  ```bash
  podman run --rm --network ir-edge \
    -v "$PWD/test/lib/oidc_login.py:/t.py:ro,z" localhost/ir-workstation:latest \
    python3 /t.py https://ir-platform.local:8443 https://ir-platform.local:8443/ \
    default-admin default-admin-pw
  ```
  A clean cookie jar — if this passes but the browser fails, the fault is browser state.
  Swap `oidc_login.py` for [`oidc_logout.py`](../test/lib/oidc_logout.py) to assert the reverse:
  that sign-out ends the gate **and** IdP sessions, so re-entry hits the login form.

---

## Evidence path, hop by hop

### 1. Collector — endpoint
- **Config:** [`collector/collect.sh`](../collector/collect.sh), sealed with
  [`shared/custody.py`](../shared/custody.py). Writes a bundle to a mounted volume; never
  contacts the platform.
- **Probe:** `ls <evidence>/reports/<host>/_custody_platform.json` then
  `python3 shared/custody.py verify <evidence>/reports/<host>`.

### 2. Receiver — DMZ
- **Config:** [`dmz/receiver.py`](../dmz/receiver.py). Accepts, **closes the connection**,
  verifies custody, holds verified bundles as opaque blobs. Holds **no** internal credentials.
- **Probe:**
  ```bash
  curl -s http://127.0.0.1:8090/healthz     # {"status":"ok","held":N,"quarantined":M}
  ```
  `held` climbing = the puller isn't draining. `quarantined` climbing = seals are failing.

### 3. Puller — enclave (the only DMZ↔enclave bridge)
- **Config:** [`dmz/puller.py`](../dmz/puller.py) + the `puller` service; `RECEIVER_URL` is the
  cross-hardware coupling. Initiates **outbound**, fetches, closes.
- **Probe:**
  ```bash
  podman logs ir-enclave_puller_1 | tail -5
  podman exec ir-enclave_puller_1 python -c \
    "import urllib.request as u;print(u.urlopen('http://receiver:8090/pending',timeout=5).read())"
  ```

### 4. MinIO / Postgres / worker
- **Config:** the `minio`, `db`, `worker` services. The worker is the malware-facing sandbox:
  no egress, all caps dropped, read-only rootfs, non-root. Postgres and MinIO listen on
  loopback only; their Connect sidecars are the sole listeners, so "the database is
  unreachable while healthy" usually means a sidecar left its service's namespace — request
  the **mesh-reattach** repair from the Enclave Repairs page, or run `deploy.sh enclave`.
- **Probe:**
  ```bash
  podman exec ir-enclave_backend_1 python -c "
  import urllib.request as u, json
  r=u.Request('http://127.0.0.1:8000/api/stats/',headers={'Authorization':'Token <IR_BROKER_TOKEN>'})
  print(json.load(u.urlopen(r,timeout=8)))"
  ```
  `runs>0` = ingest works. `captures>0` = the object store works. Memory findings on the run =
  the sandbox works.

- **Analysis inside the worker:** the toolkit's own stack — `analyze_memory_linux.py` with
  its Volatility plugins, `memory_enrich.py`, and the `investigation/` engine that assigns
  verdicts. Verify the analyzer and the engine are both present:
  ```bash
  podman exec ir-enclave_worker_1 sh -c \
    'test -f /opt/toolkit/playbooks/linux/threat_hunting/analyze_memory_linux.py && echo "analyzer ok"
     PYTHONPATH=/opt/toolkit python3 -c "from playbooks.linux.investigation import live_runner; print(\"engine ok\")"'
  ```
  A missing engine is why a run can complete with findings but no verdicts.

---

## Reverse-engineering path

### 1. Carved regions — enclave
- **Config:** written by the worker's per-process YARA pass to `ir-carved-<hostname>`, one
  bucket per host, held separately from `ir-evidence`.
- **Probe:**
  ```bash
  podman exec -i ir-enclave_backend_1 python - <<'PY'
  import os, django
  os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ir_platform.settings"); django.setup()
  from cases import storage
  host = "HOSTNAME"
  print(storage.carved_bucket(host), len(storage.list_carved_regions(host)))
  PY
  ```
  An empty bucket after a completed analysis usually means the per-process YARA pass
  exhausted its budget — see [`MEMORY-ANALYSIS.md`](MEMORY-ANALYSIS.md).

### 2. Mediator — `stage_regions.sh`
- **Config:** runs where the operator is. It holds the store credentials, and writes one
  host's regions into `session-<HOST>/` at `0400`. The manifest keeps object keys and sizes
  and drops the payloads, so the session carries provenance and no route back to the store.
- **Probe:** the script reports how many regions it staged. `podman exec` needs `-i` here;
  without it the enclave-side step receives no stdin and silently produces nothing.

### 3. RE workstation — `launch.sh`
- **Config:** `--network none`, `--cap-drop ALL`, `--security-opt no-new-privileges`,
  `/regions` mounted read-only, `--rm`. `--userns=keep-id:uid=1001,gid=1001` maps the host
  user onto the unprivileged account so the X socket is reachable without running as root.
- **Probe:**
  ```bash
  podman exec ir-re-session sh -c 'ip -o addr | wc -l; getent hosts example.com || echo "no DNS"'
  ```
  Zero interfaces and no DNS. [`../test/uat_re_workstation.sh`](../test/uat_re_workstation.sh)
  asserts the full set.

---

## Boundary assertions (these MUST fail)

Run [`diagnose.sh --net`](diagnose.sh), or individually:

| From | To | Expected |
|---|---|---|
| endpoint | enclave API / MinIO | **no route** |
| DMZ receiver | enclave API / DB / MinIO | **no route** |
| workstation | API / DB / MinIO / receiver | **no route** |
| workstation | public DNS (1.1.1.1:53) | **blocked** |
| analysis worker | internet (1.1.1.1:443) | **blocked** |
| RE session | anything at all — no interfaces, no DNS | **no route** |
| RE session | write to `/regions` | **read-only** |
| analyst | Keycloak `/admin`, `/realms/master` | **403** |

A boundary that starts *succeeding* is a regression in the security model, not a convenience.

---

## Bisecting a failure

1. `diagnose.sh` — names the broken hop and flags any boundary that opened up.
2. Follow the path above from the failing hop **outward**, using each component's probe.
3. Cross-reference [`RUNBOOK.md`](RUNBOOK.md) for the symptom.
4. For login problems specifically: run `test/lib/oidc_login.py` first. It isolates
   configuration (fails) from browser state (passes headlessly, fails in the browser).
