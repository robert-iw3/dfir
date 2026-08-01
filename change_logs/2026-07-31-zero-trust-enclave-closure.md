# The HashiCorp zero-trust enclave: from declared to enforced

@RW: Final baseline changes, private track remains for enterprise edition.

**Date:** 2026-07-31 · **Status:** closed — every control below is live and proven by a UAT

The platform's segmentation claims were partly declarative: policy existed in files that the
running enclave did not enforce, secrets were static, and the analyst ingress was a connection
broker with no session awareness. This entry closes that gap. Each section states the defect,
the evidence, the change, and the verification.

## 1. The service mesh evaluated policy and enforced none of it

**Defect.** Consul intentions existed and evaluated correctly, but no traffic passed through a
sidecar: every enclave service could reach Postgres and MinIO directly. The control plane
itself ran cleartext HTTP with no ACLs and unencrypted gossip.

**Evidence.** A denied source could open a TCP connection to the database from any container on
the internal network; `consul intention check` said deny while the connection succeeded.

**Change.** Postgres and MinIO bind loopback only (`IR_DB_LISTEN`, `IR_MINIO_LISTEN`); each
consumer and destination gets a Connect sidecar sharing its network namespace, so the sidecar
is the only listener and every connection passes an intention check. Policy moved to
`hashicorp/consul/config-entries/`, written to Consul on every deploy — bootstrap-embedded
entries never update an existing cluster. The control plane now runs TLS on every port
(cleartext disabled), encrypted gossip, and default-deny ACLs with per-service tokens that
cannot alter the intentions governing them. Static mesh addresses (`IR_IP_*` /
`IR_MESH_ADDR_*`) and a sidecar-port overlay support multi-host deployment; deploy-time
convergence (`mesh_orphan_check`, namespace-inode comparison) repairs sidecars stranded by
container recreation.

**Verification.** `test/uat_consul.sh` — 49 assertions: cleartext ports closed, uncertified
clients refused, untokened requests denied, denied pairs refused on the wire, allowed pairs
carrying traffic, per-sidecar namespace-inode match.

## 2. Application secrets were static values in a file

**Defect.** The tier split left Vault behind: database credentials and the custody HMAC key
were static `.env` strings, unrotatable without a manual edit on every host.

**Change.** Vault runs in the enclave, reached through the mesh. Database users are dynamic,
minted against a stable owning role; app secrets and the custody HMAC come from KV via Vault
Agent; rotation is one script (`rotate-app-creds.sh`) that revokes, re-issues and restarts the
application tier in order; break-glass mints a temporary root from the unseal key and revokes
it after use.

**Verification.** `test/uat_vault.sh` — 23 assertions, including a live credential minted
through the mesh and revocation taking effect.

## 3. The broker was a forwarder; it is now a session-aware ingress

**Defect.** The analyst path terminated at a port forwarder: no identity on the wire, no
session record, and a dead broker stayed dead until a redeploy. Sessions abandoned by replaced
broker containers stayed "active" in Boundary until expiry, so the access record over-counted
live access; the record showed principals as opaque ids.

**Change.** The DMZ runs a Boundary session client and nothing else — controller, database,
grants and encryption roots are in the enclave, and the client supervises its session:
re-authenticates and re-establishes on any exit, cancels the sessions it abandons, and reaps
its predecessors' on start. An enclave redeploy re-establishes the broker it disrupted. The
Brokered Sessions page is the access record — principal, target, client address, duration,
bytes, termination — read with a session-auditor credential that can list and read and nothing
else (user resolution granted at the org scope, where users live). Every analyst session is
attributable to a principal and auditable in the UI.

**Verification.** `test/uat_boundary.sh` — placement, no authority in the DMZ, one target,
attribution, traffic end to end, healing (a canceled session is replaced by a new authorized
one, unattended), and reporting authenticity: the page's record matches the controller's own
records read via a different authority, and the page's credential is refused a cancel.
`test/uat_tailnet.sh` — the tunnel carries the session and bounds it.

## 4. Repairing the platform required the container runtime in the web tier — or a human

**Defect.** Known repairs (re-applying mesh policy, re-attaching sidecars, unsealing Vault,
rotating credentials) were operator-only; exposing them in the UI would have meant mounting the
runtime socket into a request-serving service.

**Change.** The UI records a **request** naming one of six repairs; a remediation agent — its
own compose project, no network, `pid: host`, the runtime socket its only authority — claims
the request, matches the action name against the allow-list in its own script, executes, and
reports back under a service credential. Claims are atomic, outcomes final, requests audited.

**Verification.** `test/uat_repairs.sh` — 18 assertions: catalogue/allow-list agreement,
executor posture from the running container, refusal of unknown actions and non-admin
principals, the deployed agent closing the loop, the repair verifiably restoring policy, and
outcome rewrite refused. All six repairs also executed from the UI, each recorded succeeded
with output and exit code.

## Closure

`test/uat_e2e.sh` passes 32/32 across the full path — collect → ship → pull → analyze →
enforce → audit → carve → stage → reverse engineer on both GUI workstations — with the platform
under all of the controls above. `platform/SECURITY-MODEL.md` now states the enforced model
(P9 mesh authorization, P10 request-not-capability repairs) and its open items: Redis is not
yet on the mesh, and the enclave still runs on podman-compose rather than pods/quadlets.
