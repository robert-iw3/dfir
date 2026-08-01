# Security model

The principles this platform is built on, what enforces each one, and the test that proves it.

This is the document a change gets checked against. If a change cannot be made without weakening
something here, that is the finding — not an obstacle to route around.

---

## What this platform handles

Memory images from hosts believed to be compromised. A capture contains everything the host had
in RAM at the moment it was taken: credentials, private keys, session tokens, open documents,
and the intruder's own tooling. Two consequences run through every decision below.

**The evidence is hostile.** It is parsed by code that must assume the input was crafted to
exploit the parser. Analysis therefore runs where a successful exploit gains the least.

**The evidence is sensitive.** A capture is often more valuable than the host it came from — it
holds credentials for systems the host could reach. Losing one is a second incident.

---

## P1 — The enclave is the trust boundary, and it is one-way

Evidence moves inward. Nothing moves outward on its own.

The enclave holds the database, the object store, the identity provider, the secrets store, the
analysis worker and the access broker's authority. The DMZ holds what untrusted parties touch.
The enclave **pulls** from the DMZ; the DMZ never pushes and holds no credential for anything
inside.

**Enforced by:** `puller` dials the receiver outbound. No enclave service accepts a connection
originated in the DMZ except the Boundary controller's API and the egress worker's proxy port,
both authenticated (P4).

**Proven by:** `test/uat_dns.sh` — the enclave can resolve exactly one cross-tier name
(`receiver`) and nothing else; `test/uat_boundary.sh` — the bastion cannot reach the enclave
ingress except through a session.

> A second inbound path is the failure mode to watch for. It never arrives labelled as one: it
> arrives as a container joined to one more network for a reason that seems local at the time.
> Every network membership in the tier compose files is load-bearing; a UAT asserts the bastion
> has no direct route so the regression is caught the day it is introduced.

## P2 — Authority lives where it is trusted, never in the tier assumed compromised

The Boundary controller, its database, the grants and the encryption roots are in the
**enclave**. The recovery key authenticates with **no account at all** — anything holding it can
create a target and grant itself access. The DMZ runs a session **client** and holds none of it.

The egress worker is also in the enclave, because a worker must have a route to its target. A
worker in the DMZ would need a route onto the enclave's internal network, which is the reach
this split exists to deny.

Application secrets live in **Vault**, in the enclave: the application tier's database users are
**dynamic**, minted by Vault against a stable owning role and rotated on demand
(`hashicorp/vault/rotate-app-creds.sh`); the custody HMAC key and app secrets come from KV via
Vault Agent. The unseal key is the operator's, not a container's.

**Enforced by:** placement in `deploy/enclave/docker-compose.yml`; the DMZ broker's environment
carries only the analyst credential and the controller's public certificate; the application
tier reads credentials from the agent-rendered file, never from a static compose value.

**Proven by:** `test/uat_boundary.sh` — asserts no recovery key, root key, worker-auth key or
database URL in the DMZ, no Boundary server there, and no readable private key;
`test/uat_vault.sh` — asserts credentials are dynamic, minted live, and revocation works.

## P3 — Deny by default, and the allow-list is a thing that exists

An analyst reaches exactly one target: the SSO gate. Every other service in the enclave has no
target, and therefore no route — enforced per session and per principal, not by the absence of
a forwarding rule someone might add.

**Enforced by:** one Boundary target (`sso-gate`), one grant
(`ids=<target>;actions=authorize-session`), scoped to one project.

**Proven by:** `test/uat_boundary.sh` — asserts exactly one target exists and it is the SSO gate.

## P4 — Nothing crosses a tier boundary in the clear

| Path | Protection |
|---|---|
| Collector → receiver | TLS 1.2+, receiver certificate pinned by the collector (`--ca-cert`) |
| Analyst → controller API | TLS, certificate pinned via `BOUNDARY_CACERT` |
| Worker ↔ controller | Boundary's own mutually authenticated TLS from worker-auth material |
| Session data path | Boundary's per-session ephemeral TLS |
| Tailnet | WireGuard; DERP relay over TLS, control-plane certificate pinned |
| Service ↔ service (enclave) | Consul Connect mutual TLS between sidecars (P9) |
| Mesh control plane | Consul RPC/HTTPS/gRPC under TLS with the enclave CA; gossip encrypted |

Boundary's `cluster` and `proxy` listeners take no TLS configuration because they manage their
own — `tls_disable` on those purposes is **silently ignored**, so writing it describes a
cleartext channel that does not exist. The listener that genuinely needs a certificate is `api`.

Health/`ops` listeners bind `127.0.0.1` only. A listener no network can reach needs no
certificate, and giving it one would mean every health check carried trust material.

**Enforced by:** `RECEIVER_ALLOW_PLAINTEXT` defaults off and the receiver refuses to start
without a certificate; `boundary_session.sh` refuses a non-`https` controller address with no
override; Consul's cleartext HTTP and gRPC ports are disabled outright (`http = -1`).

**Proven by:** `test/uat_boundary.sh` — client address is `https`, certificate pinned, the
controller API does not answer plaintext; `test/uat_consul.sh` — cleartext ports closed, TLS
served with the enclave CA, an uncertified client refused, gossip keyring encrypted.

## P5 — Every access is attributable, and the record is truthful

A session is bound to a principal with an account. A session that cannot be traced to an
identity is an unauthenticated forwarder with extra steps, which is what Boundary replaced.

Attribution only matters if the record is honest, so the platform holds itself to that:

- The **Brokered Sessions** page is the access record — who connected, from where, to what, for
  how long, how much moved, why it ended. It reads Boundary live with its own credential, which
  can list and read sessions and **nothing else**: watching access is not a route to obtaining
  it.
- The broker **cancels the sessions it abandons**. A replaced or killed session client leaves
  its session "active" until expiry, and an access record that over-counts live access is
  wrong in the dangerous direction. The broker reaps its own stale sessions on start and cancels
  on shutdown, so "active" means active.
- The session is **supervised**: when it ends — controller rebuilt, worker recreated, expiry, a
  fatal proxy error — the broker re-authenticates and re-establishes. Every re-establishment is
  a new authorized, attributable session, never a lingering socket.

**Enforced by:** password auth method; the analyst user, its account, and the role binding it to
`authorize-session` are provisioned and **verified** by `boundary_bootstrap.sh`; the
session-auditor principal holds `list,read` on sessions (project scope) and users (org scope)
and no other grant.

**Proven by:** `test/uat_boundary.sh` — the live session belongs to the provisioned analyst;
the page's record matches the controller's own (read via a different authority), exactly one
session is live, its client address is the running broker, and the auditor credential is
refused when it attempts a cancel; a canceled session is replaced by a new authorized one,
unattended.

## P6 — No egress, and no DNS to tunnel over

All three container networks are `--internal`. Each tier's resolver answers in-zone names and
**REFUSES** everything else, with no recursive path and no root hints. DNS is a classic covert
exfiltration channel and the enclave is where the evidence is.

CoreDNS is an egress **backstop**, not the primary resolver: while a network is internal there
is nothing to forward, and it arms the moment a network gains a route out.

**Proven by:** `test/uat_dns.sh` — no service resolves an outside name; both resolvers refuse
when queried directly; no service pins an address except the two resolvers, which must.

## P7 — Analysis is contained, and reverse engineering more so

The worker parses hostile input. A reverse-engineering session opens carved regions of a
compromised host's memory in a full disassembler.

**Enforced by:** RE sessions run with **no network namespace at all**, every capability
dropped, and the regions mounted read-only. Both supported tools (Binary Ninja Free, Ghidra)
need no license server, activation or call-home, so containment costs nothing.

**Proven by:** `test/uat_re_workstation.sh`; `test/uat_e2e.sh` re-asserts the same properties
from kernel state (`CapEff`, the mount table) on the sessions it launches.

## P8 — Custody is sealed, so transport can be untrusted

A bundle is self-contained and carries a custody HMAC. The seal proves the bundle was not
**altered**; it does nothing to stop it being **read**, which is why P4 exists alongside it.

Because the seal makes transport untrusted-by-design, a bundle may legitimately arrive on
removable media from an air-gapped host — dropped at the **DMZ receiver**, never straight into
the enclave, so there is one ingress path with one set of checks.

## P9 — Inside the enclave, a service reaches another only through an authorized channel

The tier boundary is not the only boundary. A compromised container inside the enclave must not
be able to open a connection to the evidence stores just because it shares a network with them.

Postgres and MinIO bind **loopback only**; the sole route to them is their Consul Connect
sidecar, which terminates mutual TLS and enforces **intentions** — an explicit allow-list of
which service may reach which, default-deny. The policy lives in
`hashicorp/consul/config-entries/` and is written to Consul **on every deploy**, so the file and
the enforced state converge. The control plane itself is hardened: ACLs default-deny with
per-service tokens that cannot alter the intentions governing them, TLS on every port, gossip
encrypted.

**Enforced by:** loopback binds (`IR_DB_LISTEN`, `IR_MINIO_LISTEN`) with sidecars sharing each
service's network namespace; Consul intentions; ACL tokens issued per service identity by
`consul-acl-bootstrap.sh`.

**Proven by:** `test/uat_consul.sh` — denied pairs are refused on the wire, allowed pairs carry
traffic, a service token cannot delete the intention governing it, and Vault mints a live
credential through the mesh. The **Service Mesh** page renders the catalog and the enforced
authorization matrix live from Consul, and calls out any service registered without a sidecar.

## P10 — Privileged operations are requests, not capabilities

Repairing the platform requires driving the container runtime, and the web tier must never hold
that: a runtime socket in a request-serving service is a container-escape path.

An admin **requests** a named repair; the platform records it; the remediation agent — an
isolated executor with **no network**, deployed as its own compose project — claims the request
and matches the action **name** against the allow-list in its own script. No command, argument
or path crosses the boundary. Outcomes are written back under a service credential an admin
does not hold, transitions are guarded server-side, and a finished outcome cannot be rewritten
— the history is an audit record, not a note.

**Enforced by:** `troubleshooting/remediation-agent.sh` (the allow-list),
`deploy/agent/docker-compose.yml` (network none, socket-only), transition guards in the API,
and the audit ledger entry written at request time.

**Proven by:** `test/uat_repairs.sh` — the catalogue and allow-list match, the executor's
posture is asserted from the running container, unknown actions and non-admin principals are
refused, the deployed agent closes the loop, the repair verifiably repairs, and a recorded
outcome cannot be re-claimed or overwritten.

---

## Applying this to a change

Ask in order:

1. **Does it add an inbound path into the enclave?** If so, what authenticates it, and why can
   the existing one not carry it? (P1)
2. **Does it place a key, a database or a grant outside the enclave?** (P2)
3. **Does it widen what an analyst can reach beyond the one target?** (P3)
4. **Does anything now cross a tier boundary unencrypted or unpinned?** (P4)
5. **Can every new access be traced to a principal, and does the record stay truthful?** (P5)
6. **Does it give any container a route out, or a resolver that answers more?** (P6)
7. **Does it let one enclave service reach another without an intention allowing it?** (P9)
8. **Does it hand any web-facing service an execution capability instead of a request?** (P10)
9. **Which UAT proves the answer?** If none does, that test is part of the change.

A principle weakened for a reason that is genuinely worth it should be **written down here**,
with the reason. An undocumented exception is indistinguishable from a mistake six months later.

## Gap Analysis (private dev track will remediate, not in public mirror)

Stated plainly rather than implied by omission.

- **Redis is not on the mesh.** It binds its network address without authentication and without
  a sidecar, so P9 does not yet hold for the task queue. Its exposure is one internal network,
  but the standard for the data tier is loopback-plus-sidecar and Redis does not meet it.
- **The enclave tier runs on podman-compose, not pods/quadlets.** Namespace-sharing sidecars
  are re-attached by deploy-time convergence checks (`mesh_orphan_check`) rather than being
  structurally inseparable from their services. The checks are proven, but a pod would make the
  class of fault impossible instead of repaired.
- **The remediation agent's socket is operator-equivalent authority.** Accepted by design — the
  executor must drive the runtime — and bounded by its isolation (no network, no listener, an
  action-name-only input surface). Anyone altering its allow-list is altering the platform's
  privileged command set and should treat it as such.
- **The platform's web certificate is self-signed** and not pinned by the browser, unlike the
  receiver's and headscale's. The analyst reaches it only through an authenticated session, so
  this is a defense-in-depth gap rather than an open path.
- **Multi-analyst session tracking** is provisioned as a single shared analyst principal. P5
  holds at the mechanism level; per-analyst attribution needs one principal per analyst.
