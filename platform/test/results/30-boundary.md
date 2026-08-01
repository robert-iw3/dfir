## Brokered access — Boundary session into the enclave

*What passing proves:* The analyst's hop into the enclave is an authenticated, authorized, auditable session against exactly one target; the DMZ holds no authority and has no route of its own.

- Run: `uat_boundary.sh` — 2026-07-31 22:32:15Z

**Placement — authority in the enclave, a client in the DMZ**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | controller is running in the enclave |
| ✅ PASS | egress worker is running in the enclave |
| ✅ PASS | controller database is running in the enclave |
| ✅ PASS | session client is running in the DMZ |
| ✅ PASS | no Boundary server in the DMZ — it runs a session client and nothing else |

**The DMZ holds no authority**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | BOUNDARY_RECOVERY_KEY is not in the DMZ |
| ✅ PASS | BOUNDARY_ROOT_KEY is not in the DMZ |
| ✅ PASS | BOUNDARY_WORKER_AUTH_KEY is not in the DMZ |
| ✅ PASS | BOUNDARY_POSTGRES_URL is not in the DMZ |
| ✅ PASS | the DMZ holds the controller certificate but not its key |

**The allow-list**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | exactly one target exists — everything else in the enclave has no route |
| ✅ PASS | the target is the SSO gate, not a service behind it |
| ✅ PASS | exactly one worker is registered — no stale registration to hand a session to |
| ✅ PASS | the worker advertises the enclave egress address |

**Attribution**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | a live session exists |
| ✅ PASS | the session is bound to principal u_rAOgVpmcyW |
| ✅ PASS | that principal is the provisioned analyst |

**The session carries traffic**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the brokered session carried an HTTP request end to end (status 302) |
| ✅ PASS | the far end is the SSO gate — it redirected to identity |

**The session re-establishes after disruption**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | session s_MMFcIAzEDX was canceled and the broker re-established unattended — traffic flows again |
| ✅ PASS | the recovery is a NEW authorized session (s_bWYAeeDY9l), not a lingering socket |

**The DMZ has no route of its own**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the bastion cannot reach the enclave ingress except through the session |

**Encryption on the link**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the client reaches the controller over TLS (https://boundary:9200) |
| ✅ PASS | the controller certificate is pinned by the client |
| ✅ PASS | the client reported pinning at startup |
| ✅ PASS | the controller API does not serve plaintext |

**Reporting authenticity — the UI's access record against the controller's own**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the page reads live from Boundary with its own credential |
| ✅ PASS | the record is complete: page 9 sessions, controller 9, id sets match |
| ✅ PASS | live count matches the controller (1 == 1) |
| ✅ PASS | exactly one live session — the running broker, no ghosts of replaced brokers (1 live) |
| ✅ PASS | the live session's client address is the running broker (10.89.0.236 == 10.89.0.236) |
| ✅ PASS | the principal resolves to a name, not an id (analyst) |
| ✅ PASS | byte counters are real — the session that carried the request shows transfer |
| ✅ PASS | the page's auditor credential authenticates on its own |
| ✅ PASS | the auditor credential CANNOT cancel a session — watching access is not a way to control it |

**Result**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | brokered access holds: authority in the enclave, one target, attributable, encrypted, carrying traffic, and reported truthfully |

**Verdict: PROVEN** — 36 assertions passed, 0 failed.
