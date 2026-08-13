## Brokered access — Boundary session into the enclave

*What passing proves:* The analyst's hop into the enclave is an authenticated, authorized, auditable session against exactly one target; the DMZ holds no authority and has no route of its own.

- Run: `uat_boundary.sh` — 2026-08-13 21:58:22Z

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
| ✅ PASS | exactly 3 workers are registered — the expected set, no stale registration to hand a session to |
| ✅ PASS | every worker advertises its own enclave egress address — sessions can dial each one distinctly |

**Attribution**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | live sessions exist |
| ✅ PASS | 8 live sessions are bound to 8 DISTINCT principals — each session individually attributable |
| ✅ PASS | every live principal is a provisioned session principal — no session runs as anything else |

**The session carries traffic**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the brokered session carried an HTTP request end to end (status 302) |
| ✅ PASS | the far end is the SSO gate — it redirected to identity |

**The session re-establishes after disruption**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | session s_HKfmdNM4p6 was canceled and the analyst path kept carrying — traffic flows |
| ✅ PASS | the recovery is a NEW authorized session (s_PqmZw9w4Q7), and s_HKfmdNM4p6 is gone — not a lingering socket |

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
| ✅ PASS | the record is complete: every one of the controller's 29 sessions is on the page (29 shown) |
| ✅ PASS | the page shows no session the controller does not have |
| ✅ PASS | every session the controller reports live is live on the page (8 of 8) |
| ✅ PASS | 8 live sessions, one per brokered port (expected 8) — separate failure domains, and no ghosts of replaced brokers |
| ✅ PASS | every session that carried a connection came from the running broker (7 of 8 addressed, 10.89.0.13) |
| ✅ PASS | every session resolves to its own session principal (8 distinct, all analyst-s*) |
| ✅ PASS | byte counters are real — the session that carried the request shows transfer |
| ✅ PASS | the page's auditor credential authenticates on its own |
| ✅ PASS | the auditor credential CANNOT cancel a session — watching access is not a way to control it |

**One session per client — the shape a fleet of workstations needs**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | 8/8 concurrent connections carried over the analyst path — capacity at this size is not the constraint |
| · | each of the 8 sessions runs as its own principal; binding a PERSON to a principal needs workstation identity (M1) |

**The fleet is spread across the sessions, not piled onto one**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | a connection distributor is deployed in the DMZ |
| ✅ PASS | no session port is reachable from the analyst network — the distributor is the only way in |
| ✅ PASS | the distributor is layer 4 (mode tcp) — it passes bytes through and cannot read the session |
| ✅ PASS | the distributor holds no TLS material — encryption stays end to end |
| ✅ PASS | no backend health probing — the checker cannot cause the failure it would report |
| ✅ PASS | redispatch is on — a connection to a dead session is retried on a sibling rather than dropped |
| ✅ PASS | held connections were carried by 2 of 3 egress workers (w1=0 w2=1 w3=4 ) — connection setup no longer funnels through one handshake path |
| · | 5 of 8 cold connections established in one burst ({'SSLEOFError': 3}) — the egress worker's setup ceiling, M3 |
| ✅ PASS | 5 connections reached 4 distinct sessions of 8 (busiest 40%, 18443=0 18444=1 18445=0 18446=2 18447=1 18448=0 18449=1 18450=0 ) — no session carries the fleet |

**One session's death is not the fleet's — measured, not asserted**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | 8 independent sessions are listening (18443-18450) — separate failure domains behind one analyst port |
| ✅ PASS | killing one session left the other 7 serving — a death costs 1/8 of the fleet, not all of it |
| ✅ PASS | the analyst port still carried a request while that session was down — the distributor routed around it |
| ✅ PASS | and the killed session came back on its own — its supervisor replaced only its own client |

**One egress worker's death is not the fleet's**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the analyst port carried a request with worker ir-egress-2 DOWN — its sessions' loss is not the fleet's |
| ✅ PASS | worker restarted and the full complement of 8 sessions is live again — recovery is unattended |

**Result**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | brokered access holds: authority in the enclave, one target, attributable, encrypted, carrying traffic, and reported truthfully |

**Verdict: PROVEN** — 52 assertions passed, 0 failed.
