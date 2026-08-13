## Platform baseline — identity and SSO gate

*What passing proves:* The deployed platform serves its API behind the SSO gate, with identity enforced rather than assumed.

- Run: `uat_baseline.sh` — 2026-08-13 21:59:16Z

**Components — every tier answers**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | ir-enclave_db_1 running |
| ✅ PASS | ir-enclave_redis_1 running |
| ✅ PASS | ir-enclave_minio_1 running |
| ✅ PASS | ir-enclave_backend_1 running |
| ✅ PASS | ir-enclave_worker_1 running |
| ✅ PASS | ir-enclave_puller_1 running |
| ✅ PASS | ir-dmz_receiver_1 running |
| ✅ PASS | receiver resolves by name (receiver -> 10.89.0.11) |

**Collector — identity is the machine's, not the container's**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | collection produced ubuntu-main/ |
| ✅ PASS | hostname resolved from host-mount (ubuntu-main) |
| ✅ PASS | machine-id recorded (32 chars, value withheld) |
| ✅ PASS | toolkit and collector agree on the hostname |

**Memory capture — succeeds, or says exactly why not**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | synthetic fallback records why: Error: error: unable to parse /proc/iomem caused by:     0: … |
| ✅ PASS | fallback warned loudly in the log |

**DMZ receiver — accepts a verified bundle, refuses what will not fit**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | bundle accepted and custody-verified |
| ✅ PASS | oversized upload refused up front (400) |

**Transport — evidence does not cross the wire in the clear**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the configured receiver URL is https (https://receiver:8090) |
| ✅ PASS | receiver negotiates TLS (TLSv1.3) |
| ✅ PASS | receiver's certificate verifies against the pinned CA |
| ✅ PASS | a client without the pinned CA is rejected (verification is real) |

**Boundary — the DMZ cannot reach in, and leaks nothing about the enclave**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | receiver cannot reach ir-enclave_db_1:5432 |
| ✅ PASS | receiver cannot reach ir-enclave_minio_1:9000 |
| ✅ PASS | receiver cannot reach ir-enclave_backend_1:8000 |
| · | /stats not reachable from the edge network (also acceptable) |

**Enclave — the bundle lands, and joins the host it came from**

| Result | Assertion — with evidence |
|---|---|
| · | collection runs currently recorded: 117 |
| ✅ PASS | no machine-id maps to two host records |

**Analysis — the parser gate holds on real evidence**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | no C2/config findings on a clean host (0) |
| ✅ PASS | no run is marked compromised by synthetic content alone |

**Component health — every reporter is present and current**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | 7 component(s) reporting resources |
| · | stale reporters: worker (27e338e1f438),worker (7e7480b4bd16) (expected shortly after a restart) |
| · | open capacity/resource alerts: 6 |

**Login branding — the custom theme is actually served**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | login page serves the platform theme |
| ✅ PASS | login page carries the platform wordmark |
| ✅ PASS | no theme-load failures in the identity provider |

**Manifests describe what is actually here**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the code graph matches the tree — services, scripts, routes and their UATs are current |
| ✅ PASS | every documented link resolves, and every document is in the change-management inventory |
| ✅ PASS | no narrative comments, and no file is majority prose |
| ✅ PASS | runtime locks: 95 of 2048 in use (46 volumes, 49 containers) — room to create containers |

**Baseline**

| Result | Assertion — with evidence |
|---|---|

**Verdict: PROVEN** — 34 assertions passed, 0 failed.
