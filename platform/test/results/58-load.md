## Load — 50 concurrent analysts, contention, CIA

*What passing proves:* Under a fleet's worth of concurrent real logins and colliding writes, the platform provisions correctly, answers within thresholds, refuses what RBAC forbids, loses no write, keeps every agent's identity its own, and its audit chain still verifies.

- Run: `uat_load.sh` — 2026-08-17 23:56:42Z

**Preflight — targets, snapshots, samplers**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | contention targets: investigation 13, findings 355,356,357,358,359 (verdicts snapshotted for restore) |
| ✅ PASS | the analyst path is carrying traffic before any load is applied — the baseline is a working platform |
| ✅ PASS | availability sampler running (1 Hz, own container, analyst path) |

**K — 50 users provisioned through the platform's own API, 2/s arrivals**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | all 50 users provisioned concurrently (p95 801ms per create) |
| ✅ PASS | provisioning fidelity: 50 in Django and 50 in Keycloak — no half-created account |
| ✅ PASS | every provisioned account carries exactly its intended role group |
| ✅ PASS | export right granted to 5 of 40 analysts — holders and non-holders both exist, so the boundary is testable in both directions |

**L/A/R — login storm, contended activity (60s), ramp to the knee**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | login storm: 50/50 full OIDC flows (forced change included) completed concurrently |
| ✅ PASS | storm p95 823ms over 50 completed logins, within the 8000ms ceiling (max 873ms) |
| ✅ PASS | 50 DISTINCT server-side sessions created (redis db1 0 -> 51) |
| ✅ PASS | every session was minted through an OIDC callback (51 for 50 agents) — no agent was admitted by a shortcut around the identity provider |
| ✅ PASS | the gate recorded 51 successful authentications — each agent's session is the gate's own, not a forged cookie |
| ✅ PASS | no loadtest account still carries a forced password change — every one of the 50 logins actually completed the credential rotation the platform demanded |
| ✅ PASS | zero CSRF-cookie failures at the gate across the whole storm |
| ✅ PASS | read_stats: p95 442ms within 1500ms under 50-wide contention |
| ✅ PASS | read_findings: p95 192ms within 1500ms under 50-wide contention |
| ✅ PASS | write_note: p95 337ms within 2500ms while colliding on one investigation |
| ✅ PASS | write_verdict: p95 847ms within 2500ms while colliding on one investigation |
| ✅ PASS | the application raised nothing across 4530 operations — every loss below is transport, not logic |
| ✅ PASS | 123 of 4530 operations (2%) lost their connection, within the 3% a brokered path allows — 30 session replacement(s) account for them, and each costs only its own share |
| ✅ PASS | RBAC under load: all 170 auditor writes that reached authorization were refused 403 (2 never served) |
| ✅ PASS | an unauthenticated caller was refused on every data path during the storm (401,401,401) — the platform did not shed authentication to keep up |
| ✅ PASS | confidentiality: zero identity-bleed or privilege violations across 1158 concurrent checks (3 requests never served, excluded) |
| ✅ PASS | export boundary exercised both ways under load (23 completed, 139 refused) |
| ✅ PASS | data fidelity: 661 notes for 656 the agents counted as accepted — 5 written by a request that arrived without its answer getting back, within the 5 the agents could not count |
| ✅ PASS | data fidelity: all 662 accepted adjudications are present; 1 further row(s) committed with the response lost on the way back — one for each of the 9 connection(s) the agents saw dropped, which loses nothing |
| ✅ PASS | the export ledger accounts for every attempt (24 completed, 139 denied); 1 decision(s) recorded whose answer never reached the agent, within the 4 attempt(s) it could not count |
| ✅ PASS | the audit hash chain verifies over the entire storm's entries |
| ✅ PASS | adjudication precedence survived contention: all 5 churned findings are analyst-owned with full history |
| ✅ PASS | availability 99.44% over 177 independent 1 Hz samples (health p95 3ms) — floor 99% |
| ✅ PASS | database peak 0 connections of 100 — headroom held under the whole storm |
| ✅ PASS | zero deadlocks while 50 writers collided on one investigation (0 rollbacks) |
| ❌ **FAIL** | measured capacity is 10 concurrent agents against a target of 50 — first degradation: {'step': 20, 'read_p95': 1037.9, 'errors': 6, 'error_pct': 1.63, 'budget_pct': 1.0, 'reason': 'errors', 'failing_categories': {'me': {'n': 60, 'ok': 55, 'errors_5xx': 0, 'resets': 5, 'resent': 0, 'throttled_429': 0, 'p50': 499.9, 'p95': 3400.0, 'p99': 3745.9, 'error_kinds': {'SSLEOFError: [SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of pr': 5}}, 'read_stats': {'n': 60, 'ok': 59, 'errors_5xx': 0, 'resets': 1, 'resent': 0, 'throttled_429': 0, 'p50': 107.6, 'p95': 1037.9, 'p99': 3549.3, 'error_kinds': {'SSLEOFError: [SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of pr': 1}}}} |

**Teardown — the stack keeps nothing of the storm but the ledgers**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | torn down: 50 Keycloak accounts and every loadtest note, reclassification and Django account removed; churned verdicts restored |
| · | export-ledger rows from the storm are KEPT — an export that happened is a record, not residue |
| ✅ PASS | default-admin restored to provisioned state |

**Results**

| Result | Assertion — with evidence |
|---|---|
| · | measurements: test/results/58-load-measurements.md (table) + .json (for comparison against the next run) |

**Verdict: NOT PROVEN** — 34 assertions passed, 1 failed.
