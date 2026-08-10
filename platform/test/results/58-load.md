## Load — 50 concurrent analysts, contention, CIA

*What passing proves:* Under a fleet's worth of concurrent real logins and colliding writes, the platform provisions correctly, answers within thresholds, refuses what RBAC forbids, loses no write, keeps every agent's identity its own, and its audit chain still verifies.

- Run: `uat_load.sh` — 2026-08-10 02:22:09Z

**Preflight — targets, snapshots, samplers**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | contention targets: investigation 13, findings 305,306,307,308,309 (verdicts snapshotted for restore) |
| ✅ PASS | the analyst path is carrying traffic before any load is applied — the baseline is a working platform |
| ✅ PASS | availability sampler running (1 Hz, own container, analyst path) |

**K — 50 users provisioned through the platform's own API, 2/s arrivals**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | all 50 users provisioned concurrently (p95 399ms per create) |
| ✅ PASS | provisioning fidelity: 50 in Django and 50 in Keycloak — no half-created account |
| ✅ PASS | every provisioned account carries exactly its intended role group |
| ✅ PASS | export right granted to 5 of 40 analysts — holders and non-holders both exist, so the boundary is testable in both directions |

**L/A/R — login storm, contended activity (60s), ramp to the knee**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | login storm: 50/50 full OIDC flows (forced change included) completed concurrently |
| ✅ PASS | storm p95 795ms over 50 completed logins, within the 8000ms ceiling (max 918ms) |
| ✅ PASS | 50 DISTINCT server-side sessions created (redis db1 153 -> 204) |
| ✅ PASS | every session was minted through an OIDC callback (51 for 50 agents) — no agent was admitted by a shortcut around the identity provider |
| ✅ PASS | the gate recorded 51 successful authentications — each agent's session is the gate's own, not a forged cookie |
| ✅ PASS | no loadtest account still carries a forced password change — every one of the 50 logins actually completed the credential rotation the platform demanded |
| ✅ PASS | zero CSRF-cookie failures at the gate across the whole storm |
| ✅ PASS | read_stats: p95 154ms within 1500ms under 50-wide contention |
| ✅ PASS | read_findings: p95 115ms within 1500ms under 50-wide contention |
| ✅ PASS | write_note: p95 266ms within 2500ms while colliding on one investigation |
| ✅ PASS | write_verdict: p95 316ms within 2500ms while colliding on one investigation |
| ✅ PASS | the application raised nothing across 5311 operations — every loss below is transport, not logic |
| ✅ PASS | 14 of 5311 operations (0%) lost their connection, within the 3% a brokered path allows — 15 session replacement(s) account for them, and each costs only its own share |
| ✅ PASS | RBAC under load: all 269 auditor writes that reached authorization were refused 403 (0 never served) |
| ✅ PASS | an unauthenticated caller was refused on every data path during the storm (401,401,401) — the platform did not shed authentication to keep up |
| ✅ PASS | confidentiality: zero identity-bleed or privilege violations across 1898 concurrent checks (0 requests never served, excluded) |
| ✅ PASS | export boundary exercised both ways under load (40 completed, 260 refused) |
| ✅ PASS | data fidelity: 1071 notes in the database — exactly the 1071 the agents recorded as accepted, none lost, none duplicated |
| ✅ PASS | data fidelity: 1071 reclassification history rows — one per accepted adjudication under contention |
| ✅ PASS | the export ledger accounts for every attempt under load (40 completed, 260 denied — matching the agents exactly) |
| ✅ PASS | the audit hash chain verifies over the entire storm's entries |
| ✅ PASS | adjudication precedence survived contention: all 5 churned findings are analyst-owned with full history |
| ✅ PASS | availability 100.00% over 221 independent 1 Hz samples (health p95 3ms) — floor 99% |
| ✅ PASS | database peak 0 connections of 100 — headroom held under the whole storm |
| ✅ PASS | zero deadlocks while 50 writers collided on one investigation (0 rollbacks) |
| ✅ PASS | measured capacity: the design held at 50 concurrent agents (target 50); degradation: None |

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

**Verdict: PROVEN** — 35 assertions passed, 0 failed.
