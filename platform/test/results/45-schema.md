## Schema integrity — invariants enforced by the database

*What passing proves:* Identity and idempotency are refused at the store, not merely avoided by the application: a concurrent duplicate host is rejected, a re-posted collection cannot duplicate, and the queries the UI runs use the indexes built for them. Adjudication is held to the same standard — a re-analysis supersedes rather than deletes, and an automated pass cannot discard an analyst's verdict without recording that it disagreed.

- Run: `uat_schema.sh` — 2026-08-14 23:52:22Z

**Preconditions**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | ir-enclave_backend_1 running |

**Host identity — one machine cannot become two**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | a second host claiming the same machine-id is REFUSED by the database |
| ✅ PASS | hosts with NO machine-id remain distinct — the constraint is partial |
| ✅ PASS | the probe left no rows behind |

**Collection idempotency — one collection cannot be counted twice**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | re-posting the same (investigation, host, stamp) is REFUSED by the database |
| ✅ PASS | a SECOND collection of the same host under a new stamp is still accepted |
| ✅ PASS | the probe left no runs behind |

**Host identity is historised, not overwritten**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | a renamed machine still resolves to ONE host (machine-id is the key) |
| ✅ PASS | the host follows the current name |
| ✅ PASS | the rename produced exactly one history row (1) |
| ✅ PASS | the history names what it WAS and what it became (uat-old-name -> uat-new-name) |
| ✅ PASS | the history names the collection that observed it (uat-stamp-2) |
| ✅ PASS | an unchanged name writes NO history row |
| ✅ PASS | a container-fallback name is REFUSED as a rename — identity is not rewritten by it |
| ✅ PASS | the rename probe left no rows behind |

**Indexes serve the queries they were built for**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the ATT&CK containment query uses the GIN index |
| ✅ PASS | the source index serves the source filter |
| ✅ PASS | Finding.raw carries no index — it is read in Python, never queried by key in SQL |

**S5 — a re-analysis supersedes the prior adjudication, never deletes it**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | a run carrying engine adjudication exists to assert against |
| ✅ PASS | the run's current adjudication is present (1 PIDs) |
| ✅ PASS | no PID carries two live verdicts (0 duplicated) |
| ✅ PASS | superseding DESTROYS NOTHING — 1 rows before, 1 after |
| ✅ PASS | the superseded pass leaves the live set (1 -> 0) |
| ✅ PASS | every superseded row records WHEN it was superseded |
| ✅ PASS | the supersede probe left the deployment's adjudication as it found it |

**S6 — purging an image keeps the conclusions drawn from it**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | an analyzed capture exists to assert against |
| ✅ PASS | purging the image leaves every analysis run intact (1) |
| ✅ PASS | purging the image leaves its findings intact (18) |
| ✅ PASS | purging the image leaves the per-PID adjudication intact (1) |
| ✅ PASS | the purge probe left the capture's retention state as it found it |

**S3/S4 — an automated pass may not quietly discard a human determination**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | an adjudicated run with a memory analysis pass exists to assert against |
| ✅ PASS | a finding the engine holds a verdict for exists to assert against |
| ✅ PASS | an engine pass does NOT overwrite the analyst's verdict (kept True Positive; the engine said Indeterminate) |
| ✅ PASS | the disagreement is RECORDED for review instead of applied (engine: Indeterminate) |
| ✅ PASS | the conflict names the pass that disagreed (run 937) |
| ✅ PASS | a refused overwrite writes no history — nothing changed to record |
| ✅ PASS | a verdict the ENGINE owns is still revised by a later pass (True Positive -> Indeterminate) |
| ✅ PASS | the change of mind is history naming BOTH values (True Positive -> Indeterminate) |
| ✅ PASS | the history row names the analysis pass that decided it |
| ✅ PASS | the finding records which pass produced its verdict |
| ✅ PASS | where the engine AGREES, the standing conflict is cleared |
| ✅ PASS | agreement does not quietly transfer ownership away from the analyst |
| ✅ PASS | the precedence probes left the finding exactly as they found it (Indeterminate) |
| ✅ PASS | no engine-adjudicated finding was left unowned by the backfill (0 stranded) |
| ✅ PASS | every finding an analyst reclassified is marked as theirs (0 unprotected) |
| ✅ PASS | a new investigation starts open |
| ✅ PASS | the model REFUSES open -> archived; archival cannot skip conclusion |
| ✅ PASS | concluding stamps concluded_at for the stalled-case query |
| ✅ PASS | reopening CLEARS concluded_at — a reopened case is not a concluded one |
| ✅ PASS | archived is terminal — its evidence has been moved out |
| ✅ PASS | a bundle's ISO timestamp parses to a datetime |
| ✅ PASS | a datetime passes through still aware |
| ✅ PASS | a naive timestamp is made aware rather than refused — the instant is still real |
| ✅ PASS | an absent or unparseable timestamp yields None, so the caller falls back to now() |
| ✅ PASS | ingest writes an indicator sighting beside the IOC rows |
| ✅ PASS | the sighting carries its investigation and hostname denormalized |
| ✅ PASS | a re-collection increments the sighting rather than duplicating it |
| ✅ PASS | deleting the runs took their IOC rows with them |
| ✅ PASS | and the indicator sighting SURVIVED — the cross-case pivot still answers |
| ✅ PASS | T1/T2 left nothing behind — the probe is re-runnable |

**Probe completed**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | every assertion in the probe ran — no section was cut short |

**The audit chain stays linear when writers collide**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | 24 concurrent appenders all wrote (24/24) — none lost to lock contention |
| ✅ PASS | every racing row chained from a DIFFERENT predecessor (24/24 distinct) — the appenders serialized |
| ✅ PASS | 24 simultaneous appends left the chain exactly as they found it (ok) — concurrency adds no break |

**An acknowledged discontinuity is not a way to clear a real one**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the chain verifies with 0 acknowledged discontinuit(ies) and no unexplained break |
| ✅ PASS | editing a row still breaks the chain (detected at entry 14947) — checkpoints do not blanket-forgive |
| ✅ PASS | a checkpoint naming the wrong hashes did NOT clear the break (still 14947) — an acknowledgement must match its gap |
| ✅ PASS | the ledger is unchanged by this test (0 discontinuities, same as before) |

**Result**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the schema enforces its own invariants — the application no longer has to be careful |

**Verdict: PROVEN** — 69 assertions passed, 0 failed.
