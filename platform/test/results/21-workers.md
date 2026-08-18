## N memory-analysis workers drain one surge in parallel

*What passing proves:* With five workers consuming the one analysis queue, a 25-endpoint surge is analyzed with real overlap across at least three distinct workers, every capture exactly once, each analysis attributed to the worker that ran it, and every replica registered in the mesh under the ir-worker name with its own sidecar.

- Run: `uat_workers.sh` — 2026-08-14 14:20:43Z

**1/4  The worker fleet is real — containers, mesh identities, isolation**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | worker + 4 replicas running (worker-2..worker-5) |
| ✅ PASS | the mesh carries 5 instances under ONE service name (ir-worker,ir-worker-2,ir-worker-3,ir-worker-4,ir-worker-5) — intentions cover all of them unchanged |
| ✅ PASS | every replica has its own Envoy sidecar in its own namespace |
| ✅ PASS | every replica stages on its OWN scratch volume — no replica can evict another's capture |

**2/4  The surge — a fleet's memory arrives at once**

| Result | Assertion — with evidence |
|---|---|

**Preconditions**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | ir-dmz_receiver_1 running |
| ✅ PASS | ir-enclave_puller_1 running |
| ✅ PASS | ir-enclave_backend_1 running |
| ✅ PASS | ir-enclave_worker_1 running |
| ✅ PASS | collector image current with collector/ |
| ✅ PASS | the collector runs the full forensics collection (--deep) |
| ✅ PASS | 25 endpoint scenarios generated — the flagged fleet |
| ✅ PASS | prior INC-CORPUS data reset (real evidence untouched) |
| ✅ PASS | receiver holds an address on the edge network |
| ✅ PASS | all 25 bundles collected, sealed and accepted by the receiver |
| ✅ PASS | 25 endpoints collected and shipped in one burst |
| ✅ PASS | 25 INC-CORPUS runs ingested through receiver -> puller -> ingest |
| ✅ PASS | 25 distinct hosts with 25 distinct machine ids — no endpoint merged into another |
| ✅ PASS | every capture reached a terminal analysis and compromise settled (25/25 analyzed, 16 compromised) |
| ✅ PASS | every analysis completed (25) |
| ✅ PASS | every analysis was adjudicated by the investigation engine (25) |

**3/4  The proof — parallel, distributed, exactly once**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | 16 re-analyses dispatched in ONE burst through the platform's own endpoint |
| ✅ PASS | 16 analyses completed for the burst |
| ✅ PASS | the load was carried by 5 distinct workers (worker\|worker-2\|worker-3\|worker-4\|worker-5) — one queue, many hands |
| ✅ PASS | every capture was analyzed EXACTLY once — N consumers did not double-draw from the queue |
| ✅ PASS | true parallelism: 6 analyses were in flight at one instant, by the platform's own timestamps |

**4/4  The fleet is observable and attributable**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | every worker reports under its OWN role (worker,worker-2,worker-3,worker-4,worker-5) — a sick replica is findable |
| ✅ PASS | every analysis names the worker that performed it — reproducibility material, like the engine version |

**Verdict: PROVEN** — 27 assertions passed, 0 failed.
