## Corpus S — 20 endpoints, eight months of dwell

*What passing proves:* A campaign that dwells for 238 days correlates as one, with four members carrying no movement record and every indicator rotated away — while two unrelated endpoints running the same unsanctioned tool 190 days apart stay separate, and the host whose delivery evidence aged out reports that it could not be established rather than that nothing was found.

- Run: `uat_corpus_slow.sh` — 2026-08-06 16:57:25Z

**Preconditions**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | ir-dmz_receiver_1 running |
| ✅ PASS | ir-enclave_puller_1 running |
| ✅ PASS | ir-enclave_backend_1 running |
| ✅ PASS | ir-enclave_worker_1 running |
| ✅ PASS | collector image rebuilt from current source |
| ✅ PASS | the collector runs the full forensics collection (--deep) |
| ✅ PASS | 20 endpoint scenarios generated |
| ✅ PASS | manifest published to the backend for comparison |
| ✅ PASS | prior INC-CORPUS-S data reset (real evidence untouched) |
| ✅ PASS | receiver holds an address on the edge network |

**Collection — 20 real collector runs, shipped from the edge**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | all 20 bundles collected, sealed and accepted by the receiver |

**Ingest — the puller delivers all 20 runs**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | 20 INC-CORPUS-S runs ingested through receiver -> puller -> ingest |
| ✅ PASS | 20 distinct hosts with 20 distinct machine ids — no endpoint merged into another |

**Analysis — every capture is analyzed and adjudicated before compromise is read**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | captures terminal and compromise settled (20 analyzed, 9 compromised) |
| ✅ PASS | every analysis completed (20) |
| ✅ PASS | every analysis was adjudicated by the investigation engine (20) |

**Correlation**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | correlation ran for INC-CORPUS-S (1 investigation(s)) |

**Classification — eight months of evidence, and the estate's own noise throughout**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | 9 endpoints classify compromised across 238 days |
| ✅ PASS | 11 endpoints classify clean |
| · | campaign span 238d, largest gap between hosts 56d, shadow-IT installs 190d apart |

**L0 — the habits span the campaign, the infrastructure does not**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the WMI subscription is on 7 of the 7 compromised hosts |
| ✅ PASS | the staging file convention is on 3 of the 7 compromised hosts |
| ✅ PASS | the attributed family is on 7 of the 7 compromised hosts |
| ✅ PASS | no C2 domain reaches more than 3 of 7 hosts — the infrastructure rotated |
| ✅ PASS | the unsanctioned remote-access tool is an artifact on 2 hosts |

**L1/L2 — 238 days is one campaign, and 190 days apart is not**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | all 7 hosts touched over 238 days are ONE campaign (7 found) |
| ✅ PASS | the 4 endpoints reached over the VPN — no movement record — are members |
| ✅ PASS | the two shadow-IT endpoints 190 days apart are NOT in the campaign |
| ✅ PASS | and the pair is DECLINED on its own merits (weight 0.2973, temporal 0.584) |
| ✅ PASS | patient zero is the first host touched, 238 days before the last (RD-WS-04) |
| ✅ PASS | no clean endpoint appears in any campaign (11 clean) |

**L1 — coherence measures the shared evidence, not the estate's schedule**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | a pair 38d apart reads MORE coherent than one 238d apart (0.917 vs 0.478) |
| ✅ PASS | no accepted link inside the campaign sits at the coherence floor (14 links) |
| ✅ PASS | the 190d shadow-IT pair reads less coherent than a campaign hop (0.584 vs 0.917) |

**L3 — evidence that aged out reads as undetermined, not as absent**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the host whose logs rotated carries its undetermined-scan finding (1) |
| ✅ PASS | and it is adjudicated Indeterminate rather than treated as a clean result (Indeterminate) |
| ✅ PASS | RD-WS-04 is still a campaign member despite its thinner evidence |
| · | RD-WS-04: band=probable why=link to IT-WS-01 at 0.44 with 11 evidence kind(s) |

**L4 — the sequence is the operator's eight months, in order**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the campaign has naming conventions (4): ['persistence_wmi:BVT<name> -> BVT<name>', 'sideloaded_dll:<name>.dll', 'yara_rule:APT_<name><name>_<name>', 'staging_name:~WRD<number>.tmp'] |
| ✅ PASS | the estate's own scheduled task is not reported as this operator's tradecraft |
| ✅ PASS | nor is the unsanctioned remote-access tool from an unrelated compromise |
| ✅ PASS | credential access precedes certificate theft in the sequence (['T1574', 'T1546', 'T1071', 'T1003', 'T1560', 'T1021', 'T1649', 'T1041']) |
| ✅ PASS | persistence precedes exfiltration |
| ✅ PASS | and the sequence ends on the exfiltration it was all for (['T1021', 'T1649', 'T1041']) |

**Population — a fourth fleet leaves the others alone**

| Result | Assertion — with evidence |
|---|---|
| · | deployment host population at correlation time: 95 |
| ✅ PASS | INC-CORPUS-A still classifies 12 compromised with a fourth fleet present |
| ✅ PASS | no INC-CORPUS-A campaign reaches a Glass Heron endpoint |
| ✅ PASS | INC-CORPUS-B still classifies 4 compromised with a fourth fleet present |
| ✅ PASS | no INC-CORPUS-B campaign reaches a Glass Heron endpoint |
| ✅ PASS | INC-CORPUS-L still classifies 10 compromised with a fourth fleet present |
| ✅ PASS | no INC-CORPUS-L campaign reaches a Glass Heron endpoint |
| ✅ PASS | INC-CORPUS-R still classifies 18 compromised with a fourth fleet present |
| ✅ PASS | no INC-CORPUS-R campaign reaches a Glass Heron endpoint |

**Verdict: PROVEN** — 50 assertions passed, 0 failed.
