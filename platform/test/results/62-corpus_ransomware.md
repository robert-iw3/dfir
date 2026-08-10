## Corpus R — 24 endpoints, mass encryption and destruction

*What passing proves:* A ransomware event correlates as ONE campaign despite its signature being on most of the fleet, 13 members having no movement record, two never being encrypted and one only being destroyed — and the hosts whose logs the actor cleared report their compromise date as unanswered rather than guessing.

- Run: `uat_corpus_ransomware.sh` — 2026-08-09 02:11:00Z

**Preconditions**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | ir-dmz_receiver_1 running |
| ✅ PASS | ir-enclave_puller_1 running |
| ✅ PASS | ir-enclave_backend_1 running |
| ✅ PASS | ir-enclave_worker_1 running |
| ✅ PASS | collector image rebuilt from current source |
| ✅ PASS | the collector runs the full forensics collection (--deep) |
| ✅ PASS | 24 endpoint scenarios generated |
| ✅ PASS | manifest published to the backend for comparison |
| ✅ PASS | prior INC-CORPUS-R data reset (real evidence untouched) |
| ✅ PASS | receiver holds an address on the edge network |

**Collection — 24 real collector runs, shipped from the edge**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | all 24 bundles collected, sealed and accepted by the receiver |

**Ingest — the puller delivers all 24 runs**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | 24 INC-CORPUS-R runs ingested through receiver -> puller -> ingest |
| ✅ PASS | 24 distinct hosts with 24 distinct machine ids — no endpoint merged into another |

**Analysis — every capture is analyzed and adjudicated before compromise is read**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | captures terminal and compromise settled (24 analyzed, 18 compromised) |
| ✅ PASS | every analysis completed (24) |
| ✅ PASS | every analysis was adjudicated by the investigation engine (24) |

**Correlation**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | correlation ran for INC-CORPUS-R (1 investigation(s)) |

**Classification — impact, delivery and destruction all read as compromise**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | 18 endpoints classify compromised, exactly the planted set |
| ✅ PASS | 6 endpoints classify clean inside the same ninety minutes |
| ✅ PASS | ENG-WS-05 was staged and never encrypted, and still classifies compromised |
| ✅ PASS | SRV-PRINT-01 was staged and never encrypted, and still classifies compromised |
| ✅ PASS | SRV-BKP-01 carries destruction without encryption and still classifies compromised |

**L0 — impact vocabulary reaches the graph**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the ransom note is an artifact node valued '!!!_RESTORE_YOUR_FILES_!!!.txt' on 12 host(s) |
| ✅ PASS | the policy object the payload rode out on is an artifact node valued 'Corp-Endpoint-Baseline-v4' on 1 host(s) |
| ✅ PASS | the deployment task is an artifact node valued '\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestart' on 16 host(s) |
| ✅ PASS | the attributed family is an artifact node valued 'VaultSerpent' on 12 host(s) |
| · | the ransom note is on 12 of 24 endpoints in this fleet |

**L1/L2 — one event, one campaign, whatever stage each host reached**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | all 16 affected endpoints are ONE campaign (16 found) |
| ✅ PASS | the fleet resolves to exactly two compromises, not fragments ([16, 2]) |
| ✅ PASS | the 13 endpoints reached by policy — no movement record anywhere — are members |
| ✅ PASS | ENG-WS-05 is a member despite carrying no encryption |
| ✅ PASS | SRV-PRINT-01 is a member despite carrying no encryption |
| ✅ PASS | SRV-BKP-01 is a member despite carrying no encryption |
| ✅ PASS | patient zero is the phished workstation (FIN-WS-03) |
| ✅ PASS | no pair is joined by the estate's own scheduled task or backup account, which touch every host in the same hour |
| ✅ PASS | no clean endpoint appears in any campaign (6 clean) |
| ✅ PASS | the unrelated data theft is NOT pulled in by the rclone.exe both operators used |
| ✅ PASS | and the two hosts it did touch are their own campaign (cohesion 0.6794) |

**L3 — where the actor removed the history, the date reads as unanswered**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the campaign's hosts carry membership bands (18) |
| ✅ PASS | every band comes from the declared vocabulary |
| ✅ PASS | the event reaches the top band (['confirmed', 'probable']) |
| ✅ PASS | every band decomposes into its named factors |
| · | DC-R1: band=confirmed timeline=consistent — FIN-WS-03 shows compromise from 2026-07-29T19:12:00+00:00, movement at 2026-07-29T22:05 |
| · | SRV-BKP-01: band=probable timeline=None |
| · | SRV-FS-01: band=confirmed timeline=consistent — FIN-WS-03 shows compromise from 2026-07-29T19:12:00+00:00, movement at 2026-07-29T21:40 |
| · | SRV-VC-01: band=probable timeline=None |
| ✅ PASS | every host whose membership involves movement states what the timeline test found (3/3: ['DC-R1', 'FIN-WS-03', 'SRV-FS-01']) |
| ✅ PASS | FIN-WS-03 states the finding in words (consistent — FIN-WS-03 shows compromise from 2026-07-29T19:12:00+00:00, movement) |
| ✅ PASS | SRV-FS-01 states the finding in words (consistent — FIN-WS-03 shows compromise from 2026-07-29T19:12:00+00:00, movement) |
| ✅ PASS | DC-R1 states the finding in words (consistent — FIN-WS-03 shows compromise from 2026-07-29T19:12:00+00:00, movement) |
| ✅ PASS | a host with no movement on any link reports no timeline finding rather than inventing one |

**L4/L5 — the affiliate's habits, and what they are not attributed to**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the campaign has naming conventions (5): ['ransom_note:!!!_RESTORE_YOUR_FILES_!!!.txt', 'yara_rule:RANSOM_<name><name>_<name>_v<number>', 'staging_name:_<name>.7z', 'gpo_name:<name>-<name>-<name>-v<number>'] |
| ✅ PASS | the estate's own update task is not reported as this affiliate's tradecraft |
| ✅ PASS | the technique sequence ends on impact (['T1562', 'T1490', 'T1489', 'T1486', 'T1070']) |
| ✅ PASS | and opens on the delivery that started it (['T1566', 'T1574', 'T1003', 'T1105']) |
| ✅ PASS | the event is not attributed to any other corpus actor |

**Population — a third fleet in the deployment leaves the other two alone**

| Result | Assertion — with evidence |
|---|---|
| · | deployment host population at correlation time: 95 |
| ✅ PASS | INC-CORPUS-A still classifies 12 compromised with a third fleet present |
| ✅ PASS | no INC-CORPUS-A campaign reaches a Vault Serpent endpoint |
| ✅ PASS | INC-CORPUS-B still classifies 4 compromised with a third fleet present |
| ✅ PASS | no INC-CORPUS-B campaign reaches a Vault Serpent endpoint |
| ✅ PASS | INC-CORPUS-L still classifies 10 compromised with a third fleet present |
| ✅ PASS | no INC-CORPUS-L campaign reaches a Vault Serpent endpoint |
| ✅ PASS | corpus L still clusters all 8 of its hosts (8) |

**Verdict: PROVEN** — 58 assertions passed, 0 failed.
