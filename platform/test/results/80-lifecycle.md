## The forensic lifecycle, end to end, on one real case

*What passing proves:* Ember Fox is collected from endpoints, sealed, shipped, pulled inward, analyzed and correlated; three analysts carry it across the board with their own notes and a peer review; and the case ends as a technical report and a plain-language summary whose figures match the evidence they came from, before going cold and coming back whole.

- Run: `uat_lifecycle.sh` — 2026-08-17 21:19:50Z

**1/9  Identification — real collections from the endpoints**

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
| ✅ PASS | 25 endpoint scenarios generated (Ember Fox plus the fleet it hides in) |
| ✅ PASS | prior INC-CORPUS data reset (real evidence untouched) |
| ✅ PASS | receiver holds an address on the edge network |
| · | collections are signed with the key the enclave verifies against |
| ✅ PASS | all 25 bundles collected, sealed and accepted by the receiver |
| ✅ PASS | 25 endpoints collected, sealed at the point of collection and shipped |

**2/9  Preservation — the enclave pulls inward and custody survives the journey**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | 25 INC-CORPUS runs ingested through receiver -> puller -> ingest |
| ✅ PASS | 25 distinct hosts with 25 distinct machine ids — no endpoint merged into another |
| ✅ PASS | the enclave pulled all 25 collections inward; nothing was pushed to it |
| ✅ PASS | every one of the 20 Ember Fox collections verified its custody seal on arrival |

**3/9  Analysis — memory is analyzed and the campaign is correlated**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | every capture reached a terminal analysis and compromise settled (25/25 analyzed, 16 compromised) |
| ✅ PASS | every analysis completed (25) |
| ✅ PASS | every analysis was adjudicated by the investigation engine (25) |
| ✅ PASS | correlation ran for INC-CORPUS (7 investigation(s)) |
| ✅ PASS | Ember Fox is investigation 10 |

**4/9  Three analysts, each with their own identity**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | three analysts and an admin, each a distinct principal |

**5/9  The board carries the work — and each analyst signs their own part**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the collector opens the first task in Identification |
| ✅ PASS | collector records what they did and moves it to Preservation |
| ✅ PASS | the examiner opens their own task in Analysis and links the evidence it rests on |
| ✅ PASS | the reviewer returns work to Analysis and says why — the board records the disagreement |
| ✅ PASS | the examiner answers the review and moves to Documentation |
| ✅ PASS | a blocked task keeps its stage and carries why — blocking is not a column |
| ✅ PASS | a peer-review document uploads and is hashed on receipt (3ab1e2641bc0…, 325 bytes) |
| ✅ PASS | one task carries both an uploaded document and a reference to held evidence |
| ✅ PASS | the stored bytes hash to what was recorded — the attachment is the file that arrived |
| ✅ PASS | three distinct analysts left notes on this case — the work is attributable to people |

**5b/9  The same machine, seen again in a later engagement**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the rebuilt machine is ONE host (12) with 2 collections across two cases, not two hosts |
| ✅ PASS | the host page answers 'seen before?': 2 collections over 2 cases, 17 rename, 21 findings |

**6/9  Documentation — the record, including what was ruled OUT**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | summary, recommendation, containment action and a ruled-out hypothesis are on the record |

**7/9  Presentation — two reports, generated from the case's own data**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the technical report generates |
| ✅ PASS | the plain-language summary generates |
| ✅ PASS | and the same report renders to PDF inside the enclave, offline |
| ✅ PASS | the PDF is a real document — 25 paginated pages, not one long dump |
| ✅ PASS | it is typeset — a body face, bold headings and a monospace for identifiers |

**8/9  The report is the evidence — every figure checked against its table**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the report's host count is the run table's (20) |
| ✅ PASS | its finding count is the finding table's (250) |
| ✅ PASS | its evidence inventory counts every capture (20) |
| ✅ PASS | the ruled-out hypothesis reached the report |
| ✅ PASS | the chain of custody is a section, not a claim in prose |
| ✅ PASS | links the engine CONSIDERED AND DECLINED are reported |
| ✅ PASS | attribution carries its restraint — the platform names no culprit |
| ✅ PASS | the negative finding is stated in full, with how it was tested |
| ✅ PASS | the report declares its timezone |
| ✅ PASS | custody and ledger verification are recomputed at render, not read from a flag |
| ✅ PASS | every indicator is defanged — nothing in the report can be clicked into a live C2 |
| ✅ PASS | all 35 renders are recorded with their hash and the moment the data was read |
| ✅ PASS | taking the report OUT is refused without the export right — generating is not exporting |
| ✅ PASS | an identity holding the right takes it out |
| ✅ PASS | and the export ledger records what left the platform (9 row(s)) |
| ✅ PASS | every step of the lifecycle is in the audit ledger (5 action kinds) and the chain still verifies |

**9/9  Retention — the finished case goes cold and comes back whole**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the case being archived is a real one — 250 findings, 20 captures, 1 correlation run(s) |
| ✅ PASS | the bundle is sealed and uploaded, and read back from cold storage before a single row is deleted |
| ✅ PASS | and it is flagged as archived while still open — the anomaly is recorded, not smoothed over |
| ✅ PASS | the hot tier sheds the bulk — findings, indicators and verdicts are gone from it |
| ✅ PASS | the evidence itself stays — all 20 captures are still addressable |
| ✅ PASS | the case is still listed, marked cold, with the counts it went in with (250 findings) |
| ✅ PASS | the retention queue is admin-only — an analyst is not shown what is about to be aged out |
| ✅ PASS | the queue states its own windows — 120-day grace, 180-day ceiling |
| ✅ PASS | restoring is admin-only — an analyst cannot pull a case back on their own authority |
| ✅ PASS | an admin restores it through the API, verified against its seal first |
| ✅ PASS | the findings come back identical, original ids and all (b6c223db3f72…) |
| ✅ PASS | so do the indicators (182) and the adjudicated verdicts (20) |
| ✅ PASS | the report regenerates from the restored case with the figures it had before it went cold (250 findings, 20 captures) |
| ✅ PASS | and it is still drawn from the tables, not from the bundle — custody verified against the restored rows |
| ✅ PASS | an expired restore re-cools itself on the next sweep |
| ✅ PASS | the hot rows are shed again and the case reads cold, with no loan outstanding |
| ✅ PASS | and it restores again after re-cooling — the case is left hot, whole and workable |
| ✅ PASS | archive, restore and re-cool are each in the ledger, and it still verifies |

**Verdict: PROVEN** — 73 assertions passed, 0 failed.
