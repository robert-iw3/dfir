## Corpus v2 — 25 endpoints, end to end

*What passing proves:* 25 real collector runs — 16 compromised across two investigations, 9 clean, fleet-wide benign noise on all — ship, ingest, analyze and correlate through the production path; clean hosts classify clean and join no campaign.

- Run: `uat_corpus.sh` — 2026-08-12 14:16:47Z

**Preconditions**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | ir-dmz_receiver_1 running |
| ✅ PASS | ir-enclave_puller_1 running |
| ✅ PASS | ir-enclave_backend_1 running |
| ✅ PASS | ir-enclave_worker_1 running |
| ✅ PASS | collector image current with collector/ |
| ✅ PASS | the collector runs the full forensics collection (--deep) |
| ✅ PASS | 25 endpoint scenarios generated |
| ✅ PASS | prior corpus data reset (real evidence untouched) |
| ✅ PASS | receiver holds an address on the edge network |

**Collection — 25 real collector runs, shipped from the edge**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | all 25 bundles collected, sealed and accepted by the receiver |

**Ingest — the puller delivers all 25 runs**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | 25 corpus runs ingested through receiver -> puller -> ingest |
| ✅ PASS | 25 distinct hosts with 25 distinct machine ids — no endpoint merged into another |

**Analysis — every capture is analyzed and adjudicated before compromise is read**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | all 25 captures terminal and compromise settled (16 compromised) |
| ✅ PASS | every corpus analysis completed (25) |
| ✅ PASS | every analysis was adjudicated by the investigation engine (25) |

**Classification — compromise is derived from verdicts, and clean means clean**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the 9 clean endpoints classify CLEAN despite carrying the full benign baseline |
| ✅ PASS | the 16 seeded intrusions classify compromised |

**Memory — the analyzer derives the scenario's artifacts from the image itself**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | WS-007's memory image analysis surfaced its C2 address — derived from the image, not declared |

**Correlation — computed from the ingested evidence**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | no clean endpoint appears in ANY campaign |
| ✅ PASS | Ember Fox correlates with WS-007 as patient zero |
| ✅ PASS | Quiet Fox correlates with WS-101 as patient zero |
| ✅ PASS | the cryptominer stays separate DESPITE sharing a fleet-wide account (G2 closed) |

**Weighted linkage — evidence is scored, and weak links are declined with reasons**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | correlation ran at the weighted algorithm version (2.0) |
| ✅ PASS | the Ember/miner pair was CONSIDERED — the shared fleet-wide account makes it a candidate (20 pairs) |
| ✅ PASS | every Ember/miner candidate was DECLINED — G2 closed by weighting, not by absence |
| ✅ PASS | the ubiquitous helpdesk account is in the behavior graph |
| ✅ PASS | the fleet-wide account reads as ENVIRONMENT (rarity 0.334 across 20 carriers) |
| ✅ PASS | declined weights sit below the threshold (heaviest 0.1835 < 0.35) |
| ✅ PASS | Ember's own pairs LINK on their real evidence (37 at or above threshold) |
| ✅ PASS | every link decomposes into all four named factors plus their product |
| ✅ PASS | campaign pz=WS-007: cohesion_min equals its weakest internal link (0.4277) |
| ✅ PASS | campaign pz=WS-012: cohesion_min equals its weakest internal link (0.4388) |
| ✅ PASS | the miner campaign scores visibly weaker than Ember (mean 0.4388 vs 0.5669; min 0.4388 vs 0.4277) |
| ✅ PASS | the miner rests on shared indicators alone (['indicator']) |
| ✅ PASS | Ember rests on observed movement as well (['artifact', 'movement']) |
| ✅ PASS | Quiet Fox links are carried by tradecraft and movement, never a shared indicator (['artifact', 'movement']) |
| ✅ PASS | DC-101 is linked into the campaign despite no movement to it |
| ✅ PASS | DC-101's link is carried by a shared ARTIFACT — the tradecraft path, proven ({'artifact'}) |
| ✅ PASS | the linking artifact is the actor's persistence service name (['EF-2026-Q3', 'WinDefendHelper']) |
| ✅ PASS | Quiet Fox clusters all four hosts despite per-host C2 and hashes (['DC-101', 'JUMP-101', 'SRV-FILE-101', 'WS-101']) |

**L3 — banding truth table**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | correlation banding truth table: 72 run, 0 failed, 0 errored |

**L3 — membership confidence decomposes into the evidence that produced it**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | every campaign host carries a band from the declared vocabulary (16 hosts) |
| ✅ PASS | every band decomposes into its named factors, not just a label |
| ✅ PASS | each band names the host and the weight it rests on (16 linked hosts) |
| ✅ PASS | the Ember intrusion reaches the top band (['confirmed', 'probable']) |
| ✅ PASS | the contradiction host bands BELOW its peers (probable vs confirmed on WS-101) |
| ✅ PASS | and the stated reason names the contradiction rather than only scoring it lower |
| ✅ PASS | no host outranks one with a stronger link (12 compared, 0 inversions) |
| ✅ PASS | a host with no cross-host link reads INDETERMINATE, not weak (0 such) |

**Indicator completeness — nothing recovered is stranded before correlation**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the implant's user-agent reaches the graph as a user_agent node on 9 hosts |
| ✅ PASS | the implant's mutex reaches the graph as a mutex node on 9 hosts |
| ✅ PASS | the extracted C2 campaign id reaches the graph as a c2_campaign_id node on 9 hosts |
| ✅ PASS | the YARA rule that matched reaches the graph as a yara_rule node on 9 hosts |
| ✅ PASS | the attributed malware family reaches the graph as a malware_family node on 9 hosts |
| ✅ PASS | RE-recovered C2 infrastructure reaches the graph (network_indicator) |
| ✅ PASS | RE-recovered wallet reaches the graph (crypto_material) |
| ✅ PASS | the user-agent is shared across Quiet Fox endpoints (4 hosts on one node) |
| ✅ PASS | the shared user-agent and mutex are CARRIED as link evidence (['T1021.001', 'T1021.002', 'account', 'c2_campaign_id', 'c2_sleep', 'campaign_id', 'domain', 'hash', 'ja3', 'mutex', 'persistence_autorun', 'persistence_service', 'persistence_task', 'pipe', 'registry_key', 'technique', 'user_agent']) |
| ✅ PASS | WS-007: the implant's identifying material is in its IOC index (missing: []) |
| ✅ PASS | WS-101: the implant's identifying material is in its IOC index (missing: []) |
| ✅ PASS | the extracted C2 address is in the IOC index (deduplicated against the hunt's own row) |
| ✅ PASS | config-recovered fields reach the index with their provenance recorded |
| ✅ PASS | the config's sleep interval is NOT indexed — it identifies nothing |
| ✅ PASS | no indicator is indexed twice within a run (0 duplicated) |
| ✅ PASS | the shared mutex pivots across the campaign's hosts (13 hosts) |
| ✅ PASS | attribution stays ONE node per determination, not split across kinds (0 strays) |
| ✅ PASS | every declared indicator kind populates (16/16) |
| ✅ PASS | MWCP config field 'campaign_id' populates as artifact/c2_campaign_id |
| ✅ PASS | MWCP config field 'sleep' populates as artifact/c2_sleep |
| ✅ PASS | MWCP config field 'address' populates as artifact/c2_address |
| ✅ PASS | MWCP config field 'port' populates as artifact/c2_port |

**Behavior graph — tradecraft is a first-class node, traceable to its findings**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | both corpus investigations carry a current graph-bearing run |
| ✅ PASS | graphs populated (A: 77 nodes, B: 52 nodes) |
| ✅ PASS | persistence task name spans 2 Ember hosts as ONE artifact node |
| ✅ PASS | the SAME persistence artifact appears in Quiet Fox's graph (rotated indicators, identical tradecraft) |
| ✅ PASS | fleet-wide benign hash visible as environment (20 hosts on one node) |
| ✅ PASS | every finding-derived event is traceable to its custody-sealed finding |

**L4/L5 — fingerprints built from behavior, attribution kept advisory**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | every campaign got a fingerprint (3) |
| ✅ PASS | Quiet Fox has a fingerprint despite per-host rotated indicators |
| ✅ PASS | artifact conventions are name SHAPES, not literal names (['c2_address:<name>.<name>-<name>.net', 'c2_campaign_id:EF-<number>-Q<number>', 'c2_sleep:<number>s/<number>%']) |
| ✅ PASS | each fingerprint carries all five named components plus its basis |
| ✅ PASS | every fingerprint states whether it carries enough tradecraft to compare |
| ✅ PASS | every attribution candidate is marked heuristic (0) |
| ✅ PASS | every candidate carries a per-component rationale, not just a score |
| · | no actor profiles staged — run seed_actor_profiles; L5 has nothing to rank against |
| ✅ PASS | no two different corpus campaigns are scored near-identical (0.611) |
| ✅ PASS | every similarity names the components it rests on |

**Render path — the values the collector planted reach the API the UI calls**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the API serves the technique SEQUENCE, not only the id-sorted set (12) |
| ✅ PASS | and it is a real order rather than the set relabelled (T1566 > T1204 > T1105 > T1071...) |
| ✅ PASS | which starts at the initial access the scenario planted (T1566) |
| ✅ PASS | the MWCP-extracted campaign id the collector planted is served as the example behind its shape (EF-2026-Q3) |
| ✅ PASS | the staging archive name the collector planted is served as the example behind its shape (_archive.7z) |
| ✅ PASS | a generic name shape is refused as a convention while the value still links hosts (WinDefendHelper) |
| ✅ PASS | and the shape beside it is an abstraction, so rotation is what it survives |
| ✅ PASS | every example states how many hosts carried it (5 conventions) |
| ✅ PASS | an archive extension survives abstraction intact (.7z is not read as digits) |
| ✅ PASS | the attack graph endpoint is populated (10 nodes, 9 edges) |
| ✅ PASS | the tradecraft-only campaign renders behavioral edges (4) |
| ✅ PASS | and one is carried by tradecraft the collector planted (['EF-2026-Q3', 'WinDefendHelper']) |
| ✅ PASS | movement edges name the collected account, not a placeholder (['CORP\\da_admin', 'CORP\\j.okafor']) |
| ✅ PASS | every banded host on the graph carries its stated reason (10) |

**Result**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the corpus rode the production path end to end, and benign stayed benign |

**Verdict: PROVEN** — 101 assertions passed, 0 failed.
