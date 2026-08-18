## Corpus X — two concurrent actors in one fleet

*What passing proves:* Two intrusions running at the same time, sharing commodity tooling and one victim host, separate into TWO campaigns rather than merging into one; the shared tools link nothing on their own; the shared victim belongs to both; and a host renamed mid-campaign stays one host.

- Run: `uat_corpus_twin.sh` — 2026-08-17 23:09:03Z

**Preconditions**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | ir-dmz_receiver_1 running |
| ✅ PASS | ir-enclave_puller_1 running |
| ✅ PASS | ir-enclave_backend_1 running |
| ✅ PASS | ir-enclave_worker_1 running |
| ✅ PASS | collector image current with collector/ |
| ✅ PASS | the collector runs the full forensics collection (--deep) |
| ✅ PASS | 26 endpoint scenarios generated (two actors, one fleet) |
| ✅ PASS | manifest published to the backend for comparison |
| ✅ PASS | prior INC-CORPUS-X data reset (real evidence untouched) |
| ✅ PASS | receiver holds an address on the edge network |

**Collection — 26 real collector runs, shipped from the edge**

| Result | Assertion — with evidence |
|---|---|
| · | collections are signed with the key the enclave verifies against |
| ✅ PASS | all 26 bundles collected, sealed and accepted by the receiver |

**Ingest — the puller delivers all 26 runs**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | 26 INC-CORPUS-X runs ingested through receiver -> puller -> ingest |
| ✅ PASS | 25 distinct hosts with 25 distinct machine ids — no endpoint merged into another |

**Analysis — every capture is analyzed and adjudicated before compromise is read**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | every capture reached a terminal analysis and compromise settled (26/26 analyzed, 12 compromised) |
| ✅ PASS | every analysis completed (26) |
| ✅ PASS | every analysis was adjudicated by the investigation engine (26) |

**Correlation**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | correlation ran for INC-CORPUS-X (1 investigation(s)) |

**Identity — the renamed machine is ONE host, not two**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the machine that was RELAY-01 resolves to a single host row — now 'RELAY-02' |
| ✅ PASS | it carries its CURRENT name 'RELAY-02' |
| ✅ PASS | no second host lingers under the old name 'RELAY-01' — a rename is history, not a new machine |
| ✅ PASS | both collections attach to that one host (2 of 2) |
| ✅ PASS | the rename is recorded as history: RELAY-01 -> RELAY-02 |

**Classification — both actors' victims read as compromised, the fleet does not**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | DC-X1 (Copper Adder) classifies compromised |
| ✅ PASS | JUMP-X1 (Copper Adder) classifies compromised |
| ✅ PASS | SRV-X01 (Copper Adder) classifies compromised |
| ✅ PASS | SRV-X02 (Copper Adder) classifies compromised |
| ✅ PASS | WS-X03 (Copper Adder) classifies compromised |
| ✅ PASS | DC-X2 (Iron Adder) classifies compromised |
| ✅ PASS | RELAY-02 (Iron Adder) classifies compromised |
| ✅ PASS | SRV-X02 (Iron Adder) classifies compromised |
| ✅ PASS | SRV-X04 (Iron Adder) classifies compromised |
| ✅ PASS | VPN-X1 (Iron Adder) classifies compromised |
| ✅ PASS | the two administrators who ran the same commodity tools are flagged too (['DEV-X01', 'SRV-X05']) — identical bytes cannot be told apart, and pretending otherwise would be the defect |

**TWO campaigns — the property this corpus exists for**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the run produced 4 campaign(s) — two actors must not merge into one |
| ✅ PASS | a campaign contains Copper's entry point WS-X03 |
| ✅ PASS | a campaign contains Iron's entry point VPN-X1 |
| ✅ PASS | they are DIFFERENT campaigns — the two intrusions are not one |
| ✅ PASS | no Iron-only host was pulled into Copper's campaign |
| ✅ PASS | no Copper-only host was pulled into Iron's campaign |
| ✅ PASS | Copper's campaign holds all of its own hosts (['DC-X1', 'JUMP-X1', 'SRV-X01', 'SRV-X02', 'WS-X03']) |
| ✅ PASS | Iron's campaign holds all of its own hosts (['DC-X2', 'RELAY-02', 'SRV-X02', 'SRV-X04', 'VPN-X1']) |
| ✅ PASS | the shared victim SRV-X02 belongs to BOTH campaigns — copper=True iron=True |
| ✅ PASS | DEV-X01 ran the same tools and joined NEITHER campaign — tooling is not membership |
| ✅ PASS | SRV-X05 ran the same tools and joined NEITHER campaign — tooling is not membership |

**Commodity tooling links nothing on its own**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the engine considered 16 cross-actor pair(s) — it looked |
| ✅ PASS | no DIRECT cross-actor pair was linked — weighted linkage refuses them on the evidence |
| ✅ PASS | every considered cross-actor pair records its strongest factor and weight (16/16) — a decline with no basis is an accident, not a judgement |
| ✅ PASS | no accepted link anywhere rests on PsExec or Mimikatz as its strongest factor |

**Attribution — two families, neither claimed as one actor**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | both families reach the graph as distinct artifacts (['CopperAdder', 'IronAdder']) |
| ✅ PASS | cdn-copper-sync.example.net is an artifact node (domain, 5 host(s)) |
| ✅ PASS | updates-iron-mesh.example.org is an artifact node (domain, 5 host(s)) |

**Verdict: PROVEN** — 51 assertions passed, 0 failed.
