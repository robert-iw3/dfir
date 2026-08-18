## Reverse engineering — contained analysis of carved regions

*What passing proves:* Carved regions from a compromised host open in a disassembler that has no network namespace at all.

- Run: `uat_re_workstation.sh` — 2026-08-17 23:17:21Z

**0/6  Session under test**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | host: e2e-endpoint |

**1/6  Regions staged by the mediator, not fetched by the session**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | 36 region(s) staged |
| ✅ PASS | session is scoped to exactly one host (e2e-endpoint) |
| ✅ PASS | mediator refuses to mix a second host into the same session |

**2/6  The session has no network at all**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | cannot reach the internet |
| ✅ PASS | cannot reach the enclave object store |
| ✅ PASS | cannot reach the DMZ receiver |
| ✅ PASS | cannot resolve internal names (no DNS) |

**3/6  Regions are readable but never writable**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | carved regions are readable |
| ✅ PASS | regions are read-only (analysis cannot alter evidence) |
| ✅ PASS | regions cannot be deleted from the session |
| ✅ PASS | the session cannot rewrite its own security settings |

**4/6  The session holds no credentials**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | no credentials in the session environment |
| ✅ PASS | no object-store credentials on disk |

**5/6  The session runs without privilege**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | all capabilities dropped (CapEff=0000000000000000) |
| ✅ PASS | no-new-privileges is set |

**6/6  Binary Ninja is present and needs no network**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | Binary Ninja launcher present in the image |

**Worksets — which regions a session is for**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the platform proposes a ranked shortlist for e2e-endpoint (4 of 4 considered, case 141) |
| ✅ PASS | every proposed region carries the reasons it ranked (4/4) |
| ✅ PASS | the proposal is ONE case (141), with 8 other(s) named rather than mixed in |
| ✅ PASS | workset ws-141-e2e-endpoint-1 assembled — 4 region(s), named and bounded |
| ✅ PASS | a workset beyond the cap is refused — the bound is the feature, not a limit to raise |
| ✅ PASS | regions from two investigations are refused — a session sees one case's malware, ever |
| ✅ PASS | the platform mints a procedure (2 steps) and a kit to run it — it never reaches into the workstation itself |
| ✅ PASS | minting is audited — the platform records that a session was intended, though it runs beyond its sight |
| ✅ PASS | staging pulled exactly the workset's 4 region(s) — one file each, none collapsed onto another |
| ✅ PASS | the workset reports itself STAGED once the mediator pulled it — an open session is visible to the platform |
| ✅ PASS | the session holds 4 of the host's 36 carved regions — the curated set, not the bucket |
| ✅ PASS | the staged manifest names the workset it came from — provenance without a path back to the store |
| ✅ PASS | recording a determination answers 201 — the write and the reply both succeed |
| ✅ PASS | a determination recorded during the session names it (ws-141-e2e-endpoint-1) — the platform can say what came out of a session, not only what is known about a region |
| ✅ PASS | that determination is in the investigation record — reverse-engineering work reaches the case, not a silo |
| ✅ PASS | a second workset of the same host stages concurrently (ws-141-e2e-endpoint-2) without disturbing the first |
| ✅ PASS | a region belongs to both worksets by reference (4 shared) — the platform can say which sessions examined it |
| ✅ PASS | a restricted case's carved regions are invisible to a non-member (0 of 4) and whole to someone entitled (4) — the compartment reaches the bytes |

**The session kit, end to end — download it, run it, and the malware is gone afterwards**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the UI hands over a session kit (8688 bytes) |
| ✅ PASS | the kit is self-contained and runnable — run.sh, the mediator, the launcher and a README |
| ✅ PASS | no carved region travels in the kit — malware reaches the workstation through the mediator, never through a browser |
| ✅ PASS | the kit names who it was issued to — found later, it says whose session it was for |
| ✅ PASS | run.sh staged this workset's regions on its own — one command, no lookups |
| ✅ PASS | IR_KEEP_SESSION=1 keeps the staged regions (4) — deliberate, and the only way they persist |
| ✅ PASS | the staged malware is gone when the session ends — nothing accumulates on the host |
| ✅ PASS | staging REFUSES bytes that do not match the hash recorded at carve time — a hash never checked is not integrity |

**Verdict: PROVEN** — 43 assertions passed, 0 failed.
