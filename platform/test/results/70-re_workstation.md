## Reverse engineering — contained analysis of carved regions

*What passing proves:* Carved regions from a compromised host open in a disassembler that has no network namespace at all.

- Run: `uat_re_workstation.sh` — 2026-08-15 00:58:17Z

**0/6  Session under test**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | host: e2e-endpoint |

**1/6  Regions staged by the mediator, not fetched by the session**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | 16 region(s) staged |
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

**Verdict: PROVEN** — 17 assertions passed, 0 failed.
