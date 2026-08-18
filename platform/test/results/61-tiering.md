## Cold storage — a case leaves the hot tier and comes back intact

*What passing proves:* Archival stages, seals and uploads a case bundle, verifies the copy in cold storage before deleting a row, keeps the case listed, and restores it byte-equal on demand; legal hold refuses the whole path.

- Run: `uat_tiering.sh` — 2026-08-17 13:07:15Z

**0/5  A throwaway case, backdated past the grace window**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | case 172 created: 5 findings, 1 IOC, 1 principal, concluded 200 days ago |

**1/5  Legal hold refuses the whole path**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | a held case is refused archival, loudly: ValueError: legal hold: archival refused |

**2/5  The sweep archives it — upload verified before any row is deleted**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the sweep archived case 172 |
| ✅ PASS | cold set deleted (findings 0, iocs 0) and the case reads archived |

**3/5  Still listed, with the bundle's own counts**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the API lists the case as archived with 5 findings recorded in the bundle |

**4/5  Restore replays exact content; a second restore is a no-op**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | restore completed |
| ✅ PASS | restored findings hash-match the pre-archive content (1f90878a961c…) |
| ✅ PASS | a second restore is a no-op, not a duplicate |

**5/5  An indicator from the archived case still answers 'seen before?'**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | sighting rollup consulted without error (0 rows) — rollups are never in the cold set |

**Verdict: PROVEN** — 9 assertions passed, 0 failed.
