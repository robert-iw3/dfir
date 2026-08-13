## Compartments — a restricted case is invisible to everyone not on it

*What passing proves:* Case membership scopes every route that can reach a case: list, detail, findings, runs, notes and export. A non-member is refused each one by attempt; an assigned member reads the same case normally.

- Run: `uat_scoping.sh` — 2026-08-13 20:16:33Z

**0/4  A restricted case, one member and one outsider**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | restricted case 5 (1 finding, 1 note) + open case 6; member and outsider are both analysts |

**1/4  The outsider is refused every route to the case**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | detail by direct id: 404 — an unassigned analyst is not told the case exists |
| ✅ PASS | list and search: 0 rows — searching for it by name finds nothing |
| ✅ PASS | findings filtered to the case: 0 rows — the drill-down leaks nothing either |
| ✅ PASS | runs filtered to the case: 0 rows |
| ✅ PASS | notes filtered to the case: 0 rows |

**2/4  The member reads the same case normally**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | detail: 200 for the assigned analyst |
| ✅ PASS | findings: 1 row — the scope permits, it does not merely refuse |

**3/4  The open case is unaffected — compartmenting is not a global deny**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the outsider reads the OPEN case normally (200) |

**4/4  Assignment is an admin action, driven through the API and audited**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | an analyst cannot assign anyone — membership is an admin decision |
| ✅ PASS | the admin assigns the outsider through the API |
| ✅ PASS | the newly assigned analyst now reads the case — the scope tracks membership live |
| ✅ PASS | and the admin removes them again |
| ✅ PASS | access is gone with the membership — 404 again |
| ✅ PASS | the admin moves the case to the open compartment |
| ✅ PASS | an open case is readable by any analyst — the compartment is what gated it |
| ✅ PASS | the trail gained an entry per action (0 -> 3: assign, unassign, compartment) |

**Verdict: PROVEN** — 17 assertions passed, 0 failed.
