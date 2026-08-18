## Compartments — a restricted case is invisible to everyone not on it

*What passing proves:* Case membership scopes every route that can reach a case: list, detail, findings, runs, notes and export. A non-member is refused each one by attempt; an assigned member reads the same case normally.

- Run: `uat_scoping.sh` — 2026-08-17 13:07:27Z

**0/5  A restricted case, one member and one outsider**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | restricted case 173 (1 finding, 1 note) + open case 174; member and outsider are both analysts |

**1/5  The outsider is refused every route to the case**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | detail by direct id: 404 — an unassigned analyst is not told the case exists |
| ✅ PASS | list and search: 0 rows — searching for it by name finds nothing |
| ✅ PASS | findings filtered to the case: 0 rows — the drill-down leaks nothing either |
| ✅ PASS | runs filtered to the case: 0 rows |
| ✅ PASS | notes filtered to the case: 0 rows |

**2/5  The member reads the same case normally**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | detail: 200 for the assigned analyst |
| ✅ PASS | findings: 1 row — the scope permits, it does not merely refuse |

**3/5  The open case is unaffected — compartmenting is not a global deny**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the outsider reads the OPEN case normally (200) |

**4/5  Assignment is an admin action, driven through the API and audited**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | an analyst cannot assign anyone — membership is an admin decision |
| ✅ PASS | the admin assigns the outsider through the API |
| ✅ PASS | the newly assigned analyst now reads the case — the scope tracks membership live |
| ✅ PASS | and the admin removes them again |
| ✅ PASS | access is gone with the membership — 404 again |
| ✅ PASS | the admin moves the case to the open compartment |
| ✅ PASS | an open case is readable by any analyst — the compartment is what gated it |
| ✅ PASS | the trail gained an entry per action (33 -> 36: assign, unassign, compartment) |

**5/5  Account administration — every role provisions, and deletion is real**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | a reverse_engineer provisions through the admin endpoint — the fourth role is not second-class |
| ✅ PASS | an unknown role is refused with the full vocabulary in the answer |
| ✅ PASS | an analyst cannot delete an account — administration is the admin's act |
| ✅ PASS | an admin cannot delete their own account — the session that issued it must belong to someone |
| ✅ PASS | the admin deletes the account |
| ✅ PASS | gone from Keycloak AND the local mirror, and the deletion is in the ledger |
| ✅ PASS | deleting an absent account says so rather than pretending it worked |

**Verdict: PROVEN** — 24 assertions passed, 0 failed.
