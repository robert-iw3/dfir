## Component health separates live errors from history

*What passing proves:* A component that errors shows it with a count and a message; one that recovers keeps the record but reads as recovered, with the moment it happened; and the roll-up degrades a component only for what is wrong NOW.

- Run: `uat_health.sh` — 2026-08-14 23:53:29Z

**1/4  The self-report carries what an honest error record needs**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | an error counts once, with its message and WHEN it happened |
| ✅ PASS | a quiet interval reports zero since — while the total and the record persist |
| ✅ PASS | a NEW error replaces the record and moves the timestamp forward |

**2/4  A component that errors NOW is shown as degraded, with the reason**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | errors since the last report raise an alert carrying the message, and the count survives to the row |

**3/4  A recovered component is NOT degraded — while the record survives**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | zero errors since the last report raises NO alert — recovered is not degraded |
| ✅ PASS | and the last error is still on the record WITH its timestamp, so the UI can age it |

**4/4  The page renders the age, and every real component is fresh**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the card labels a recovered error as recovered, with when it happened |
| ✅ PASS | and visually mutes it — history must not read as a live fault |
| ✅ PASS | all 5 real components have reported within two intervals — the page shows the present, not a cache |

**Verdict: PROVEN** — 9 assertions passed, 0 failed.
