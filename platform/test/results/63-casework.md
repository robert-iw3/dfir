## Case tree, curated tags and the task board

*What passing proves:* The tree serves the hierarchy in one request with counts that match the underlying tables; tags come from an admin-curated vocabulary and free text is refused; task moves are audited; and all three are scoped by case membership.

- Run: `uat_casework.sh` — 2026-08-13 20:16:42Z

**0/4  A case with two hosts, and two analyst identities**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | case 7: 2 hosts, 2 runs, 6 findings, 2 captures |

**1/4  The tree is one request, and its counts match the tables**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | tree returns 2 hosts, 2 runs, 2 captures in one request |
| ✅ PASS | the tree's finding counts sum to the finding table (6 == 6) |

**2/4  The tag vocabulary is curated, and free text is refused**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | an admin adds 'uat-work-ransomware' to the vocabulary |
| ✅ PASS | an analyst cannot invent a tag — the vocabulary stays curated |
| ✅ PASS | the analyst applies a curated tag to the case |
| ✅ PASS | a tag id outside the vocabulary is refused, not silently created |

**3/4  The board is the forensic lifecycle, and work moves BOTH ways**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the columns are the digital forensics process, in order: identification,preservation,analysis,documentation,presentation |
| ✅ PASS | every stage states what it is for — a column explains itself |
| ✅ PASS | a task opens in Identification |
| ✅ PASS | it jumps forward to Documentation — stages are not a ratchet |
| ✅ PASS | and BACK to Analysis — late evidence reopens work, which a one-way board would hide |
| ✅ PASS | blocked is an attribute, not a column — the task stays in the stage it stalled in |
| ✅ PASS | a stage outside the process is refused — the board cannot invent columns |
| ✅ PASS | an analyst records a working note on the task |
| ✅ PASS | evidence the platform already holds is linked, never copied |
| ✅ PASS | a reference to a table outside the evidence vocabulary is refused |
| ✅ PASS | the task carries its note, its attachment and the five stages it can move to |
| ✅ PASS | every action is audited (0 -> 6: create, 3 moves, note, attach) |

**4/4  All three respect the compartment**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | tree: 404 for a non-member of the restricted case |
| ✅ PASS | tags: 404 for a non-member of the restricted case |
| ✅ PASS | tasks: 404 for a non-member of the restricted case |
| ✅ PASS | the cross-case board shows a non-member none of this case's tasks |

**Verdict: PROVEN** — 23 assertions passed, 0 failed.
