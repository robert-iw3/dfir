## Security — assessment findings, held shut by assertion

*What passing proves:* Each closed finding from the 2026-08-16 assessment is re-attempted here as its attacker would attempt it: the compartment bypass on the platform's only sanctioned egress, and the aggregate surface that reached a restricted case by direct id. A weakness that returns fails this suite rather than waiting for the next audit.

- Run: `uat_security.sh` — 2026-08-17 21:51:58Z

**0/10 A restricted case, a member, and an outsider who HOLDS the export right**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | fixture: restricted case 180, both identities hold export, only one is assigned |

**1/10 W4a — the export route scopes, and holding export is not membership**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | unfiltered export by a non-member carries 0 rows of the restricted case — the compartment survives the widest door the platform has |
| ✅ PASS | export aimed straight at the restricted case returns 0 rows for a non-member |
| ✅ PASS | the IOC bundle — the artifact meant to be shared onward — carries none of the restricted case's indicators |
| ✅ PASS | the assigned member exports the same case normally (1 row) — the scope permits, it does not merely refuse |

**2/10 W4b — the aggregate surface cannot be reached by direct id**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | stats by direct id: 404 for a non-member — and 404, not 403, so the case's existence is not confirmed |
| ✅ PASS | coverage by direct id: 404 for a non-member — and 404, not 403, so the case's existence is not confirmed |
| ✅ PASS | the assigned member reads stats normally (200) |

**3/10 W4c — a lifecycle transition is a write, and membership decides it**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | a non-member cannot move someone else's case through its lifecycle (404) |
| ✅ PASS | the case's status is unchanged (open) — the refusal held in the database, not only in the response |

**4/10 W1 — the caller cannot name their own role**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | X-AUTH-REQUEST-GROUPS: an un-grouped session stays un-grouped (no-groups) — the spoofed header names no role |
| ✅ PASS | REMOTE-GROUPS: an un-grouped session stays un-grouped (no-groups) — the spoofed header names no role |

**5/10 W1 — an absent role claim is a revocation, not 'keep what you had'**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | withdrawing the role group refuses the request AND strips the local groups and superuser flag — revocation revokes |

**6/10 W2 — the receiver serves the holding area to the puller only**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | GET /pending without the puller credential: 401 — the bundle list is not public |
| ✅ PASS | GET /fetch/<id> without it: 401 — a held memory image is not served to the fleet |
| ✅ PASS | GET /isf/pending without it: 401 — the symbol path is gated too |
| ✅ PASS | DELETE /fetch/<id> without it: 401 — evidence cannot be destroyed by whoever asks |
| ✅ PASS | /healthz stays open (200) — the gate is on evidence, not on liveness |
| ✅ PASS | the puller's own credential still reads the holding area (200) — the evidence path works |

**7/10 W3 — an evidence-controlled hostname cannot reach the generated script**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | a hostname carrying a newline and a shell command is flattened before it reaches the kit |

**8/10 W6 — the verifier decides whether a seal is ATTRIBUTABLE, not the bundle**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | a correctly sealed bundle verifies and is attributable |
| ✅ PASS | a bundle declaring itself unsigned is NEVER attributable — the seal is not the bundle's decision to make |
| ✅ PASS | a bundle collected without a signing key still ingests, and is recorded unverified rather than trusted |
| ✅ PASS | a signature that is present and wrong is REFUSED — a forged seal is not an unsigned one |
| ✅ PASS | a seal from a retired key verifies as SUPERSEDED and stays attributable — rotation does not read as forgery, and an archived case stays restorable |
| ✅ PASS | the same seal with the key neither current nor retired is refused — superseded is not a wildcard |

**9/10 W7 — the RE session does not disable the analyst's display**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | no xhost invocation remains — access control is not disabled for every local process |
| ✅ PASS | both tool paths authenticate with a cookie instead |

**10/10 W8 — a generated credential is one the service it names accepts**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the credential the app tier carries authenticates to Keycloak as admin — the generator and the account agree |
| ✅ PASS | settings.KEYCLOAK's admin credential authenticates too — the admin's user-management API works |

**Verdict: PROVEN** — 30 assertions passed, 0 failed.
