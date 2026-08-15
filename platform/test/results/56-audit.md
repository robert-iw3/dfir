## Audit trail — sign-on, every write, and attribution to a person

*What passing proves:* The platform records who signed on, what they created or changed, what they exported and when they left; each action once, in a chain that still verifies, and traceable to a person rather than to a pool principal.

- Run: `uat_audit.sh` — 2026-08-15 00:13:15Z

**Sign-on — a login the platform was never told about**

| Result | Assertion — with evidence |
|---|---|
| · | before: 295 login entries, 14948 entries in total |
| · | ephemeral account uat-audit-probe provisioned (analyst, forced first-login change armed) |
| ✅ PASS | an analyst signed in through the real OIDC flow as uat-audit-probe (analyst) |
| ✅ PASS | the sign-on produced exactly ONE user.login entry (295 → 296) across a login plus 5 further requests |
| ✅ PASS | the login entry names the person and their role: uat-audit-probe / analyst |
| ✅ PASS | the sign-on is keyed by the identity provider's own session id (key_source=oidc) — two sign-ons from one browser stay distinct |
| ✅ PASS | the login entry records where the analyst connected from and what they used (10.89.1.135, Mozilla/5.0 (X11; Linux …) |

**Writes — recorded whether or not anyone instrumented the route**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | an edit on an uninstrumented route succeeded (HTTP 200 on note 4912) — the case the catch-all exists for |
| ✅ PASS | the write was recorded with its verb, route and outcome: notes.modify by uat-audit-probe (PATCH /api/notes/4912/ → 200) |
| ✅ PASS | the explicitly audited create produced its own entry only — the catch-all added no duplicate (notes.create rows: 0, alongside 4891 note.create) |

**Sign-out — sessions that end, and sessions nobody closed**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the analyst signed out through the platform (HTTP 200, session 297) |
| ✅ PASS | the sign-out closed an OPEN sign-on rather than reporting a no-op |
| ✅ PASS | user.logout entries exist in the trail (24) — a session end is an audited event, not a gap |
| ✅ PASS | the sign-on record closed with a reason and a request count: uat-audit-probe ended by signout after 1 requests |
| ✅ PASS | a sign-on idle past the cookie lifetime is closed as expired (1 closed on that sweep) — abandoned sessions do not stay open forever |

**A dead callback restarts the flow instead of ending on a bare 403**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | a cookieless callback is refused (HTTP 403) — the gate does not accept an attempt it cannot verify |
| ✅ PASS | the 403 carries the recovery page: a sign-in control, not a dead end |
| ✅ PASS | the recovery page retries the flow automatically, bounded to one attempt |

**Tamper-evidence — the new entries are part of the chain, not beside it**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the audit chain verifies end to end with the sign-on and catch-all entries in it |
| ✅ PASS | every sign-on/sign-out entry is HMAC-signed (434/434) — the same protection as the rest of the trail |

**Coverage — the actions an auditor is entitled to ask about**

| Result | Assertion — with evidence |
|---|---|
| · | recorded: login=296\|logout=24\|create=5299\|modify=4898\|delete=17\|export=1460 |
| ✅ PASS | login is represented in the trail (296 entries) |
| ✅ PASS | logout is represented in the trail (24 entries) |
| ✅ PASS | create is represented in the trail (5299 entries) |
| ✅ PASS | export is represented in the trail (1460 entries) |

**Attribution — a session belongs to a person, or says it cannot tell**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | every brokered session carries an attribution verdict (100/100; kinds seen: exact,none,overlapping) |
| ✅ PASS | sessions reported as exact carry a named analyst (93 of 100 named overall) |

**A-2 — a session belongs to a workstation, and through it to one person**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the distributor holds 2 workstation pins — a known workstation's connections land on ITS session |
| ✅ PASS | two analysts signed on CONCURRENTLY from two workstations (uat-a2-analyst@analyst, uat-a2-ws-002@ws-002) |
| ✅ PASS | each sign-on names its workstation (uat-a2-analyst: analyst, uat-a2-ws-002: ws-002) |
| ✅ PASS | the analyst-pinned session attributes exact to uat-a2-analyst while both analysts are signed on |
| ✅ PASS | the ws-002-pinned session attributes exact to uat-a2-ws-002 while both analysts are signed on |

**A-3b  Attribution survives a session the broker replaces under the analyst**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | a session opened after the analyst's last request still names them (overlapping:uat-a2-analyst,uat-a3b-analyst) |

**Verdict: PROVEN** — 30 assertions passed, 0 failed.
