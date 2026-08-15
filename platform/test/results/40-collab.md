## Presence, locks, mentions, search and shift handover

*What passing proves:* Three analysts share a case: one holds a task and the other is told without being stopped, a mention reaches only someone cleared for the case, the feed comes from the audit ledger itself, and search and handover refuse to show a compartmented case to a non-member.

- Run: `uat_collab.sh` — 2026-08-14 23:53:07Z

**1/7  Three analysts and two cases — one of them compartmented**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | alice and bob share case 89; only alice is in compartment case 90 |

**2/7  Presence — who else is on this case, and who is not told**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | a heartbeat is accepted and answers with the roster |
| ✅ PASS | alice sees bob on the same case |
| ✅ PASS | and does not see herself listed as company |
| ✅ PASS | carol is never shown that anyone is inside the compartmented case |
| ✅ PASS | and cannot announce herself into it — a non-member gets 'no such case', not 'forbidden' |

**3/7  Soft locks inform. They do not block — that is the whole design**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | alice takes the soft lock on the task |
| ✅ PASS | bob is told alice holds it, by name |
| ✅ PASS | and is answered 200, not 409 — he is being informed, not refused |
| ✅ PASS | AND BOB'S EDIT STILL LANDS — an unreachable colleague can never block an investigation |
| ✅ PASS | alice releases it when she closes the drawer |
| ✅ PASS | and bob can then take it |
| ✅ PASS | one analyst cannot release another's lock |

**4/7  Mentions reach the people who may read the case, and no one else**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | bob, working the same case, is notified |
| ✅ PASS | a mention of carol INSIDE the compartment reaches no one — and alice is not told it failed, which would leak the membership list |
| ✅ PASS | it is waiting for him as an unread in-app notification (1) |
| ✅ PASS | and nothing from the compartmented case is in her tray |
| ✅ PASS | mentioning yourself notifies no one |
| ✅ PASS | being given a task notifies the person it was given to |
| ✅ PASS | marking them read clears the count (2 marked) |

**5/7  The activity feed IS the audit ledger — not a second copy of it**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the case's actions are on its feed (4 event(s): task.note,task.update) |
| ✅ PASS | and every one of them is a row in the signed ledger (4) |
| ✅ PASS | a non-member asking for the compartmented case's feed is told it does not exist |

**6/7  Global search — the easiest place to bypass access control**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | alice, a member, finds the compartmented case by name |
| ✅ PASS | CAROL SEES NOTHING OF THE COMPARTMENT — a search box that ignores it is an access-control bypass |
| ✅ PASS | and she still finds the open case's matching task in the SAME query — scoped, not blanked |
| ✅ PASS | search reaches inside tasks, not only case names |
| ✅ PASS | a one-character query is refused rather than returning the estate |
| ✅ PASS | matching is case-insensitive — analysts do not type the way data was stored |

**7/7  Shift handover — what the next analyst inherits**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the handover renders and states the window it covers |
| ✅ PASS | the open task on this case is on it (18 open) |
| ✅ PASS | carol's handover carries nothing from the compartmented case — not the case, not the task title |
| ✅ PASS | while still handing her the ordinary case's open work |
| ✅ PASS | alice's carries both — her compartmented case AND the ordinary one |
| ✅ PASS | the window is honoured — a future 'since' reports nothing new, not everything |

**Verdict: PROVEN** — 35 assertions passed, 0 failed.
