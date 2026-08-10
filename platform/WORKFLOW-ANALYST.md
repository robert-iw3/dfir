# Analyst workflow

The analyst works one incident at a time: reviewing what the platform concluded about each
host, deciding what it means, and recording that decision as part of the investigation
record.

Access is through one SSO-gated origin (`https://ir-platform.local:8443`). No other port is
reachable from the analyst side.

Related: [`WORKFLOW-RE.md`](WORKFLOW-RE.md), [`WORKFLOW-ADMIN.md`](WORKFLOW-ADMIN.md),
[`WORKFLOW-AUDITOR.md`](WORKFLOW-AUDITOR.md), [`UI_OVERVIEW.md`](../UI_OVERVIEW.md).

---

## 0. First login

`deploy.sh enclave` provisions the demo accounts and **prints each initial credential in
its output** when it creates the account — the deploy printout is where the password is
found. The values come from `deploy/.env` (`IR_DEMO_*_PASSWORD`).

An initial credential is **single-use**: Keycloak refuses the first login a session until
the password is replaced, so a printed value stops working the moment anyone has used it.

| Account | Role |
|---|---|
| `default-admin` | platform administration |
| `default-analyst` | investigation work (this document) |
| `default-auditor` | read-only audit review |
| `default-reverse-engineer` | carved-region analysis |

Locked out, or the password is gone? An administrator runs
[`admin/kc-userctl.sh`](admin/kc-userctl.sh) — `unlock` clears a lockout, `reset` issues a
new single-use temporary password. Both work only on the host running Keycloak; that is
the safeguard, not a limitation.

---

## 1. Open the incident

**Investigations → the incident.** The detail page lists every host collected under it,
each host's collection runs, and the investigation record.

Hosts are listed with their compromise state, which is derived from verdicts rather than
set by hand.

## 2. Read the host's adjudication

**Investigations → host → run.** Adjudication is the first section on a run, above the
findings.

The investigation engine judges **processes**, not individual findings. Each row is one
process with:

| Column | Meaning |
|---|---|
| Verdict | `True Positive`, `Undetermined`, `False Positive`, `Noise Closed` |
| Weight | Sum of independent positive dimensions behind the verdict |
| Agreed on by | Which detection sources landed on this process, and how many times |
| Signals | Count of dimensions that fired positive |

The engine's reasoning appears beneath each row. The conclusion is always shown; the
contributing signals expand behind a count.

A verdict rests on **provenance**, not on a rule name: where the binary lives, whether it
is package-owned and unmodified, whether it is deleted or memfd-backed, and whether several
independent signals converge on the same process.

**Attack chains** follow, reconstructing lineage across findings. Event counts open the
full sequence for one chain.

## 3. Work the findings

The findings summary distinguishes two states that both read as "Indeterminate":

- **Not yet judged** — nothing has looked at these.
- **Awaiting corroboration** — the engine judged them and could not conclude. Real leads,
  not actionable on the capture alone.

`Findings` lists everything with server-side paging, filtering and sorting. Verdict changes
require a note of at least 10 characters and are recorded with the previous verdict, the
new one, the actor and the reason.

Bulk verdict changes apply the same requirement.

## 4. Record what you conclude

The investigation record holds every annotation on the incident: analyst entries,
verdict changes, reverse-engineering determinations, and evidence disposals, in one
chronological view.

An entry carries:

| Field | Purpose |
|---|---|
| Kind | Observation, analysis, decision, action, containment, eradication, handoff, request |
| Summary | The one line that appears on the timeline |
| Occurred at | When the event happened, as distinct from when it was written down |
| Host | The host it concerns, or the whole investigation |
| Confidence | High / medium / low |
| Findings | The evidence the entry rests on |

Entries are append-only. A mistaken entry is retracted with a stated reason and remains
visible; it is not edited or deleted.

## 5. Cross-host and cross-incident

- **Correlation** — the multi-host picture: shared indicators, campaign graph, timeline.
- **IOC Search** — one indicator across every investigation ever collected.
- **Memory diff** — the same capture re-analyzed at a newer ruleset, showing what the newer
  detection set adds.

## 6. Request more evidence

- **Re-analyze** a capture at the current ruleset.
- **Rescan** a host to validate eradication or a restored baseline. The result is diffed
  against the baseline run.

## 7. Export

`Findings → Export` produces CSV, JSON, or an IOC bundle, honoring the active filters.
Every export is recorded in the audit trail with the row count and filters used.

---

## What the analyst does not do

| Action | Role |
|---|---|
| Open carved regions | Reverse engineer |
| Purge a carved region | Reverse engineer |
| Purge a capture, apply legal hold | Admin |
| Create users, view platform health | Admin |
| Export the audit trail | Auditor or admin |
