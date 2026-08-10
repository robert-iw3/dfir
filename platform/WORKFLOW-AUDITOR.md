# Auditor workflow

The auditor reads. The role has no capability to change a verdict, alter a record, or
remove evidence, and that is what makes its account of the platform worth reading.

Related: [`WORKFLOW-ANALYST.md`](WORKFLOW-ANALYST.md), [`WORKFLOW-RE.md`](WORKFLOW-RE.md),
[`WORKFLOW-ADMIN.md`](WORKFLOW-ADMIN.md).

---

## 1. The audit trail

**Audit Trail** shows the ledger, newest first, with search and filters on actor, action
and object type.

Every mutation is recorded: ingest, analysis, verdict change, reclassification,
reverse-engineering determination, region purge, capture purge, legal hold, user creation,
export, deletion.

Each entry carries the actor, their role, the action, the object, the request path, a
detail payload, and its position in the hash chain.

**Sign-on and sign-out are recorded too** — `user.login`, `user.logout`, and
`user.session.expired` for a session abandoned rather than ended. A login entry carries where
the analyst connected from, what browser they used, and how the session was identified:
`key_source: oidc` means it is keyed by the identity provider's own session id, `derived`
means requests were grouped by caller instead, which cannot separate two sign-ons from one
browser. Treat a `derived` sign-on as a weaker record.

Filter on `user.` to read arrivals and departures alone; **Brokered Sessions** answers the
same question from the network side, and the two should agree.

**Writes on routes with no action of their own** appear as `<resource>.<verb>` —
`hosts.create`, `findings.modify`, `investigations.delete`. These carry the field NAMES a
request touched, never the values: case content stays in the record it was written to rather
than being copied into a trail that leaves the platform on export.

## 2. Chain verification

The trail is append-only and hash-chained: each entry's hash covers the previous entry's
hash. Verification runs over the whole ledger on every view, not over the page being
displayed — a page-local check would miss tampering outside the window.

The header states whether the chain is intact, and where it first breaks if not.

## 3. Export

`Export CSV` and `Export JSON` produce the trail with the chain verification attached:

- **JSON** carries `chain_intact` and `first_broken_id` alongside the entries.
- **CSV** carries the same in the `X-Audit-Chain-Intact` and `X-Audit-First-Broken-Id`
  response headers.

Exports honor the active filters and accept `since` and `until`. Each entry includes its
`hash` and `prev_hash`, so the chain can be verified independently of the platform.

Taking an export is itself an auditable act and is recorded in the trail before the file is
sent.

## 4. The investigation record

Each investigation carries a record of every annotation on it: analyst entries,
verdict changes with the reasons given, reverse-engineering determinations, and evidence
disposals, in one chronological view.

Entries are append-only. A retracted entry remains visible with its stated reason.

The record answers who asserted what, when the event occurred as distinct from when it was
written down, and what evidence the assertion rests on.

## 5. Custody

Each collection run carries a custody summary stating whether the bundle's seal verified on
receipt, and a custody ledger of events against the evidence: ingest, verification,
analysis, access, purge.

Purged evidence retains its custody record and, for carved regions, the SHA-256 captured
before deletion.

---

## Scope

| Visible | Not available |
|---|---|
| Investigations, hosts, runs, findings | Changing a verdict |
| Adjudication and the engine's reasoning | Writing or retracting a record entry |
| The investigation record | Purging evidence or applying legal hold |
| Audit trail, chain state, exports | Creating accounts |
| Custody summaries and ledgers | Opening carved regions |

---

## Acknowledged discontinuities

A hash chain that breaks stays broken — rewriting the rows to make verification pass is exactly
what the chain exists to detect. A break with a known cause is instead **declared**: an
`AuditCheckpoint` records the entry where the chain restarts, the hashes on both sides of the
gap, why, and who accepted it, signed under the audit key.

Verification reports the two separately:

| Verdict | Meaning |
|---|---|
| acknowledged discontinuity | a recorded gap with a stated cause — the trail continues past it |
| unexplained break | tampering or loss — the chain does not verify |

No audit row is ever modified. The gap stays visible; it gains an explanation. An
acknowledgement whose hashes do not match its gap, or whose signature does not verify, clears
nothing.
