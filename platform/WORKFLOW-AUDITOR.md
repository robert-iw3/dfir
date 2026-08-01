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
