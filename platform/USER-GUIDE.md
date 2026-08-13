# User guide — what the DFIR Framework can do, and where

Every capability the framework ships, grouped by what you are trying to accomplish. Each
entry says where it lives, what is recorded when you use it, and the one constraint that
is not obvious. Where a task needs more than a paragraph, it links to the document that
covers it.

The five stages of the digital forensics process are the spine of the whole framework —
sections 1 to 7 below follow them in order. **▶ [Watch the walkthrough](img/concept_demo_alpha.mp4)**.

For the path through a whole case in order, read
[`WORKFLOW-LIFECYCLE.md`](WORKFLOW-LIFECYCLE.md) instead — this document is the index; that
one is the walkthrough.

A capability marked **declined** was argued for and rejected; the reason is given, because
someone will look for it and should know it is not coming. Work that is simply not built
yet is not listed here at all — this document describes the platform as it is, and
[`planning/CONSOLIDATED-BACKLOG.md`](../planning/CONSOLIDATED-BACKLOG.md) says what is
still to come.

---

## 1. Getting evidence in

| Capability | Where | What to know |
|---|---|---|
| **Collect from an endpoint** | `collector/respond.sh` on the machine | Runs with no network namespace and seals the evidence *at the point of collection*. That seal is what every later verification checks against. |
| **Deep collection profile** | `--deep` (the default path) | SUID files, authorized_keys, shell-init persistence and running-binary hashes are only collected here. A reduced pass leaves those blind. |
| **Ship to the platform** | automatic | TLS to the DMZ receiver with the receiver's own certificate pinned. The enclave accepts no push — its puller reaches out, drains the holding area, and verifies each seal inward. |
| **Offline / air-gapped drop** | media into the receiver's holding directory | The seal is what makes this legitimate; a bundle that arrives on a disk is verified exactly like one that arrived over the wire. |
| **Re-analyze an existing capture** | *Run detail → Reanalyze* | Produces a second analysis against the current ruleset. The old one is kept — *Analysis diff* shows what a newer ruleset changed on that host. |
| **Request a rescan of a host** | *Investigation detail → Rescan* | Records the request against the case; the broker fulfils it and the result diffs against the baseline run. |
| **Supply memory symbols (ISF)** | `symbols/provision.sh` | Volatility cannot parse a Linux image without the matching kernel's symbols. The platform records what each capture needs; acquisition happens on an internet-connected machine and ships inward over the evidence path. See [`symbols/README.md`](symbols/README.md). |

## 2. Evidence integrity

| Capability | Where | What to know |
|---|---|---|
| **Custody chain** | *Run detail → Custody* | Every handling event is appended and hash-linked. Verification is *recomputed* when you look, never read from a stored flag. |
| **Chain-of-custody in the report** | technical report §3 | Same recomputation at render time. A report that repeats a stale "verified" is worse than one that says nothing. |
| **Retention** | automatic on analysis completion | A clean host's capture is purged; a compromised host's is retained. The findings and the custody record survive a purge — only the image goes. |
| **Legal hold** | *capture → legal hold* | Retains regardless of disposition, and blocks archival absolutely. The one thing convenience never overrides. |
| **Purge an image** | *capture → purge* | Deletes the bytes, keeps the record and every conclusion drawn from it. |

## 3. Analysis

| Capability | Where | What to know |
|---|---|---|
| **Server-side memory analysis** | automatic on ingest | Runs in a sandbox with no egress. Produces memory findings, adjudicated process verdicts, and carved regions for anything a rule fired on. |
| **Adjudicate a finding** | *Findings → a finding → reclassify* | The engine proposes, you decide. **An analyst verdict outranks the engine's and the disagreement is kept** — both values, with who and when. |
| **Bulk triage** | *Findings → select → bulk verdict* | Writes one reclassification row per finding, not one summary entry. A bulk action is still individually attributable. |
| **Verdict ladder** | throughout | False Positive · Likely False Positive · Indeterminate · Likely True Positive · True Positive. Only the top two assert compromise; the rest record degrees of uncertainty and are reported as such. |
| **Filter and page findings** | *Findings* | Filtering, sorting and paging happen in the database. The URL carries the view state, so a filtered view is a link you can send someone. |
| **Analysis diff** | *Run detail → Analysis diff* | What a newer ruleset added or removed on this host, rather than two lists to compare by eye. |

## 4. Correlation — the multi-host picture

| Capability | Where | What to know |
|---|---|---|
| **Campaign detection** | *Correlation* | Hosts are joined by weighted evidence, not by sharing any single indicator. Weight = type × rarity × verdict × temporal coherence. |
| **Why a link exists** | *Correlation → a link* | The evidence kinds carrying it. A link resting only on a shared C2 address dies when the actor rotates; one carried by mutex, JA3 and campaign id does not. |
| **Links declined, and why** | *Correlation*, technical report §11 | What the engine **considered and rejected**, with the reason. The difference between a conclusion and a coincidence. |
| **Confidence bands** | *Correlation* | Membership is banded (confirmed / probable / possible), double-encoded by color *and* stroke so the band survives monochrome printing. |
| **Campaign fingerprints** | *Correlation* | Tradecraft rather than indicators — a campaign with too little tradecraft is declined, not scored. |
| **Attribution** | *Correlation*, technical report §12 | Candidates carry a score and **an explicit refusal to name a culprit**. Resemblance is reported as resemblance. |
| **Cross-investigation similarity** | *Correlation* | Whether this campaign resembles one you have seen before. |
| **IOC search** | *IOC search* | Where else an indicator appears, across cases, with its host spread and first-seen. |

## 5. Reverse engineering

| Capability | Where | What to know |
|---|---|---|
| **Carved regions** | *Reverse Engineering* | Regions carved out of a capture are live malware, kept in a bucket per host, apart from evidence. |
| **Claim and analyze a region** | *Reverse Engineering → claim* | Work happens on an isolated RE workstation with no route to the case data. See [`re-workstation/README.md`](re-workstation/README.md). |
| **Record a determination** | *Reverse Engineering → analysis* | Written by the person who did the work; the conclusion reaches the incident as a finding on the owning run. |
| **Purge a region** | *Reverse Engineering → purge* | Removes the malware bytes; the determination survives. |

## 6. Case management

| Capability | Where | What to know |
|---|---|---|
| **Case tree** | *Investigation → Case tree* | Investigation → host → run → capture → region with counts, in one request. Expanding reveals what was already fetched. |
| **Host history** | click any host | That endpoint across *every* case — renames, collections, verdict spread. Identity is (hostname, machine_id), so a rename is history rather than a new machine. |
| **Task board** | *Investigation → Tasks* | The five stages of the digital forensics process. Movement is free **in both directions** — late evidence genuinely sends work back. Blocked is an attribute, so a stalled task keeps the stage it stalled in. |
| **Working notes on a task** | open a card | Append-only. What was thought at the time stays as it was written. |
| **Attachments** | open a card | Documents stored with their sha256 recorded on receipt; evidence links point at what the platform already holds and copy nothing. |
| **Curated tags** | *Investigation → Tags* | An admin-managed vocabulary. Free text is refused, because a free-text field produces three spellings of one idea. |
| **Investigation record** | *Investigation → record* | Notes, verdict changes with their stated reasons, RE determinations, evidence disposals — one record rather than four screens. Append-only; a mistaken entry is retracted with a reason and stays visible. |
| **Negative findings** | the case's ruled-out list | A hypothesis tested and rejected, with how it was tested. A report that says only what was found invites a reader to invent their own explanation. |
| **Case membership** | *Investigation → assignments* (admin) | Who is on the case. Recorded for every case, so "who could see this" is answerable after the fact. |
| **Compartments** | *Investigation → compartment* (admin) | `restricted` makes a case visible only to its members and admins. Auditors see everything by remit. |
| **Per-artifact permissions** | *declined* | A per-file matrix lets two analysts reach different conclusions from different visible subsets of one case — what an opposing expert attacks. Membership is the scoping unit instead. |

## 6a. Working alongside other people

Everything in this section is **advisory**. None of it can stop you writing, and that is
deliberate: an analyst who closed their laptop must never be able to block a live
investigation.

| Capability | Where | What to know |
|---|---|---|
| **Who else is here** | the case page | A roster of everyone with the case open, refreshed every 30 seconds. Someone who closes the tab drops off in about a minute. |
| **Soft locks** | open a task card | Taking a card marks you as working on it. A colleague opening the same card is told **you** have it, by name — and can still edit. Released when you close the card, and expires on its own after 15 minutes. |
| **@mentions** | any task note or record entry | Type `@username`. They get an in-app notification. A mention of someone who cannot read the case reaches no one and is **not** reported back to you — telling you who is cleared would leak the membership list. |
| **Notifications** | the bell, top right | In-app only. The enclave has no egress and is not gaining one so that a mention can become an email. |
| **Assignment notices** | automatic | Being given a task notifies you. Assigning yourself notifies nobody. |
| **Case activity** | *Investigation → Activity* | Who did what, newest first — read from the **signed audit ledger itself**, not from a second log beside it. |
| **Global search** | the box above every page | Cases, findings, notes, tasks and indicators at once. Case-insensitive and matches inside identifiers, because people search for `svc_` and half a filename. **It shows only what you may open** — a compartmented case is not in your results and is not hinted at. |
| **Shift handover** | *Shift Handover* | What the next analyst inherits: open work, criticals that landed in the window, the queue awaiting a verdict, analyses still running, and what was added to the record. The window is stated and adjustable, so two people reading it see the same shift. |
| **Chat / war room** | *declined* | The activity feed carries the useful part. The platform should not become a messaging system it must then secure and retain. |
| **Hard locks** | *declined* | See the top of this section. |

## 7. Reporting

| Capability | Where | What to know |
|---|---|---|
| **Plain-language summary** | *Investigation → Reports* | For the affected party: what happened, how it started and how it did *not*, what was done, what remains, and a glossary. |
| **Technical analysis** | *Investigation → Reports* | The evidentiary record — 19 sections including custody, tools and versions, declined links, negative findings, **the reverse engineer's determinations**, **the full investigation record**, limitations, and the audit trail with its verification. |
| **PDF** | *Reports → PDF* | Typeset inside the enclave with no network: title page, contents, running headers, and "Page N of M" so a reader can tell the document is complete. |
| **Read a report** | *Reports → read* | Reading in the browser keeps it inside the enclave and is an analyst right. |
| **Export a report** | *Reports → export* | A **separate right**. Taking evidence out is not the same act as reading it, and every export is ledgered with the report's hash. |
| **Everything on the case feeds it** | automatic | Analyst notes of every kind, verdict changes *with the stated reason*, RE determinations and evidence disposals all reach the report — rendered from the same assembler the record view uses, so the report and the screen cannot disagree. |
| **Report provenance** | the reports table | Every render records its template version, sha256, and the moment the data was read. A second render after new evidence is a different document, not an update. |
| **Defanged indicators** | automatic | Rendered unclickable at render time. Nothing in a report can be clicked into attacker infrastructure. |

## 8. Cold storage

| Capability | Where | What to know |
|---|---|---|
| **Automatic archival** | scheduled sweep | Concluded + 120 days, or open + 180 days (archived anyway, and flagged). Legal hold refuses absolutely. |
| **Due-for-archival list** | *Platform Health* | A 14-day warning window, so a case can be finished or extended rather than surprising someone. |
| **Restore** | *Investigation → Restore* (admin) | Seal verified before a single row is inserted; rows return with original ids so a second restore is a no-op; restored data expires and is re-cooled. |
| **The bundle** | `ir-archive` bucket | Gzipped NDJSON per table plus a manifest — readable with ordinary tools and restorable without this platform. |

Full procedure: [`WORKFLOW-ADMIN.md`](WORKFLOW-ADMIN.md) §6.

## 9. Access and accountability

| Capability | Where | What to know |
|---|---|---|
| **Sign-in** | the analyst kiosk | SSO through the identity provider. The platform is not a second source of identity truth. |
| **Roles** | admin / analyst / auditor / reverse_engineer | Enforced per endpoint. Deletion is admin-only. |
| **Export right** | held alongside a role | Reading evidence and removing it are different acts with different blast radii. |
| **Just-in-time elevation** | `admin/kc-userctl.sh grant --ttl` | A group membership with an expiry, enforced by the identity provider. Host-bound: there is no network path to it. |
| **Brokered sessions** | *Brokered Sessions* | Who is connected, through which session, from which workstation — the access record for the platform. |
| **Audit trail** | *Audit Trail* | Every create, modify, delete, login, export and evidence disposal, hash-chained and attributable to a person. |
| **Chain verification** | *Audit Trail → verify* | Recomputed on demand. A rotated signing key and a forged row produce *different* verdicts. |
| **Export ledger** | *Audit Trail* | What left the platform: who, what, when, how many rows, and the hash — including refusals. |

## 9a. Logs and troubleshooting  *(admin only)*

Every tier writes its log to a file as well as to container output; a shipper moves those
files into their own object-storage bucket, apart from evidence; and *Logs* reads them back.
The point is that diagnosing a problem never requires shell access to the host running the
containers — that access is what the rest of the design spends its effort removing.

| Capability | Where | What to know |
|---|---|---|
| **Shipped log archive** | *Logs → Shipped log archive* | Ingress, web tier, API and analysis worker. Survives the container that wrote it, which container output does not. |
| **API requests** | *Logs → API requests* | Who called what and what it answered, filterable to server errors and refusals. |
| **Browser errors** | *Logs → Browser errors* | Failures only the client can see. A page that broke in the browser leaves no server-side trace. |
| **Download a log** | *Logs → download* | Always as an attachment, never rendered — a log line is arbitrary text from arbitrary sources. |
| **Who may read them** | admins only | A log line can carry a path or identifier from a case the reader is not cleared for. Analysts are refused, and every read and export is in the audit ledger. |
| **Are logs evidence?** | **No** | They are operational records: their own bucket, no custody seal, and the platform says so wherever it serves one. Evidence has a chain of custody; this does not, and must not be presented as if it did. |

Proven end to end by `test/uat_logging.sh`: it makes a request, finds that request's own line
in the file each tier wrote, ships it, and reads the same line back out of the archive
through the API — then confirms an analyst is refused at every one of those steps.

## 10. Running the platform

| Capability | Where | What to know |
|---|---|---|
| **Platform health** | *Platform Health* | Service state, queue depth, throughput and storage, measured live per request. |
| **Component health** | *Component Health* | What each component reports about *itself* every 15 minutes — a container's real limits are only visible from inside it. Includes what each endpoint declared its next collection will need. |
| **Analysis queue over time** | *Component Health* | Depth alone hides a stuck queue; the sampled series says whether the backlog is being worked down. |
| **Service mesh** | *Service Mesh* | What is registered, and what the policy actually authorizes — read live from the control plane, not from the repository's files. Cells carry first-person evidence where a component can testify about its own sidecar. |
| **Enclave repairs** | *Enclave Repairs* | A fixed set of named repairs, executed by a privileged agent outside the web tier. The web tier never executes anything. |
| **Deployment** | `deploy/deploy.sh` | Staged per tier. See [`deploy/README.md`](deploy/README.md). |
| **Troubleshooting** | [`troubleshooting/RUNBOOK.md`](troubleshooting/RUNBOOK.md) | Symptom → cause → where to fix. |

---

## What the platform will refuse

Not failures — decisions, each with a reason:

| Refused | Because |
|---|---|
| Reading a restricted case you are not assigned to | Compartments are membership-based; a non-member is not told the case exists |
| Inventing a tag | The vocabulary is curated; free text produces three spellings of one idea |
| Moving a task to a stage outside the process | The board cannot grow columns by accident |
| Exporting without the export right | Removing evidence is a different act from reading it |
| Archiving a case under legal hold | An evidentiary obligation outranks convenience |
| Deleting anything as an analyst | Deletion is admin-only and audited; the record is append-only by design |
| Naming a threat actor | Resemblance is not identity, and the report says so |
| Reaching the internet from the analysis sandbox | It parses hostile memory; egress would be the exfiltration path |
