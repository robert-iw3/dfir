# Reverse-engineer workflow

The reverse engineer opens carved memory regions — extracted malware — and records what
each one is. Determinations flow back into the incident the region came from.

The workstation is the most hazardous surface in the platform, and its containment is the
reverse of the analyst tier: that one is hardened to stop evidence getting out, this one to
stop malware getting anywhere.

Related: [`WORKFLOW-ANALYST.md`](WORKFLOW-ANALYST.md),
[`re-workstation/README.md`](re-workstation/README.md).

---

## 1. Where regions come from

Carving happens during memory analysis, in the per-process YARA pass. Regions are uploaded
to a bucket per host — `ir-carved-<hostname>` — kept separate from evidence captures in
`ir-evidence`. One bucket per host means a session can be granted exactly one host's
regions and see no other case.

## 2. Review the queue

**Reverse Engineering** lists regions by host and triage state: unanalyzed, in progress,
analyzed, benign. Each row carries the region's size, the rule that carved it, and the PID
it was attributed to where the analyzer could determine one.

Claim a region before working it.

## 3. Stage a session

Regions do not stream to the workstation. The session has no network namespace at all, so
it cannot reach the object store; regions are staged to it first by a mediator that does
have store access.

```bash
cd platform/re-workstation
./stage_regions.sh --host UAT-ENDPOINT
```

This pulls that host's regions into `session-<HOST>/`, sets each file `0400`, and writes a
manifest of object keys and sizes **without payloads** — the session has provenance for
every region and no path back to the store.

One host per session. The stager refuses to mix two hosts in one directory.

## 4. Open the session

```bash
./launch.sh --host UAT-ENDPOINT
```

Binary Ninja starts with the regions mounted read-only at `/regions`. Files are opened from
there.

Session containment, all enforced at launch:

| Control | Setting |
|---|---|
| Network | `--network none` — no interfaces, no DNS, no route |
| Capabilities | `--cap-drop ALL` |
| Privilege escalation | `--security-opt no-new-privileges` |
| Regions | Read-only mount, files `0400` |
| Lifetime | `--rm` — destroyed on exit |

The container is destroyed when the session ends. Nothing written inside it survives.

## 5. Record the determination

Determinations are entered in the platform, not on the workstation. Each carries a verdict
and the evidence behind it:

| Verdict | Requirement |
|---|---|
| `benign` | Statement of why |
| `inconclusive` | Statement of what was examined |
| `suspicious` | Statement (40+ chars), capability, corroborating evidence |
| `malicious` | As above |
| `malicious` at `definitive` confidence | As above, plus malware family and file characteristics |

Supporting fields: capabilities, strings of interest, YARA matches, file characteristics,
network indicators, crypto material, extracted configuration, related hashes, MITRE
techniques.

A malicious or suspicious determination raises a Finding on the owning run, so the analyst
sees the conclusion without opening the region. Every determination is attached to the
investigation the region came from and appears in its record.

## 6. Purge a benign region

A region assessed benign can be purged from object storage. This is the only irreversible
action available to the role.

Requirements:

- The region's triage state is `benign`.
- A reason and a full statement, recorded with the actor and a timestamp.
- The region's SHA-256 is captured before deletion.

The `CarvedRegion` row and its analyses are kept. What a region was determined to be
remains part of the investigation after the sample is gone. The purge appears in the
investigation record and in the custody ledger.

## 7. Close the session

Exiting Binary Ninja destroys the container. Remove the staged directory when the work is
finished — it holds live malware on the workstation filesystem.

```bash
rm -rf session-UAT-ENDPOINT
```

---

## Host the session runs on

The container's containment protects everything outside it. It does not make the machine
underneath disposable, and that machine is the one holding decrypted malware in memory and
on disk for the length of a session.

**Once analysis confirms an implant, run the role on a VDI instance rather than on physical
hardware.** The requirements are the same either way; a VDI makes the last one achievable.

| Requirement | Why |
|---|---|
| Dedicated instance per engagement, not shared with any other role | A workstation that has opened one case's malware is not a clean place to open another's |
| Network isolated to the DMZ only — no enclave, no analyst segment, no internet | The session itself needs no network; the host needs only the path that delivers regions to it |
| No mapped drives, no shared clipboard, no shared folders to the analyst estate | These are the routes by which a sample leaves the workstation |
| Snapshot before the session | Makes the rebuild a revert rather than a reinstall |
| **Rebuilt to a known-good baseline when the engagement closes** | The only reliable statement about a machine that has run malware |

Rebuild on completion, not on suspicion of compromise. A session that ended without incident
is not evidence the host is clean: the samples were opened deliberately, and a disassembler
is not a sandbox. Treat the rebuild as part of closing the case.

Staged region directories hold live malware on that host's filesystem. Remove them before
the rebuild so a sample is never carried into a snapshot or a backup.

---

## Boundaries

`test/uat_re_workstation.sh` asserts the container-level containment above. A boundary that
starts passing traffic is a regression in the segmentation model, not a convenience.

The host-level controls — instance isolation, VDI segmentation, rebuild — are deployment
decisions the test cannot assert. They belong in the engagement's runbook.
