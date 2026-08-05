# IR Toolkit - Offline Incident Response Workflow

[Gitbook](https://rob-weber.gitbook.io/dfir-toolkit)

> **Development disclaimer.** This toolkit is under active parallel development as an investigatory
> follow-on platform. The current focus is on refining and validating the manual investigation
> workflows that a human analyst executes after anomalous activity has been confirmed beyond a
> reasonable doubt. Every workflow documented here is a candidate for future automation — once a
> step is proven reliable across real investigations it becomes a target for encoding into an
> **autonomous agentic DCO (Defensive Cyber Operations) platform**. This project is a standalone
> incident response toolkit and **does not represent the same workflow, architecture, or scope** as
> that agentic platform. The toolkit serves as the human-in-the-loop validation layer; the
> autonomous platform is a separate initiative.

Single-command incident response for **Windows**, **Linux**, and **Cloud** (AWS / Azure / GCP).

This file is the summary. The detailed, per-platform operating instructions live in:

| Platform | Workflow doc | Runtime |
|---|---|---|
| **Windows** | [WORKFLOW-WINDOWS.md](WORKFLOW-WINDOWS.md) | native PowerShell (no Python on target) |
| **Linux** | [WORKFLOW-LINUX.md](WORKFLOW-LINUX.md) | Python 3 (stdlib) + bash |
| **Cloud** | [WORKFLOW-CLOUD.md](WORKFLOW-CLOUD.md) | Python 3 + bash via `aws`/`az`/`gcloud` |

---

## Executive summary

**The toolkit tells you what to look at; the analyst decides whether it is a threat.**

Novice-to-intermediate tactics are caught out of the box — known signatures, volume
anomalies, common scripting tools — because they rely on predictable patterns. Advanced
tradecraft does not. A capable actor mimics legitimate administration to live off the land,
leaving small clues scattered across host, network and identity telemetry. The toolkit
gathers that evidence from every layer and narrows it to what is worth an analyst's time;
assembling it into a chain of events is the analyst's work.

Collection casts the widest possible net — process memory, event logs and journald, file
entropy, network state, registry, Amcache/ShimCache, YARA — with no pre-filtering. The
later phases narrow it:

1. **Collection** — snapshot everything without judgment. Nothing is excluded at collection
   time.
2. **Detection** — score-based alerting over everything collected (LOLBin score ≥3, entropy
   ≥7.2, process hidden from the standard API, execution from user-writable paths). Never
   suppressed by publisher or vendor: a Microsoft-signed binary in `AppData\Roaming` is
   still flagged.
3. **Adjudication** — every raw finding verified against its concrete artifact: signature
   chain, file existence, install path, hash. The ladder is **False Positive → Likely False
   Positive → Indeterminate → Likely True Positive → True Positive**. A validly signed
   binary in a user-writable path earns **Indeterminate**, not clearance.
4. **Likely True Positive is the actionable signal** — the evidence pattern is anomalous but
   the final call needs analyst context.
5. **Refinement loop** — detectors → adjudication → reports → eradication. TP-class findings
   cluster into a renderable kill chain (12–15 nodes), each with an evidence bundle.

**Filtering principle:** exclude only what is physically impossible as a threat vector.
Everything else surfaces with context and confidence.

**No network dependency during collection** — tools, YARA rules and dependencies are staged
to USB in advance; the toolkit never contacts the target host.

---

## End-to-end lifecycle

One invocation runs the whole chain. Collection is read-only and offline; eradication is
dry-run by default and writes a rollback journal so every change is reversible.

```
collection  →  analysis  →  reporting  →  memory forensics  →  eradication  →  restoration
```

All three platforms follow this shape. Each platform's workflow doc has its own end-to-end
diagram and specifics: [Windows](WORKFLOW-WINDOWS.md) · [Linux](WORKFLOW-LINUX.md) · [Cloud](WORKFLOW-CLOUD.md).
Cross-cutting: [WORKFLOW-YARA.md](WORKFLOW-YARA.md) - how memory YARA hits are enriched (region /
perms / backing file / matched strings) and the logic, with examples, for calling a finding benign vs
a true positive without a doubt. And the per-platform **hand-off to the analyst** guides -
[Windows](WORKFLOW-INVESTIGATION-WINDOWS.md) · [Linux](WORKFLOW-INVESTIGATION-LINUX.md) ·
[Cloud](WORKFLOW-INVESTIGATION-CLOUD.md) - how to read the adjudicated output (validated IOCs,
offline IP→country, implant config DNA on hosts; identity + control-plane chain in cloud) and
reconstruct the chain of events safely with OSINT.

> ### ⚠️ Capture and analyze memory - it is imperative, not optional
>
> For any serious investigation, **capture volatile memory first and analyze it.** Memory is the
> only place that holds evidence which *never touches disk*:
> - **Fileless / in-memory-only malware** - reflective loading, `memfd_create`, packed/decrypted-
>   in-RAM payloads. A disk-and-logs-only investigation **does not see these at all.**
> - **Process injection & live C2** - injected code regions, established attacker connections,
>   and the decoded commands behind obfuscated one-liners exist only in RAM.
> - **Rootkit ground truth** - kernel rootkits actively hide processes, modules, and hooks from
>   the *live* OS; raw memory exposes them by cross-referencing kernel structures (DKOM).
> - **Cleartext secrets** - credentials, keys, and tokens that are encrypted on disk sit
>   decrypted in memory.
> - **Anti-forensics resilience** - a present attacker can wipe logs and tamper disk artifacts;
>   the memory image reflects the machine's true state at the instant of capture.
>
> RAM is the **most volatile** evidence (RFC 3227 order of volatility): once the host is rebooted
> or powered off, it is **gone forever** - acquisition is a one-shot. Skipping memory means a
> forensic analysis that is incomplete by construction and can be actively deceived. Memory
> capture + analysis is wired into every platform here (Windows: MemProcFS; Linux: Volatility 3).

---

## Reports

Every platform writes per-host evidence to `reports/<HOSTNAME>/`. The report generator
(`playbooks/reporting/generate_reports.{py,ps1}`) reads the per-host folder and emits:

- **`Incident_Report.md`** - severity, ATT&CK chain, true-positive findings, adjudication funnel, remediation, IOC appendix.
- **`Attack_Graph.md`** - Mermaid graph reconstructing the chain of events from the findings (each TP finding a node, ordered along the kill chain, coloured by tactic, C2 branching off). Built from whatever findings exist, so different incidents render different graphs.
- **`Retrospective.md`** - objective post-incident review with kill-chain coverage and gap analysis.
- **`Timeline.md`** - chronological events, labelling **activity** time vs **detection** time.
- **`IOCs.json`** - C2 endpoints, file hashes, tools, ATT&CK techniques (emitted in analysis, consumed by eradication).
- **`Principals.json`** - implicated accounts for credential revocation.
- **`_clock.json`** - host timezone / UTC offset / NTP-sync / clock-skew (timeline normalization).
- **`_custody_*.json` + `_custody_log.jsonl`** - chain-of-custody seal of the sha256 manifest (operator identity + GPG/OpenSSL/HMAC signature; `evidence_custody.py --verify` detects tamper).

The optional **AI incident review** (`llm_incident_review.py`) writes `LLM_Incident_Review.{md,json}` - advisory only (`source=LLM`), redaction-first, configurable frontier/local/provider-native model (see [WORKFLOW-CLOUD.md](WORKFLOW-CLOUD.md)).

`IOCs.json` is emitted in the **analysis** stage so eradication's C2 re-block never depends on
reports being generated. Every orchestrator writes a uniform `_status.json`
(`COMPLETED`/`PARTIAL`/`FAILED` + per-phase results + `tp_count`) for SOAR gating.

**Cross-host campaign correlation:** `playbooks/reporting/correlate_campaign.py --root <dir-of-host-folders>`
finds indicators shared by more than one host and emits `Campaign_Report.md` + `campaign.json`.

---

## AI incident review (optional, advisory)

`playbooks/reporting/llm_incident_review.py` runs an LLM over a `reports/<host>/` collection and
writes `LLM_Incident_Review.{md,json}` - a triage summary, likely attack narrative, analyst pivots,
and Indeterminate-resolution suggestions. **Advisory only**: it never changes adjudicated verdicts;
output is flagged `source=LLM`.

Configurable, no SDK dependency (stdlib-only, so it stages to an air-gapped analyst box). Use a
**frontier** API or a **local** OpenAI-compatible server:

```bash
# Frontier (Anthropic Claude)
ANTHROPIC_API_KEY=… python3 playbooks/reporting/llm_incident_review.py \
    --host-folder reports/<host> --provider anthropic --model claude-sonnet-4-6

# Local / offline (Ollama, vLLM, LM Studio, llama.cpp, OpenRouter, …) - any OpenAI-compatible API
python3 playbooks/reporting/llm_incident_review.py --host-folder reports/<host> \
    --provider openai-compatible --base-url http://localhost:11434/v1 --model llama3.1 --no-redact
```

**Guardrails:** internal identifiers (private IPs, usernames, hostnames, emails) are redacted to
placeholders before any frontier call (reversible map kept locally, never sent); evidence is wrapped
in untrusted-data delimiters with an anti-prompt-injection system prompt; output enums are validated.
Redaction is on by default - `--no-redact` only for a local model you trust.

---

## Offline toolkit (optional depth tools)

Run on an internet-connected machine before deploying to an isolated host. Both builders write
a sha256 `tools/STAGED_MANIFEST.json`. The core workflow runs offline without any of these;
they only enable optional depth (memory capture, YARA, extended persistence).

- **Windows** - `Build-OfflineToolkit.ps1` with optional flags:

  | Flag | What it stages | Used by |
  |------|---------------|---------|
  | `-IncludeMemory` | go-winpmem (AFF4 capture) + ProcDump | `Invoke-IRCollection.ps1 -CaptureMemory` |
  | `-IncludeYaraRules` | YARA rule set (memory + file, Windows-filtered) | `memory_forensic.py`, `Invoke-YaraFileScan` |
  | `-IncludeMemProcFS` | MemProcFS + Python 3.12 embeddable (AFF4 native) | `Analyze-Memory.ps1`, `memory_forensic.py`, `memory_enrich.py` |
  | `-IncludeVolatility` | Volatility 3 standalone (raw/dmp images) | `Analyze-Memory.ps1` on raw images |
  | `-IncludeCapa` | capa capability fingerprinter | `memory_enrich.py` — ATT&CK on carved regions |
  | `-IncludeFloss` | FLARE FLOSS deobfuscator | `memory_enrich.py` — decoded strings from carved regions |
  | `-IncludeGeoIP` | db-ip Country Lite CSV (offline) | `memory_enrich.py` — IP→country with no network calls |
  | `-IncludeMWCP` | DC3-MWCP + GenericMutex/GenericC2 parsers | `memory_enrich.py` — binary config extraction from carved regions; `EDR_Toolkit.ps1 -ScanMWCP` — file-scan config extraction |

  Full recommended staging for a Windows deployment:
  ```powershell
  .\Build-OfflineToolkit.ps1 -IncludeMemory -IncludeYaraRules -IncludeMemProcFS `
      -IncludeVolatility -IncludeCapa -IncludeFloss -IncludeGeoIP -IncludeMWCP
  ```
- **Linux** - `Build-OfflineToolkit-Linux.sh [--include-memory] [--include-cloud] [--stage-symbols] [--check-only]`
  (memory analysis: **Volatility 3** wheels + `dwarf2json` + kernel ISF, vendored for offline use)

See each platform's workflow doc and [DEPENDENCIES.md](DEPENDENCIES.md) for the full dependency
inventory and deployment steps.

---

## IR Platform (`platform/`)

The toolkit collects and analyzes one host at a time, offline. The platform runs the same
analysis across many hosts as a network-wide system of record: captures are taken at the
endpoint, moved into an isolated enclave, analyzed there, and adjudicated by the toolkit's
own investigation engine.

The analysis is not reimplemented. The platform's worker carries
`analyze_memory_linux.py`, its Volatility plugins, the YARA rule set, `memory_enrich.py`
and `investigation/`, and runs them against the report-folder layout they already expect. A
verdict shown in the web app is the verdict the engine reaches offline.

**Tiers**

| Tier | Runs | Holds |
|---|---|---|
| Endpoint | Collection container, privileged, no internet | Nothing after transfer |
| DMZ | Store-and-forward receiver, broker | Nothing at rest |
| Enclave | API, worker, Postgres, MinIO, Keycloak | Evidence, metadata, symbols |
| Analyst workstation | Hardened browser | Nothing |
| RE workstation | Binary Ninja, no network namespace | One host's carved regions, per session |

Evidence moves one way: the DMZ receiver terminates the connection and the enclave pulls.
Nothing in the enclave dials out. Symbol tables travel the same route on their own channel,
because Volatility needs an ISF matching the captured kernel and the enclave cannot build
one.

**Capabilities**

- Server-side memory analysis, re-runnable against a stored capture at a newer ruleset.
- Adjudication per process, with the engine's reasoning and reconstructed attack chains.
- Carved regions to a bucket per host, staged to an isolated workstation for reverse
  engineering; determinations flow back into the incident.
- An append-only investigation record: analyst entries, verdict changes, RE determinations
  and evidence disposals in one chronological view.
- Cross-investigation IOC search and weighted multi-host correlation: hosts join a campaign
  when their shared evidence clears a threshold, every link decomposes into the factors that
  scored it, and campaigns carry a behavioral fingerprint so an actor is recognizable across
  engagements after rotating infrastructure. Attribution stays advisory.
- Hash-chained audit trail with export and independent chain verification.
- Custody sealing on ingest, retention applied by disposition, legal hold.
- DISA Web Server SRG hardening of the web tier, tracked item by item against the published
  XCCDF with a STIG Viewer checklist as evidence.

**Roles** — [analyst](platform/WORKFLOW-ANALYST.md),
[reverse engineer](platform/WORKFLOW-RE.md), [admin](platform/WORKFLOW-ADMIN.md),
[auditor](platform/WORKFLOW-AUDITOR.md).

**Deployment** — the baseline brings every tier up with Compose on a single host, staged in
dependency order and gated on a health check at each stage; see
[`platform/README.md`](platform/README.md). Multi-host deployment is
**Ansible** to prepare and provision bare metal, and **HashiCorp Nomad** as the workload
orchestrator scheduling the same tiers across it — both on the private track.

**Troubleshooting** — [`platform/troubleshooting/`](platform/troubleshooting/) holds the
runbook, the component map, memory-analysis diagnostics, and where to look when a page
renders blank, empty or wrong.
