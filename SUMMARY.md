# Table of contents

## Start here

* [IR Toolkit - Offline Incident Response Workflow](README.md)
* [Dependency Inventory](DEPENDENCIES.md)

## Operator guidance — the manual workflow

* [Operator Guidance — the manual, by-hand DFIR workflow](operator_guidance/README.md)
  * [Windows — the manual operator workflow](operator_guidance/windows/README.md)
    * [00 · Mindset & First Principles](operator_guidance/windows/00-mindset-and-first-principles.md)
    * [01 · Triage the Alert](operator_guidance/windows/01-triage-the-alert.md)
    * [02 · Contain Without Destroying Evidence](operator_guidance/windows/02-contain-without-destroying-evidence.md)
    * [03 · Capture Volatile Memory](operator_guidance/windows/03-capture-volatile-memory.md)
    * [04 · Snapshot Live System State](operator_guidance/windows/04-snapshot-live-system-state.md)
    * [05 · Persistence & Execution History](operator_guidance/windows/05-persistence-and-execution-history.md)
    * [06 · Hunt the Host](operator_guidance/windows/06-hunt-the-host.md)
    * [07 · Adjudicate Findings](operator_guidance/windows/07-adjudicate-findings.md)
    * [08 · Memory Forensics](operator_guidance/windows/08-memory-forensics.md)
    * [09 · Build the Timeline & Chain of Events](operator_guidance/windows/09-build-the-timeline-and-chain.md)
    * [10 · Eradicate](operator_guidance/windows/10-eradicate.md)
    * [11 · Restore & Recover](operator_guidance/windows/11-restore-and-recover.md)
    * [12 · Report & Retrospective](operator_guidance/windows/12-report-and-retrospective.md)
  * [Linux — the manual operator workflow](operator_guidance/linux/README.md)
    * [00 · Mindset & First Principles (Linux)](operator_guidance/linux/00-mindset-and-first-principles.md)
    * [01 · Triage the Alert (Linux)](operator_guidance/linux/01-triage-the-alert.md)
    * [02 · Contain Without Destroying Evidence (Linux)](operator_guidance/linux/02-contain-without-destroying-evidence.md)
    * [03 · Capture Volatile Memory (Linux)](operator_guidance/linux/03-capture-volatile-memory.md)
    * [04 · Snapshot Live System State (Linux)](operator_guidance/linux/04-snapshot-live-system-state.md)
    * [05 · Persistence & Execution History (Linux)](operator_guidance/linux/05-persistence-and-execution-history.md)
    * [06 · Hunt the Host (Linux)](operator_guidance/linux/06-hunt-the-host.md)
    * [07 · Adjudicate Findings (Linux)](operator_guidance/linux/07-adjudicate-findings.md)
    * [08 · Memory Forensics (Linux)](operator_guidance/linux/08-memory-forensics.md)
    * [09 · Build the Timeline & Chain of Events (Linux)](operator_guidance/linux/09-build-the-timeline-and-chain.md)
    * [10 · Eradicate (Linux)](operator_guidance/linux/10-eradicate.md)
    * [11 · Restore & Recover (Linux)](operator_guidance/linux/11-restore-and-recover.md)
    * [12 · Report & Retrospective (Linux)](operator_guidance/linux/12-report-and-retrospective.md)
  * [AWS — the manual operator workflow](operator_guidance/aws/README.md)
    * [00 · Mindset & First Principles (AWS / Cloud)](operator_guidance/aws/00-mindset-and-first-principles.md)
    * [01 · Triage the Alert (AWS)](operator_guidance/aws/01-triage-the-alert.md)
    * [02 · Contain — Identity First (AWS)](operator_guidance/aws/02-contain-identity-first.md)
    * [03 · Preserve Evidence (AWS)](operator_guidance/aws/03-preserve-evidence.md)
    * [04 · Collect Telemetry (AWS)](operator_guidance/aws/04-collect-telemetry.md)
    * [05 · Analyze the Control Plane (AWS)](operator_guidance/aws/05-analyze-control-plane.md)
    * [06 · Analyze Data Plane & Identity (AWS)](operator_guidance/aws/06-analyze-data-plane-and-identity.md)
    * [07 · Adjudicate Findings (AWS)](operator_guidance/aws/07-adjudicate-findings.md)
    * [08 · Timeline & Blast Radius (AWS)](operator_guidance/aws/08-timeline-and-blast-radius.md)
    * [09 · Eradicate (AWS)](operator_guidance/aws/09-eradicate.md)
    * [10 · Restore & Recover (AWS)](operator_guidance/aws/10-restore-and-recover.md)
    * [11 · Report & Retrospective (AWS)](operator_guidance/aws/11-report-and-retrospective.md)
  * [Azure — the manual operator workflow](operator_guidance/azure/README.md)
    * [00 · Mindset & First Principles (Azure / Cloud)](operator_guidance/azure/00-mindset-and-first-principles.md)
    * [01 · Triage the Alert (Azure)](operator_guidance/azure/01-triage-the-alert.md)
    * [02 · Contain — Identity First (Azure)](operator_guidance/azure/02-contain-identity-first.md)
    * [03 · Preserve Evidence (Azure)](operator_guidance/azure/03-preserve-evidence.md)
    * [04 · Collect Telemetry (Azure)](operator_guidance/azure/04-collect-telemetry.md)
    * [05 · Analyze the Control Plane (Azure)](operator_guidance/azure/05-analyze-control-plane.md)
    * [06 · Analyze Identity & M365 (Azure)](operator_guidance/azure/06-analyze-identity-and-m365.md)
    * [07 · Adjudicate Findings (Azure)](operator_guidance/azure/07-adjudicate-findings.md)
    * [08 · Timeline & Blast Radius (Azure)](operator_guidance/azure/08-timeline-and-blast-radius.md)
    * [09 · Eradicate (Azure)](operator_guidance/azure/09-eradicate.md)
    * [10 · Restore & Recover (Azure)](operator_guidance/azure/10-restore-and-recover.md)
    * [11 · Report & Retrospective (Azure)](operator_guidance/azure/11-report-and-retrospective.md)
  * [GCP — the manual operator workflow](operator_guidance/gcp/README.md)
    * [00 · Mindset & First Principles (GCP / Cloud)](operator_guidance/gcp/00-mindset-and-first-principles.md)
    * [01 · Triage the Alert (GCP)](operator_guidance/gcp/01-triage-the-alert.md)
    * [02 · Contain — Identity First (GCP)](operator_guidance/gcp/02-contain-identity-first.md)
    * [03 · Preserve Evidence (GCP)](operator_guidance/gcp/03-preserve-evidence.md)
    * [04 · Collect Telemetry (GCP)](operator_guidance/gcp/04-collect-telemetry.md)
    * [05 · Analyze the Control Plane (GCP)](operator_guidance/gcp/05-analyze-control-plane.md)
    * [06 · Analyze Data Plane & Identity (GCP)](operator_guidance/gcp/06-analyze-data-plane-and-identity.md)
    * [07 · Adjudicate Findings (GCP)](operator_guidance/gcp/07-adjudicate-findings.md)
    * [08 · Timeline & Blast Radius (GCP)](operator_guidance/gcp/08-timeline-and-blast-radius.md)
    * [09 · Eradicate (GCP)](operator_guidance/gcp/09-eradicate.md)
    * [10 · Restore & Recover (GCP)](operator_guidance/gcp/10-restore-and-recover.md)
    * [11 · Report & Retrospective (GCP)](operator_guidance/gcp/11-report-and-retrospective.md)

## Toolkit workflows — collection and triage

* [WORKFLOW-WINDOWS](WORKFLOW-WINDOWS.md)
* [Linux Workflow](WORKFLOW-LINUX.md)
* [Cloud Workflow (AWS / Azure / GCP)](WORKFLOW-CLOUD.md)
* [YARA Findings Analysis Workflow (Windows + Linux)](WORKFLOW-YARA.md)

## From output to a chain of events

* [Investigation Workflow - from toolkit output to the chain of events](WORKFLOW-INVESTIGATION-WINDOWS.md)
* [Investigation Workflow (Linux) - from toolkit output to the chain of events](WORKFLOW-INVESTIGATION-LINUX.md)
* [Investigation Workflow (Cloud: AWS / Azure / GCP) - from toolkit output to the chain of events](WORKFLOW-INVESTIGATION-CLOUD.md)

## Detailed follow-on investigation

* [Detailed Follow-On Investigation — Windows](DETAILED-FOLLOW-ON-WINDOWS.md)
* [Detailed Follow-On Investigation — Linux](DETAILED-FOLLOW-ON-LINUX.md)
* [Detailed Follow-On Investigation — Cloud](DETAILED-FOLLOW-ON-CLOUD.md)

## Playbooks — the automation behind the workflows

* [playbooks](playbooks/README.md)
  * [windows](playbooks/windows/README.md)
    * [Windows Investigation Engine](playbooks/windows/investigation/README.md)
    * [Windows Threat Hunting & Forensics Toolkit](playbooks/windows/threat_hunting/readme.md)
      * [IR Toolkit mwcp Parsers](playbooks/windows/threat_hunting/mwcp_parsers/README.md)
        * [mwcp Parser Roadmap](playbooks/windows/threat_hunting/mwcp_parsers/ROADMAP.md)
  * [Linux investigation engine](playbooks/linux/investigation/README.md)
    * [IR Toolkit Linux mwcp_parsers](playbooks/linux/threat_hunting/mwcp_parsers/README.md)

## IR Platform

* [IR Platform](platform/README.md)
  * [Security model — the principles, what enforces each, and the test that proves it](platform/SECURITY-MODEL.md)
  * [Code graph — components, wiring, and what proves what](platform/CODE_GRAPH.md)
  * [Deploying the IR Platform](platform/deploy/README.md)
  * [Network design — VLANs, routing, firewall and IDPS placement](platform/deploy/NETWORKING.md)
  * [Collection on a suspect endpoint](platform/collector/README.md)
  * [Symbol acquisition (ISF)](platform/symbols/README.md)
  * [Administrative access](platform/admin/README.md)
* [Web application — screen by screen](platform/UI_OVERVIEW.md)
* Role workflows
  * [Analyst workflow](platform/WORKFLOW-ANALYST.md)
  * [Reverse-engineer workflow](platform/WORKFLOW-RE.md)
  * [Admin workflow](platform/WORKFLOW-ADMIN.md)
  * [Auditor workflow](platform/WORKFLOW-AUDITOR.md)
* Troubleshooting
  * [Troubleshooting runbook — symptom → cause → where to fix](platform/troubleshooting/RUNBOOK.md)
  * [Component schematic — configs, network path, and how to probe each hop](platform/troubleshooting/COMPONENTS.md)
  * [Memory analysis — diagnosing a run](platform/troubleshooting/MEMORY-ANALYSIS.md)

## Reverse engineering

* [tools](tools/README.md)
  * [Carved regions → Ghidra](tools/ghidra/readme.md)
  * [binja](tools/binja/readme.md)
    * [Binary Ninja Plugins](tools/binja/plugins.md)
    * [Carved memory regions → Binary Ninja](tools/binja/data/readme.md)
    * [plugins](tools/binja/plugins-1/README.md)
      * [Binary Ninja MCP](tools/binja/plugins/binary_ninja_mcp/README.md)
      * [Binary Ninja Ollama (v1.0.9)](tools/binja/plugins/binaryninja-ollama/README.md)
      * [Obfuscation Detection (v2.3)](tools/binja/plugins/obfuscation_detection/README.md)
        * [Example Use Cases](tools/binja/plugins/obfuscation_detection/examples/README.md)
      * [x64dbgbinja](tools/binja/plugins/x64dbgbinja/README.md)

## Infrastructure

* [Ephemeral cloud-IR container](docker/readme.md)
* [IR evidence storage (Terraform)](terraform/readme.md)

## Testing

* [Tests](test/readme.md)
  * [Cloud-IR Lab Environment](test/lab/README.md)
  * [Terraform/OpenTofu validate lab](test/tf_validate/README.md)

## Change logs

* [Change logs](change_logs/README.md)
  * [The HashiCorp zero-trust enclave: from declared to enforced](change_logs/2026-07-31-zero-trust-enclave-closure.md)
  * [Teardown deleted all ingested evidence without warning](change_logs/2026-07-30-teardown-destroyed-evidence.md)
  * [Tailnet nodes could not register, and the DERP relay was never used](change_logs/2026-07-30-tailnet-registration-and-derp.md)
  * [Pinned images had drifted, unnoticed](change_logs/2026-07-30-stale-pinned-images.md)
  * [Evidence crossed the wire in cleartext](change_logs/2026-07-30-evidence-transport-plaintext.md)
  * [DNS exfiltration was open on the DMZ link, and services were addressed by pinned IP](change_logs/2026-07-30-dns-exfiltration-and-naming.md)
  * [Four components reported healthy while doing nothing](change_logs/2026-07-30-components-reported-healthy.md)
  * [The backend image could never be rebuilt, so backend fixes never deployed](change_logs/2026-07-30-backend-could-not-be-rebuilt.md)
  * [mwcp parser false positives on ordinary content](change_logs/2026-07-29-mwcp-parser-false-positives.md)
  * [Memory capture never succeeded, and the fallback was silent](change_logs/2026-07-29-memory-capture-never-succeeded.md)
  * [Host identity for correlating collection with memory analysis](change_logs/2026-07-29-host-identity-correlation.md)
  * [The DMZ transport could not carry a real capture](change_logs/2026-07-29-dmz-transport-scale.md)
  * [Capacity was only discoverable after a collection failed](change_logs/2026-07-29-component-health.md)
  * [Component Health figures were unreadable at the values that matter](change_logs/2026-07-29-component-health-rendering.md)
  * [Hostname and synthetic-capture attribution](change_logs/2026-07-29-collection-attribution.md)
