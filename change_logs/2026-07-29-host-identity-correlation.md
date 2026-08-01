# Host identity for correlating collection with memory analysis

**Date:** 2026-07-29

**Area:** `platform/collector/collect.sh`, `platform/ingest/ir_ingest.py`, `platform/backend/cases/`

**Status:** fixed

## Defect

A host was identified by its hostname string. Ingest resolved one with
`Host.objects.get_or_create(hostname=...)`, so any difference in the reported name created a
second host record for the same machine.

A hostname does not identify a machine. It is renamed, reused across environments, and — when
collection runs in a container without the host filesystem mounted — reported as the container
id, which differs on every run.

The consequence is a split that the platform cannot see. Collection artifacts land within
minutes; a memory image of the same machine is analyzed and lands hours later. If the two
report the name differently, they file under different hosts, and corroborating a memory
finding against the collection finding that supports it compares two unrelated hosts and finds
nothing. The adjudication engine is not wrong in that case and raises no error — the evidence
simply never meets.

Observed during validation: the first collection run recorded the container id, and the 24 GB
memory capture hung off that record, while the corrected collection created a second host
under the machine's real name. Two host records, one machine.

This becomes structural rather than incidental once several workers analyze different images
in parallel: arrivals interleave and are out of order, and every one of them has to converge
on the same host record.

## Changes

**`platform/collector/collect.sh`** — records `/etc/machine-id` (generated once at install,
stable across reboots and renames) and the current boot id, both read from the mounted host
filesystem for the same reason the hostname is: the container has its own. Written to
`_host_identity.json` by the collector rather than the toolkit, because identity is a property
of the machine being collected from, and the toolkit also runs offline against images where
these do not apply. A missing machine-id is warned about explicitly, naming the consequence.

`resolve_hostname()` also now reports where the name came from — `host-mount`, `override`, or
`container-fallback`. Those are not equally trustworthy and cannot be told apart from the
string itself.

**`platform/ingest/ir_ingest.py`** — reads `_host_identity.json` and carries `machine_id`,
`boot_id` and `hostname_source` in the ingest payload's host block.

**`platform/backend/cases/models.py`** — `Host.machine_id`, indexed, blank permitted.
Migration `0006_host_machine_id`, additive.

**`platform/backend/cases/ingest.py`** — `resolve_host()` replaces the inline
`get_or_create`. It resolves on machine-id first and falls back to the hostname, so a bundle
carrying no machine-id behaves exactly as before. When a machine-id first arrives for a host
already known by name, it is recorded on that host rather than creating a second one, so
existing hosts adopt an identity without operator action. A rename is followed only when the
incoming name is trustworthy — a `container-fallback` name never overwrites a resolved one.

**`platform/backend/cases/management/commands/merge_host.py`** — new. Merges one host into
another for evidence collected before identity was recorded, moving collection runs, notes and
rescan requests; memory captures follow their run. Prints the plan and changes nothing without
`--apply`, requires `--reason`, writes one audit entry naming both hosts and every record
moved, and refuses to remove a host that still has runs referencing it.

## Verification

Host resolution, exercised against the arrival patterns above and rolled back:

| Case | Result |
|---|---|
| machine-id first seen for a host already known by name | adopted, no second host |
| memory image lands later reporting a container id | same host, good name held |
| genuine rename reported from the host mount | same host, follows new name |
| second machine | new host |
| bundle with no machine-id | falls back to hostname, joins existing |

The merge was then applied to the split observed during validation: one collection run and
two memory captures moved from the container-id record onto the named host, which was removed
once empty. All three memory analyses resolved to the single remaining host afterwards, and
the audit chain verified.

## Note

`machine_id` is recorded but not yet unique-constrained, because hosts collected before this
change have it blank and more than one such row is legitimate. A partial unique index over
non-blank values is the eventual shape, once the existing estate has been merged.
