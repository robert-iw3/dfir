# Hostname and synthetic-capture attribution

**Date:** 2026-07-29

**Area:** `Invoke-IRCollection-Linux.sh`, `platform/collector/`, `platform/backend/cases/`

**Status:** 3 defects fixed, 1 open

## Defect

**Results were attributed to the container, not the host.** Collection run in a container
recorded the container ID as the hostname. Every finding, IOC and custody record for a host
landed under a name that changes on each run and matches nothing an analyst can act on.

Two layers computed a hostname independently. `platform/collector/collect.sh` resolved it for
the output path; the toolkit `Invoke-IRCollection-Linux.sh` computed its own via `hostname -s`
and wrote that into `_status.json` and the manifest, which is what platform ingest reads. The
output directory was named for the host while the metadata inside it named the container.

`/proc/sys/kernel/hostname` is UTS-namespaced, so bind-mounting it does not expose the host's
name.

**Synthetic captures drove compromise state.** When memory acquisition falls back to a
synthetic capture, its planted indicators — a C2 URL and a reverse-shell token — were counted
as evidence. Runs were marked compromised on content the tool generated itself, and the web app
showed the result with no indication of its origin.

## Changes

**`platform/collector/collect.sh`** — `resolve_hostname()` reads `/host/root/etc/hostname`,
then `/host/etc/hostname`, honours an `IR_HOSTNAME` override, and warns loudly when it falls
back to the container's own name. It exports `IR_HOSTNAME` so the toolkit inherits the same
value rather than deriving its own.

**`Invoke-IRCollection-Linux.sh`** — accepts the `IR_HOSTNAME` override ahead of `hostname -s`.
This also serves offline analysis, where a responder collecting against a mounted image needs
the results attributed to the host the image came from.

**`platform/backend/cases/models.py`** — `evaluate_compromise()` excludes findings derived from
a capture flagged `is_synthetic`.

**`platform/backend/cases/promotion.py`** — records `raw.synthetic` on promoted findings, and
holds the entry verdict at Indeterminate for them.

**`platform/frontend/src/pages/RunDetail.jsx`** — labels synthetic-derived findings inline.

## Verification

Collection re-run in a container with `/proc` and `/` mounted read-only, then shipped through
the DMZ receiver to the enclave. Confirmed:

- The collector wrapper and the toolkit report the same hostname, and it is the host's rather
  than the container's.
- `_status.json` and the collection manifest — the files ingest reads — carry that hostname.
- The run appears in the platform under the host it was collected from, custody verified, with
  its findings and IOCs attached.
- The capture is flagged `is_synthetic=True` with `capture_tool=synthetic-fallback`, and its
  findings no longer contribute to the run's compromise state.

## Follow-on: the incident id did not propagate either

Found while verifying the above and fixed the same day. The collector and toolkit both
recorded the supplied incident id — present in `_status.json` and the manifest — but every run
was created under the default investigation regardless of what the responder specified, so the
whole estate collapsed into one incident.

`ir_ingest.py` took the incident from its own process environment. It runs inside the enclave
as part of the puller, which has no idea which incident a given bundle belongs to; the
responder set it at the endpoint and the collector wrote it into the bundle. The bundle is the
authority, so ingest now reads it from `_status.json` (falling back to the manifest, then to
its own default) and says which source it used. The same value keys the object-storage path,
so captures file under the incident they were collected for.

Verified: a collection run with `IR_INCIDENT_ID=INC-2026-0042` created a run under that
investigation rather than the default.
