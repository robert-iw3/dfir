# Capacity was only discoverable after a collection failed

**Date:** 2026-07-29

**Area:** `platform/shared/sysstats.py`, `platform/backend/cases/`, `platform/dmz/`,
`platform/collector/preflight.py`, `platform/frontend/`

**Status:** fixed

## Defect

The platform reported whether each service was reachable and how much object storage was
consumed. Neither answers the question that decides whether a collection succeeds.

A memory image is the size of the collected endpoint's RAM, and it has to fit on the DMZ
holding volume, the puller's scratch space, object storage and the worker's scratch space in
turn. None of those figures was visible anywhere. A shortfall surfaced as a transfer that
failed hours in, after the capture was already taken.

Two things made it invisible rather than merely unreported:

- A container's real limits are only observable from inside it. Its cgroup memory ceiling is
  not the host's RAM, and the filesystem one component writes to is not the one another sees,
  so an external probe cannot measure any of it.
- The DMZ receiver has no route into the enclave, by design. Nothing inside could poll it.

## Changes

**`platform/shared/sysstats.py`** — one stdlib-only collector used by every component:
per-volume free space, host memory alongside the cgroup ceiling that actually predicts an OOM
kill, load against available CPUs, process and file-descriptor counts against their limits,
per-interface error and drop counters, and a `LogCounter` that counts warnings and errors
in-process. Counting in-process keeps the figure exact and avoids handing the web tier the
container runtime socket it would otherwise need to read a log stream.

**Reporting on a 15-minute interval.** The backend and workers hold a database connection
already and write directly, from a thread started by the role the process was launched with.
The puller reports over HTTP and carries the receiver's report with it on its outbound poll —
the only way a component with no inward route can be seen from inside. Each worker reports
under its own hostname, so scaling analysis out gives one row per worker with no extra wiring.

**`ComponentHealth` model** (migration `0007`) — one row per component, overwritten in place,
with the collection time so a reporter that has gone quiet reads as stale rather than as
healthy-but-idle.

**`componenthealth.py`** — thresholds that produce an action, not just a color. Absolute free
space as well as percentage, because 5% of 20 TB is plenty and 5% of 100 GB is not; and a
direct comparison against the largest capture this deployment has actually handled, which
tracks the hardware it collects from better than any constant.

**`platform/collector/preflight.py`** — the endpoint computes what its next collection needs
from its own RAM and declares it before capturing. It is a declaration, not a query: asking
the platform whether there is room would hand a potentially compromised host a map of the
enclave's storage, which is what the one-way boundary exists to prevent. The requirement is
printed at the endpoint and travels inward with the bundle; the comparison against free space
happens inside, and nothing is returned to the endpoint.

**Component Health page** (`/component-health`, admin only) — kept separate from Platform
Health, which answers a different question and would be crowded by this one.

## Verification

Four components reporting: backend, worker, puller and receiver. The capacity comparison
found a real problem on its first run — the worker's `/tmp` is an 11.3 GiB tmpfs against a
23.6 GiB capture, and the alert names the volume to expand. The declaration path produced the
matching warning at the endpoint before its capture ran.

Asserted in `platform/test/uat_baseline.sh`: every component reporting, none stale, and
`/stats` exposing only the receiver's own resources to the endpoint network.

## Notes

Two problems surfaced only once this ran against the deployed stack.

`podman-compose` did not merge an `environment:` block with an `env_file:`, so the variable
naming each process's role never arrived and both reported nothing while looking correctly
configured. The role is now derived in `entrypoint.sh` from the command the process was
launched with — one mechanism instead of two, neither of them silent.

Workers are keyed by container hostname, which changes whenever one is replaced, so rows for
departed workers accumulated until the page was mostly gone workers. Worker rows are pruned
after four missed intervals. Rows for the backend, puller and receiver are kept however old
they get: those are named for their role rather than their container, and one of them going
silent is itself the incident.
