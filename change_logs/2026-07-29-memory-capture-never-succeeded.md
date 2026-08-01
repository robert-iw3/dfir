# Memory capture never succeeded, and the fallback was silent

**Date:** 2026-07-29

**Area:** `platform/collector/collect.sh`

**Status:** fixed

## Defect

The collector invoked `avml <output-path>`. avml 0.20 takes a subcommand — `avml acquire
<output-path>` — and rejects the older spelling with `unrecognized subcommand`. Every capture
attempt therefore failed on argument parsing, before any question of host memory access arose.

The call discarded stderr (`>/dev/null 2>&1`) and the failure branch reported a fixed
explanation: `avml unavailable (no host kernel memory access)`. That message named a plausible
cause that was not the actual one, so the real error was never seen and the version mismatch
stayed invisible.

Both together mean every collection produced a synthetic sample, on any host, regardless of
privileges. A synthetic sample analyzes cleanly end to end and yields a completed run, so
nothing downstream indicates that no real memory was ever acquired. The run is flagged
`is_synthetic`, but that reads as a property of the capture rather than as a failure.

A second constraint, independent of the bug: acquiring real memory requires `CAP_SYS_ADMIN`
over the host's `/proc/iomem`. A rootless container cannot hold it however privileged it is
declared, because the capability is namespaced. The collector must run rootful or on the host.
With the invocation corrected, avml reports this itself:

```
Error: error: unable to parse /proc/iomem
caused by:
    0: need CAP_SYS_ADMIN to read /proc/iomem
```

## Changes

**`platform/collector/collect.sh`**

- Calls `avml acquire <path>`, and retries the flat form when avml reports an unrecognized
  subcommand, so the collector works against both CLI generations an endpoint may have staged.
- Captures avml's stderr instead of discarding it. The reason is printed on failure and
  recorded in `_capture_meta.json` as `capture_error`, so a run carrying a synthetic sample
  says why.
- The fallback warning states that the sample is not evidence, and that real acquisition needs
  `CAP_SYS_ADMIN` over the host's `/proc/iomem` — naming the rootless-container limit rather
  than a generic "unavailable".

**`resolve_hostname()`** assigns `HOST_S` and `HOSTNAME_SRC` directly instead of echoing the
name. A caller writing `HOST_S="$(resolve_hostname)"` runs the function in a subshell, and the
variable it set there is discarded when that subshell exits — `hostname_source` was recorded as
`unknown` for every collection, which suppressed legitimate host renames on ingest.

## Verification

Collection re-run rootless, with the mounts the documented invocation uses:

- `hostname_source` records `host-mount` rather than `unknown`.
- `machine_id` and `boot_id` are recorded.
- The capture failure is reported with avml's own error text, and `_capture_meta.json` carries
  it in `capture_error`.

Real acquisition is unchanged by this fix where the capability is absent — it fails, but now
says so accurately. Confirming a successful `avml acquire` requires a rootful run.

## Open

The synthetic fallback still produces a run that looks complete. Flagging the capture is
necessary but not sufficient: a collection whose memory acquisition failed is a partial
collection, and the platform has no state that says so. Consider surfacing `capture_error` on
the run itself so an analyst sees it without opening the capture record.
