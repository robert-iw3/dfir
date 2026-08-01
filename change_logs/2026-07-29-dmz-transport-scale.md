# The DMZ transport could not carry a real capture

**Date:** 2026-07-29

**Area:** `platform/dmz/receiver.py`, `platform/dmz/puller.py`

**Status:** fixed

## Defect

The receiver capped uploads at 4 GiB and read the whole body into memory before writing it to
disk. `/fetch` served held bundles the same way, and the puller read each fetch fully into
memory on the enclave side.

An evidence bundle carries a memory image, so its size tracks the collected endpoint's RAM. A
22 GiB workstation compresses to roughly 7 GiB and a 512 GiB server to well over a hundred.
The first real capture was refused with `400 bad content length` at 6.87 GiB — 2.87 GiB over
the limit.

Raising the limit alone would have moved the failure rather than fixed it: three separate
places buffered a capture-sized file in memory, in processes deliberately smaller than the
hosts they serve.

**Why this had never been hit.** Every bundle that had ever crossed the DMZ was the 24 MB
synthetic sample — 3.2 MiB compressed, **1285× under the cap**. At that size the limit is
invisible and buffering is free. The one real capture already in the platform had been staged
directly into object storage and never crossed this path at all. A separate defect
([memory capture never succeeded](2026-07-29-memory-capture-never-succeeded.md)) kept every
collection synthetic, which held the whole transport in a regime where its own limits were
unreachable.

## Changes

**Upload limit replaced with a capacity check.** `RECEIVER_MAX_BYTES` now defaults to `0`,
meaning no fixed ceiling; an upload is refused only when it will not fit. Free space on the
holding volume is checked before a byte is read, keeping `RECEIVER_DISK_HEADROOM` (8 GiB) in
reserve — a transfer that runs the volume dry part-way through leaves a partial bundle and a
receiver that cannot serve any other host. An explicit `RECEIVER_MAX_BYTES` still imposes a
hard ceiling where a deployment wants one.

No constant is correct here: any value chosen is wrong for some machine the collector will
legitimately be pointed at.

**Symbol uploads keep a real ceiling.** `RECEIVER_MAX_ISF_BYTES` (2 GiB) is separate, so
removing the evidence limit does not widen the symbol path. Symbol tables are tens of
megabytes; nothing legitimate there approaches it.

**Streaming throughout.** `_stream_to_file()` copies exactly `Content-Length` bytes in 8 MB
blocks and reports a short read as an incomplete upload rather than accepting a truncated
bundle. `/fetch` streams from disk with `copyfileobj`. The puller's `_download()` streams to
disk instead of returning bytes, with a timeout sized to a capture rather than to a
responsive API.

**Spool moved onto the holding volume.** Accepting a bundle is now a rename rather than a
second copy of a capture-sized file, and one filesystem is checked for capacity rather than
two.

## Verification

A 6.87 GiB bundle from a 25.4 GB capture was accepted and custody-verified, pulled into the
enclave, and its image uploaded to object storage. An upload declaring a `Content-Length`
larger than the holding volume is refused with `400` before any body is read, asserted in
`platform/test/uat_baseline.sh`.

## Note

The enclave-side puller survived the first 6.87 GiB pull on the old buffering code only
because the host had more RAM than the bundle. On a larger endpoint that same code would have
exhausted memory rather than reported anything useful.
