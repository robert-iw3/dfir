# Field collector — `ir-collect`

One statically linked binary for collecting memory from a **suspected endpoint in production
use**: a workstation a SIEM flagged, belonging to a regular employee, that may be compromised.

Design and rationale: [`planning/COLLECTOR-DEPLOYMENT.md`](../../../planning/COLLECTOR-DEPLOYMENT.md).

> **DRAFT — not built, not compiled, not tested.** Acquisition and upload are stubs carrying
> their contracts. Nothing here should be run against an endpoint.
>
> The toolchain is pinned (Rust 1.97.1, edition 2024) but has never been run: no `Cargo.lock`
> exists, so `avml = "*"` is unresolved and the dependency set is unproven. `./build.sh --lock`
> then `./build.sh --check` is where this resumes.

## Why this exists beside `collector/`

`platform/collector/` is a **container**: its entrypoint needs `bash`, `python3` and the toolkit
at `/opt/toolkit`. That is correct for controlled and lab collection, and it stays.

A flagged employee workstation typically has **no container runtime at all**, and may have no
usable Python. Installing either is invasive, loud, changes the machine under investigation, and
needs a package manager that may be locked down.

So this path assumes the endpoint has **nothing**, and ships one artifact that needs nothing.

| | `collector/` (container) | `collector/bin/` (this) |
|---|---|---|
| Needs on endpoint | container runtime, Python, toolkit mount | nothing |
| Delivery | image, pulled or loaded | one binary over SSH, into memory |
| Disk footprint | evidence volume | **zero** |
| Use | controlled, lab, corpus | suspected endpoint in production |

## Build

The toolchain is not a host dependency — the same rule the platform applies to every other
build. The container compiles; the **binary** lands on the host.

```bash
./build.sh --lock    # resolve dependencies, write Cargo.lock
./build.sh --check   # cargo check, clippy, rustfmt — no artifact
./build.sh           # build and export dist/ir-collect
./build.sh --verify  # rebuild and require the hash to match
```

The build **refuses to emit a dynamically linked artifact** — a collector that needs a loader on
the endpoint is what this track exists to avoid, and that failure would otherwise surface
mid-incident on a machine we do not control.

Check the recorded hash before deploying. The endpoint cannot vouch for what ran on it.

`Cargo.lock` is committed, because the hash means nothing without it: an upstream release would
otherwise change the binary while the source stayed identical, and `--verify` would report drift
it cannot explain.

`rust-toolchain.toml` pins the compiler. `build.sh` passes that channel as the builder's base
image tag, so the two cannot disagree; the build also proves the toolchain accepts edition 2024
rather than failing later with an error that reads like a syntax problem.

## Layout

| Path | Holds |
|---|---|
| `Dockerfile` | Build container; the `artifact` stage exports the binary |
| `build.sh` | Builds, verifies static linkage, records the hash |
| `src/manifest.rs` | The sealed manifest — the contract with the platform |
| `src/chunk.rs` | One pass: chunk, hash, elide zero pages, encode |
| `src/conditions.rs` | Records the conditions the run happened under |
| `src/snapshot.rs` | Volatile snapshot, taken before and after |
| `src/main.rs` | Lifecycle, plus the acquisition and upload stubs |

## What it does, in order

1. **Harden** — `PR_SET_DUMPABLE=0`, so a non-root observer cannot attach or read this
   process's memory. Useless against root, so the outcome is *recorded*, not relied on.
2. **Snapshot** — process table, connections, modules, mounts. Seconds.
3. **Acquire, chunk, seal, stream — one pass.** The image is read once and never staged to
   disk. Memory footprint is one chunk; disk footprint is zero.
4. **Snapshot again** — the delta shows what changed *during* the capture, which is evidence:
   a process that appeared or vanished mid-acquisition is worth knowing about.
5. **Seal** — HMAC over the manifest, which carries content hashes computed during the pass.
6. **Verify delivery, then exit.** The job is done when the platform confirms the Merkle root,
   not when the last chunk is sent.

## Two boundaries the code holds

**The endpoint asserts nothing.** `conditions.rs` records `ptrace`, loader environment, kernel
taint, module list hash, acquisition fallbacks and read rate — and draws no conclusion. Anti-
tamper on a host we do not control is bounded: a kernel rootkit sees and can alter anything a
userspace collector does, including these reads. The platform judges; the collector reports.

**Non-obvious to the user, fully visible to the organization.** No prompt, no notification, no
artifact, no perceptible slowdown — *and* allowlisted in EDR rather than evasive of it, with the
endpoint's own authentication record left intact. That record is the evidence the action was
authorized. Erasing it would be destroying evidence on a host the organization owns.

## Open before this can be finished

Tracked as O-009 to O-011 in [`planning/DECISIONS.md`](../../../planning/DECISIONS.md):

- Does the AVML crate expose the fallback chain programmatically **and** stream, rather than
  writing a file? If it only writes a file, this design needs revisiting — a 24 GB write to the
  endpoint's disk is the one thing it refuses.
- Hardened kernels where no acquisition method works. It must **say so**, never substitute.
- Whether a LiME kernel-module fallback is ever acceptable on a production host. Default: no.
