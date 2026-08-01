# Symbol acquisition (ISF)

Volatility 3 cannot parse a Linux memory image without an **ISF** — a JSON symbol table
matching the exact kernel build. Struct offsets and symbol addresses differ per build, and
a generic BTF `vmlinux.h` is not a substitute.

Producing an ISF needs DWARF debug symbols, which normally means downloading them. The
analysis enclave has no egress and never will, so acquisition happens **here, outside the
enclave**, and only the resulting ISF is carried inward.

```
collection            outside the enclave           inside the enclave
──────────            ───────────────────           ──────────────────
_symbols.json    →    build_isf.sh                →  symbol store  →  worker
(requisites)          (downloads, builds ISF)        (ISF only)       (Volatility 3)
```

## Why the builder is per-distro but the analyzer is not

The **analyzer** is distro-agnostic. Volatility parses the raw image through the ISF; no
target code runs and nothing links against the target's libc. An Alpine worker analyzes an
Ubuntu image correctly.

The **builder** is not, because acquiring DWARF has three paths and only one is portable:

| Path | Distro-bound | Notes |
|---|---|---|
| Debug vmlinux already present | no | Fastest; nothing to download |
| `debuginfod` by build-id | **no** | Distro-agnostic — the preferred path, which is why the collector captures the build-id |
| Package-manager dbgsym | **yes** | Needs that family's tooling and repositories: `apt` + ddebs, `dnf` + debuginfo repos, `zypper` |
| Launchpad published binaries | **yes** (Debian/Ubuntu) | Retains builds the ddebs archive prunes — often the only route left for a superseded kernel ABI |

So there is one builder per distro family, used only when debuginfod does not have the
build. Each is a container, so the host running acquisition needs no distro tooling of its
own.

## Usage

```bash
./build_isf.sh --requisites <bundle>/_symbols.json --out ./store
./build_isf.sh --requisites <bundle>/_symbols.json --out ./store --family rhel
```

The driver picks a builder from `os_release.ID`/`ID_LIKE` in the requisites unless
`--family` overrides it. It writes `<store>/<symbol_key>.json` and validates that the
ISF's banner matches the one recorded at collection — a mismatched ISF produces confident,
wrong answers, so it is rejected rather than used.

## Carrying the ISF inward

The store is mounted read-only into the worker at `/symbols`. It contains symbol tables
only: no executables, no archives, no network configuration. Moving it inward is the same
one-way, operator-initiated transfer as any other inbound artifact.

## When the archive has already pruned the kernel

Distributions remove debug packages for superseded kernel ABIs, so the kernel in a capture
taken weeks ago may no longer be in `ddebs.ubuntu.com`. Launchpad keeps published binaries
after that pruning, and the acquisition script falls back to it:

```
https://launchpad.net/ubuntu/+archive/primary/+files/<pkg>_<version>_<arch>.ddeb
```

It selects the plain architecture rather than a micro-architecture variant such as
`amd64v3` — those are separate builds whose symbols do not match a generic-kernel capture.

This is why acquiring symbols promptly matters, and why maintaining a store for the
fleet's kernel inventory ahead of any incident is the reliable approach.

## When no ISF can be produced

Some kernels have no published debug symbols. The worker then falls back to a structural
byte scan, and records `engine=native-scan` on the analysis run so the reduced depth is
visible in the UI rather than implied to be a full analysis.
