#!/usr/bin/env python3
"""
Record what is needed to build a Volatility 3 ISF for THIS kernel.

Volatility cannot parse a Linux memory image without a symbol table (ISF) matching the exact
kernel build — struct offsets and symbol addresses are per-build, so a vmlinux.h or a BTF
blob from some *other* kernel does not substitute. The ISF is normally produced by fetching
DWARF debug symbols, which needs internet access the analysis enclave deliberately does not
have.

So the requisites are captured here, at collection time, on the host that actually has them.
That includes THIS kernel's own BTF, which is a different case from a generic one: it is
generated from the same build as the running kernel, so it matches the capture by
construction. It is worth taking because published DWARF is the fragile link — a distribution
prunes it for a superseded ABI and does not publish it the instant a new one ships, so a host
patched ahead of its archive has no downloadable symbols at all while its own type
information sits in /sys.

The ISF is built later, outside the enclave, and staged into the enclave's symbol store.
Nothing in this file needs network access; it only reads local kernel metadata.

Written as `_symbols.json` beside the capture, sealed with the rest of the bundle, and
ingested into `MemoryCapture.symbol_context`.
"""
import hashlib
import json
import os
import platform
import struct
import subprocess
import sys

# Paths a distro may already have DWARF symbols at. Their presence means the ISF can be
# built without any download at all.
VMLINUX_PATHS = [
    "/usr/lib/debug/boot/vmlinux-{r}",
    "/usr/lib/debug/lib/modules/{r}/vmlinux",
    "/boot/vmlinux-{r}",
    "/lib/modules/{r}/build/vmlinux",
    "/usr/lib/modules/{r}/vmlinux",
]


def read_text(path, limit=4096):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(limit).strip()
    except OSError:
        return ""


# Where the collected host's root filesystem is mounted when this runs inside the collector.
# Overridable so the same script is correct run directly on a host, where there is no prefix.
HOST_ROOT = os.environ.get("IR_HOST_ROOT", "/host/root")


def host_path(path):
    """The collected host's copy of `path`, falling back to this filesystem's.

    Anything describing the MACHINE — its distribution, its installed debug symbols — must come
    from the host, not from the container reading it. The two differ, and the difference is not
    cosmetic: the collector image is Alpine while the hosts it collects are not, so reading the
    container's own /etc/os-release reports `ID=alpine` and `provision.sh` then refuses to pick
    a builder for a distribution nobody is running.

    Values that describe the KERNEL are exempt and read normally: /proc/version,
    /proc/kallsyms and /sys/kernel/notes are the host kernel's regardless of namespace,
    because a container shares it.
    """
    candidate = os.path.join(HOST_ROOT, path.lstrip("/"))
    if HOST_ROOT and os.path.exists(candidate):
        return candidate
    return path


def build_id():
    """NT_GNU_BUILD_ID of the running kernel — the key debuginfod resolves against.

    This is the most valuable single field here: with it, symbols can be fetched for a
    kernel from any distro, without matching a package name or version scheme.
    """
    try:
        data = open("/sys/kernel/notes", "rb").read()
    except OSError:
        return ""
    off = 0
    while off + 12 <= len(data):
        namesz, descsz, ntype = struct.unpack_from("<III", data, off)
        off += 12
        name = data[off:off + namesz]
        off += (namesz + 3) & ~3
        desc = data[off:off + descsz]
        off += (descsz + 3) & ~3
        if ntype == 3 and name.startswith(b"GNU"):      # NT_GNU_BUILD_ID
            return desc.hex()
    return ""


def os_release():
    src = host_path("/etc/os-release")
    # The container's own file is NOT a fallback: recording ID=alpine for an Ubuntu host
    # sends provisioning to a builder that cannot exist. Unknown is recorded as unknown,
    # and provision.sh refuses it loudly instead of building against the wrong release.
    if src == "/etc/os-release":
        return {k: "" for k in ("ID", "ID_LIKE", "VERSION_ID", "PRETTY_NAME")}
    out = {}
    for line in read_text(src, 8192).splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip().strip('"')
    return {k: out.get(k, "") for k in ("ID", "ID_LIKE", "VERSION_ID", "PRETTY_NAME")}


def local_dwarf(release):
    for pattern in VMLINUX_PATHS:
        path = host_path(pattern.format(r=release))
        if os.path.isfile(path):
            return path
    return ""


# The kernel's own type information, exported for eBPF. Not namespaced: a container reading
# this gets the host kernel's, verified by hash against the host.
BTF_PATH = "/sys/kernel/btf/vmlinux"


def capture_btf(out_dir):
    """Copy the running kernel's BTF beside the requisites, and describe it.

    BTF carries struct layouts and member offsets — the part of an ISF that symbol addresses
    alone cannot supply, and the reason DWARF is otherwise needed. It is generated from the
    same build as the running kernel, so it matches the capture by construction: no version
    to resolve, no archive to depend on.

    That matters because published debug symbols are the fragile link in this chain. A
    distribution prunes them for superseded ABIs and does not publish them instantly for new
    ones, so a host patched ahead of its archive cannot be analyzed at all — while the type
    information sits on the machine being collected. Taking it costs seven megabytes.

    Captured unconditionally rather than only as a fallback: it is small, it is the only
    source guaranteed to match, and deciding later is cheaper than re-collecting.
    """
    if not os.path.isfile(BTF_PATH):
        return {}
    dest = os.path.join(out_dir, "_btf_vmlinux")
    h = hashlib.sha256()
    try:
        with open(BTF_PATH, "rb") as src, open(dest, "wb") as dst:
            for chunk in iter(lambda: src.read(1 << 20), b""):
                h.update(chunk)
                dst.write(chunk)
    except OSError as exc:
        return {"btf_error": str(exc)[:200]}
    return {"btf_file": os.path.basename(dest),
            "btf_size": os.path.getsize(dest),
            "btf_sha256": h.hexdigest()}


def main(out_path):
    release = platform.release()
    # The banner is what Volatility matches an ISF against, so it is recorded verbatim.
    banner = read_text("/proc/version")

    doc = {
        "kernel_release": release,
        "arch": platform.machine(),
        "banner": banner,
        "build_id": build_id(),
        "os_release": os_release(),
        # Present locally means the ISF can be built with no download at all.
        "local_vmlinux": local_dwarf(release),
        "system_map": next(
            (p for p in (host_path(f"/boot/System.map-{release}"),
                         host_path(f"/lib/modules/{release}/System.map"))
             if os.path.isfile(p)), ""),
        "kallsyms_readable": os.access("/proc/kallsyms", os.R_OK),
        # An ISF already on the collected host is worth shipping as-is.
        "isf_present": next(
            (p for p in (host_path(f"/usr/share/volatility3/symbols/linux/{release}.json"),
                         host_path(f"/opt/volatility3/symbols/linux/{release}.json"))
             if os.path.isfile(p)), ""),
    }

    # The kernel's own type information, taken while the machine is in front of us. Published
    # debug symbols may be pruned for an old ABI or not yet published for a new one; this is
    # the one source that always matches the capture.
    doc.update(capture_btf(os.path.dirname(os.path.abspath(out_path)) or "."))

    # Enough to identify the kernel even if the banner is unavailable.
    doc["symbol_key"] = doc["build_id"] or f"{doc['os_release'].get('ID','linux')}-{release}"

    missing = [k for k in ("banner", "build_id") if not doc[k]]
    doc["complete"] = not missing
    if missing:
        # Stated rather than silently degraded: without these, the ISF must be built from
        # a matching kernel package instead of resolved by build-id.
        doc["missing"] = missing

    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
    btf = f" btf={doc['btf_size'] // 1024}KiB" if doc.get("btf_size") else " btf=absent"
    print(f"[symbols] {release} build_id={doc['build_id'][:16] or 'unknown'} "
          f"complete={doc['complete']}{btf}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "_symbols.json"))
