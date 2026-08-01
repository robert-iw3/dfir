#!/usr/bin/env python3
"""Declare what this collection will need, before it needs it.

A memory image is the size of the endpoint's RAM. A 512 GiB server produces a bundle no
fixed allowance covers, and the failure surfaces at the far end of a transfer that has
already taken hours — after the capture is on disk and the responder has moved on.

So the requirement is computed and announced first. It is a DECLARATION, not a query: the
collector says how much it will need and learns nothing back. Asking the platform whether
there is room would hand a potentially compromised endpoint a map of the enclave's storage,
which is the one thing the one-way boundary exists to prevent. The admin reads the
declaration in the console and expands storage there; the endpoint is told nothing.

Written to `_capacity_declaration.json` in the report directory so it travels with the
bundle, and printed to the collection log so a responder standing at the endpoint sees the
number without a console at all.
"""
from __future__ import annotations

import json
import os
import shutil
import sys

# Observed on real captures: a LiME image of live RAM compresses to roughly a third, because
# most of a running machine's memory is page cache and zeroes. Deliberately conservative —
# under-declaring is the failure that matters, since it is the one that lets a collection
# start that cannot finish.
COMPRESSION_RATIO = 0.45
# Both the raw image and the compressed bundle exist on the endpoint at the same time during
# packaging, so local space has to cover the pair plus room for artifacts.
LOCAL_OVERHEAD = 1.15


def _meminfo_total_bytes():
    """MemTotal from the mounted host's /proc, not the container's.

    Both report the host kernel's figure, but reading the mounted copy keeps this correct if
    the collector is ever run somewhere the two differ.
    """
    for path in ("/host/proc/meminfo", "/proc/meminfo"):
        try:
            with open(path) as fh:
                for line in fh:
                    if line.startswith("MemTotal:"):
                        parts = line.split()
                        if len(parts) >= 2 and parts[1].isdigit():
                            return int(parts[1]) * 1024
        except OSError:
            continue
    return 0


def _gib(n):
    return f"{n / 1024 ** 3:.1f} GiB"


def build(out_dir, hostname, incident_id, evidence_dir):
    ram = _meminfo_total_bytes()
    raw = ram                                  # a full image is one byte per byte of RAM
    bundle = int(raw * COMPRESSION_RATIO)
    local_needed = int((raw + bundle) * LOCAL_OVERHEAD)

    free_local = 0
    try:
        free_local = shutil.disk_usage(evidence_dir).free
    except OSError:
        pass

    decl = {
        "hostname": hostname,
        "incident_id": incident_id,
        "host_ram_bytes": ram,
        "expected_raw_bytes": raw,
        "expected_bundle_bytes": bundle,
        "local_required_bytes": local_needed,
        "local_free_bytes": free_local,
        # What each downstream hop will have to absorb. Stated by the endpoint as a
        # requirement; whether it can be met is decided inside, where the free space is known.
        "requires": {
            "receiver_holding_bytes": bundle,
            "puller_scratch_bytes": bundle + raw,
            "object_store_bytes": raw,
            "worker_scratch_bytes": raw,
        },
    }

    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "_capacity_declaration.json"), "w") as fh:
        json.dump(decl, fh, indent=2)

    print(f"[preflight] host RAM {_gib(ram)} -> image {_gib(raw)}, bundle ~{_gib(bundle)}")
    print(f"[preflight] this endpoint needs ~{_gib(local_needed)} locally; "
          f"{_gib(free_local)} free")
    print(f"[preflight] downstream will need: receiver ~{_gib(bundle)}, "
          f"object store ~{_gib(raw)}, worker scratch ~{_gib(raw)}")
    print("[preflight] declared to the platform — an admin can confirm capacity in the "
          "console before this transfers")

    if free_local and free_local < local_needed:
        print(f"[preflight] WARN: {_gib(free_local)} free here is less than the "
              f"~{_gib(local_needed)} this collection needs. Capture may fail part-way; "
              f"expand the evidence volume or mount a larger one.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("usage: preflight.py <out_dir> <hostname> <incident_id> <evidence_dir>",
              file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(build(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]))
