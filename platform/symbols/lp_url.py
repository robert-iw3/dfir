#!/usr/bin/env python3
"""Pick the download URL for a published dbgsym from a Launchpad API response.

Launchpad retains binaries the ddebs archive prunes, so for a superseded kernel ABI this
is often the only remaining source of DWARF.
"""
import json
import sys

ARCH = "amd64"


def main(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return 1
    for entry in doc.get("entries", []):
        name = entry.get("display_name", "")
        # Match the plain architecture, not micro-architecture variants such as amd64v3:
        # those are separate builds whose symbols would not match a generic-kernel image.
        if not name.endswith(" " + ARCH) or entry.get("status") != "Published":
            continue
        parts = name.split()
        if len(parts) < 2:
            continue
        pkg, version = parts[0], parts[1]
        print("https://launchpad.net/ubuntu/+archive/primary/+files/"
              f"{pkg}_{version}_{ARCH}.ddeb")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else ""))
