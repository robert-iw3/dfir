#!/usr/bin/env python3
"""Run every mwcp parser over ordinary content on this host and report what fires.

Nothing sampled here is malicious, so every finding printed is a false positive. The
synthetic FP set in `samples/fp/` is built from what malware looks like with a signal
removed; this is built from what an uncompromised machine's own files look like, which is a
different distribution and catches different defects. Four of the six defects recorded in
`planning/BACKLOG.md` §12b were invisible to code review until this produced counts.

It is deliberately not a pytest test: results depend on what is installed on the box, so it
would be non-deterministic in CI. Run it by hand after changing a parser, and compare the
total against the last recorded run.

    python3 test/linux/lab_mwcp/fp_corpus_audit.py [--files-per-root N] [--json]

`extract_all()` is the production contract -- `memory_enrich.py` and `edr_hunt.py` call only
that -- so the family counts are what an analyst would actually see. Per-parser `identify()`
counts are reported alongside, because a parser whose `identify()` fires but whose `extract()`
returns nothing is one changed line away from being a live false positive.

Scope: this reads files, so it represents what `edr_hunt.py`'s on-disk structural pass sees.
It cannot represent process-heap content, which is where §12a's false positives came from --
carved regions from a real capture remain the check for that.
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import random
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
sys.path.insert(0, REPO)

from playbooks.linux.threat_hunting.mwcp_parsers import driver  # noqa: E402
from playbooks.linux.threat_hunting.mwcp_parsers import (  # noqa: E402
    c2_frameworks, cloud_saas, delivery, native, ransomware, specialized)

# Matches the read cap edr_hunt.py applies, so truncation-dependent paths (an ELF too large
# to parse, a window past the scan bound) are exercised the same way here.
MAX_BYTES = 4 * 1024 * 1024
SEED = 7

ROOTS = {
    "syslib":  ["/usr/lib/x86_64-linux-gnu", "/usr/lib64"],
    "bin":     ["/usr/bin", "/usr/sbin"],
    "etc":     ["/etc"],
    "docs":    ["/usr/share/doc", "/usr/share/man"],
    "devtool": [os.path.expanduser("~/.local/lib"), "/usr/lib/python3",
                "/usr/lib/node_modules"],
}
# Kernel-generated text a live scan reads directly. /proc/self/status matters specifically:
# it contains the TracerPid: field name that the anti-debug parser keys on.
PROC_FILES = ("/proc/self/status", "/proc/self/stat", "/proc/self/maps",
              "/proc/self/cmdline", "/proc/cpuinfo", "/proc/meminfo")


def _parsers():
    out = []
    for pkg in (c2_frameworks, cloud_saas, delivery, native, ransomware, specialized):
        for mod in pkg.MODULES:
            out.append((mod.__name__.rsplit(".", 1)[-1], mod))
    return out


def _corpus(per_root: int):
    rng = random.Random(SEED)
    out = [("proc", p) for p in PROC_FILES]
    for label, dirs in ROOTS.items():
        files = []
        for d in dirs:
            if not os.path.isdir(d):
                continue
            for dirpath, _, names in os.walk(d):
                files.extend(os.path.join(dirpath, n) for n in names)
                if len(files) > 24000:
                    break
        rng.shuffle(files)
        out.extend((label, f) for f in files[:per_root])
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--files-per-root", type=int, default=450,
                    help="files sampled per corpus root (default 450)")
    ap.add_argument("--json", action="store_true", help="emit machine-readable results")
    args = ap.parse_args()

    parsers = _parsers()
    families = collections.Counter()
    identifies = collections.Counter()
    examples = collections.defaultdict(list)
    id_examples = collections.defaultdict(list)
    scanned = collections.Counter()

    for label, path in _corpus(args.files_per_root):
        try:
            if os.path.islink(path) or not os.path.isfile(path):
                continue
            with open(path, "rb") as fh:
                data = fh.read(MAX_BYTES)
        except OSError:
            continue
        if not data:
            continue
        scanned[label] += 1

        for hit in driver.extract_all(data):
            fam = hit.get("family", "?")
            families[fam] += 1
            if len(examples[fam]) < 5:
                examples[fam].append(path)
        for name, mod in parsers:
            if not hasattr(mod, "identify"):
                continue
            try:
                fired = mod.identify(data)
            except Exception:      # a parser that raises is a separate bug; not this report
                continue
            if fired:
                identifies[name] += 1
                if len(id_examples[name]) < 5:
                    id_examples[name].append(path)

    total_files = sum(scanned.values())
    total_findings = sum(families.values())

    if args.json:
        print(json.dumps({
            "files_scanned": total_files,
            "files_by_root": dict(scanned),
            "false_findings_total": total_findings,
            "false_findings_by_family": dict(families),
            "identify_hits_by_parser": dict(identifies),
            "identify_hit_examples": {k: v for k, v in id_examples.items()},
        }, indent=2, sort_keys=True))
        return 0

    print(f"scanned {total_files} ordinary files: {dict(scanned)}")
    print("nothing here is malicious -- every finding below is a false positive\n")

    print(f"{'family reported (extract_all)':<52} {'count':>6}")
    print("-" * 60)
    for fam, n in families.most_common():
        print(f"{fam:<52} {n:>6}")
    print(f"\nTOTAL false findings: {total_findings}")

    if identifies:
        print(f"\n{'parser identify() fired':<40} {'files':>6}   (extract() may still gate)")
        print("-" * 60)
        for name, n in identifies.most_common():
            print(f"{name:<40} {n:>6}")
            # The file, not just the count: a count says a gate is loose and the path says
            # why, which is the difference between recording the number and fixing it.
            for p in id_examples[name]:
                print(f"{'':<40}        {p}")

    if examples:
        print("\n--- where they fired ---")
        for fam, _ in families.most_common():
            for path in examples[fam]:
                print(f"{fam:<44} {path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
