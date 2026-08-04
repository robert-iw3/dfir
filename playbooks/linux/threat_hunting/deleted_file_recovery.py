#!/usr/bin/env python3
"""deleted_file_recovery.py - recover the CONTENTS of unlinked files still held open.

A file removed from disk while a process holds it open is still fully readable through
/proc/<pid>/fd/<n> until the last descriptor closes. For a dropper that unlinks its payload,
or an operator staging an archive and deleting it before exfil, that descriptor holds the
only copy in existence -- and it stops existing when the process dies or the host reboots.
The collection already flagged a deleted-but-running binary and could hand the analyst
nothing but its path.

Recovery is deliberately narrow, and the reason is measured rather than assumed: an ordinary
desktop was carrying 378 deleted descriptors, of which 214 were `/memfd:` objects (anonymous
memory, no file behind them at all) and the remaining 160 were browser shared-memory
segments, gvfs metadata and leveldb compaction leftovers. Recovering by directory would have
copied a user's browser storage and IndexedDB into a forensic bundle -- volume, and somebody's
private data, for no evidential gain.

So the question is not where the file lived but what it is and who is holding it:

  * its contents are executable (ELF, or a shebang);
  * or the process holding it is itself untrusted -- its own binary deleted, memfd-backed,
    or staged in a world-writable directory.

On the workstation above, both together select **zero** of the 160.

Bounded and honest about it: per-file and total byte caps, and anything skipped is recorded
in the manifest with the reason. A file that was not recovered must never look like a file
that was not there.

    deleted_file_recovery.py [--report-dir DIR] [--stamp ...] [--max-bytes N] [--quiet]
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import stat

# Caps: a deleted database or log can be tens of gigabytes, and a collection that fills the
# disk it writes to has destroyed the evidence it came for.
DEFAULT_MAX_FILE = 64 * 1024 * 1024
DEFAULT_MAX_TOTAL = 512 * 1024 * 1024

WRITABLE_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/")
_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def _now():
    return datetime.datetime.now().isoformat(timespec="seconds")


def _finding(sev, ftype, target, details, mitre):
    return {"Timestamp": _now(), "Severity": sev, "Type": ftype, "Target": target,
            "Details": details, "MITRE": mitre, "Source": "deleted_file_recovery"}


def _read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def proc_pids():
    return [p for p in os.listdir("/proc") if p.isdigit()]


def process_trust(pid):
    """Why this process's own binary is untrusted, or None when it is ordinary."""
    try:
        link = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return None
    if link.endswith(" (deleted)"):
        return "its own binary was deleted from disk while running"
    if link.startswith("/memfd:"):
        return "it is running from an anonymous memory file (memfd)"
    for d in WRITABLE_DIRS:
        if link.startswith(d):
            return f"its binary is staged under {d}"
    return None


def classify(fd_path, holder_untrusted):
    """(reason, head_bytes) if this descriptor is worth recovering, else (None, head)."""
    try:
        head = open(fd_path, "rb").read(4)
    except OSError:
        return None, b""
    if head[:4] == b"\x7fELF":
        return "executable content (ELF)", head
    if head[:2] == b"#!":
        return "executable content (script)", head
    if holder_untrusted:
        return f"held by an untrusted process - {holder_untrusted}", head
    return None, head


def _sha256_copy(src, dest, limit):
    """Copy up to `limit` bytes, returning (bytes_written, sha256, truncated)."""
    h = hashlib.sha256()
    written = 0
    truncated = False
    with open(src, "rb") as rf, open(dest, "wb") as wf:
        while written < limit:
            chunk = rf.read(min(1 << 20, limit - written))
            if not chunk:
                break
            h.update(chunk)
            wf.write(chunk)
            written += len(chunk)
        truncated = bool(rf.read(1))
    return written, h.hexdigest(), truncated


def scan(out_dir, max_file=DEFAULT_MAX_FILE, max_total=DEFAULT_MAX_TOTAL):
    """Walk every process's descriptors; recover what qualifies. Returns (entries, denied)."""
    recovered_dir = os.path.join(out_dir, "deleted_files")
    entries = []
    denied = 0
    total = 0
    self_pids = {str(os.getpid()), str(os.getppid())}

    for pid in sorted(proc_pids(), key=int):
        if pid in self_pids:
            continue                      # this collection's own descriptors are not evidence
        fd_dir = f"/proc/{pid}/fd"
        try:
            fds = os.listdir(fd_dir)
        except PermissionError:
            denied += 1
            continue
        except OSError:
            continue
        comm = _read(f"/proc/{pid}/comm").strip()
        untrusted = process_trust(pid)
        for fd in fds:
            fd_path = os.path.join(fd_dir, fd)
            try:
                target = os.readlink(fd_path)
            except OSError:
                continue
            if not target.endswith(" (deleted)"):
                continue
            original = target[:-len(" (deleted)")]
            # A memfd has no file behind it and never had one; check_memfd owns that signal.
            if original.startswith("/memfd:"):
                continue
            try:
                st = os.stat(fd_path)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue                  # a deleted FIFO or device is not content to recover
            reason, _head = classify(fd_path, untrusted)
            if not reason:
                continue

            entry = {"pid": pid, "process": comm, "fd": fd, "original_path": original,
                     "size": st.st_size, "reason": reason}
            if st.st_size > max_file:
                entry.update(recovered=False,
                             skipped=f"{st.st_size} bytes exceeds the {max_file}-byte "
                                     f"per-file cap; raise IR_DELETED_MAX_BYTES to recover it")
                entries.append(entry)
                continue
            if total + st.st_size > max_total:
                entry.update(recovered=False,
                             skipped=f"the {max_total}-byte total cap was reached before this "
                                     f"file; raise IR_DELETED_MAX_TOTAL to recover it")
                entries.append(entry)
                continue
            os.makedirs(recovered_dir, exist_ok=True)
            name = f"pid{pid}-fd{fd}-{_SAFE.sub('_', os.path.basename(original))[:80] or 'unnamed'}"
            dest = os.path.join(recovered_dir, name)
            try:
                written, digest, truncated = _sha256_copy(fd_path, dest, max_file)
            except OSError as exc:
                entry.update(recovered=False, skipped=f"read failed: {exc}")
                entries.append(entry)
                continue
            total += written
            entry.update(recovered=True, saved_as=os.path.join("deleted_files", name),
                         bytes_recovered=written, sha256=digest, truncated=truncated)
            entries.append(entry)
    return entries, denied


def to_findings(entries, denied):
    out = []
    for e in entries:
        where = f"PID {e['pid']} ({e['process']}) fd {e['fd']}"
        if not e.get("recovered"):
            out.append(_finding(
                "Info", "Deleted File Not Recovered", e["original_path"],
                f"{where} holds deleted {e['original_path']} ({e['size']} bytes) and it was "
                f"NOT recovered: {e['skipped']}. The descriptor is the only copy, and it is "
                f"gone when this process exits.", "T1070.004 (File Deletion)"))
            continue
        executable = e["reason"].startswith("executable content")
        sev = "High" if executable else "Medium"
        out.append(_finding(
            sev, "Deleted Executable Recovered" if executable else "Deleted File Recovered",
            e["original_path"],
            f"{where} held {e['original_path']}, deleted from disk while open - recovered "
            f"{e['bytes_recovered']} byte(s) to {e['saved_as']} (sha256 {e['sha256'][:16]}…). "
            f"Selected because: {e['reason']}."
            + (" Content was longer than the per-file cap and is truncated."
               if e.get("truncated") else ""),
            "T1070.004 (File Deletion)"))
    if denied:
        out.append(_finding(
            "Info", "Deleted File Scan Incomplete", f"{denied} process(es)",
            f"{denied} process(es) would not list their descriptors for this user. Their "
            f"deleted-but-open files were not examined; run the collection as root to close "
            f"this. Nothing here says those processes hold none.", "T1070.004 (File Deletion)"))
    return out


def main():
    ap = argparse.ArgumentParser(description="Recover deleted-but-open file contents")
    ap.add_argument("--report-dir", default=".")
    ap.add_argument("--stamp", default=datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
    ap.add_argument("--max-bytes", type=int,
                    default=int(os.environ.get("IR_DELETED_MAX_BYTES", DEFAULT_MAX_FILE)),
                    help="per-file recovery cap")
    ap.add_argument("--max-total", type=int,
                    default=int(os.environ.get("IR_DELETED_MAX_TOTAL", DEFAULT_MAX_TOTAL)),
                    help="total recovery cap for the run")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    entries, denied = scan(args.report_dir, args.max_bytes, args.max_total)
    findings = to_findings(entries, denied)

    with open(os.path.join(args.report_dir, "deleted_files_manifest.json"), "w",
              encoding="utf-8") as fh:
        json.dump({"generated": _now(), "processes_unreadable": denied, "entries": entries},
                  fh, indent=2)
    out_path = os.path.join(args.report_dir, f"Deleted_File_Findings_{args.stamp}.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=2)

    if not args.quiet:
        got = sum(1 for e in entries if e.get("recovered"))
        print(f"[deleted] {got} recovered, {len(entries) - got} skipped, "
              f"{denied} process(es) unreadable")
    print(out_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
