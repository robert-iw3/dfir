"""Raw login databases -> findings (playbooks/linux/threat_hunting/login_records.py).

The collection copies wtmp/btmp/utmp/lastlog byte-for-byte because `last` and `lastb` read
them through the endpoint's own binaries: a truncated file, a replaced `last`, or a single
removed record all produce a clean-looking report. These tests build the records themselves,
so what is asserted is the parse and the cross-check -- not that some tool agreed with itself.

The record layouts are glibc's, which is what the format assumes; a musl or otherwise
mismatched file must be reported as unparsed rather than contributing zero findings quietly.
"""
import os
import struct
import sys
import time

from conftest import LINUX_HUNT

sys.path.insert(0, LINUX_HUNT)
import login_records as lr  # noqa: E402

USER_PROCESS = lr.USER_PROCESS


def _utmp(ut_type, user, host, ts, line="pts/0", pid=1234):
    return struct.pack(lr._UTMP_FMT, ut_type, pid, line.encode(), b"ts/0",
                       user.encode(), host.encode(), 0, 0, 0, int(ts), 0, b"\x00" * 16)


def _lastlog(entries, max_uid=None):
    """entries: {uid: (ts, line, host)} -> a flat uid-indexed array."""
    top = max_uid if max_uid is not None else max(entries) if entries else 0
    out = b""
    for uid in range(top + 1):
        ts, line, host = entries.get(uid, (0, "", ""))
        out += struct.pack(lr._LASTLOG_FMT, int(ts), line.encode(), host.encode())
    return out


def _bundle(tmp_path, **files):
    for name, data in files.items():
        (tmp_path / name).write_bytes(data if isinstance(data, bytes) else data.encode())
    return str(tmp_path)


def _types(findings):
    return {f["Type"] for f in findings}


def _of(findings, ftype):
    return next(f for f in findings if f["Type"] == ftype)


# --- the parse --------------------------------------------------------------------------

def test_record_sizes_match_the_glibc_layout():
    assert lr._UTMP_SIZE == 384
    assert lr._LASTLOG_SIZE == 292


def test_parse_utmp_recovers_user_host_and_time():
    now = int(time.time())
    recs, rem = lr.parse_utmp(_utmp(USER_PROCESS, "alice", "10.0.0.5", now))
    assert rem == 0 and len(recs) == 1
    assert recs[0]["user"] == "alice" and recs[0]["host"] == "10.0.0.5"
    assert recs[0]["ts"] == now and recs[0]["type"] == USER_PROCESS


def test_parse_lastlog_skips_never_logged_in_uids():
    data = _lastlog({0: (1_700_000_000, "pts/0", "workstation")}, max_uid=5)
    parsed = lr.parse_lastlog(data)
    assert list(parsed) == [0]          # uids 1..5 are all-zero: nobody has ever logged in
    assert parsed[0]["host"] == "workstation"


# --- sequence integrity -----------------------------------------------------------------

def test_append_only_file_in_order_is_not_flagged(tmp_path):
    base = int(time.time()) - 3600
    wtmp = b"".join(_utmp(USER_PROCESS, "alice", "", base + i * 60) for i in range(5))
    f = lr.analyze(_bundle(tmp_path, wtmp=wtmp))
    assert "Login Record Sequence Broken" not in _types(f)


def test_a_record_older_than_its_predecessor_is_a_rewrite(tmp_path):
    """wtmp is appended to, never edited. Out-of-order entries mean it was rebuilt."""
    base = int(time.time()) - 3600
    wtmp = (_utmp(USER_PROCESS, "alice", "", base + 600)
            + _utmp(USER_PROCESS, "bob", "", base))          # earlier than the one before
    f = lr.analyze(_bundle(tmp_path, wtmp=wtmp))
    assert "Login Record Sequence Broken" in _types(f)
    assert _of(f, "Login Record Sequence Broken")["Severity"] == "High"


def test_clock_change_records_do_not_count_as_regression(tmp_path):
    """NTP stepping the clock backwards is recorded as its own record type, legitimately."""
    base = int(time.time()) - 3600
    wtmp = (_utmp(USER_PROCESS, "alice", "", base + 600)
            + _utmp(4, "", "", base)                          # OLD_TIME
            + _utmp(USER_PROCESS, "bob", "", base + 900))
    f = lr.analyze(_bundle(tmp_path, wtmp=wtmp))
    assert "Login Record Sequence Broken" not in _types(f)


# --- two databases that must agree ------------------------------------------------------

PASSWD = "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n"


def test_lastlog_login_with_no_wtmp_session_is_a_removed_record(tmp_path):
    """The check the raw files exist for.

    Truncation is visible from the file size; a single deleted session is not -- wtmp is
    still full of plausible records. lastlog is written independently, so the two disagree.
    """
    base = int(time.time()) - 3600
    wtmp = (_utmp(USER_PROCESS, "root", "", base)
            + _utmp(USER_PROCESS, "root", "", base + 1800))
    lastlog = _lastlog({0: (base, "pts/0", ""),
                        1000: (base + 900, "pts/1", "203.0.113.77")})
    f = lr.analyze(_bundle(tmp_path, wtmp=wtmp, lastlog=lastlog, passwd=PASSWD))
    assert "Login Record Removed" in _types(f)
    hit = _of(f, "Login Record Removed")
    assert hit["Severity"] == "High" and "alice" in hit["Details"]


def test_agreeing_databases_are_not_flagged(tmp_path):
    base = int(time.time()) - 3600
    wtmp = (_utmp(USER_PROCESS, "root", "", base)
            + _utmp(USER_PROCESS, "alice", "203.0.113.77", base + 900, line="pts/1"))
    lastlog = _lastlog({0: (base, "pts/0", ""),
                        1000: (base + 900, "pts/1", "203.0.113.77")})
    f = lr.analyze(_bundle(tmp_path, wtmp=wtmp, lastlog=lastlog, passwd=PASSWD))
    assert "Login Record Removed" not in _types(f)


def test_login_older_than_the_surviving_wtmp_is_rotation_not_deletion(tmp_path):
    """wtmp rotates. A lastlog entry predating every surviving record proves nothing."""
    base = int(time.time()) - 3600
    wtmp = _utmp(USER_PROCESS, "root", "", base)
    lastlog = _lastlog({0: (base, "pts/0", ""),
                        1000: (base - 86400 * 30, "pts/1", "old-session")})
    f = lr.analyze(_bundle(tmp_path, wtmp=wtmp, lastlog=lastlog, passwd=PASSWD))
    assert "Login Record Removed" not in _types(f)


def test_no_passwd_means_no_uid_claim_and_says_so(tmp_path):
    """Without the host's own passwd a uid cannot be tied to a name, so the check is skipped.

    Reaching for the reader's /etc/passwd instead would attribute a removed session to
    whoever holds that uid on the analyst's machine. Skipping silently would be worse still:
    the run would look like the two databases agreed.
    """
    base = int(time.time()) - 3600
    wtmp = _utmp(USER_PROCESS, "root", "", base)
    lastlog = _lastlog({1000: (base + 900, "pts/1", "203.0.113.77")})
    f = lr.analyze(_bundle(tmp_path, wtmp=wtmp, lastlog=lastlog))
    assert "Login Record Removed" not in _types(f)
    assert "did not run" in _of(f, "Login Record Cross-Check Skipped")["Details"]


def test_passwd_can_be_named_explicitly(tmp_path):
    """A live run points at /etc/passwd; a bundle carries its own copy."""
    base = int(time.time()) - 3600
    pw = tmp_path / "elsewhere-passwd"
    pw.write_text(PASSWD)
    wtmp = _utmp(USER_PROCESS, "root", "", base)
    lastlog = _lastlog({0: (base, "pts/0", ""),
                        1000: (base + 900, "pts/1", "203.0.113.77")})
    f = lr.analyze(_bundle(tmp_path, wtmp=wtmp, lastlog=lastlog), passwd_path=str(pw))
    assert "Login Record Removed" in _types(f)


def test_bundle_forensics_passwd_is_found(tmp_path):
    """The collection drops /etc/passwd into forensics/, so a bundle needs no extra flag."""
    base = int(time.time()) - 3600
    (tmp_path / "forensics").mkdir()
    (tmp_path / "forensics" / "passwd").write_text(PASSWD)
    wtmp = _utmp(USER_PROCESS, "root", "", base)
    lastlog = _lastlog({0: (base, "pts/0", ""),
                        1000: (base + 900, "pts/1", "203.0.113.77")})
    f = lr.analyze(_bundle(tmp_path, wtmp=wtmp, lastlog=lastlog))
    assert "Login Record Removed" in _types(f)


# --- btmp + wtmp together ---------------------------------------------------------------

def test_failure_burst_without_success_is_an_attempt(tmp_path):
    base = int(time.time()) - 3600
    btmp = b"".join(_utmp(USER_PROCESS, "root", "203.0.113.77", base + i * 10)
                    for i in range(8))
    f = lr.analyze(_bundle(tmp_path, btmp=btmp))
    assert _of(f, "Brute Force Attempt")["Severity"] == "Medium"


def test_failures_then_a_session_from_the_same_source_is_a_compromise(tmp_path):
    """Neither file carries this alone: btmp has the failures, wtmp has the success."""
    base = int(time.time()) - 3600
    btmp = b"".join(_utmp(USER_PROCESS, "root", "203.0.113.77", base + i * 10)
                    for i in range(8))
    wtmp = _utmp(USER_PROCESS, "root", "203.0.113.77", base + 200)
    f = lr.analyze(_bundle(tmp_path, btmp=btmp, wtmp=wtmp))
    hit = _of(f, "Brute Force Succeeded")
    assert hit["Severity"] == "Critical" and "203.0.113.77" in hit["Target"]
    assert "Brute Force Attempt" not in _types(f)


def test_slow_failures_are_not_a_burst(tmp_path):
    """Eight failures over two days is a user who forgot a password, not a spray."""
    base = int(time.time()) - 86400 * 2
    btmp = b"".join(_utmp(USER_PROCESS, "alice", "203.0.113.77", base + i * 21600)
                    for i in range(8))
    f = lr.analyze(_bundle(tmp_path, btmp=btmp))
    assert "Brute Force Attempt" not in _types(f)


# --- honest failure ---------------------------------------------------------------------

def test_unparseable_file_is_reported_not_silently_empty(tmp_path):
    """A different libc's layout must not read as "no logins, nothing to see"."""
    f = lr.analyze(_bundle(tmp_path, wtmp=b"\x01\x02\x03" * 40))
    hit = _of(f, "Login Record Unparsed")
    assert hit["Target"] == "wtmp"
    assert "did not run" in hit["Details"]


def test_trailing_partial_record_is_reported_and_the_rest_still_parses(tmp_path):
    base = int(time.time()) - 3600
    wtmp = _utmp(USER_PROCESS, "alice", "", base) + b"\x00" * 17
    f = lr.analyze(_bundle(tmp_path, wtmp=wtmp))
    assert "Login Record Unparsed" in _types(f)
    assert "Login History" in _types(f)          # the whole record before it still counted


def test_history_is_one_finding_not_one_per_session(tmp_path):
    """A session list is context. Delivered as hundreds of rows it buries the findings."""
    base = int(time.time()) - 3600
    wtmp = b"".join(_utmp(USER_PROCESS, f"u{i}", "", base + i) for i in range(200))
    f = lr.analyze(_bundle(tmp_path, wtmp=wtmp))
    assert len([x for x in f if x["Type"] == "Login History"]) == 1
    assert "200 session(s)" in _of(f, "Login History")["Target"]


def test_empty_bundle_yields_no_findings(tmp_path):
    assert lr.analyze(str(tmp_path)) == []


def test_findings_carry_the_common_schema(tmp_path):
    base = int(time.time()) - 3600
    f = lr.analyze(_bundle(tmp_path, wtmp=_utmp(USER_PROCESS, "alice", "", base)))
    assert f
    for x in f:
        assert set(x) >= {"Timestamp", "Severity", "Type", "Target", "Details", "MITRE"}
        assert x["Source"] == "login_records"
