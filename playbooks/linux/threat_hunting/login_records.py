#!/usr/bin/env python3
"""login_records.py - raw wtmp/btmp/utmp/lastlog -> findings engine.

The collection copies these files byte-for-byte rather than shipping `last`/`lastb` output,
because the endpoint's own tools read them through the endpoint's own binaries: a truncated
wtmp, a replaced `last`, or a surgically removed record all produce a clean-looking report.
Parsing the records here is what makes that answer independent of the machine under
investigation.

Three questions only the raw files can answer:

  * Is the record sequence intact? wtmp is append-only, so timestamps run forward. A record
    older than the one before it means the file was rewritten, not appended to.
  * Do the two databases agree? lastlog is a separate file, indexed by uid, holding each
    user's last login. A lastlog entry with no corresponding wtmp session is a session that
    was removed from one file and missed in the other -- selective deletion, which truncation
    checks cannot see because the file is still full of plausible records.
  * Did a source that was failing start succeeding? btmp holds the failures and wtmp holds
    the successes; neither file alone carries that sequence.

Read-only, offline, never fatal: a file that is absent, truncated mid-record or written by a
libc with a different layout is reported as unparsed rather than silently contributing zero.

    login_records.py [--bundle DIR] [--report-dir DIR] [--stamp YYYYmmdd_HHMMSS] [--quiet]
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import struct
from collections import Counter, defaultdict

# glibc struct utmp, x86_64: 384 bytes, no implicit padding under '<' so it is spelled out.
_UTMP_FMT = "<h2xi32s4s32s256shhiii16s20x"
_UTMP_SIZE = struct.calcsize(_UTMP_FMT)

# glibc struct lastlog: int32 time, 32-byte tty, 256-byte host, indexed by uid.
_LASTLOG_FMT = "<i32s256s"
_LASTLOG_SIZE = struct.calcsize(_LASTLOG_FMT)

BOOT_TIME, USER_PROCESS, DEAD_PROCESS = 2, 7, 8
# Clock adjustments legitimately move time backwards and are recorded as their own types.
_TIME_CHANGE = (3, 4)

DEFAULT_BRUTE_THRESHOLD = 5
DEFAULT_WINDOW_SECONDS = 600


def _now():
    return datetime.datetime.now().isoformat(timespec="seconds")


def _finding(sev, ftype, target, details, mitre):
    return {"Timestamp": _now(), "Severity": sev, "Type": ftype, "Target": target,
            "Details": details, "MITRE": mitre, "Source": "login_records"}


def _cstr(raw):
    return raw.split(b"\x00", 1)[0].decode("utf-8", "replace").strip()


def parse_utmp(data):
    """(records, trailing_bytes). Each record: type, pid, line, user, host, ts."""
    out = []
    n, rem = divmod(len(data), _UTMP_SIZE)
    for i in range(n):
        chunk = data[i * _UTMP_SIZE:(i + 1) * _UTMP_SIZE]
        try:
            (ut_type, pid, line, _id, user, host,
             _e1, _e2, _sess, tv_sec, _tv_usec, _addr) = struct.unpack(_UTMP_FMT, chunk)
        except struct.error:
            continue
        out.append({"type": ut_type, "pid": pid, "line": _cstr(line), "user": _cstr(user),
                    "host": _cstr(host), "ts": tv_sec})
    return out, rem


def parse_lastlog(data):
    """{uid: {ts, line, host}} for every non-zero entry. Index IS the uid."""
    out = {}
    for uid in range(len(data) // _LASTLOG_SIZE):
        chunk = data[uid * _LASTLOG_SIZE:(uid + 1) * _LASTLOG_SIZE]
        try:
            ts, line, host = struct.unpack(_LASTLOG_FMT, chunk)
        except struct.error:
            continue
        if ts:
            out[uid] = {"ts": ts, "line": _cstr(line), "host": _cstr(host)}
    return out


def _read(path):
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError:
        return None


def _uid_map(passwd_text):
    """name -> uid from a collected /etc/passwd. Absent means uid cross-checks are skipped."""
    out = {}
    for ln in (passwd_text or "").splitlines():
        parts = ln.split(":")
        if len(parts) >= 3 and parts[2].isdigit():
            out[parts[0]] = int(parts[2])
    return out


def check_sequence(records, source):
    """wtmp is append-only. A record older than its predecessor means a rewrite."""
    out = []
    prev = None
    regressions = []
    for r in records:
        if r["type"] in _TIME_CHANGE or not r["ts"]:
            continue
        if prev is not None and r["ts"] < prev:
            regressions.append((prev, r))
        prev = max(prev or 0, r["ts"])
    if regressions:
        first_prev, first_now = regressions[0]
        out.append(_finding(
            "High", "Login Record Sequence Broken", source,
            f"{len(regressions)} record(s) in {source} are older than the record before them "
            f"(first: {datetime.datetime.fromtimestamp(first_prev)} followed by "
            f"{datetime.datetime.fromtimestamp(first_now['ts'])} for user "
            f"{first_now['user'] or '?'}). The file is append-only, so entries out of order "
            f"mean it was rewritten rather than appended to.",
            "T1070.002 (Clear Linux Logs)"))
    return out


def check_lastlog_agreement(lastlog, wtmp_records, uids):
    """A lastlog entry with no wtmp session for that user = a record removed from one file.

    Only claims anything when wtmp actually covers the period: a lastlog timestamp older
    than the oldest surviving wtmp record is normal rotation, not deletion.
    """
    out = []
    if not lastlog or not wtmp_records or not uids:
        return out
    by_uid = {uid: name for name, uid in uids.items()}
    sessions = defaultdict(list)
    for r in wtmp_records:
        if r["type"] == USER_PROCESS and r["user"]:
            sessions[r["user"]].append(r["ts"])
    covered_from = min((r["ts"] for r in wtmp_records if r["ts"]), default=None)
    if covered_from is None:
        return out
    missing = []
    for uid, entry in sorted(lastlog.items()):
        name = by_uid.get(uid)
        if not name or entry["ts"] < covered_from:
            continue
        # Same login recorded by two independent writers; allow a small clock/window skew.
        if not any(abs(ts - entry["ts"]) <= 60 for ts in sessions.get(name, ())):
            missing.append((name, entry))
    if missing:
        name, entry = missing[0]
        out.append(_finding(
            "High", "Login Record Removed", "wtmp",
            f"{len(missing)} login(s) recorded in lastlog have no matching wtmp session "
            f"(first: {name} from {entry['host'] or entry['line'] or '?'} at "
            f"{datetime.datetime.fromtimestamp(entry['ts'])}), while wtmp does cover that "
            f"period. Two independent databases disagree about the same login, which "
            f"selective deletion from one produces and rotation does not.",
            "T1070.002 (Clear Linux Logs)"))
    return out


def check_brute_force(btmp_records, wtmp_records, threshold, window):
    """Failure bursts, and the source that stopped failing and started succeeding."""
    out = []
    by_source = defaultdict(list)
    for r in btmp_records:
        key = r["host"] or r["line"] or "?"
        by_source[key].append((r["ts"], r["user"]))
    successes = defaultdict(list)
    for r in wtmp_records:
        if r["type"] == USER_PROCESS:
            successes[r["host"] or r["line"] or "?"].append((r["ts"], r["user"]))
    for source, attempts in sorted(by_source.items()):
        attempts.sort()
        burst = 0
        for i, (ts, _u) in enumerate(attempts):
            in_window = [t for t, _ in attempts[max(0, i - threshold + 1):i + 1]]
            if len(in_window) >= threshold and ts - in_window[0] <= window:
                burst = max(burst, len(in_window))
        if not burst:
            continue
        last_fail = attempts[-1][0]
        after = [(t, u) for t, u in successes.get(source, ()) if t >= attempts[0][0]]
        if after:
            t, u = min(after)
            out.append(_finding(
                "Critical", "Brute Force Succeeded", source,
                f"{len(attempts)} failed login(s) from {source} (burst of {burst} within "
                f"{window}s) followed by a successful session as {u or '?'} at "
                f"{datetime.datetime.fromtimestamp(t)}. The failures are in btmp and the "
                f"success is in wtmp; neither file carries this sequence alone.",
                "T1110 (Brute Force)"))
        else:
            out.append(_finding(
                "Medium", "Brute Force Attempt", source,
                f"{len(attempts)} failed login(s) from {source}, burst of {burst} within "
                f"{window}s, most recent {datetime.datetime.fromtimestamp(last_fail)}. No "
                f"successful session from this source.",
                "T1110 (Brute Force)"))
    return out


def _inventory(records, lastlog, unparsed):
    """One finding, not one per login. A session list is context, and context that arrives
    as hundreds of Info rows buries the findings an analyst is reading for."""
    out = []
    sessions = [r for r in records if r["type"] == USER_PROCESS]
    if sessions:
        users = Counter(r["user"] for r in sessions if r["user"])
        remote = {r["host"] for r in sessions if r["host"]}
        span = (datetime.datetime.fromtimestamp(min(r["ts"] for r in sessions if r["ts"])),
                datetime.datetime.fromtimestamp(max(r["ts"] for r in sessions if r["ts"])))
        out.append(_finding(
            "Info", "Login History", f"{len(sessions)} session(s)",
            f"{len(sessions)} session(s) between {span[0]} and {span[1]}; users "
            f"{', '.join(f'{u}x{n}' for u, n in users.most_common(8))}; "
            f"remote sources {', '.join(sorted(remote)[:8]) or 'none'}. "
            f"lastlog holds {len(lastlog)} user entr(ies).", "N/A"))
    for name, why in unparsed:
        out.append(_finding(
            "Info", "Login Record Unparsed", name,
            f"{name} could not be read as login records ({why}). Its checks did not run; "
            f"this is not a statement that they passed.", "N/A"))
    return out


def analyze(bundle, threshold=DEFAULT_BRUTE_THRESHOLD, window=DEFAULT_WINDOW_SECONDS,
            passwd_path=None):
    """Every check, over the raw databases in a collection bundle.

    `passwd_path` names the account file belonging to THIS bundle. lastlog is indexed by uid
    and by nothing else, so a uid can only be tied to a name by the passwd of the host the
    records came from. Defaulting to the reader's own /etc/passwd would attribute a removed
    session to whoever holds that uid on the analyst's machine, so it is not defaulted at
    all: absent, the uid checks are skipped and say so.
    """
    findings, unparsed = [], []
    parsed = {}
    for name in ("wtmp", "btmp", "utmp"):
        # A bundle holds all four side by side. On a live host utmp is the one that lives
        # elsewhere, so it is looked for where the running system keeps it too.
        candidates = [os.path.join(bundle, name)]
        if name == "utmp":
            candidates += ["/run/utmp", "/var/run/utmp"]
        data = next((d for d in (_read(p) for p in candidates) if d is not None), None)
        if data is None:
            continue
        if not data:
            parsed[name] = []
            continue
        records, rem = parse_utmp(data)
        if not records:
            unparsed.append((name, f"{len(data)} bytes, no {_UTMP_SIZE}-byte records - a "
                                   f"different libc layout or a partial file"))
            continue
        if rem:
            unparsed.append((name, f"{rem} trailing byte(s) after the last whole record"))
        parsed[name] = records

    ll_data = _read(os.path.join(bundle, "lastlog"))
    lastlog = parse_lastlog(ll_data) if ll_data else {}
    pw = passwd_path or next(
        (p for p in (os.path.join(bundle, "passwd"),
                     os.path.join(bundle, "forensics", "passwd")) if os.path.isfile(p)), None)
    uids = _uid_map(_read_text(pw)) if pw else {}
    if lastlog and not uids:
        findings.append(_finding(
            "Info", "Login Record Cross-Check Skipped", "lastlog",
            f"lastlog holds {len(lastlog)} entr(ies) but no account file for this host was "
            f"available, and lastlog is indexed by uid alone. The wtmp/lastlog agreement "
            f"check did not run; this is not a statement that the two agree.", "N/A"))

    wtmp = parsed.get("wtmp", [])
    findings += check_sequence(wtmp, "wtmp")
    findings += check_lastlog_agreement(lastlog, wtmp, uids)
    findings += check_brute_force(parsed.get("btmp", []), wtmp, threshold, window)
    findings += _inventory(wtmp, lastlog, unparsed)
    return findings


def _read_text(path):
    data = _read(path)
    return data.decode("utf-8", "replace") if data else ""


def main():
    ap = argparse.ArgumentParser(description="Raw login databases -> findings")
    ap.add_argument("--bundle", default="/var/log",
                    help="directory holding wtmp/btmp/utmp/lastlog (a collection bundle, or "
                         "/var/log to read this host)")
    ap.add_argument("--report-dir", default=".")
    ap.add_argument("--stamp", default=datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
    ap.add_argument("--passwd", help="account file for the host these records came from. "
                                     "lastlog is indexed by uid, so without it a uid cannot "
                                     "be tied to a name and those checks are skipped.")
    ap.add_argument("--brute-threshold", type=int, default=DEFAULT_BRUTE_THRESHOLD)
    ap.add_argument("--window-seconds", type=int, default=DEFAULT_WINDOW_SECONDS)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    findings = analyze(args.bundle, args.brute_threshold, args.window_seconds,
                       passwd_path=args.passwd)
    out_path = os.path.join(args.report_dir, f"Login_Findings_{args.stamp}.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=2)
    if not args.quiet:
        sev = Counter(f["Severity"] for f in findings)
        print(f"[login] {args.bundle} -> {len(findings)} finding(s) {dict(sev)}")
    print(out_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
