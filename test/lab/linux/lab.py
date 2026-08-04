#!/usr/bin/env python3
"""
Linux endpoint lab — plant known artifacts, run the REAL collection, assert it found them.

Runs inside a disposable container that stands in for an endpoint. Nothing about the
collector is stubbed: `Invoke-IRCollection-Linux.sh` executes exactly as it would on a host,
and every assertion asks whether the collection recovered something this script planted.

Three subcommands, in the order the lab uses them:

    plant   <scenario.json>              put the artifacts on the endpoint
    collect <scenario.json> <outroot>    run the collection orchestrator
    verify  <scenario.json> <outroot>    assert the collection recovered them

Why planting is separate from asserting: a plant that could not be performed — no
CAP_LINUX_IMMUTABLE for `chattr +i`, no kernel support — must never let its assertion pass.
It is recorded as SKIPPED and `verify` refuses to score it either way, so an unprovable claim
is visibly unproven rather than quietly green.
"""
from __future__ import annotations

import glob
import json
import os
import shutil
import struct
import subprocess
import sys
import tarfile
import time
from collections import Counter

PLANT_STATE = "/tmp/ir-lab-planted.json"


# --- plumbing ---------------------------------------------------------------------------

def sh(*args, **kw):
    return subprocess.run(args, capture_output=True, text=True, **kw)


def load(path):
    with open(path) as fh:
        return json.load(fh)


# --- planting ---------------------------------------------------------------------------
#
# Each planter returns None on success or a string saying why it could not run. The reason is
# carried through to `verify`, because "the endpoint could not host this artifact" and "the
# collector missed it" are different results and must never be confused.

def _write(path, content, mode=None):
    os.makedirs(os.path.dirname(path) or "/", exist_ok=True)
    with open(path, "w") as fh:
        fh.write(content)
    if mode is not None:
        os.chmod(path, int(mode, 8) if isinstance(mode, str) else mode)


def plant_file(p):
    _write(p["path"], p.get("content", "ir-lab\n"), p.get("mode"))


def plant_suid(p):
    # A real binary, so the collector's `find -perm /6000` has something with content to hash
    # rather than an empty file that a later integrity check would treat as a special case.
    shutil.copy("/bin/true", p["path"])
    os.chmod(p["path"], 0o4755)


def plant_world_writable_exec(p):
    shutil.copy("/bin/true", p["path"])
    os.chmod(p["path"], 0o777)


def plant_immutable(p):
    _write(p["path"], p.get("content", "ir-lab immutable\n"))
    r = sh("chattr", "+i", p["path"])
    if r.returncode != 0:
        # Needs CAP_LINUX_IMMUTABLE and a filesystem that supports it. Overlayfs in a
        # container often does not, which is a property of the lab, not of the collector.
        return f"chattr +i unavailable: {(r.stderr or r.stdout).strip()[:120]}"


def plant_authorized_key(p):
    home = p.get("home", "/root")
    _write(os.path.join(home, ".ssh", "authorized_keys"), p["key"] + "\n", 0o600)


def plant_cron(p):
    _write(p.get("path", "/etc/cron.d/ir-lab"), p["line"] + "\n", 0o644)


def plant_systemd_timer(p):
    base = p.get("dir", "/etc/systemd/system")
    _write(os.path.join(base, p["name"] + ".timer"), p.get("content", "[Timer]\nOnBootSec=1min\n"))
    _write(os.path.join(base, p["name"] + ".service"), p.get("service", "[Service]\nExecStart=/bin/true\n"))


def plant_openrc_service(p):
    """An OpenRC service: the init script, its conf.d override, and the runlevel symlink.

    All three are needed for the plant to be what it claims. The script alone is a file on
    disk; the symlink under /etc/runlevels is what makes it start at boot, and conf.d is the
    override an intruder can use without touching a package-owned script.
    """
    name = p["name"]
    if not os.path.isdir("/etc/runlevels"):
        return "endpoint does not run OpenRC"
    script = p.get("script", "#!/sbin/openrc-run\ncommand=/usr/local/bin/ir-lab-implant\n")
    _write(os.path.join("/etc/init.d", name), script, 0o755)
    if p.get("conf"):
        _write(os.path.join("/etc/conf.d", name), p["conf"], 0o644)
    level = p.get("runlevel", "default")
    os.makedirs(os.path.join("/etc/runlevels", level), exist_ok=True)
    link = os.path.join("/etc/runlevels", level, name)
    if not os.path.lexists(link):
        os.symlink(os.path.join("/etc/init.d", name), link)


def plant_ld_preload(p):
    """A real shared object, preloaded — not a dangling path.

    A file the loader cannot open still lands in ld.so.preload and is still collected, but it
    makes every subsequent command on the endpoint print a loader error, which is noise the
    lab should not manufacture. Copying a real library makes the hook behave like one.
    """
    src = next((s for s in glob.glob("/lib/*/libutil.so.1") + glob.glob("/lib/*/libdl.so.2")
                if os.path.exists(s)), None)
    if src:
        os.makedirs(os.path.dirname(p["path"]), exist_ok=True)
        shutil.copy(src, p["path"])
    _write("/etc/ld.so.preload", p["path"] + "\n")


def _long_runner(dest):
    """Copy a binary to `dest` that still runs when renamed, and return its argv tail.

    Not `/bin/sleep`. On Alpine that is busybox, and coreutils there is a single multi-call
    binary behind symlinks — both dispatch on argv[0], so a copy named `ir-lab-fileless` is not
    a valid applet and exits immediately. The plant reported success and the process was gone
    before the collection ran, which reads as a collection gap and is not one.

    The interpreter ignores argv[0] for behaviour, so the same plant works on glibc and musl.
    """
    src = next((s for s in ("/usr/bin/python3", "/usr/local/bin/python3", "/bin/python3")
                if os.path.exists(s)), None)
    if not src:
        return None
    os.makedirs(os.path.dirname(dest) or "/", exist_ok=True)
    shutil.copy(src, dest)
    os.chmod(dest, 0o755)
    return ["-c", "import time; time.sleep(600)"]


def plant_deleted_running(p):
    """A process whose binary is unlinked while it runs — the classic fileless residency.

    The collector should see it through /proc/<pid>/exe reporting '(deleted)'. The process is
    left running for the collection to find; the container is torn down afterwards.
    """
    path = p["path"]
    tail = _long_runner(path)
    if tail is None:
        return "no interpreter available to stand in for a running binary"
    proc = subprocess.Popen([path] + tail)
    os.unlink(path)
    __import__("time").sleep(0.4)
    return None if proc.poll() is None else "process exited before its binary was unlinked"


def plant_deleted_open_payload(p):
    """A payload written, unlinked, and held open — the descriptor is the only copy left.

    Distinct from `deleted_running`: nothing executes this file, so /proc/<pid>/exe is clean
    and the process table shows an ordinary interpreter. The evidence exists solely as an
    open descriptor, and it stops existing when the holder is killed or the host reboots.
    """
    path = p.get("path", "/tmp/ir-lab-dropped-payload")
    marker = p.get("marker", "IRLABDELETEDPAYLOAD")
    src = next((s for s in ("/usr/bin/python3", "/usr/local/bin/python3", "/bin/python3")
                if os.path.exists(s)), None)
    if not src:
        return "no interpreter available to hold the descriptor"
    body = ("import os,time\n"
            f"fh=open({path!r},'wb')\n"
            # ELF magic so the recovery selects it on content, then a locatable marker.
            f"fh.write(b'\\x7fELF' + b'\\x00'*124 + {marker.encode()!r} * 4)\n"
            "fh.flush()\n"
            f"os.unlink({path!r})\n"
            "time.sleep(3600)\n")
    proc = subprocess.Popen([src, "-c", body])
    __import__("time").sleep(0.6)
    if proc.poll() is not None:
        return "the holder exited before the collection could read its descriptor"
    if os.path.exists(path):
        return "the payload is still on disk; it was not unlinked"


def plant_wtmp_trim(p):
    """Truncate the login record — anti-forensics that `last` cannot report on itself.

    A session is recorded FIRST, in lastlog, because zeroing wtmp on a host nobody ever
    logged into produces the same bytes as a container that has simply never had a session.
    Without the record there is nothing for a wipe to have removed, and asserting the finding
    would be asserting a conclusion the evidence does not carry.

    The lastlog record is glibc's `struct lastlog` — int32 time, 32-byte tty, 256-byte host —
    indexed by uid; uid 0 is offset 0.
    """
    if not os.path.exists("/var/log/wtmp"):
        return "no wtmp on this image to trim"
    rec = struct.pack("<i32s256s", int(time.time()) - 3600,
                      b"pts/0", b"workstation.example.internal")
    with open("/var/log/lastlog", "wb") as fh:
        fh.write(rec)
    for f in ("/var/log/wtmp", "/var/log/btmp"):
        if os.path.exists(f):
            open(f, "wb").close()


_UTMP_FMT = "<h2xi32s4s32s256shhiii16s20x"
_LASTLOG_FMT = "<i32s256s"


def plant_login_record_delete(p):
    """One session removed from wtmp while lastlog still records it.

    Truncating the whole file is the loud version and the file size gives it away. This is
    the quiet one: wtmp stays full of plausible sessions and a single login is gone from it.
    Only a second, independently written database still holding that login can show it.
    """
    if not os.path.exists("/var/log/wtmp"):
        return "no wtmp on this image"
    now = int(time.time())
    removed = now - 1800
    kept = (now - 3600, now - 600)

    def rec(ts, user="root", host="203.0.113.77", line="pts/1"):
        return struct.pack(_UTMP_FMT, 7, 4242, line.encode(), b"ts/1",
                           user.encode(), host.encode(), 0, 0, 0, int(ts), 0, b"\x00" * 16)

    with open("/var/log/wtmp", "wb") as fh:
        for ts in kept:
            fh.write(rec(ts))
    with open("/var/log/lastlog", "wb") as fh:      # uid 0 is offset 0
        fh.write(struct.pack(_LASTLOG_FMT, removed, b"pts/1", b"203.0.113.77"))


def plant_sudoers(p):
    _write(p.get("path", "/etc/sudoers.d/ir-lab"), p["line"] + "\n", 0o440)


def plant_capability(p):
    """A file capability instead of SUID — the same privilege, and `find -perm /6000` misses it."""
    shutil.copy("/bin/true", p["path"])
    os.chmod(p["path"], 0o755)
    r = sh("setcap", p.get("cap", "cap_setuid+ep"), p["path"])
    if r.returncode != 0:
        return f"setcap unavailable: {(r.stderr or r.stdout).strip()[:120]}"


def plant_bash_history(p):
    _write(p.get("path", "/root/.bash_history"), "\n".join(p["lines"]) + "\n", 0o600)


def plant_ssh_known_hosts(p):
    _write(os.path.join(p.get("home", "/root"), ".ssh", "known_hosts"),
           "\n".join(p["hosts"]) + "\n", 0o644)


def plant_listener(p):
    """A process holding a listening socket — what a backdoor shell looks like to `ss`."""
    port = int(p.get("port", 41337))
    code = (f"import socket,time\n"
            f"s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
            f"s.bind(('0.0.0.0',{port}));s.listen(1)\ntime.sleep(600)\n")
    path = p.get("path", "/usr/local/bin/ir-lab-listener")
    _write(path, code, 0o755)
    proc = subprocess.Popen(["python3", path],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        if sh("ss", "-tlnp").stdout.find(str(port)) >= 0:
            return None
        __import__("time").sleep(0.1)
    return "listener did not bind" if proc.poll() is not None else None


def plant_masquerade_proc(p):
    """A userland process wearing a kernel-thread name.

    The masquerade is in `argv[0]`, not the filename — which is how it is actually done, and
    the reason the file on disk looks unremarkable. `[kworker/1:2]` cannot be a filename
    anyway: it contains a slash.
    """
    path = p.get("path", "/usr/local/bin/ir-lab-masq")
    fake = p.get("argv0", "[kworker/1:2]")
    tail = _long_runner(path)
    if tail is None:
        return "no interpreter available to stand in for a running binary"
    proc = subprocess.Popen([fake] + tail, executable=path)
    __import__("time").sleep(0.4)
    return None if proc.poll() is None else "masquerading process exited immediately"


def plant_proc_shell(p):
    """A live process whose argv is the tradecraft.

    `bash -c '<command>; sleep N'` — the command runs for real (and fails, because the lab has
    no network), then the shell sleeps so the process is still there when the collection walks
    /proc. What is under test is the argv a hunt reads, and that is genuine either way.
    """
    # `sleep N & wait`, not `sleep N`. Bash execs the LAST command of a -c string over itself
    # to save a fork, so a trailing `sleep` replaces the shell and the argv under test — the
    # very thing being planted — disappears from /proc. Backgrounding it and waiting keeps
    # bash alive holding the original command line.
    cmd = f"{p['command']}; sleep {p.get('hold', 600)} & wait"
    proc = subprocess.Popen(["bash", "-c", cmd],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    __import__("time").sleep(0.3)
    return None if proc.poll() is None else "shell exited before the collection could see it"


def plant_staged_credentials(p):
    """Copies of credential stores parked in a writable directory, ready to leave."""
    for src, dst in p["copies"].items():
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        if os.path.exists(src):
            shutil.copy(src, dst)
        else:
            _write(dst, f"ir-lab staged credential material from {src}\n")


def plant_mode(p):
    """Loosen permissions on an existing file — e.g. a world-readable /etc/shadow."""
    if not os.path.exists(p["path"]):
        return f"{p['path']} does not exist on this image"
    os.chmod(p["path"], int(p["mode"], 8))


def plant_timestomp(p):
    """Backdate a file's content timestamps the way every timestomping tool does.

    `os.utime` sets atime and mtime and cannot touch ctime — the kernel updates that on the
    inode change and exposes no way to rewrite it. So this reproduces the real artifact: an
    old-looking file whose ctime is now.
    """
    path = p["path"]
    _write(path, p.get("content", "ir-lab backdated implant\n"), p.get("mode", 0o755))
    old = __import__("time").time() - int(p.get("age_days", 400)) * 86400
    os.utime(path, (old, old))
    st = os.lstat(path)
    if st.st_ctime - st.st_mtime < 86400:
        return "filesystem did not preserve the ctime/mtime split"


def plant_tamper_packaged_binary(p):
    """Backdoor a binary the package manager owns, and make it SUID.

    This is the toolkit's declared trust anchor under test. `adjudicate.py` calls a
    package-owned-but-modified binary "Likely True Positive, High" regardless of finding type,
    and the correlator promotes it to a DEFINITIVE dimension — the strongest verdict the Linux
    side can reach, because a package manager does not let installed files drift from their
    recorded contents.

    Appending a byte is what makes it modified; the SUID bit is what gives it a finding to be
    the subject of, so adjudication resolves ownership and integrity for it. Both are what a
    real backdoored system binary looks like.
    """
    path = p["path"]
    if not os.path.exists(path):
        return f"{path} is not present on this image"
    try:
        with open(path, "ab") as fh:
            fh.write(b"\n# ir-lab tamper\n")
        os.chmod(path, 0o4755)
    except OSError as exc:
        return f"could not tamper {path}: {exc}"


def plant_bulk_backdated(p):
    """What `tar -xp` / `rsync -a` / `cp -pr` leave behind: many files, old mtimes, one ctime.

    Ordinary and constant on a developer or build host — unpacking a release archive does
    exactly this. It is also, file for file, indistinguishable from timestomping; only the
    fact that it happened to dozens of files in the same second tells them apart.
    """
    base = p.get("dir", "/tmp/ir-lab-release")
    old = __import__("time").time() - int(p.get("age_days", 300)) * 86400
    os.makedirs(base, exist_ok=True)
    for i in range(int(p.get("count", 25))):
        f = os.path.join(base, f"lib{i}.so")
        _write(f, f"benign extracted artifact {i}\n", 0o755)
        os.utime(f, (old, old))


def plant_tmp_exec(p):
    """Running from a world-writable directory — present on disk, unlike the deleted case."""
    path = p.get("path", "/tmp/ir-lab-dropper")
    tail = _long_runner(path)
    if tail is None:
        return "no interpreter available to stand in for a running binary"
    proc = subprocess.Popen([path] + tail)
    __import__("time").sleep(0.4)
    return None if proc.poll() is None else "dropper exited immediately"


def plant_log_truncate(p):
    """`> /var/log/auth.log` — the file survives, its contents do not.

    Written with content first, then emptied. A minimal container image ships without these
    logs at all, and "absent" is a different condition from "present and zero bytes": the
    detection turns on a security log that EXISTS and holds nothing, which is what a wipe
    leaves behind and what an absent file would never exercise.
    """
    for f in p.get("paths", ["/var/log/auth.log", "/var/log/syslog"]):
        os.makedirs(os.path.dirname(f), exist_ok=True)
        with open(f, "w") as fh:
            fh.write("pre-existing log content that the intruder removes\n")
        open(f, "wb").close()


PLANTERS = {
    "file": plant_file,
    "sudoers": plant_sudoers,
    "capability": plant_capability,
    "bash_history": plant_bash_history,
    "ssh_known_hosts": plant_ssh_known_hosts,
    "listener": plant_listener,
    "masquerade_proc": plant_masquerade_proc,
    "proc_shell": plant_proc_shell,
    "staged_credentials": plant_staged_credentials,
    "mode": plant_mode,
    "timestomp": plant_timestomp,
    "bulk_backdated": plant_bulk_backdated,
    "tamper_packaged_binary": plant_tamper_packaged_binary,
    "tmp_exec": plant_tmp_exec,
    "log_truncate": plant_log_truncate,
    "suid": plant_suid,
    "world_writable_exec": plant_world_writable_exec,
    "immutable": plant_immutable,
    "authorized_key": plant_authorized_key,
    "cron": plant_cron,
    "systemd_timer": plant_systemd_timer,
    "openrc_service": plant_openrc_service,
    "ld_preload": plant_ld_preload,
    "deleted_running": plant_deleted_running,
    "deleted_open_payload": plant_deleted_open_payload,
    "wtmp_trim": plant_wtmp_trim,
    "login_record_delete": plant_login_record_delete,
}


def cmd_plant(scenario_path):
    scen = load(scenario_path)
    state = {}
    for p in scen.get("plant", []):
        pid = p["id"]
        fn = PLANTERS.get(p["type"])
        if fn is None:
            state[pid] = f"unknown plant type {p['type']!r}"
            print(f"  PLANT-ERR {pid}: unknown type {p['type']!r}")
            continue
        try:
            why = fn(p)
        except Exception as exc:                       # noqa: BLE001
            why = f"{type(exc).__name__}: {exc}"
        state[pid] = why
        print(f"  {'PLANT-SKIP' if why else 'PLANTED   '} {pid}" + (f": {why}" if why else ""))
    with open(PLANT_STATE, "w") as fh:
        json.dump(state, fh)
    return 0


# --- collection -------------------------------------------------------------------------

def cmd_collect(scenario_path, outroot, extra=()):
    scen = load(scenario_path)
    toolkit = os.environ.get("IR_TOOLKIT", "/toolkit")
    # The flags the PLATFORM passes, so the default profile the lab measures is the one that
    # actually ships. `extra` is how the runner adds --deep for the comparison.
    cmd = ["bash", os.path.join(toolkit, "Invoke-IRCollection-Linux.sh"),
           "--output-root", outroot,
           "--incident-id", scen.get("incident_id", "IR-LAB"),
           "--no-egress-monitor", "--skip-reports"]
    cmd += scen.get("collect_args", [])
    cmd += list(extra)
    print(f"  running: {' '.join(cmd[1:])}")
    r = subprocess.run(cmd, text=True, capture_output=True)
    # The orchestrator degrades rather than failing, so its exit code is not the assertion —
    # what it produced is. The output is kept for diagnosis when a claim fails.
    tail = (r.stdout or "")[-1500:]
    print("\n".join("    | " + ln for ln in tail.splitlines()[-25:]))
    return 0


# --- verification -----------------------------------------------------------------------

def _out_dir(outroot):
    dirs = [d for d in glob.glob(os.path.join(outroot, "*")) if os.path.isdir(d)]
    return dirs[0] if dirs else None


def _read_candidates(out_dir, rel):
    """Every place a collected artifact may live, as (label, text) pairs.

    The inline forensics phase writes loose files; the deep collector writes into
    /var/ir and copies a tarball in. An assertion names the artifact, not the delivery
    mechanism, so both are searched — which is also what lets the same scenario measure
    exactly what running with and without `--deep` costs.
    """
    out = []
    # A glob, because some artifacts are named after runtime facts. A recovered deleted file
    # carries the holder's pid and descriptor in its name, and asserting on the manifest
    # instead would prove the collection knew about the file, not that it got the bytes.
    for loose in ([p for p in sorted(glob.glob(os.path.join(out_dir, rel))) if os.path.isfile(p)]
                  if any(c in rel for c in "*?[") else
                  [os.path.join(out_dir, rel)] if os.path.isfile(os.path.join(out_dir, rel))
                  else []):
        try:
            out.append((f"loose:{os.path.relpath(loose, out_dir)}",
                        open(loose, errors="replace").read()))
        except OSError:
            pass
    for tgz in glob.glob(os.path.join(out_dir, "*.tar.gz")):
        try:
            with tarfile.open(tgz) as tf:
                for m in tf.getmembers():
                    if m.isfile() and m.name.endswith(os.path.basename(rel)):
                        fh = tf.extractfile(m)
                        if fh:
                            out.append((f"{os.path.basename(tgz)}:{m.name}",
                                        fh.read().decode(errors="replace")))
        except (tarfile.TarError, OSError):
            pass
    return out


def _findings_text(out_dir):
    blobs = []
    for pat in ("Combined_Findings_*.json", "EDR_Report_*.json", "Adjudication_*.json"):
        for f in glob.glob(os.path.join(out_dir, pat)):
            try:
                blobs.append(open(f, errors="replace").read())
            except OSError:
                pass
    return "\n".join(blobs)


def _has_subsystem(name):
    if name == "systemd":
        return bool(shutil.which("systemctl")) and os.path.isdir("/etc/systemd")
    if name == "openrc":
        # Not /etc/init.d — systemd distros ship that too, for sysvinit compat. OpenRC is
        # the runlevel symlink tree plus the tool that maintains it.
        return bool(shutil.which("rc-update")) and os.path.isdir("/etc/runlevels")
    return True


def _findings_records(out_dir):
    """Findings as records rather than text, for counting by severity and type."""
    for pat in ("Combined_Findings_*.json", "EDR_Report_*.json"):
        for f in sorted(glob.glob(os.path.join(out_dir, pat))):
            try:
                d = json.load(open(f))
            except (OSError, ValueError):
                continue
            rows = d if isinstance(d, list) else (d.get("findings") or [])
            if rows:
                return [r for r in rows if isinstance(r, dict)]
    return []


def _adjudication_entries(out_dir):
    """Every adjudicated entry, flattened out of whatever shape the file uses."""
    out = []
    for f in glob.glob(os.path.join(out_dir, "Adjudication_*.json")):
        try:
            d = json.load(open(f))
        except (OSError, ValueError):
            continue
        rows = d if isinstance(d, list) else (d.get("entries") or d.get("findings") or [])
        out += [r for r in rows if isinstance(r, dict)]
    return out


def cmd_verify(scenario_path, outroot):
    scen = load(scenario_path)
    planted = load(PLANT_STATE) if os.path.exists(PLANT_STATE) else {}
    out_dir = _out_dir(outroot)
    if not out_dir:
        print("FAIL  the collection produced no host folder at all")
        return 1

    npass = nfail = nskip = 0
    findings = _findings_text(out_dir)

    for exp in scen.get("expect", []):
        label = exp.get("id") or exp.get("artifact") or exp.get("finding_contains")
        needs = exp.get("needs_plant")
        if needs and planted.get(needs):
            print(f"SKIP  {label} — plant {needs!r} could not run: {planted[needs]}")
            nskip += 1
            continue
        # An expectation about a subsystem the endpoint does not run is a statement about the
        # distro, not the collector. Alpine has no systemd, so asserting a planted .timer
        # reaches systemd_unit_files.txt there would fail for the one reason that is not a
        # defect. (That the collector does not collect OpenRC services IS a gap — a separate
        # expectation on an Alpine-specific scenario, not this one silently passing.)
        req = exp.get("requires")
        if req and not _has_subsystem(req):
            print(f"SKIP  {label} — endpoint does not run {req}")
            nskip += 1
            continue

        if "artifact" in exp:
            found = _read_candidates(out_dir, exp["artifact"])
            if not found:
                print(f"FAIL  {label} — artifact not collected at all ({exp['artifact']})")
                nfail += 1
                continue
            want = exp.get("contains")
            where = [n for n, text in found if not want or want in text]
            if where:
                print(f"PASS  {label} — {where[0]}")
                npass += 1
            else:
                print(f"FAIL  {label} — {exp['artifact']} collected but does not carry "
                      f"{want!r} (looked in {len(found)} copy/copies)")
                nfail += 1

        elif "finding_contains" in exp:
            want = exp["finding_contains"]
            if isinstance(want, dict):
                # {"type": ..., "contains": ...} — a substring anywhere in the findings text
                # proves SOMETHING fired, not that the intended check did. Naming the type
                # binds the assertion to one check, so two checks covering the same planted
                # artifact cannot stand in for each other when one regresses.
                hits = [r for r in _findings_records(out_dir)
                        if r.get("Type") == want["type"]
                        and want["contains"] in json.dumps(r)]
                if hits:
                    print(f"PASS  {label} — {want['type']!r} names {want['contains']!r}"
                          f" [{hits[0].get('Severity')}]")
                    npass += 1
                else:
                    seen = sorted({r.get("Type") for r in _findings_records(out_dir)})
                    print(f"FAIL  {label} — no {want['type']!r} finding names "
                          f"{want['contains']!r}; types present: {seen}")
                    nfail += 1
            elif want in findings:
                print(f"PASS  {label} — a finding names {want!r}")
                npass += 1
            else:
                print(f"FAIL  {label} — no finding names {want!r}")
                nfail += 1

        elif "max_findings" in exp:
            # The false-positive claim, and the only one that scales. Every other expectation
            # asks "did you find what I hid?" — this asks "what else did you say?", which is
            # the question the lab could not put and every live run answered painfully.
            want = exp["max_findings"]
            sev = want.get("severity")
            hits = [r for r in _findings_records(out_dir)
                    if (not sev or r.get("Severity") == sev)
                    and (not want.get("type") or r.get("Type") == want["type"])]
            cap = want["at_most"]
            if len(hits) <= cap:
                print(f"PASS  {label} — {len(hits)} (cap {cap})")
                npass += 1
            else:
                print(f"FAIL  {label} — {len(hits)} findings, cap {cap}")
                for r in hits[:8]:
                    print(f"        {r.get('Severity')} {r.get('Type')}: "
                          f"{str(r.get('Target'))[:80]}")
                nfail += 1

        elif "only_types" in exp:
            # The allow-list form of the false-positive claim. A per-type cap only constrains
            # the types someone thought to name, and a severity budget only constrains the
            # total — a check added later that misfires on ordinary content satisfies both.
            # Here anything not declared is a failure, so a new detector proves itself against
            # a benign host before it can ship.
            want = exp["only_types"]
            allow = want.get("allow", {})
            recs = _findings_records(out_dir)
            counts = Counter(r.get("Type") for r in recs)
            undeclared = {t: n for t, n in counts.items() if t not in allow}
            over = {t: n for t, n in counts.items() if t in allow and n > allow[t]}
            if not undeclared and not over:
                print(f"PASS  {label} — {sum(counts.values())} findings, all declared")
                npass += 1
            else:
                print(f"FAIL  {label}")
                # An example of each, because the count says a check misfired and the
                # target says why — and the point of this expectation is that whoever
                # sees it decides whether to fix the check or declare the finding.
                for tag, group in (("UNDECLARED", undeclared), ("OVER CAP", over)):
                    for t, n in sorted(group.items(), key=lambda kv: -kv[1]):
                        eg = next(r for r in recs if r.get("Type") == t)
                        cap = f" (allowed {allow[t]})" if tag == "OVER CAP" else ""
                        print(f"        {tag:<10} {n:>3}  [{eg.get('Severity')}] {t}{cap}")
                        print(f"                        e.g. {str(eg.get('Target'))[:100]}")
                nfail += 1

        elif "adjudication" in exp:
            # Reads the adjudication record by field rather than grepping its JSON text.
            # PkgOwner/PkgModified are the trust anchor, and "the string appears somewhere in
            # the file" would pass on a record about a different binary entirely.
            want = exp["adjudication"]
            hits = [e for e in _adjudication_entries(out_dir)
                    if want["subject_contains"] in str(e.get("SubjectPath") or "")]
            if not hits:
                print(f"FAIL  {label} — no adjudication entry for "
                      f"{want['subject_contains']!r}")
                nfail += 1
            else:
                got = hits[0].get(want["field"])
                # `contains` exists because package identifiers are distro-shaped: `dpkg -S`
                # answers "coreutils", `rpm -qf` answers "coreutils-9.6-8.fc42.x86_64". Both
                # name the same package correctly, and an assertion that demanded one of them
                # would be testing the distro rather than the toolkit.
                if "contains" in want:
                    okval = want["contains"] in str(got or "")
                    expect = f"containing {want['contains']!r}"
                else:
                    okval = got == want["equals"]
                    expect = repr(want["equals"])
                if okval:
                    print(f"PASS  {label} — {want['field']}={got!r}")
                    npass += 1
                else:
                    print(f"FAIL  {label} — {want['field']}={got!r}, expected {expect}")
                    nfail += 1

        elif "finding_absent" in exp:
            # The negative claim. A detector that fires on everything satisfies every
            # positive assertion in this file, so at least one control has to prove it
            # discriminates rather than merely triggers.
            unwanted = exp["finding_absent"]
            if unwanted in findings:
                print(f"FAIL  {label} — a finding names {unwanted!r}, which should NOT be flagged")
                nfail += 1
            else:
                print(f"PASS  {label} — nothing flagged {unwanted!r}")
                npass += 1
        else:
            print(f"FAIL  {label} — malformed expectation")
            nfail += 1

    print(f"\n  {npass} passed, {nfail} failed, {nskip} skipped ({scen['name']})")
    return 1 if nfail else 0


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    cmd = sys.argv[1]
    if cmd == "plant":
        return cmd_plant(sys.argv[2])
    if cmd == "collect":
        return cmd_collect(sys.argv[2], sys.argv[3], sys.argv[4:])
    if cmd == "verify":
        return cmd_verify(sys.argv[2], sys.argv[3])
    print(f"unknown subcommand {cmd!r}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
