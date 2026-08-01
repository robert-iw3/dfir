"""
Resource and environment statistics a component reports about itself.

Every component in this platform runs in a container, and the numbers that matter to an
admin are the ones that predict a failure rather than describe one that already happened: a
holding volume with less room than the next capture needs, a worker whose cgroup limit is
lower than the image it is about to map, a link dropping frames under a multi-gigabyte
transfer. Those are visible from inside a container; a probe from outside sees only that the
service still answers.

Self-reported, because a container's real limits are not observable from elsewhere. The
cgroup memory ceiling is not the host's RAM, the filesystem a component writes to is not the
one another component sees, and a bind-mounted volume's free space depends on where it came
from. Each component reads its own and says so.

Stdlib only: this is imported by the DMZ receiver, which deliberately carries no dependencies.
"""
from __future__ import annotations

import os
import shutil
import socket
import time

_STARTED = time.time()

# /proc and /sys are the interfaces every one of these figures comes from. Reading them
# defensively throughout: a container runtime may hide any of them, and a missing statistic
# must degrade the report rather than fail it.


def _read(path, default=""):
    try:
        with open(path) as fh:
            return fh.read().strip()
    except OSError:
        return default


def _read_int(path, default=None):
    raw = _read(path)
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


def disk(paths):
    """Free/total for each path that exists, keyed by path.

    Paths are passed in by the caller because the volume that matters differs per component:
    the receiver's holding area, the worker's scratch space, the object store's data
    directory. A component reports the filesystem it will actually run out of.
    """
    out = {}
    for p in paths:
        if not p or not os.path.exists(p):
            continue
        try:
            usage = shutil.disk_usage(p)
        except OSError:
            continue
        out[p] = {
            "total_bytes": usage.total,
            "used_bytes": usage.used,
            "free_bytes": usage.free,
            "percent_used": round(usage.used * 100.0 / usage.total, 1) if usage.total else None,
        }
    return out


def memory():
    """Host-visible memory, plus the cgroup ceiling this container is actually held to.

    A container sees the host's MemTotal through /proc/meminfo whether or not it may use it,
    so the cgroup limit is the number that predicts an OOM kill.
    """
    out = {}
    info = {}
    for line in _read("/proc/meminfo").splitlines():
        name, _, rest = line.partition(":")
        parts = rest.split()
        if parts and parts[0].isdigit():
            info[name] = int(parts[0]) * 1024        # kB -> bytes
    if info:
        total = info.get("MemTotal")
        available = info.get("MemAvailable")
        out.update({
            "host_total_bytes": total,
            "host_available_bytes": available,
            "host_percent_used": (round((total - available) * 100.0 / total, 1)
                                  if total and available is not None else None),
            "swap_total_bytes": info.get("SwapTotal"),
            "swap_free_bytes": info.get("SwapFree"),
        })

    # cgroup v2 first, then v1. "max" means unlimited, which is not a number to compare against.
    limit = _read("/sys/fs/cgroup/memory.max") or _read("/sys/fs/cgroup/memory/memory.limit_in_bytes")
    current = (_read_int("/sys/fs/cgroup/memory.current")
               or _read_int("/sys/fs/cgroup/memory/memory.usage_in_bytes"))
    if limit and limit != "max":
        try:
            limit_bytes = int(limit)
            # cgroup v1 reports a sentinel near 2^63 for "no limit".
            if limit_bytes < (1 << 62):
                out["cgroup_limit_bytes"] = limit_bytes
                if current:
                    out["cgroup_used_bytes"] = current
                    out["cgroup_percent_used"] = round(current * 100.0 / limit_bytes, 1)
        except ValueError:
            pass
    elif current:
        out["cgroup_used_bytes"] = current
    return out


def cpu():
    out = {"count": os.cpu_count()}
    try:
        one, five, fifteen = os.getloadavg()
        out.update({"load_1m": round(one, 2), "load_5m": round(five, 2),
                    "load_15m": round(fifteen, 2)})
        if out["count"]:
            # Load relative to available CPUs is the comparable figure across components
            # sized differently.
            out["load_per_cpu"] = round(one / out["count"], 2)
    except OSError:
        pass
    quota = _read("/sys/fs/cgroup/cpu.max")
    if quota and quota != "max":
        parts = quota.split()
        if len(parts) == 2 and parts[0] != "max":
            try:
                out["cgroup_cpu_limit"] = round(int(parts[0]) / int(parts[1]), 2)
            except (ValueError, ZeroDivisionError):
                pass
    return out


def network():
    """Per-interface counters, and the error/drop figures that explain a stalled transfer.

    Byte counts are cumulative since boot; an admin reads them as deltas between reports.
    Errors and drops are what matter on their own — a multi-gigabyte capture moving across a
    link that is dropping frames retransmits rather than fails, and shows up as a transfer
    that never finishes rather than one that errors.
    """
    out = {}
    for line in _read("/proc/net/dev").splitlines()[2:]:
        name, _, rest = line.partition(":")
        name = name.strip()
        fields = rest.split()
        if name == "lo" or len(fields) < 12:
            continue
        out[name] = {
            "rx_bytes": int(fields[0]), "rx_errors": int(fields[2]), "rx_dropped": int(fields[3]),
            "tx_bytes": int(fields[8]), "tx_errors": int(fields[10]), "tx_dropped": int(fields[11]),
        }
    return out


def process():
    """This container's own footprint: how many processes it runs and against what ceiling."""
    out = {"pid": os.getpid(), "uptime_seconds": int(time.time() - _STARTED)}
    current = _read_int("/sys/fs/cgroup/pids.current")
    limit = _read("/sys/fs/cgroup/pids.max")
    if current is not None:
        out["pids_current"] = current
    if limit and limit != "max":
        try:
            out["pids_max"] = int(limit)
        except ValueError:
            pass
    fd_dir = f"/proc/{os.getpid()}/fd"
    try:
        out["open_fds"] = len(os.listdir(fd_dir))
    except OSError:
        pass
    return out


class LogCounter:
    """Counts warnings and errors a component has emitted.

    A component knows its own failures precisely; reading them back out of a container log
    stream requires access to the runtime that an enclave service does not have and should
    not be given. Counting in-process keeps the figure accurate and the boundary intact.

    Both a running total and the count since the previous report are kept: the total says how
    bad things have been, and the delta says whether they are still going wrong now.
    """

    def __init__(self):
        self.warnings = 0
        self.errors = 0
        self._last_warnings = 0
        self._last_errors = 0
        self.last_error = ""
        self.last_error_at = None

    def warn(self, message=""):
        self.warnings += 1

    def error(self, message=""):
        self.errors += 1
        if message:
            self.last_error = str(message)[:300]
            self.last_error_at = time.time()

    def snapshot(self):
        since_warn = self.warnings - self._last_warnings
        since_err = self.errors - self._last_errors
        self._last_warnings, self._last_errors = self.warnings, self.errors
        out = {
            "warnings_total": self.warnings, "errors_total": self.errors,
            "warnings_since_last_report": since_warn,
            "errors_since_last_report": since_err,
        }
        if self.last_error:
            out["last_error"] = self.last_error
            out["last_error_at"] = self.last_error_at
        return out


def collect(component, tier="", disk_paths=(), log_counter=None, extra=None):
    """One component's full self-report."""
    report = {
        "component": component,
        "tier": tier,
        "hostname": socket.gethostname(),
        "collected_at": time.time(),
        "disk": disk(disk_paths),
        "memory": memory(),
        "cpu": cpu(),
        "network": network(),
        "process": process(),
    }
    if log_counter is not None:
        report["logs"] = log_counter.snapshot()
    if extra:
        report["extra"] = extra
    return report
