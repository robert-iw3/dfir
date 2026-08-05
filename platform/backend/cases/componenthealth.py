"""
Component self-reports, and the thresholds that turn them into something actionable.

`opsmetrics` answers "is each service up", which is the question asked after something has
already failed. This answers "will the next collection succeed", which is the one worth
asking beforehand. A memory capture is sized by the endpoint's RAM, so the figure that
matters is not how full a volume is but whether what is coming will fit on it.

Reports arrive on an interval, so an admin's warning time is the gap between two of them.
That makes a reporter that has gone quiet as important to surface as one reporting a
problem: a stale row is not a healthy one.
"""
from __future__ import annotations

import datetime
import time

from django.utils import timezone

from .models import ComponentHealth, MemoryCapture

# Reporters send every 15 minutes. Two missed intervals is a reporter that stopped rather
# than one that was briefly busy.
REPORT_INTERVAL_SECONDS = 15 * 60
STALE_AFTER_SECONDS = REPORT_INTERVAL_SECONDS * 2

# Two kinds of reporter, with different meanings when they go quiet.
#
# A worker is instance-scoped: it reports under its container hostname, which changes every
# time one is replaced, and scaling analysis out means they come and go by design. A row for a
# worker that no longer exists warns about nothing, and left alone they accumulate until the
# page is mostly departed workers and a genuinely stuck one is lost among them. Pruned once it
# has missed enough intervals to be gone rather than busy.
#
# The backend, puller and receiver are role-scoped: one of each, named for the job rather than
# the container. One of those going quiet IS the incident, so its row is kept however old it
# gets — disappearing would turn an outage into an absence nobody notices.
INSTANCE_PRUNE_AFTER_SECONDS = REPORT_INTERVAL_SECONDS * 4
INSTANCE_PREFIXES = ("worker (",)

# A volume with less headroom than this cannot take another capture from a mid-sized host,
# whatever its percentage says. Percentages hide the thing that matters: 5% of 20 TB is
# plenty and 5% of 100 GB is not.
DISK_FREE_WARN_BYTES = 50 * 1024 ** 3
DISK_FREE_CRITICAL_BYTES = 10 * 1024 ** 3
DISK_PERCENT_WARN = 85.0
DISK_PERCENT_CRITICAL = 95.0

MEMORY_PERCENT_WARN = 85.0
MEMORY_PERCENT_CRITICAL = 95.0
PIDS_PERCENT_WARN = 80.0
LOAD_PER_CPU_WARN = 2.0

# Log record storage warns at 75% of its declared allocation (SRG-APP-000359-WSR-000065)
# and goes critical where the disk thresholds do.
LOG_STORAGE_PERCENT_WARN = 75.0
LOG_STORAGE_PERCENT_CRITICAL = 95.0


def _declarations():
    """What each collected endpoint said its next collection will need.

    Declared by the collector from the endpoint's RAM, before the capture runs, and carried
    inward with the bundle. The endpoint is never told whether it fits — that comparison
    happens here, where the free space is known and the answer stays inside.
    """
    from .models import Host

    out = []
    for host in Host.objects.all():
        d = (host.clock_context or {}).get("capacity_declaration") or {}
        if not d.get("expected_raw_bytes"):
            continue
        out.append({
            "hostname": host.hostname,
            "host_ram_bytes": d.get("host_ram_bytes", 0),
            "expected_raw_bytes": d.get("expected_raw_bytes", 0),
            "expected_bundle_bytes": d.get("expected_bundle_bytes", 0),
            "requires": d.get("requires", {}),
        })
    return sorted(out, key=lambda r: -r["expected_raw_bytes"])


def _declaration_alerts(declarations, components):
    """Compare the largest declared requirement against what each hop actually has free.

    This is the whole point of declaring up front: the shortfall is nameable before the
    transfer starts, and it names which volume to expand rather than only that something
    was too small.
    """
    if not declarations:
        return []
    worst = declarations[0]
    alerts = []
    for row in components:
        free = min((d.get("free_bytes", 0) for d in (row.get("disk") or {}).values()),
                   default=None)
        if free is None:
            continue
        # The receiver holds the compressed bundle; everything inward handles the image.
        needed = (worst["expected_bundle_bytes"] if row["tier"] == "dmz"
                  else worst["expected_raw_bytes"])
        if needed and free < needed:
            alerts.append({
                "level": "warning", "kind": "declared-capacity", "component": row["component"],
                "message": (f"{worst['hostname']} declared it needs {_gib(needed)}; "
                            f"{row['component']} has {_gib(free)} free"),
                "action": (f"expand {row['component']}'s volume before collecting from "
                           f"{worst['hostname']} again"),
            })
    return alerts


def _largest_capture_bytes():
    """The biggest capture handled so far, as a stand-in for what the next one will need.

    Better than a constant: an estimate drawn from this deployment's own history tracks the
    hardware it actually collects from.
    """
    sizes = MemoryCapture.objects.filter(is_synthetic=False).values_list("size_bytes", flat=True)
    return max(sizes, default=0)


def _disk_alerts(component, disk_metrics, expected_capture_bytes):
    alerts = []
    for path, d in (disk_metrics or {}).items():
        free = d.get("free_bytes") or 0
        pct = d.get("percent_used")
        if free < DISK_FREE_CRITICAL_BYTES or (pct is not None and pct >= DISK_PERCENT_CRITICAL):
            level = "critical"
        elif free < DISK_FREE_WARN_BYTES or (pct is not None and pct >= DISK_PERCENT_WARN):
            level = "warning"
        else:
            level = None
        if level:
            alerts.append({
                "level": level, "kind": "disk", "component": component, "path": path,
                "message": (f"{path} has {_gib(free)} free"
                            + (f" ({pct}% used)" if pct is not None else "")),
                "action": f"expand the volume backing {path} on {component}",
            })
        # Independent of how full it is: can the next capture actually land here?
        if expected_capture_bytes and free < expected_capture_bytes:
            alerts.append({
                "level": "warning", "kind": "capacity", "component": component, "path": path,
                "message": (f"{path} has {_gib(free)} free; the largest capture handled here "
                            f"was {_gib(expected_capture_bytes)}"),
                "action": (f"expand {path} on {component} before the next collection from a "
                           f"host of that size"),
            })
    return alerts


def _log_storage_alerts(component, metrics):
    """Warnings on log record storage, measured against its declared allocation.

    The figure is bucket consumption, not disk fullness: log records live in the object
    store, whose volume also holds evidence, so a percentage of the disk says nothing
    about the logs' share of it. The reporter declares an allocation and reports usage;
    the warning fires at 75% of that allocation."""
    ls = (metrics.get("extra") or {}).get("log_storage") or {}
    used, alloc = ls.get("used_bytes") or 0, ls.get("alloc_bytes") or 0
    if not alloc:
        return []
    pct = used * 100.0 / alloc
    if pct >= LOG_STORAGE_PERCENT_CRITICAL:
        level = "critical"
    elif pct >= LOG_STORAGE_PERCENT_WARN:
        level = "warning"
    else:
        return []
    return [{
        "level": level, "kind": "log-storage", "component": component,
        "message": (f"log record storage at {pct:.0f}% of its {_gib(alloc)} allocation "
                    f"({_gib(used)} used)"),
        "action": ("raise IR_LOGS_ALLOC_BYTES or expire aged objects from the "
                   "log bucket before records are refused"),
    }]


def _gib(n):
    if not n:
        return "0 GiB"
    return f"{n / 1024 ** 3:.1f} GiB"


def _resource_alerts(component, metrics):
    alerts = []
    mem = metrics.get("memory") or {}
    pct = mem.get("cgroup_percent_used")
    if pct is not None:
        if pct >= MEMORY_PERCENT_CRITICAL:
            alerts.append({"level": "critical", "kind": "memory", "component": component,
                           "message": f"at {pct}% of its container memory limit",
                           "action": f"raise the memory limit for {component}"})
        elif pct >= MEMORY_PERCENT_WARN:
            alerts.append({"level": "warning", "kind": "memory", "component": component,
                           "message": f"at {pct}% of its container memory limit",
                           "action": f"raise the memory limit for {component}"})

    proc = metrics.get("process") or {}
    cur, mx = proc.get("pids_current"), proc.get("pids_max")
    if cur and mx and (cur * 100.0 / mx) >= PIDS_PERCENT_WARN:
        alerts.append({"level": "warning", "kind": "pids", "component": component,
                       "message": f"{cur} of {mx} permitted processes in use",
                       "action": f"raise the pids limit for {component}"})

    cpu = metrics.get("cpu") or {}
    if (cpu.get("load_per_cpu") or 0) >= LOAD_PER_CPU_WARN:
        alerts.append({"level": "warning", "kind": "cpu", "component": component,
                       "message": f"load {cpu['load_1m']} across {cpu.get('count')} CPUs",
                       "action": f"give {component} more CPU, or reduce concurrent analyses"})

    for iface, n in (metrics.get("network") or {}).items():
        bad = (n.get("rx_errors", 0) + n.get("tx_errors", 0)
               + n.get("rx_dropped", 0) + n.get("tx_dropped", 0))
        if bad:
            alerts.append({
                "level": "warning", "kind": "network", "component": component,
                "message": (f"{iface}: {n.get('rx_errors',0)}/{n.get('tx_errors',0)} rx/tx "
                            f"errors, {n.get('rx_dropped',0)}/{n.get('tx_dropped',0)} dropped"),
                "action": ("check the link — a capture-sized transfer stalls rather than "
                           "fails when frames are dropped"),
            })

    logs = metrics.get("logs") or {}
    if logs.get("errors_since_last_report"):
        alerts.append({
            "level": "warning", "kind": "logs", "component": component,
            "message": (f"{logs['errors_since_last_report']} error(s) since the last report"
                        + (f": {logs['last_error']}" if logs.get("last_error") else "")),
            "action": f"read {component}'s logs",
        })
    return alerts


def report_component(component, tier, metrics, note=""):
    """Record one component's self-report, replacing whatever it said last."""
    # A reporter stamps its own collection time, so the age shown is the age of the reading
    # rather than of the write. Falls back to now() when a report arrives without one.
    reported = metrics.get("collected_at")
    when = (datetime.datetime.fromtimestamp(reported, tz=datetime.timezone.utc)
            if reported else timezone.now())
    obj, _ = ComponentHealth.objects.update_or_create(
        component=component,
        defaults={"tier": tier or "", "reported_at": when, "metrics": metrics,
                  "note": note or ""},
    )
    return obj


def overview():
    """Every reporting component, its figures, and what an admin should do about them."""
    expected = _largest_capture_bytes()
    now = time.time()
    rows, alerts = [], []

    cutoff = timezone.now() - datetime.timedelta(seconds=INSTANCE_PRUNE_AFTER_SECONDS)
    for prefix in INSTANCE_PREFIXES:
        ComponentHealth.objects.filter(
            component__startswith=prefix, reported_at__lt=cutoff).delete()

    for ch in ComponentHealth.objects.all():
        age = now - ch.reported_at.timestamp()
        stale = age > STALE_AFTER_SECONDS
        metrics = ch.metrics or {}
        row = {
            "component": ch.component,
            "tier": ch.tier,
            "reported_at": ch.reported_at.isoformat(),
            "age_seconds": int(age),
            "stale": stale,
            "note": ch.note,
            "disk": metrics.get("disk", {}),
            "memory": metrics.get("memory", {}),
            "cpu": metrics.get("cpu", {}),
            "network": metrics.get("network", {}),
            "process": metrics.get("process", {}),
            "logs": metrics.get("logs", {}),
            "log_storage": (metrics.get("extra") or {}).get("log_storage", {}),
        }
        if stale:
            row_alerts = [{
                "level": "warning", "kind": "stale", "component": ch.component,
                "message": (f"last reported {int(age // 60)} minutes ago; reports are due "
                            f"every {REPORT_INTERVAL_SECONDS // 60}"),
                "action": f"check whether {ch.component} is running",
            }]
        else:
            row_alerts = (_disk_alerts(ch.component, metrics.get("disk"), expected)
                          + _resource_alerts(ch.component, metrics)
                          + _log_storage_alerts(ch.component, metrics))
        row["alerts"] = row_alerts
        alerts.extend(row_alerts)
        rows.append(row)

    declarations = _declarations()
    alerts.extend(_declaration_alerts(declarations, rows))

    order = {"critical": 0, "warning": 1}
    alerts.sort(key=lambda a: order.get(a["level"], 2))
    return {
        "components": rows,
        "alerts": alerts,
        "declarations": declarations,
        "expected_capture_bytes": expected,
        "report_interval_seconds": REPORT_INTERVAL_SECONDS,
        "worst_level": alerts[0]["level"] if alerts else "ok",
    }
