"""Periodic self-reporting for the components that share this codebase.

The backend and the analysis workers hold a database connection already, so they record
their own reports directly rather than posting to an API. The DMZ receiver and the puller
cannot — they reach the platform over HTTP, and the receiver only via the puller.

A thread rather than a scheduled task: adding a beat service would mean another container
to run and supervise for one periodic write, and a beat lock shared across workers would
report one worker's resources as if they were all of them. Each process reports itself,
keyed by its own hostname, so scaling to parallel workers gives one row per worker with no
further wiring.
"""
from __future__ import annotations

import os
import socket
import threading

import sysstats

REPORT_INTERVAL = int(os.environ.get("IR_HEALTH_REPORT_INTERVAL", "900"))

# Counted in-process and reported as a delta. What an admin wants from a log figure is
# whether something is going wrong *now*, which a running total cannot say.
LOGS = sysstats.LogCounter()

_started = False
_lock = threading.Lock()


def _worker_paths():
    """Filesystems an analysis worker can actually exhaust.

    Scratch holds the decompressed capture during analysis, which is the largest single
    thing this platform writes; the symbol store grows with every kernel it has to support.
    """
    return tuple(p for p in (
        os.environ.get("IR_SCRATCH_DIR", "/scratch"),
        os.environ.get("IR_SYMBOLS_DIR", "/symbols"),
        "/tmp",
    ) if p)


def _collect(component, tier, paths, extra=None):
    return sysstats.collect(component, tier=tier, disk_paths=paths,
                            log_counter=LOGS, extra=extra)


def _schema_not_ready(exc):
    """True when the failure is 'the table is not there yet' rather than a real fault.

    Matched on the database's own error class, not on message text: Postgres reports a missing
    relation as UndefinedTable, and matching the wording would break under a different locale or
    a version that rephrases it.
    """
    try:
        from django.db.utils import ProgrammingError, OperationalError
    except Exception:                                 # noqa: BLE001
        return False
    if not isinstance(exc, (ProgrammingError, OperationalError)):
        return False
    # psycopg exposes the SQLSTATE; 42P01 is undefined_table.
    code = getattr(getattr(exc, "__cause__", None), "sqlstate", None) \
        or getattr(getattr(exc, "__cause__", None), "pgcode", None)
    return code == "42P01"


def report_once(component, tier, paths, extra=None):
    """Write one report. Imported lazily so this module stays importable without Django."""
    from . import componenthealth

    metrics = _collect(component, tier, paths, extra)
    componenthealth.report_component(component, tier, metrics)
    return metrics


def _loop(component, tier, paths):
    from django.db import connections

    while True:
        try:
            report_once(component, tier, paths)
        except Exception as exc:                      # noqa: BLE001
            # A missing table means migrations have not finished yet. The worker starts beside
            # the backend that applies them, so the first report can legitimately land before
            # the schema exists — and reporting that as an error surfaces a failure on every
            # cold start, which teaches operators that this component's error channel is noise
            # and hides the reports that do matter. Wait for the schema instead; anything else
            # is still an error.
            if _schema_not_ready(exc):
                LOGS.info("health schema not migrated yet — deferring the first report")
            else:
                LOGS.error(f"health report failed: {exc}")
        finally:
            # A long-lived thread that reports every 15 minutes would otherwise hold an idle
            # connection open between writes, and a database restart would leave it broken.
            try:
                connections.close_all()
            except Exception:                         # noqa: BLE001
                pass
        threading.Event().wait(REPORT_INTERVAL)


def start(component=None, tier="application", paths=None):
    """Begin reporting in the background. Safe to call more than once."""
    global _started
    with _lock:
        if _started:
            return
        _started = True
    name = component or f"worker ({socket.gethostname()})"
    thread = threading.Thread(
        target=_loop, args=(name, tier, tuple(paths) if paths else _worker_paths()),
        name="component-health", daemon=True)
    thread.start()
    return thread
