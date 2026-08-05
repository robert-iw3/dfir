"""
Ship web-tier access logs into a private object-storage bucket.

The web tier's own records — the ingress access log, the application server's access and error
logs — live in container filesystems, where losing the container loses the log and nothing can
review them centrally. This moves them into `ir-logs`, held apart from evidence and carved
regions and reachable only through the mesh.

Object storage rather than a log product: the store already exists, is backed up as a unit, has
a retention lifecycle the platform understands, and adds no egress path. An external monitor or
SIEM reads the bucket; it is never given a route to the ingress.

The runtime socket is deliberately not involved (SECURITY-MODEL P10). Traefik and nginx are
configured to write FILES, this reads those files from read-only mounts, and no container needs
the ability to inspect another.

Resumable by construction: a byte offset per source is kept in the bucket beside the objects, so
a restarted shipper neither re-uploads what it already sent nor skips what arrived meanwhile.
Truncation is detected (a file smaller than the offset) and reads restart from zero — which is
what a rotated file looks like from here.

  manage.py ship_logs              ship once and exit
  manage.py ship_logs --follow     ship on an interval, forever
"""
from __future__ import annotations

import json
import os
import socket
import time
from datetime import datetime, timezone
from pathlib import Path

from django.core.management.base import BaseCommand

from cases import storage

# Each source is a file this container can read and a name its objects are keyed under. The
# mounts are read-only: shipping must never be able to alter the record it is shipping.
SOURCES = {
    "traefik-access": "/logs/traefik/access.log",
    "frontend-access": "/logs/frontend/access.log",
    "frontend-error": "/logs/frontend/error.log",
}
OFFSETS_KEY = "_state/offsets.json"
INTERVAL = int(os.environ.get("IR_LOG_SHIP_INTERVAL", "60"))
# Bounded so one pass cannot try to hold an arbitrarily large file in memory; the remainder is
# picked up on the next pass, because the offset advances by what was actually shipped.
MAX_CHUNK = int(os.environ.get("IR_LOG_SHIP_MAX_BYTES", str(8 * 1024 * 1024)))
# Declared log record storage allocation (SRG-APP-000357-WSR-000150). Usage is reported
# against it, and Component Health warns at 75% (SRG-APP-000359-WSR-000065).
ALLOC_BYTES = int(os.environ.get("IR_LOGS_ALLOC_BYTES", str(10 * 1024 ** 3)))


def bucket_name() -> str:
    return os.environ.get("IR_LOGS_BUCKET", "ir-logs")


def ensure_bucket(s3):
    name = bucket_name()
    try:
        s3.head_bucket(Bucket=name)
    except Exception:
        try:
            s3.create_bucket(Bucket=name)
        except Exception as exc:
            # A failed HEAD does not prove absence — a probe during sidecar warm-up fails
            # while the bucket sits there owned. Creating what exists is success, not error.
            if "BucketAlreadyOwnedByYou" not in str(exc) and "BucketAlreadyExists" not in str(exc):
                raise
    return name


def read_offsets(s3, bucket) -> dict:
    try:
        return json.loads(s3.get_object(Bucket=bucket, Key=OFFSETS_KEY)["Body"].read())
    except Exception:
        # Absent on the first run, and unreadable is treated the same: start from zero rather
        # than skip. Duplicated lines are recoverable; a silent gap in an access log is not.
        return {}


def write_offsets(s3, bucket, offsets: dict):
    s3.put_object(Bucket=bucket, Key=OFFSETS_KEY,
                  Body=json.dumps(offsets, indent=1, sort_keys=True).encode(),
                  ContentType="application/json")


def log_storage() -> dict:
    """Bucket consumption against the declared allocation, for the health report."""
    s3 = storage.client()
    bucket = bucket_name()
    used, token = 0, None
    while True:
        kwargs = {"Bucket": bucket, "MaxKeys": 1000}
        if token:
            kwargs["ContinuationToken"] = token
        page = s3.list_objects_v2(**kwargs)
        used += sum(o["Size"] for o in page.get("Contents", []))
        if not page.get("IsTruncated"):
            break
        token = page.get("NextContinuationToken")
    return {"log_storage": {"used_bytes": used, "alloc_bytes": ALLOC_BYTES,
                            "bucket": bucket}}


def ship_once(stdout=None) -> int:
    s3 = storage.client()
    bucket = ensure_bucket(s3)
    offsets = read_offsets(s3, bucket)
    host = socket.gethostname()
    shipped = 0

    for name, path in SOURCES.items():
        p = Path(path)
        if not p.exists():
            continue
        size = p.stat().st_size
        start = int(offsets.get(name, 0))
        # Smaller than where we left off means the file was rotated or truncated under us, and
        # the bytes we were pointing at are gone. Reading from the old offset would return
        # nothing forever, so the source is followed back to the beginning.
        if size < start:
            start = 0
        if size <= start:
            continue

        with p.open("rb") as fh:
            fh.seek(start)
            data = fh.read(MAX_CHUNK)
        if not data:
            continue

        # Whole lines only: a chunk boundary in the middle of a record would split one log line
        # across two objects, and neither half parses.
        cut = data.rfind(b"\n")
        if cut == -1:
            continue
        data, consumed = data[:cut + 1], cut + 1

        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        day = datetime.now(timezone.utc).strftime("%Y/%m/%d")
        key = f"{name}/{day}/{host}-{stamp}-{start}.log"
        s3.put_object(Bucket=bucket, Key=key, Body=data, ContentType="text/plain")
        offsets[name] = start + consumed
        shipped += 1
        if stdout:
            stdout.write(f"[ship-logs] {name}: {consumed} bytes -> s3://{bucket}/{key}")

    if shipped:
        write_offsets(s3, bucket, offsets)
    return shipped


class Command(BaseCommand):
    help = "Ship web-tier access logs into the private ir-logs bucket."

    def add_arguments(self, parser):
        parser.add_argument("--follow", action="store_true",
                            help="ship on an interval instead of once")

    def handle(self, *args, **opts):
        if not opts.get("follow"):
            n = ship_once(self.stdout)
            self.stdout.write(f"[ship-logs] {n} object(s) shipped")
            return

        # The shipper reports itself the way the backend and workers do. Its row carries the
        # source mounts, bucket usage against the allocation, and any pass failures — which is
        # how a processing failure reaches the admin (SRG-APP-000108-WSR-000166).
        from cases import healthreporter

        self.stdout.write(f"[ship-logs] following {len(SOURCES)} source(s) every {INTERVAL}s "
                          f"-> s3://{bucket_name()}/")
        started = False
        while True:
            try:
                ship_once(self.stdout)
            except Exception as exc:  # noqa: BLE001
                # A shipper that exits on a transient store error stops collecting the records
                # that would explain the outage. It reports and retries instead, and the
                # failure rides the next health report as an alert.
                healthreporter.LOGS.error(f"ship pass failed: {exc}")
                self.stderr.write(f"[ship-logs] pass failed: {exc}")
            if not started:
                # After the first pass, never before it: the pass warms every lazy import the
                # reporter's thread also touches, and two threads first-importing that chain
                # concurrently deadlock — leaving the reporter silently absent.
                healthreporter.start(component="log-shipper", tier="web",
                                     paths=("/logs/traefik", "/logs/frontend"),
                                     extra=log_storage)
                started = True
            time.sleep(INTERVAL)
