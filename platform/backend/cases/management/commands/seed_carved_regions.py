"""Load binaries into a host's carved-region bucket as if a YARA pass had carved them.

WHAT THIS IS FOR. Producing real carved regions means running a full memory analysis over a
capture the size of a host's RAM, which takes hours. That is the right test for the *analyzer*
and the wrong one for everything downstream of it: the object-store layout, the staging step,
the per-host bucket boundary and the reverse-engineering session all need exercising far more
often than a multi-hour scan can support, and a bug in any of them is indistinguishable from a
bug in the scan when the only way to reach them is through it.

So this puts known bytes into the same buckets, under the same keys, with the same database
rows the analyzer would have written. Everything downstream then runs against real objects and
real records, and a failure is attributable to the component under test rather than to the
hours of scanning that preceded it.

IT IS NOT A SUBSTITUTE FOR THE ANALYZER. Nothing here decides what is worth carving — the
regions are named as suspicious because they were chosen to be. A run seeded this way proves
that regions can be stored, staged, bounded by host and opened; it proves nothing about whether
the analyzer would have found them.

The same path serves REPLAY: evidence archived from a closed investigation can be put back into
the pipeline for re-examination without re-running the collection that produced it.

    python manage.py seed_carved_regions --host ubuntu-main \\
        --source /labs/samples --incident INC-2026-0043
"""
import hashlib
import os
import random

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from cases import storage
from cases.models import (CarvedRegion, CollectionRun, Host, Investigation,
                          MemoryAnalysisRun, MemoryCapture)


class Command(BaseCommand):
    help = "Load binaries into a host's carved-region bucket as simulated carved regions."

    def add_arguments(self, parser):
        parser.add_argument("--host", required=True,
                            help="Host the regions belong to; selects the bucket.")
        parser.add_argument("--source", required=True,
                            help="Directory of files to load (searched recursively).")
        parser.add_argument("--incident", default="INC-SIMULATED",
                            help="Incident to file the run under.")
        parser.add_argument("--limit", type=int, default=0,
                            help="Load at most this many files (0 = all).")
        parser.add_argument("--pattern", default=".bin",
                            help="Filename suffix to load (default .bin).")

    def handle(self, *args, **opts):
        source = opts["source"]
        if not os.path.isdir(source):
            raise CommandError(f"--source {source} is not a directory")

        # isfile() follows symlinks, so a dangling link — routine in a system bin directory,
        # which is a natural --source for simulated regions — is excluded here rather than
        # crashing the load at open().
        files = sorted(
            path
            for root, _dirs, names in os.walk(source)
            for name in names
            if name.endswith(opts["pattern"])
            and os.path.isfile(path := os.path.join(root, name))
        )
        if opts["limit"]:
            files = files[: opts["limit"]]
        if not files:
            raise CommandError(f"no {opts['pattern']} files under {source}")

        hostname = opts["host"]
        host, _ = Host.objects.get_or_create(hostname=hostname)
        # An investigation is keyed by incident and carries no host of its own — hosts reach it
        # through their collection runs, because one incident routinely spans many machines.
        investigation, _ = Investigation.objects.get_or_create(
            incident_id=opts["incident"],
            defaults={"name": f"{opts['incident']} (seeded regions)"},
        )
        # get_or_create throughout: the addresses below are already deterministic so a rerun
        # is the SAME seed, and the (investigation, host, stamp) uniqueness constraint makes a
        # second create an IntegrityError — a rerun after an aborted load could otherwise
        # never finish the job it started.
        run, _ = CollectionRun.objects.get_or_create(
            host=host, investigation=investigation, stamp="",
            defaults=dict(
                collected_at=timezone.now(),
                overall_status="COMPLETED",
                # Marked as simulated in the record itself, in the two places a reader looks. A
                # seeded run must never be mistaken for a real collection by someone reviewing
                # this investigation months later, when the only evidence of its origin is the
                # database.
                toolkit_version="simulated/seed_carved_regions",
                status_json={"simulated": True,
                             "note": "regions seeded for pipeline validation, not collected"},
            ),
        )
        capture, _ = MemoryCapture.objects.get_or_create(
            run=run,
            object_key=f"{opts['incident']}/{hostname}/simulated-capture",
            defaults=dict(
                size_bytes=0,
                # The field the platform already uses to keep synthetic material from being
                # read as evidence. Setting it is what stops this run being reported as a real
                # capture.
                is_synthetic=True,
                capture_tool="simulated",
            ),
        )
        # `investigation` on this model is the analysis engine's NARRATIVE output — attack
        # chains and named findings — not a link to the Investigation row, despite the shared
        # name. Left empty: nothing here analyzed anything, and inventing a narrative would put
        # conclusions in the record that no engine reached.
        analysis, _ = MemoryAnalysisRun.objects.get_or_create(
            capture=capture, engine="simulated",
            defaults=dict(
                status="completed",
                started_at=timezone.now(), finished_at=timezone.now(),
                summary={"simulated": True,
                         "note": "regions seeded for pipeline validation; no analysis was performed"},
            ),
        )

        bucket = storage.ensure_carved_bucket(hostname)
        # Deterministic, so a rerun produces the same addresses and a diff between two runs
        # reflects the inputs rather than the seeding.
        rng = random.Random(f"{hostname}:{opts['incident']}")

        created = 0
        for path in files:
            with open(path, "rb") as fh:
                payload = fh.read()
            sha = hashlib.sha256(payload).hexdigest()
            stem = os.path.splitext(os.path.basename(path))[0]
            pid = rng.randint(300, 65000)
            # A plausible userspace mapping address, page-aligned. The reverse-engineering
            # session imports each region AT this address, so pointers inside it resolve to
            # each other instead of to file offsets — the filename is the only place that
            # address survives the trip through the object store.
            base = (rng.randrange(0x5000_0000, 0x7FFF_0000) // 0x1000) * 0x1000
            key = f"pid{pid}_{stem}_0x{base:x}.bin"

            storage.put_carved_region(hostname, path, key)
            CarvedRegion.objects.get_or_create(
                analysis=analysis,
                object_key=key,
                defaults=dict(
                    bucket=bucket,
                    size_bytes=len(payload),
                    sha256=sha,
                    carved_by="simulated",
                    trigger={
                        "simulated": True,
                        "source_file": os.path.relpath(path, source),
                        # Recorded because a reverse engineer reads this to know what to look
                        # for, and an empty trigger is how a region becomes two megabytes of
                        # unexplained heap with no stated reason for suspicion.
                        "note": "seeded for pipeline validation; not the product of a YARA pass",
                        "permissions": "rwx",
                    },
                    source_pid=pid,
                    source_process=stem[:64],
                    triage_status="unanalyzed",
                ),
            )
            created += 1

        self.stdout.write(self.style.SUCCESS(
            f"seeded {created} region(s) into bucket {bucket} "
            f"(host={hostname}, analysis={analysis.id})"))
        self.stdout.write(
            f"stage them with:  ./re-workstation/stage_regions.sh --host {hostname}")
