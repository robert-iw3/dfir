"""Close out analysis runs whose worker died.

A run is marked `running` before the work starts and only updated when it finishes. If the
worker is killed — OOM, a restart, a container recreate — the row is left claiming to be in
progress forever. That is worse than a failure: the UI shows work apparently underway, the
queue depth is wrong, and nobody is told the capture was never analyzed.

Run periodically, or after a worker restart.
"""
from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from cases.models import MemoryAnalysisRun


class Command(BaseCommand):
    help = "Fail analysis runs that have been 'running' longer than any real analysis takes."

    def add_arguments(self, parser):
        parser.add_argument(
            "--older-than-hours", type=float, default=6,
            help="A full pass over a large capture is slow, so the default is generous; "
                 "anything beyond it has lost its worker.")
        parser.add_argument("--dry-run", action="store_true")

    def handle(self, *args, **opts):
        cutoff = timezone.now() - timedelta(hours=opts["older_than_hours"])
        stale = MemoryAnalysisRun.objects.filter(status="running").filter(
            started_at__lt=cutoff
        ) | MemoryAnalysisRun.objects.filter(status="running", started_at__isnull=True,
                                             created_at__lt=cutoff)

        count = stale.count()
        if not count:
            self.stdout.write("no stale analysis runs")
            return
        for run in stale:
            self.stdout.write(
                f"{'would fail' if opts['dry_run'] else 'failing'} run {run.id} "
                f"(capture {run.capture_id}, started {run.started_at or run.created_at})")
        if not opts["dry_run"]:
            stale.update(
                status="failed",
                finished_at=timezone.now(),
                error="worker did not complete this run — marked failed by reap_stale_analyses",
            )
        self.stdout.write(f"{count} run(s) {'would be' if opts['dry_run'] else ''} closed out")
