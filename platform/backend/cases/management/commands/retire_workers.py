"""Retire Component Health rows for worker replicas a deployment no longer runs."""
from django.core.management.base import BaseCommand

from cases.models import ComponentHealth


class Command(BaseCommand):
    help = "Drop health rows for worker replicas above the declared replica count."

    def add_arguments(self, parser):
        parser.add_argument("replicas", type=int,
                            help="IR_WORKER_REPLICAS — workers this deployment runs, primary included")

    def handle(self, *args, **options):
        # A health row outlives the container it describes, so scaling down left rows that
        # read as live components gone silent. Decommissioning is an act of the deploy that
        # removed them, never a timeout — a worker that stops reporting is still an alarm.
        declared = max(1, options["replicas"])
        retired = []
        for row in ComponentHealth.objects.all():
            role = row.component.partition(" (")[0]
            if not role.startswith("worker-"):
                continue
            suffix = role.split("-", 1)[1]
            if suffix.isdigit() and int(suffix) > declared:
                retired.append(row.component)
                row.delete()
        if retired:
            self.stdout.write(f"retired {len(retired)} health row(s): {', '.join(sorted(retired))}")
