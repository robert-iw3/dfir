"""Promote memory-analysis hits into adjudicable findings.

Runs automatically when an analysis completes. This command exists for analyses that
finished before promotion was wired in, and for re-promoting after a re-analysis.
"""
from django.core.management.base import BaseCommand

from cases import promotion
from cases.models import MemoryAnalysisRun


class Command(BaseCommand):
    help = "Create findings from memory-analysis results so they can be triaged."

    def add_arguments(self, parser):
        parser.add_argument("--analysis", type=int, default=None,
                            help="one analysis run; default is every completed run")

    def handle(self, *args, **opts):
        qs = MemoryAnalysisRun.objects.filter(status="completed")
        if opts["analysis"]:
            qs = qs.filter(id=opts["analysis"])

        total = 0
        for run in qs:
            n = promotion.promote_memory_findings(run)
            if n:
                self.stdout.write(
                    f"analysis {run.id} ({run.engine}) -> promoted {n} finding(s)")
            total += n
        self.stdout.write(f"{total} finding(s) promoted")
