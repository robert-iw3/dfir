"""Run the toolkit's investigation engine over a completed analysis.

Adjudication runs automatically when an analysis finishes, on the analyzer's own report
folder. This command re-runs it from stored evidence instead, which is what you want when:

  * the analysis completed before adjudication was wired in;
  * the collector bundle for the host arrived after the memory pass, so the engine can now
    see the provenance signals it weighs most heavily;
  * the engine itself has been updated and the same evidence should be re-judged.

It does not re-run Volatility. The findings are already stored; only the verdict changes.
"""
from django.core.management.base import BaseCommand

from cases import investigation
from cases.models import MemoryAnalysisRun


class Command(BaseCommand):
    help = "Re-run the investigation engine over completed analyses."

    def add_arguments(self, parser):
        parser.add_argument("--analysis", type=int, default=None,
                            help="one analysis run; default is every completed run")
        parser.add_argument("--host", default=None, help="limit to a hostname")
        parser.add_argument("--only-unadjudicated", action="store_true",
                            help="skip analyses that already have engine verdicts")
        parser.add_argument("--timeout", type=int, default=1800)

    def handle(self, *args, **opts):
        if not investigation.available():
            raise SystemExit(
                "the investigation engine is not in this image — run this in the worker, "
                "which is the only tier that carries the toolkit"
            )

        qs = MemoryAnalysisRun.objects.filter(status="completed").select_related(
            "capture__run__host"
        )
        if opts["analysis"]:
            qs = qs.filter(id=opts["analysis"])
        if opts["host"]:
            qs = qs.filter(capture__run__host__hostname=opts["host"])
        if opts["only_unadjudicated"]:
            qs = qs.filter(investigation={})

        adjudicated = 0
        for run in qs:
            host = run.capture.run.host.hostname
            # No report folder: adjudicate() rebuilds one from the stored findings.
            result = investigation.adjudicate(run, timeout=opts["timeout"])
            if result.get("ran"):
                adjudicated += 1
                self.stdout.write(
                    f"analysis {run.id} ({host}): {result.get('pids', 0)} processes — "
                    f"TP={result.get('true_positive', 0)} "
                    f"undetermined={result.get('undetermined', 0)} "
                    f"noise={result.get('noise_closed', 0)}, "
                    f"{result.get('findings_updated', 0)} findings updated"
                )
            else:
                self.stdout.write(f"analysis {run.id} ({host}): skipped — {result.get('reason')}")

        self.stdout.write(self.style.SUCCESS(f"adjudicated {adjudicated} analysis run(s)"))
