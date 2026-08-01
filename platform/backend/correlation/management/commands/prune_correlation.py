"""Remove correlation belonging to investigations that no longer exist.

The correlation store is a separate database and records `investigation_id` as a plain
integer — there is no cross-database foreign key to cascade. A deleted investigation
therefore leaves its campaigns behind, and PostgreSQL reuses the id, so the next
investigation created inherits them and is shown another incident's hosts.

Deletion now prunes as it goes. This command clears what accumulated before that, and is
worth running after any bulk re-seed.

Correlation is derived and rebuildable: nothing removed here is evidence.
"""
from django.core.management.base import BaseCommand

from cases.models import Investigation
from correlation.models import (
    Campaign, CampaignEdge, CampaignHost, CorrelationRun, SharedIndicator,
)


class Command(BaseCommand):
    help = "Delete correlation rows whose investigation is gone or has been replaced."

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true",
                            help="report what would be removed and change nothing")

    def handle(self, *args, **opts):
        live = dict(Investigation.objects.values_list("id", "name"))

        orphans = []
        for run in CorrelationRun.objects.all():
            name = live.get(run.investigation_id)
            if name is None:
                orphans.append((run, "investigation no longer exists"))
            elif run.investigation_name and run.investigation_name != name:
                orphans.append(
                    (run, f"id now belongs to {name!r}, correlated as "
                          f"{run.investigation_name!r}"))

        if not orphans:
            self.stdout.write(self.style.SUCCESS("no orphaned correlation runs"))
            return

        for run, why in orphans:
            self.stdout.write(
                f"run {run.id} (investigation_id={run.investigation_id}, "
                f"{run.investigation_name!r}): {why}")

        if opts["dry_run"]:
            self.stdout.write(self.style.WARNING(
                f"{len(orphans)} run(s) would be removed — dry run, nothing changed"))
            return

        run_ids = [r.id for r, _ in orphans]
        campaign_ids = list(Campaign.objects.filter(run_id__in=run_ids)
                            .values_list("id", flat=True))
        CampaignEdge.objects.filter(campaign_id__in=campaign_ids).delete()
        CampaignHost.objects.filter(campaign_id__in=campaign_ids).delete()
        SharedIndicator.objects.filter(run_id__in=run_ids).delete()
        Campaign.objects.filter(id__in=campaign_ids).delete()
        CorrelationRun.objects.filter(id__in=run_ids).delete()

        self.stdout.write(self.style.SUCCESS(
            f"removed {len(orphans)} correlation run(s) and {len(campaign_ids)} campaign(s); "
            f"recompute any investigation that needs correlating"))
