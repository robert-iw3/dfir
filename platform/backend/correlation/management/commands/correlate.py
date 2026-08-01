"""Recompute correlation from collected evidence."""
import json

from django.core.management.base import BaseCommand

from cases.models import Investigation

from correlation.engine import correlate_investigation
from correlation.models import Campaign


class Command(BaseCommand):
    help = "Rebuild the derived correlation store from collected evidence."

    def add_arguments(self, parser):
        parser.add_argument("--investigation", type=int, default=None)

    def handle(self, *args, **opts):
        qs = Investigation.objects.all()
        if opts["investigation"]:
            qs = qs.filter(id=opts["investigation"])

        out = []
        for inv in qs:
            crun = correlate_investigation(inv.id, inv.name)
            for c in Campaign.objects.filter(run=crun):
                out.append({
                    "investigation": inv.name, "campaign_id": c.id,
                    "patient_zero": c.patient_zero, "initial_vector": c.initial_vector,
                    "hosts": c.host_count, "confidence": c.confidence,
                })
        self.stdout.write(json.dumps(out, indent=2))
