"""Restore an archived case from cold storage.

The custody seal is verified before a single row is inserted, rows keep their original ids
so a second restore is a no-op, and the restored data carries an expiry after which the
sweep re-cools it.
"""
import json

from django.core.management.base import BaseCommand, CommandError

from cases import tiering
from cases.models import InvestigationArchive


class Command(BaseCommand):
    help = "Verify and replay a case bundle back into the hot tier."

    def add_arguments(self, parser):
        parser.add_argument("--archive", type=int)
        parser.add_argument("--investigation", type=int,
                            help="newest archive of this investigation")
        parser.add_argument("--actor", default="system")

    def handle(self, *args, **opts):
        arc = None
        if opts["archive"]:
            arc = InvestigationArchive.objects.filter(id=opts["archive"]).first()
        elif opts["investigation"]:
            arc = (InvestigationArchive.objects
                   .filter(investigation_id=opts["investigation"])
                   .order_by("-id").first())
        if not arc:
            raise CommandError("no matching archive — pass --archive or --investigation")
        req = tiering.restore_case(arc, actor=opts["actor"])
        self.stdout.write(json.dumps({
            "state": req.state, "detail": req.detail,
            "expires_at": req.expires_at.isoformat() if req.expires_at else None},
            indent=1))
