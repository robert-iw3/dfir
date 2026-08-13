"""Archive a concluded case to cold storage, or sweep everything due.

Nothing is deleted until the uploaded bundle has been read back and its custody seal
verified. A legal hold refuses archival absolutely; an open case past the hard ceiling is
archived anyway and flagged, because an investigation still open after six months is an
unfinished one, not an active one.
"""
import json

from django.core.management.base import BaseCommand, CommandError

from cases import tiering
from cases.models import Investigation


class Command(BaseCommand):
    help = "Archive one case (walk -> seal -> upload -> verify -> scoped delete), or sweep."

    def add_arguments(self, parser):
        parser.add_argument("--investigation", type=int)
        parser.add_argument("--sweep", action="store_true",
                            help="archive every case past its grace/ceiling; re-cool "
                                 "expired restores")
        parser.add_argument("--dry-run", action="store_true")
        parser.add_argument("--actor", default="system")

    def handle(self, *args, **opts):
        if opts["sweep"]:
            report = tiering.sweep(actor=opts["actor"], dry_run=opts["dry_run"])
            self.stdout.write(json.dumps(report, indent=1))
            return
        if not opts["investigation"]:
            raise CommandError("--investigation or --sweep is required")
        inv = Investigation.objects.filter(id=opts["investigation"]).first()
        if not inv:
            raise CommandError(f"no investigation {opts['investigation']}")
        if opts["dry_run"]:
            self.stdout.write(f"would archive {inv.id} ({inv.status}); "
                              f"legal hold: {tiering.legal_hold(inv)}")
            return
        rec = tiering.archive_case(inv, actor=opts["actor"],
                                   force_open=inv.status != Investigation.CONCLUDED)
        self.stdout.write(json.dumps({
            "archive_id": rec.id, "object_key": rec.object_key,
            "sha256": rec.bundle_sha256, "rows": rec.row_counts,
            "archived_while_open": rec.archived_while_open}, indent=1))
