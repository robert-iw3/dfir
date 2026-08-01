"""
Merge one Host record into another, moving everything filed against it.

Collection performed inside a container without the host's `/etc/hostname` mounted records
the container ID as the hostname, so the same physical machine appears under a name that
changes every run. Evidence collected before that is corrected sits under the wrong host:
its collection runs, memory captures and analyses no longer line up with later collection
from the same machine, and corroborating a memory finding against a collection finding
silently compares two different hosts and finds nothing.

This moves every record filed against one Host onto another and removes the empty one. It
does not edit findings, verdicts or captures -- those reach a host through their collection
run, so repointing the run carries them.

Renaming rather than merging is not offered: the correct name usually already exists as a
separate Host, because the corrected collection created it.

    manage.py merge_host --from <container-id> --into <hostname> --reason "..." --actor me
    manage.py merge_host --from <container-id> --into <hostname> --reason "..." --apply

Prints the plan and changes nothing without --apply. Writes one audit entry recording both
names, the reason, and every record moved.
"""
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from cases.audit import audit
from cases.models import CollectionRun, Host, MemoryCapture, Note, RescanRequest


class Command(BaseCommand):
    help = "Merge one Host into another, moving its runs, notes and rescans."

    def add_arguments(self, parser):
        parser.add_argument("--from", dest="source", required=True,
                            help="hostname to merge FROM (removed when empty)")
        parser.add_argument("--into", dest="target", required=True,
                            help="hostname to merge INTO (kept)")
        parser.add_argument("--reason", default="",
                            help="why these are the same machine; recorded in the audit trail")
        parser.add_argument("--actor", default="system",
                            help="who is making the change; recorded in the audit trail")
        parser.add_argument("--apply", action="store_true",
                            help="perform the merge (otherwise print the plan and exit)")

    def handle(self, *args, **opts):
        source_name, target_name = opts["source"], opts["target"]
        if source_name == target_name:
            raise CommandError("--from and --into are the same host")

        try:
            source = Host.objects.get(hostname=source_name)
        except Host.DoesNotExist:
            raise CommandError(f"no host named {source_name!r}")
        try:
            target = Host.objects.get(hostname=target_name)
        except Host.DoesNotExist:
            raise CommandError(
                f"no host named {target_name!r}. Merging requires the destination to exist, "
                f"so the surviving record is one already carrying real evidence.")

        runs = list(CollectionRun.objects.filter(host=source).order_by("id"))
        notes = list(Note.objects.filter(host=source).order_by("id"))
        rescans = list(RescanRequest.objects.filter(host=source).order_by("id"))
        captures = list(MemoryCapture.objects.filter(run__host=source).order_by("id"))

        self.stdout.write(f"merge {source_name!r} (host {source.id}) "
                          f"-> {target_name!r} (host {target.id})")
        self.stdout.write(f"  collection runs : {[r.id for r in runs] or 'none'}")
        self.stdout.write(f"  memory captures : {[c.id for c in captures] or 'none'} "
                          f"(follow their run)")
        self.stdout.write(f"  notes           : {[n.id for n in notes] or 'none'}")
        self.stdout.write(f"  rescan requests : {[r.id for r in rescans] or 'none'}")

        if not opts["apply"]:
            self.stdout.write(self.style.WARNING(
                "\ndry run -- nothing changed. Re-run with --apply to perform the merge."))
            return

        if not opts["reason"]:
            raise CommandError("--reason is required with --apply; it is recorded in the "
                               "audit trail as the justification for moving evidence")

        with transaction.atomic():
            CollectionRun.objects.filter(host=source).update(host=target)
            Note.objects.filter(host=source).update(host=target)
            RescanRequest.objects.filter(host=source).update(host=target)

            detail = {
                "merged_from": source_name,
                "merged_into": target_name,
                "reason": opts["reason"],
                "collection_runs": [r.id for r in runs],
                "memory_captures": [c.id for c in captures],
                "notes": [n.id for n in notes],
                "rescan_requests": [r.id for r in rescans],
            }
            audit(opts["actor"], "host.merge", role="admin",
                  object_type="Host", object_id=source.id, detail=detail)

            remaining = CollectionRun.objects.filter(host=source).count()
            if remaining:
                raise CommandError(f"{remaining} run(s) still reference {source_name!r}; "
                                   f"refusing to remove it")
            source.delete()

        self.stdout.write(self.style.SUCCESS(
            f"\nmerged. {len(runs)} run(s), {len(captures)} capture(s), {len(notes)} note(s) "
            f"and {len(rescans)} rescan(s) now belong to {target_name!r}; "
            f"{source_name!r} removed. Audit entry written."))
