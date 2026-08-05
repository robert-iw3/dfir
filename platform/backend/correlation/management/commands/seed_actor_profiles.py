"""Seed the staged actor-profile library from an offline export.

Staged, never fetched. The enclave has no egress, and an attribution that depends on a
network call at analysis time is one that stops being reproducible the moment the source
changes — the whole point of recording `provenance` on every entry is that a candidate is
only as current as the library behind it, and that has to be readable months later.

    manage.py seed_actor_profiles --file /staging/actor_profiles.json
    manage.py seed_actor_profiles --builtin        # the small offline starter set

Input format (a list, or {"profiles": [...]}):

    {"key": "G0016", "name": "...", "aliases": [...], "techniques": ["T1566", ...],
     "artifact_conventions": ["persistence_service:<word><digits>"],
     "c2_pattern": {"movement_protocols": ["SMB"]},
     "provenance": {"source": "...", "version": "...", "exported": "..."}}
"""
import json

from django.core.management.base import BaseCommand, CommandError

from correlation.models import ActorProfile

# A deliberately small starter set so the path is exercised on a stack with no staged export.
# These are technique groupings from public ATT&CK group data, carrying no artifact
# conventions, because a naming habit is engagement-specific and inventing one here would
# manufacture the strongest-weighted component of the comparison out of nothing.
BUILTIN = [
    {"key": "G-RANSOM-GENERIC", "name": "Ransomware operator (generic tradecraft)",
     "techniques": ["T1190", "T1078", "T1059", "T1021", "T1486", "T1490", "T1489", "T1562"],
     "c2_pattern": {"movement_protocols": ["SMB", "RDP"]},
     "provenance": {"source": "builtin starter set", "note": "shape only, no artifact conventions"}},
    {"key": "G-ESPIONAGE-GENERIC", "name": "Espionage operator (generic tradecraft)",
     "techniques": ["T1566", "T1059", "T1547", "T1003", "T1021", "T1071", "T1560", "T1041"],
     "c2_pattern": {"movement_protocols": ["SMB"], "beacon_kinds": ["domain"]},
     "provenance": {"source": "builtin starter set", "note": "shape only, no artifact conventions"}},
    {"key": "G-CRYPTOMINER-GENERIC", "name": "Cryptomining operator (generic tradecraft)",
     "techniques": ["T1190", "T1059", "T1053", "T1496"],
     "c2_pattern": {"beacon_kinds": ["ip"]},
     "provenance": {"source": "builtin starter set", "note": "shape only, no artifact conventions"}},
]


class Command(BaseCommand):
    help = "Load or refresh the staged actor-profile library used by L5 attribution."

    def add_arguments(self, parser):
        parser.add_argument("--file", help="offline actor profile export (JSON)")
        parser.add_argument("--builtin", action="store_true",
                            help="load the small offline starter set instead of a file")
        parser.add_argument("--replace", action="store_true",
                            help="delete profiles absent from this input rather than keeping them")

    def handle(self, *args, **opts):
        if opts.get("builtin"):
            entries = BUILTIN
            origin = "builtin"
        elif opts.get("file"):
            try:
                with open(opts["file"], encoding="utf-8") as fh:
                    doc = json.load(fh)
            except (OSError, ValueError) as exc:
                raise CommandError(f"cannot read {opts['file']}: {exc}")
            entries = doc.get("profiles", doc) if isinstance(doc, dict) else doc
            origin = opts["file"]
        else:
            raise CommandError("pass --file <export.json> or --builtin")

        if not isinstance(entries, list):
            raise CommandError("expected a list of profiles")

        seen, created, updated = set(), 0, 0
        for e in entries:
            if not isinstance(e, dict) or not e.get("key"):
                self.stderr.write(f"skipping entry with no key: {str(e)[:80]}")
                continue
            seen.add(e["key"])
            _, was_created = ActorProfile.objects.update_or_create(
                key=e["key"],
                defaults={
                    "name": e.get("name", e["key"]),
                    "aliases": e.get("aliases", []),
                    "techniques": e.get("techniques", []),
                    "artifact_conventions": e.get("artifact_conventions", []),
                    "c2_pattern": e.get("c2_pattern", {}),
                    "provenance": {**e.get("provenance", {}), "loaded_from": origin},
                },
            )
            created += was_created
            updated += not was_created

        removed = 0
        if opts.get("replace"):
            # Only on request. A partial export silently deleting the rest of the library
            # would quietly narrow every future attribution, and nothing would report it.
            removed, _ = ActorProfile.objects.exclude(key__in=seen).delete()

        self.stdout.write(
            f"actor profiles: {created} created, {updated} updated"
            + (f", {removed} removed" if opts.get("replace") else "")
            + f" (from {origin})")
