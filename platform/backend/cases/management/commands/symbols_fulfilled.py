"""Mark a symbol request satisfied once its table is installed in the store.

Called by the enclave puller after it installs an ISF, so the outstanding admin alert
clears without the puller needing database access of its own.
"""
from django.core.management.base import BaseCommand

from cases import symbols


class Command(BaseCommand):
    help = "Record that a symbol table is now present in the enclave symbol store."

    def add_arguments(self, parser):
        parser.add_argument("symbol_key")
        parser.add_argument("isf_path")

    def handle(self, *args, **opts):
        req = symbols.mark_fulfilled(opts["symbol_key"], opts["isf_path"])
        if req is None:
            # An ISF can arrive for a kernel nothing asked for — pre-seeding a fleet's
            # symbols ahead of an incident is the encouraged pattern, so this is normal.
            self.stdout.write(f"no outstanding request for {opts['symbol_key']} (pre-seeded)")
            return
        self.stdout.write(f"{req.symbol_key}: {req.status} sha256={req.isf_sha256[:16]}")
