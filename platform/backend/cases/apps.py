import os

from django.apps import AppConfig


class CasesConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "cases"

    def ready(self):
        # Correlation cleanup is a signal, not a call site. The correlation store is a
        # separate database with no cross-database foreign key, so nothing cascades; wiring
        # the cleanup to one delete view left every other path — queryset deletes,
        # management commands, the admin, the shell — orphaning campaigns that stayed
        # flagged current. PostgreSQL then reuses the id and the next investigation inherits
        # another incident's hosts. post_delete fires per instance for queryset deletes too,
        # which is what lets this cover the paths a single call site cannot.
        from . import signals  # noqa: F401

        # Only the long-running server and worker processes report their resources, and only
        # when told which one they are. ready() also runs for `migrate`, `shell` and every
        # other management command; detecting the role instead of being given it would have
        # those spawn a reporting thread and write a row claiming to be a live component.
        role = os.environ.get("IR_HEALTH_REPORT_ROLE", "")
        if not role:
            return
        from . import healthreporter

        if role == "worker":
            healthreporter.start(tier="application")
        else:
            healthreporter.start(component="backend (api)", tier="application", paths=("/tmp",))
