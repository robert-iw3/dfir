import os

from django.apps import AppConfig


class CasesConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "cases"

    def ready(self):
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
