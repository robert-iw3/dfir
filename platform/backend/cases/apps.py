import os

from django.apps import AppConfig


class CasesConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "cases"

    def ready(self):
        # Correlation cleanup is a signal, not a call site. The correlation store is a separate database
        # with no cross-database foreign key, so nothing cascades; wiring the cleanup to one delete view
        # left every other path — queryset deletes, management commands, the admin, the shell —
        # orphaning campaigns that stayed flagged current.
        from . import signals  # noqa: F401

        # Only the long-running server and worker processes report their resources, and only
        # when told which one they are. ready() also runs for `migrate`, `shell` and every
        # other management command; detecting the role instead of being given it would have
        # those spawn a reporting thread and write a row claiming to be a live component.
        role = os.environ.get("IR_HEALTH_REPORT_ROLE", "")
        if not role:
            return
        from . import healthreporter

        # Both roles report what their OWN sidecar has observed about their upstreams —
        # first-person mesh evidence the health view merges into the intention matrix. The
        # backend additionally records a queue-depth sample per beat: one writer, so the
        # series has one clock, and the component already guaranteed to be running.
        from . import sidecarstats

        if role.startswith("worker"):
            # PREFIX match, because the role names WHICH worker this is — replicas set
            # worker-2, worker-3... and each must be its own Component Health row. An exact
            # comparison sent every replica into the web branch below, where four workers
            # took turns overwriting the API's row while their own were missing.
            import socket
            healthreporter.start(component=f"{role} ({socket.gethostname()})",
                                 tier="application",
                                 extra=lambda: {"mesh_upstreams": sidecarstats.upstream_observations()})
        elif role == "web":
            from . import aggregates
            healthreporter.start(component="backend (api)", tier="application", paths=("/tmp",),
                                 extra=lambda: {"mesh_upstreams": sidecarstats.upstream_observations()},
                                 beat=aggregates.record_queue_sample)
        # Any other value reports as itself, nothing more: a role this code does not know
        # must not silently claim to be the API.
        else:
            healthreporter.start(component=role, tier="application")
