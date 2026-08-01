"""
Routes the derived correlation store to its own database.

`cases` (collected evidence, chain of custody) and `correlation` (the multi-host
interpretation) are separate databases so analysis can never write to the evidentiary
record, and so the two can be scaled and replicated independently.

Both aliases may point at the same PostgreSQL instance in a small deployment; splitting
them onto separate instances is a configuration change, not a code change. Cross-database
relations are refused outright rather than silently degrading.
"""

CORRELATION_APP = "correlation"
CORRELATION_DB = "correlation"


class CorrelationRouter:
    def db_for_read(self, model, **hints):
        return CORRELATION_DB if model._meta.app_label == CORRELATION_APP else None

    def db_for_write(self, model, **hints):
        return CORRELATION_DB if model._meta.app_label == CORRELATION_APP else None

    def allow_relation(self, obj1, obj2, **hints):
        """Relations are allowed only within one store."""
        in_corr = (obj1._meta.app_label == CORRELATION_APP,
                   obj2._meta.app_label == CORRELATION_APP)
        return in_corr[0] == in_corr[1] or None

    def allow_migrate(self, db, app_label, **hints):
        if app_label == CORRELATION_APP:
            return db == CORRELATION_DB
        return db != CORRELATION_DB
