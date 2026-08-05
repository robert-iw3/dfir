"""
Routes each derived store to its own database.

`cases` holds collected evidence under chain of custody. Everything else here is derived,
higher-volume, or both, and is kept out of that database so it can never write to the
evidentiary record and so the stores scale, replicate and are retained independently:

  correlation   the multi-host interpretation — analysis output, superseded on recompute
  opslog        API request logs and browser errors — operational telemetry, not evidence,
                and by far the highest-volume thing the platform writes

Any alias may point at the same PostgreSQL instance in a small deployment; splitting them
onto separate instances is a configuration change, not a code change. Cross-database
relations are refused outright rather than silently degrading.
"""

# app_label -> database alias. One mapping, so adding a store is a line here rather than
# another router class competing for the same decisions.
SIDE_STORES = {
    "correlation": "correlation",
    "opslog": "opslog",
}


class CorrelationRouter:
    """Named for the first store it carried; it now routes every side store."""

    def db_for_read(self, model, **hints):
        return SIDE_STORES.get(model._meta.app_label)

    def db_for_write(self, model, **hints):
        return SIDE_STORES.get(model._meta.app_label)

    def allow_relation(self, obj1, obj2, **hints):
        """Relations are allowed only within one store."""
        return (SIDE_STORES.get(obj1._meta.app_label)
                == SIDE_STORES.get(obj2._meta.app_label)) or None

    def allow_migrate(self, db, app_label, **hints):
        target = SIDE_STORES.get(app_label)
        if target:
            return db == target
        # Everything else belongs in `default` and must not be created in a side store.
        return db not in set(SIDE_STORES.values())
