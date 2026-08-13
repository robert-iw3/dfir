"""Postgres backend that re-reads the Vault-rendered credential when it CONNECTS.

Vault rotates the database credential on re-auth and revokes the previous role. A process
that read the credential once at startup then fails every query with "role does not exist"
until something replaces the container — the worker sat in exactly that state for hours,
running and accepting tasks while unable to record a result. The deploy-time replacement
check only helps if a deploy happens to run after the rotation.

Re-resolving at connection time removes the window: with CONN_MAX_AGE bounding connection
reuse, a rotation costs at most one failed request before the next connect picks up the
current lease. Only Vault-issued users (the `v-` prefix is Vault's own) are re-resolved, so
a deployment on static credentials behaves exactly as stock.
"""
import os

from django.db.backends.postgresql import base


class DatabaseWrapper(base.DatabaseWrapper):
    def get_connection_params(self):
        params = super().get_connection_params()
        if str(params.get("user", "")).startswith("v-"):
            # Lazy import: settings is fully loaded long before the first connection.
            from ir_platform.settings import _load_vault_env
            _load_vault_env()
            user = os.environ.get("POSTGRES_USER")
            password = os.environ.get("POSTGRES_PASSWORD")
            if user and password:
                params["user"] = user
                params["password"] = password
        return params
