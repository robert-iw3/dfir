#!/usr/bin/env python3
"""
One-shot DB bootstrap for the Vault integration (runs in the backend image, which
has psycopg). Ensures a fixed, NOLOGIN owner role `ir_app` exists with full rights on
the app's databases, so that Vault's short-lived dynamic users — each created
`IN ROLE ir_app` with `SET role 'ir_app'` — create and access objects *as* ir_app.
That makes object ownership stable across credential rotation (the classic
dynamic-creds + migrations pitfall). Idempotent.

Covers EVERY database the application uses, not just the primary. The correlation
database has its own django_migrations, and a grant that reaches only POSTGRES_DB
leaves the app tier authenticating perfectly and then dying on the second database —
after the primary's migrations already succeeded, which points the blame everywhere
but here.

Also the place the correlation database is CREATED. `CREATE DATABASE` needs the
CREATEDB attribute, which dynamic users do not have and should not: this script is
the one legitimate holder of the static admin credential, so existence is guaranteed
here, before the application tier ever starts.
"""
import os
import sys

import psycopg

ADMIN = os.environ.get("POSTGRES_USER", "ir_platform")
PW = os.environ.get("POSTGRES_PASSWORD", "ir_platform")
HOST = os.environ.get("POSTGRES_HOST", "db")
PORT = os.environ.get("POSTGRES_PORT", "5432")

# Every database the application touches. Order matters only for the log.
DATABASES = [
    os.environ.get("POSTGRES_DB", "ir_platform"),
    os.environ.get("CORRELATION_POSTGRES_DB", "ir_correlation"),
]

# Cluster-wide, run once against the maintenance database.
CLUSTER_STMTS = [
    # Fixed owner role — no login; dynamic users act as this role.
    "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='ir_app') "
    "THEN CREATE ROLE ir_app NOLOGIN; END IF; END $$;",
]

# Per-database, run inside each one.
def db_stmts(db: str) -> list[str]:
    return [
        f'GRANT ALL PRIVILEGES ON DATABASE "{db}" TO ir_app;',
        "GRANT ALL ON SCHEMA public TO ir_app;",
        "ALTER SCHEMA public OWNER TO ir_app;",
        # Anything already created by the static bootstrap user becomes usable by ir_app.
        "GRANT ALL ON ALL TABLES IN SCHEMA public TO ir_app;",
        "GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO ir_app;",
    ]


def connect(dbname: str):
    return psycopg.connect(host=HOST, port=PORT, dbname=dbname, user=ADMIN,
                           password=PW, autocommit=True)


def main():
    try:
        with connect("postgres") as conn:
            for s in CLUSTER_STMTS:
                conn.execute(s)
            # CREATE DATABASE cannot run inside a transaction; autocommit handles that.
            for db in DATABASES:
                exists = conn.execute(
                    "SELECT 1 FROM pg_database WHERE datname = %s", (db,)).fetchone()
                if not exists:
                    conn.execute(f'CREATE DATABASE "{db}" OWNER ir_app')
                    print(f"[db-bootstrap] created database {db} (owner ir_app)")
        for db in DATABASES:
            with connect(db) as conn:
                for s in db_stmts(db):
                    conn.execute(s)
            print(f"[db-bootstrap] ir_app ensured on {db}")
    except Exception as exc:  # noqa: BLE001
        print(f"[db-bootstrap] FAILED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
