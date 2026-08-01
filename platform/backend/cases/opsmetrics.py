"""
Platform health and performance metrics, for admins.

These report on the health of the platform itself — not on what it has found. Every
number is measured live at request time; nothing is cached, because a stale health panel
is worse than none.

**Probes run from inside the enclave.** The backend opens real connections to the services
it reports on. It deliberately does not shell out to `troubleshooting/diagnose.sh`: those
scripts drive `podman` on the host, and reaching them from the web tier would mean mounting
the container runtime socket into a request-serving service — a container-escape path that
would defeat the segmentation the platform is built on. Host-level diagnostics stay an
operator tool run on the host.
"""
import os
import socket
import ssl
import time
import urllib.request

from django.conf import settings
from django.db import connections

from .models import AuditLog, CollectionRun, Finding, MemoryCapture

# Statistics available from any PostgreSQL role, so the app's least-privilege user (and
# Vault's rotating role) can read them without elevation.
DB_STATS_SQL = """
SELECT
  pg_database_size(current_database())                                   AS size_bytes,
  (SELECT count(*) FROM pg_stat_activity
     WHERE datname = current_database())                                 AS connections,
  (SELECT count(*) FROM pg_stat_activity
     WHERE datname = current_database() AND state = 'active')            AS active,
  (SELECT count(*) FROM pg_stat_activity
     WHERE datname = current_database() AND state = 'idle in transaction') AS idle_in_txn,
  (SELECT coalesce(extract(epoch FROM max(now() - query_start)), 0)
     FROM pg_stat_activity
     WHERE datname = current_database() AND state = 'active')            AS longest_query_s,
  s.xact_commit, s.xact_rollback, s.deadlocks, s.temp_files,
  s.blks_hit, s.blks_read, s.tup_returned, s.tup_fetched
FROM pg_stat_database s
WHERE s.datname = current_database()
"""

TABLE_SIZES_SQL = """
SELECT c.relname,
       pg_total_relation_size(c.oid) AS total_bytes,
       coalesce(st.n_live_tup, 0)    AS live_rows,
       coalesce(st.seq_scan, 0)      AS seq_scans,
       coalesce(st.idx_scan, 0)      AS idx_scans
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
LEFT JOIN pg_stat_user_tables st ON st.relid = c.oid
WHERE c.relkind = 'r' AND n.nspname = 'public'
ORDER BY pg_total_relation_size(c.oid) DESC
LIMIT 8
"""


def _database_metrics(alias):
    """Live statistics for one store."""
    out = {"alias": alias, "reachable": False}
    started = time.perf_counter()
    try:
        with connections[alias].cursor() as cur:
            cur.execute(DB_STATS_SQL)
            row = cur.fetchone()
            cols = [c[0] for c in cur.description]
            stats = dict(zip(cols, row)) if row else {}

            cur.execute(TABLE_SIZES_SQL)
            tables = [
                {"name": r[0], "total_bytes": int(r[1]), "live_rows": int(r[2]),
                 "seq_scans": int(r[3]), "idx_scans": int(r[4])}
                for r in cur.fetchall()
            ]
    except Exception as exc:                      # a probe must report, never raise
        out["error"] = str(exc)[:200]
        out["latency_ms"] = round((time.perf_counter() - started) * 1000, 1)
        return out

    hit = float(stats.get("blks_hit") or 0)
    read = float(stats.get("blks_read") or 0)
    commits = int(stats.get("xact_commit") or 0)
    rollbacks = int(stats.get("xact_rollback") or 0)

    out.update({
        "reachable": True,
        "latency_ms": round((time.perf_counter() - started) * 1000, 1),
        "name": connections[alias].settings_dict.get("NAME"),
        "size_bytes": int(stats.get("size_bytes") or 0),
        "connections": int(stats.get("connections") or 0),
        "active": int(stats.get("active") or 0),
        "idle_in_transaction": int(stats.get("idle_in_txn") or 0),
        "longest_query_s": round(float(stats.get("longest_query_s") or 0), 2),
        # Cache hit ratio is the first number to look at when reads slow down: below ~99%
        # on a working set this small means the shared buffers are undersized.
        "cache_hit_ratio": round(hit / (hit + read), 4) if (hit + read) else None,
        "commits": commits,
        "rollbacks": rollbacks,
        "rollback_ratio": round(rollbacks / (commits + rollbacks), 4) if (commits + rollbacks) else 0,
        "deadlocks": int(stats.get("deadlocks") or 0),
        "temp_files": int(stats.get("temp_files") or 0),
        "tables": tables,
    })
    return out


def _tcp_probe(host, port, timeout=3):
    started = time.perf_counter()
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return {"ok": True, "latency_ms": round((time.perf_counter() - started) * 1000, 1)}
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:120],
                "latency_ms": round((time.perf_counter() - started) * 1000, 1)}


def _http_probe(url, timeout=4, expect=(200, 204, 401, 403), cafile=None):
    """A reachable service that answers 401/403 is healthy — it is refusing an
    unauthenticated probe, which is the correct behavior, not an outage.

    `cafile` pins a private CA, for services whose certificate is not publicly rooted.
    """
    started = time.perf_counter()
    ctx = ssl.create_default_context(cafile=cafile) if cafile else None
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            code = r.status
    except urllib.error.HTTPError as exc:
        code = exc.code
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:120],
                "latency_ms": round((time.perf_counter() - started) * 1000, 1)}
    return {"ok": code in expect, "status": code,
            "latency_ms": round((time.perf_counter() - started) * 1000, 1)}


def component_health():
    """Probe every service the enclave depends on."""
    store = settings.OBJECT_STORE
    endpoint = (store.get("ENDPOINT_URL") or "").rstrip("/")

    components = [
        {"name": "postgres (collection)", "tier": "data",
         **_tcp_probe(connections["default"].settings_dict["HOST"],
                      connections["default"].settings_dict["PORT"] or 5432)},
        {"name": "postgres (correlation)", "tier": "data",
         **_tcp_probe(connections["correlation"].settings_dict["HOST"],
                      connections["correlation"].settings_dict["PORT"] or 5432)},
        {"name": "redis (queue broker)", "tier": "data", **_tcp_probe("redis", 6379)},
        {"name": "minio (object store)", "tier": "data",
         **(_http_probe(f"{endpoint}/minio/health/live") if endpoint
            else {"ok": False, "error": "no endpoint configured"})},
        {"name": "keycloak (identity)", "tier": "identity",
         **_http_probe("http://keycloak:8080/realms/irplatform/.well-known/openid-configuration")},
        # HTTPS with the enclave's own CA: Consul's cleartext API is disabled, so a plain
        # http:// probe here would report the mesh down whenever it is correctly hardened.
        {"name": "consul (mesh)", "tier": "identity",
         **_http_probe(f"{os.environ.get('IR_CONSUL_ADDR', 'https://consul:8501')}/v1/status/leader",
                       cafile=os.environ.get("IR_CONSUL_CACERT") or None)},
        {"name": "oauth2-proxy (SSO gate)", "tier": "application",
         **_http_probe("http://oauth2-proxy:4180/ping")},
    ]
    for c in components:
        c.setdefault("ok", False)
    return components


def queue_metrics():
    """Analysis backlog and worker liveness, read from the Celery broker."""
    out = {"reachable": False}
    try:
        import redis  # provided by the celery redis extra

        url = settings.CELERY_BROKER_URL if hasattr(settings, "CELERY_BROKER_URL") else None
        client = redis.Redis.from_url(url or "redis://redis:6379/0", socket_timeout=3)
        out["queued"] = int(client.llen("celery"))
        out["reachable"] = True
    except Exception as exc:
        out["error"] = str(exc)[:160]

    try:
        from ir_platform.celery import app as celery_app

        inspector = celery_app.control.inspect(timeout=2)
        active = inspector.active() or {}
        out["workers"] = len(active)
        out["active_tasks"] = sum(len(v) for v in active.values())
    except Exception as exc:
        out.setdefault("worker_error", str(exc)[:160])
    return out


def storage_metrics():
    """Object-store consumption, and what retention is actually holding."""
    from . import storage as storage_mod

    out = {"reachable": False, "backend": storage_mod.backend_name(),
           "bucket": storage_mod.bucket()}
    try:
        s3 = storage_mod.client()
        total = 0
        count = 0
        token = None
        while True:
            kwargs = {"Bucket": storage_mod.bucket(), "MaxKeys": 1000}
            if token:
                kwargs["ContinuationToken"] = token
            page = s3.list_objects_v2(**kwargs)
            for obj in page.get("Contents", []):
                total += obj["Size"]
                count += 1
            if not page.get("IsTruncated"):
                break
            token = page.get("NextContinuationToken")
        out.update({"reachable": True, "object_count": count, "total_bytes": total})
    except Exception as exc:
        out["error"] = str(exc)[:200]

    # Retention is the lever that keeps capacity tractable, so report what it is holding.
    by_status = {}
    for status, _ in MemoryCapture.RETENTION:
        qs = MemoryCapture.objects.filter(retention_status=status)
        by_status[status] = {
            "captures": qs.count(),
            "bytes": sum(qs.values_list("size_bytes", flat=True)) or 0,
        }
    out["retention"] = by_status
    return out


def audit_integrity():
    from . import audit as audit_mod

    ok, broken = audit_mod.verify_audit_chain()
    return {"chain_intact": ok, "first_broken_id": broken,
            "entries": AuditLog.objects.count()}


def workload_summary():
    return {
        "runs": CollectionRun.objects.count(),
        "findings": Finding.objects.count(),
        "captures": MemoryCapture.objects.count(),
        "compromised_runs": CollectionRun.objects.filter(compromised=True).count(),
    }


def collect_all():
    started = time.perf_counter()
    payload = {
        "databases": [_database_metrics("default"), _database_metrics("correlation")],
        "components": component_health(),
        "queue": queue_metrics(),
        "storage": storage_metrics(),
        "audit": audit_integrity(),
        "workload": workload_summary(),
    }
    payload["collected_in_ms"] = round((time.perf_counter() - started) * 1000, 1)
    return payload
