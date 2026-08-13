"""Reading the shipped log archive from the platform itself.

Every tier writes its logs to a file, the shipper moves them into the `ir-logs` bucket, and
this serves them back to an admin. Without it, troubleshooting means shell access to the
host running the containers — which is exactly the access the platform's design spends its
effort removing.

Read-only and admin-only, by construction:

  * There is no write path here at all. The shipper is the only writer, and the tiers mount
    their log volumes read-only into it.
  * Logs are not evidence and are not custody-sealed. They are operational records, kept in
    their own bucket away from evidence, and this says so rather than implying a chain of
    custody it does not have.
  * A log line can contain a token or a path an analyst is not cleared for, so this is
    admin-only and every read is audited.
"""
import os

from django.http import HttpResponse
from rest_framework.response import Response
from rest_framework.views import APIView

from cases import audit, storage
from cases.rbac import IsAdmin

BUCKET = os.environ.get("IR_LOGS_BUCKET", "ir-logs")
# One request must not try to hold an arbitrary object in memory, and nobody reads a
# 500 MB log line by line in a browser.
MAX_READ = int(os.environ.get("IR_LOG_READ_MAX_BYTES", str(2 * 1024 * 1024)))

# The sources the shipper writes, in the order an operator reads them when chasing a
# request through the stack: ingress first, then the tier that served it, then the tier
# that did the work.
SOURCE_ORDER = ["traefik-access", "frontend-access", "frontend-error",
                "backend-access", "backend-app", "worker-app"]


class LogSourceView(APIView):
    """What log sources exist, and what has been shipped for each."""

    permission_classes = [IsAdmin]

    def get(self, request):
        try:
            objects = storage.list_objects(BUCKET)
        except Exception as exc:                       # noqa: BLE001
            # A missing bucket is a real answer for a deployment whose shipper has not run
            # yet; it must not render as a broken page.
            return Response({"bucket": BUCKET, "sources": [], "available": False,
                             "detail": str(exc)[:300]})

        by_source = {}
        for obj in objects:
            key = obj.get("Key", "")
            if key.startswith("_state/"):
                continue
            source = key.split("/", 1)[0]
            row = by_source.setdefault(source, {"source": source, "objects": 0, "bytes": 0,
                                                "latest": None, "latest_key": ""})
            row["objects"] += 1
            row["bytes"] += int(obj.get("Size", 0) or 0)
            at = obj.get("LastModified")
            iso = at.isoformat() if at else None
            if iso and (row["latest"] is None or iso > row["latest"]):
                row["latest"] = iso
                row["latest_key"] = key

        ordered = ([by_source[s] for s in SOURCE_ORDER if s in by_source]
                   + [v for k, v in sorted(by_source.items()) if k not in SOURCE_ORDER])
        return Response({"bucket": BUCKET, "available": True, "sources": ordered,
                         "known_sources": SOURCE_ORDER})


class LogObjectView(APIView):
    """List the objects for one source, or read the tail of one."""

    permission_classes = [IsAdmin]

    def get(self, request):
        source = (request.query_params.get("source") or "").strip()
        key = (request.query_params.get("key") or "").strip()
        if not source and not key:
            return Response({"detail": "source or key is required"}, status=400)

        if key:
            # A key is a path into one bucket, and nothing outside its source prefix is
            # readable through it.
            if ".." in key or key.startswith("/") or key.startswith("_state/"):
                return Response({"detail": "not found"}, status=404)
            try:
                raw = storage.get_object_bytes(BUCKET, key)
            except Exception:                          # noqa: BLE001
                return Response({"detail": "not found"}, status=404)
            truncated = len(raw) > MAX_READ
            body = raw[-MAX_READ:] if truncated else raw
            # The ledger's object_id is a short column and a log key is a full path, so
            # the key travels in the detail and the column carries as much as it holds.
            audit.audit(getattr(request.user, "username", "") or "admin",
                        "log.read", object_type="log", object_id=key[:64],
                        detail={"key": key, "bytes": len(body), "truncated": truncated})
            return Response({
                "key": key, "bytes": len(body), "truncated": truncated,
                # Decoded leniently: a truncated read can cut a multi-byte character, and a
                # log viewer that raises on one bad byte is useless exactly when it matters.
                "text": body.decode("utf-8", "replace"),
                "note": "Operational log, not evidence. Not custody-sealed.",
            })

        try:
            objects = storage.list_objects(BUCKET, prefix=f"{source}/")
        except Exception as exc:                       # noqa: BLE001
            return Response({"source": source, "objects": [], "detail": str(exc)[:300]})
        rows = sorted(({"key": o.get("Key", ""), "bytes": int(o.get("Size", 0) or 0),
                        "at": o["LastModified"].isoformat() if o.get("LastModified") else None}
                       for o in objects if not o.get("Key", "").startswith("_state/")),
                      key=lambda r: r["at"] or "", reverse=True)
        return Response({"source": source, "objects": rows[:500]})


class LogDownloadView(APIView):
    """Take a log object out of the platform. Admin-only and audited, like reading it."""

    permission_classes = [IsAdmin]

    def get(self, request):
        key = (request.query_params.get("key") or "").strip()
        if not key or ".." in key or key.startswith("/") or key.startswith("_state/"):
            return Response({"detail": "not found"}, status=404)
        try:
            raw = storage.get_object_bytes(BUCKET, key)
        except Exception:                              # noqa: BLE001
            return Response({"detail": "not found"}, status=404)
        audit.audit(getattr(request.user, "username", "") or "admin",
                    "log.export", object_type="log", object_id=key[:64],
                    detail={"key": key, "bytes": len(raw)})
        name = key.replace("/", "_")
        resp = HttpResponse(raw, content_type="application/octet-stream")
        # Always an attachment, never inline: a log is arbitrary text from arbitrary
        # sources, and rendering it in the browser origin is a scripting hazard.
        resp["Content-Disposition"] = f'attachment; filename="{name}"'
        resp["X-Content-Type-Options"] = "nosniff"
        return resp
