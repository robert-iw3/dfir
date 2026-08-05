"""Records every API call, so a failure in the browser can be traced to a request.

Placed so it wraps the view: the duration measured is what the caller waited for, and an
exception that escapes the view is recorded with its traceback rather than only appearing in
the container's stdout, where nobody reading the UI can reach it.

Three rules it follows without exception:

  * **Logging must never break the request.** Every write is inside a try/except that
    swallows. A telemetry store that can take the application down with it is worse than no
    telemetry at all.
  * **Never log a body.** Request and response bodies carry evidence, credentials and
    analyst notes, and this database is explicitly not custody-sealed. Shape only — status,
    size, timing — never content.
  * **Say what it did not record.** When the log write itself fails, that goes to stderr, so
    a silent logging outage does not read as a quiet system.
"""
import logging
import time
import uuid

logger = logging.getLogger(__name__)

# Health checks and the log endpoints themselves. A poller writing a row per second buries
# the requests somebody is actually trying to find, and a client-error report that logged
# its own delivery would recurse.
SKIP_PREFIXES = ("/api/health", "/api/version", "/api/opslog")

# 200 with an empty body is a real failure mode — a chart with nothing in it — and the status
# code alone cannot express it, so the size is kept for every response.
MAX_ERROR_CHARS = 8000


class RequestLogMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not request.path.startswith("/api/") or request.path.startswith(SKIP_PREFIXES):
            return self.get_response(request)

        request_id = str(uuid.uuid4())
        request.opslog_request_id = request_id
        started = time.monotonic()
        error_type = error_detail = ""

        try:
            response = self.get_response(request)
        except Exception as exc:                        # noqa: BLE001
            # Recorded and re-raised. Django's own handler still produces the 500; this only
            # makes sure the reason survives somewhere an analyst can read.
            import traceback
            error_type = type(exc).__name__
            error_detail = traceback.format_exc()[:MAX_ERROR_CHARS]
            self._write(request, request_id, 500, started, 0, error_type, error_detail)
            raise

        # The id travels back so a person can quote one value from the browser and have it
        # found here without guessing at timestamps.
        response["X-Request-Id"] = request_id

        size = 0
        try:
            size = len(response.content) if hasattr(response, "content") else 0
        except Exception:                               # streaming responses have no content
            size = -1

        if response.status_code >= 400:
            try:
                error_detail = (response.content[:MAX_ERROR_CHARS].decode("utf-8", "replace")
                                if hasattr(response, "content") else "")
                error_type = f"HTTP {response.status_code}"
            except Exception:
                pass

        self._write(request, request_id, response.status_code, started, size,
                    error_type, error_detail)
        return response

    def _write(self, request, request_id, status, started, size, error_type, error_detail):
        try:
            from .models import RequestLog

            user = getattr(request, "user", None)
            RequestLog.objects.create(
                request_id=request_id,
                method=request.method[:8],
                path=request.path[:512],
                query=request.META.get("QUERY_STRING", "")[:1024],
                status=status,
                duration_ms=int((time.monotonic() - started) * 1000),
                username=(getattr(user, "username", "") or "")[:150],
                role=(getattr(request, "opslog_role", "") or "")[:32],
                source=self._source(request),
                user_agent=request.META.get("HTTP_USER_AGENT", "")[:256],
                error_type=error_type[:128],
                error_detail=error_detail,
                response_bytes=size,
            )
        except Exception as exc:                        # noqa: BLE001
            # Never propagate. But never silent either — a logging outage that looks like a
            # quiet system is how you conclude nothing happened.
            logger.warning("request log not written for %s %s: %s",
                           request.method, request.path, exc)

    @staticmethod
    def _source(request):
        ua = request.META.get("HTTP_USER_AGENT", "").lower()
        if "mozilla" in ua or "chrome" in ua or "safari" in ua:
            return "browser"
        if "python" in ua or "requests" in ua or "curl" in ua:
            return "service"
        return ""
