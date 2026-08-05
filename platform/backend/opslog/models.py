"""Operational request logging — its own database, deliberately.

**Not evidence.** Nothing here is under chain of custody and nothing here may ever be cited in
a report. It exists to answer one question an analyst cannot otherwise answer: *the page went
blank — what did it ask for, and what came back?*

Held in a third database beside `cases` and `correlation` for the same reason those two are
apart, only more so. Request logs are the highest-volume thing the platform writes: a single
analyst session produces more rows than a whole engagement's findings. In the evidence
database they would compete with collection for I/O, ride every evidence backup, and inflate
the restore of a case bundle with traffic nobody will ever read. And the retention rules are
opposite — evidence is kept because it is evidence, request logs are discarded because they
are not.

The separation is also a safety property: this app has no foreign key into `cases`, so a
runaway log volume, a truncation, or a bad migration here cannot touch the record of an
investigation.
"""
from django.db import models


class RequestLog(models.Model):
    """One API call: what was asked, what came back, how long it took, and for whom."""

    # A request id shared with the response header, so a person looking at a failure in the
    # browser can quote one value and have it found here.
    request_id = models.CharField(max_length=36, db_index=True)
    at = models.DateTimeField(auto_now_add=True, db_index=True)
    method = models.CharField(max_length=8)
    path = models.CharField(max_length=512, db_index=True)
    query = models.CharField(max_length=1024, blank=True)
    status = models.IntegerField(db_index=True)
    duration_ms = models.IntegerField(default=0)
    username = models.CharField(max_length=150, blank=True, db_index=True)
    role = models.CharField(max_length=32, blank=True)
    # Where the call came from, for separating the SPA from the collectors and the workers.
    source = models.CharField(max_length=32, blank=True)
    user_agent = models.CharField(max_length=256, blank=True)
    # Populated only when something went wrong. A traceback on every request would make the
    # table unreadable and is the one thing that must never be truncated when it matters.
    error_type = models.CharField(max_length=128, blank=True)
    error_detail = models.TextField(blank=True)
    # Response size, because "returned 200 with nothing in it" is a real failure mode and the
    # status code alone cannot express it.
    response_bytes = models.IntegerField(default=0)

    class Meta:
        ordering = ["-at"]
        indexes = [
            # The two reads that matter: what failed recently, and what one session did.
            models.Index(fields=["-at", "status"]),
            models.Index(fields=["username", "-at"]),
        ]

    def __str__(self):
        return f"{self.method} {self.path} -> {self.status} ({self.duration_ms}ms)"


class ClientError(models.Model):
    """A failure the browser saw: a render crash, or a request that never reached the API.

    Without this a blank page leaves no trace anywhere — the server logged a clean 200 for
    every call it answered, and the exception that unmounted the view existed only in one
    person's console, on a kiosk with no way to copy it out.
    """

    at = models.DateTimeField(auto_now_add=True, db_index=True)
    request_id = models.CharField(max_length=36, blank=True, db_index=True)
    username = models.CharField(max_length=150, blank=True, db_index=True)
    where = models.CharField(max_length=256, blank=True)   # route or component
    url = models.CharField(max_length=1024, blank=True)
    message = models.TextField(blank=True)
    stack = models.TextField(blank=True)
    component_stack = models.TextField(blank=True)
    user_agent = models.CharField(max_length=256, blank=True)

    class Meta:
        ordering = ["-at"]

    def __str__(self):
        return f"{self.where}: {self.message[:80]}"
