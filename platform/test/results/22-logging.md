## Every tier's logs reach the archive and an admin can read them

*What passing proves:* A request crosses the ingress, the web tier and the API; each writes its own record; the shipper moves all of them into object storage away from evidence; and an admin reads and exports them through the platform rather than by shelling into the host. An analyst is refused throughout.

- Run: `uat_logging.sh` — 2026-08-14 23:53:17Z

**1/5  Every tier writes a log FILE, not just container output**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | an analyst and an admin, to test the read boundary |
| ✅ PASS | the API writes its application log to a file, not only to container output |
| ✅ PASS | and its access log too |
| ✅ PASS | this run's own request is in it (2 line(s) carrying uat-logging-1786751598) |
| ✅ PASS | the analysis worker writes its own, separately from the API's |
| ✅ PASS | and container output still works — the file copy did not replace it |

**2/5  The shipper moves them off the container into object storage**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the log shipper is running as its own service |
| ✅ PASS | a shipping pass completes and says what it moved |
| ✅ PASS | the archive is readable and lists 10 source(s) |
| ✅ PASS | backend-app reached object storage |
| ✅ PASS | backend-access reached object storage |
| ✅ PASS | so did the web tier's own logs |

**3/5  An admin reads them back through the platform, not by shelling into the host**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the objects for a source are listed newest first |
| ✅ PASS | and one can be read back, 9409 bytes of it |
| ✅ PASS | labelled as an operational record and NOT evidence — it carries no custody seal and must not imply one |
| ✅ PASS | THE LINE THIS RUN CAUSED IS IN THE ARCHIVE — written by a container, read through the API |

**4/5  Reading logs is admin-only**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | an analyst is refused /opslog/logs/sources/ |
| ✅ PASS | an analyst is refused /opslog/logs/objects/ |
| ✅ PASS | an analyst is refused /opslog/requests/ |
| ✅ PASS | an analyst is refused /opslog/client-errors/list/ |
| ✅ PASS | and cannot export one |
| ✅ PASS | a key that climbs out of the bucket is refused, even for an admin |

**5/5  Every privileged read of a log is itself in the audit ledger**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | reading a log is recorded (log.read) |
| ✅ PASS | and the ledger still verifies after them |
| ✅ PASS | the API's own request log is readable alongside the archive (50 row(s)) |

**Verdict: PROVEN** — 25 assertions passed, 0 failed.
