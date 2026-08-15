"""
Celery tasks — server-side memory analysis.

The endpoint captures memory only; this worker pulls the stored image from object
storage and analyzes it centrally, so the same capture can be re-analyzed later at a
newer detection version (the historical-analysis goal).
"""
import os
import socket
import re
import shutil
import tempfile

from celery import shared_task
from django.utils import timezone

from . import audit, retention, storage
from . import investigation, promotion
from . import symbols as symbols_mod
from .analysis import memory_linux, vol3
from .models import MemoryAnalysisRun, MemoryCapture, MemoryFinding


def _yara_triggers_by_pid(analysis_run):
    """The signature hits that caused carving, grouped by the process they landed on.

    The analyzer records a YARA match as its own finding and names the region it carved
    after the PID. Pairing them here is what lets the reverse-engineering queue state which
    rule fired, on which strings, in what kind of memory — rather than presenting a blob
    with a filename.
    """
    triggers = {}
    for mf in MemoryFinding.objects.filter(
        analysis=analysis_run, finding_type__startswith="YARA Memory"
    ):
        detail = mf.detail or ""
        target = (mf.evidence or {}).get("target", "")
        pid_match = re.search(r"PID\s+(\d+)", target) or re.search(r"PID\s+(\d+)", detail)
        if not pid_match:
            continue
        rule = target.split("::")[0].strip() or "unnamed rule"
        strings = re.search(r"Matched strings:\s*([^.\[]+)", detail)
        perms = re.search(r"in (\w+ [-rwx]{3}) memory", detail)
        # The analyzer appends what each string actually matched, as
        # `[$id @ 0xoffset] 'excerpt'`. The identifier alone is not reviewable: it names the
        # slot in the rule, not the content, and cannot distinguish a real C2 string from a
        # rule matching its own source text quoted in a buffer.
        matches = [
            {"id": mid, "offset": off, "text": text}
            for mid, off, text in re.findall(
                r"\[(\$[\w.]+) @ (0x[0-9a-fA-F]+)\] '((?:[^'\\]|\\.)*)'", detail)
        ]
        triggers.setdefault(int(pid_match.group(1)), []).append({
            "rule": rule,
            "severity": mf.severity,
            "matched_strings": strings.group(1).strip() if strings else "",
            "matches": matches,
            "memory": perms.group(1) if perms else "",
            "detail": detail[:600],
        })
    return triggers


def _store_carved(capture, carve_dir, analysis_run):
    """Persist carved regions and register them for reverse engineering.

    Two things happen per region: the bytes go to the host's own bucket, and a row is
    created so the region enters the reverse-engineering queue. Without the row a region
    is just an object in a bucket that nobody is accountable for examining.
    """
    import glob
    import hashlib

    from .models import CarvedRegion

    hostname = capture.run.host.hostname
    triggers = _yara_triggers_by_pid(analysis_run)
    stored = 0
    for path in sorted(glob.glob(os.path.join(carve_dir, "*.bin"))):
        name = os.path.basename(path)
        key = f"{capture.run.investigation_id}/{capture.id}/{name}"
        try:
            result = storage.put_carved_region(hostname, path, key)
        except Exception:  # noqa: BLE001
            # A region that fails to upload is not worth losing the analysis over; the
            # count in the summary is what tells an operator something is missing.
            continue

        digest = hashlib.sha256()
        try:
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                    digest.update(chunk)
        except OSError:
            pass

        # The analyzer names carved files after their origin, as
        # `pid<PID>_<process>_0x<address>.bin`, so provenance is recoverable without a
        # second lookup. The process name is pulled out rather than storing the filename:
        # the queue shows this column to identify what a region came from, and a filename
        # there tells an analyst nothing they cannot already see.
        origin = re.match(r"pid[_-]?(\d+)[_-](.+?)[_-]0x[0-9a-fA-F]+", name, re.IGNORECASE)
        pid_match = origin or re.search(r"pid[_-]?(\d+)", name, re.IGNORECASE)
        CarvedRegion.objects.get_or_create(
            analysis=analysis_run,
            object_key=result["key"],
            defaults={
                "bucket": result["bucket"],
                "size_bytes": result["size"],
                "sha256": digest.hexdigest(),
                "carved_by": "yara",
                "source_pid": int(pid_match.group(1)) if pid_match else None,
                # Falls back to the filename when the name does not parse, so a region is
                # never left with nothing identifying it.
                "source_process": origin.group(2) if origin else name,
                "trigger": {
                    "hits": triggers.get(
                        int(pid_match.group(1)) if pid_match else -1, []),
                },
            },
        )
        stored += 1
    return stored


@shared_task(bind=True)
def analyze_capture(self, capture_id, ruleset_version=""):
    capture = MemoryCapture.objects.get(pk=capture_id)

    # Refuse to analyze a capture that is already being analyzed. Killing the worker mid-analysis
    # leaves the task un-acked, so the broker redelivers it when the worker comes back — and if
    # anyone queued a replacement in the meantime, both run.
    active = (MemoryAnalysisRun.objects
              .filter(capture=capture, status="running")
              .order_by("id").first())
    if active:
        return {"analysis_id": active.id, "status": "already running",
                "detail": f"capture {capture_id} is already being analyzed by run {active.id}"}

    run = MemoryAnalysisRun.objects.create(
        capture=capture,
        engine="native-scan",
        ruleset_version=ruleset_version or "current",
        status="running",
        started_at=timezone.now(),
        # Which worker performed this analysis. Reproducibility material like the engine and
        # ruleset versions — with replicas consuming one queue, "who analyzed it" is no
        # longer answerable any other way — and the UAT's proof that N workers really share
        # the load reads exactly this.
        summary={"analysis_worker": os.environ.get("IR_HEALTH_REPORT_ROLE", "worker"),
                 "analysis_container": socket.gethostname()},
    )
    tmp_dir = tempfile.mkdtemp(prefix="ir-mem-")
    local = os.path.join(tmp_dir, "capture.bin")
    report_dir = ""   # bound before the try so cleanup runs even on an early failure
    try:
        # Volatility needs a seekable local file, so the capture is staged before analysis.
        # Check the staging area can hold it first: running out of room mid-download wastes
        # the whole transfer and surfaces as an opaque ENOSPC deep inside the S3 client.
        free = shutil.disk_usage(tmp_dir).free
        needed = int(capture.size_bytes or 0)
        if needed and free < needed * 1.05:
            raise RuntimeError(
                f"staging area has {free // (1024**3)} GiB free but the capture needs "
                f"{needed // (1024**3)} GiB — point TMPDIR at a disk-backed volume "
                f"large enough for the captures this deployment ingests"
            )
        storage.download_to(capture.object_key, local)

        # Prefer the toolkit's full Volatility pass. It needs a symbol table matching the captured
        # kernel, which the enclave cannot fetch itself — when one is absent an administrator is asked
        # for it and this run proceeds at reduced depth, labeled as such so the UI never implies a full
        # analysis happened.
        raw_timeout = os.environ.get("IR_VOL3_TIMEOUT", "10800")
        try:
            vol_timeout = int(raw_timeout)
        except (TypeError, ValueError):
            vol_timeout = 10800

        isf = symbols_mod.find_isf(capture)
        findings, summary, engine = [], {}, "native-scan"
        if isf and vol3.available():
            try:
                findings, summary, carve_dir = vol3.analyze(
                    local, isf, ruleset_version=run.ruleset_version, timeout=vol_timeout,
                    host_label=capture.run.host.hostname,
                )
                report_dir = summary.pop("report_dir", "")
                engine = vol3.ENGINE
                # Carved regions are live malware and the input to reverse engineering.
                # They go to the host's own bucket, never mixed with other cases.
                summary["carved_stored"] = _store_carved(capture, carve_dir, run)
            except Exception as exc:  # noqa: BLE001
                # A failed deep pass degrades to the structural scan rather than losing the
                # analysis outright. The reason is recorded on the run AND saved
                # immediately: a fallback that is only visible once the whole run finishes
                # looks like a successful analysis while it is happening.
                run.error = f"volatility pass failed, fell back to structural scan: {exc}"[:2000]
                run.save(update_fields=["error"])
        else:
            symbols_mod.request_symbols(capture)

        if engine == "native-scan":
            yara_dir = os.environ.get("IR_YARA_RULES_DIR") or None
            result = memory_linux.analyze(local, ruleset_version=run.ruleset_version,
                                          yara_rules_dir=yara_dir)
            findings = result["findings"]
            summary = result["summary"]
            summary["reduced_depth"] = True
            summary["reason"] = ("no symbol table for this kernel — awaiting acquisition"
                                 if not isf else "volatility pass unavailable")
            run.engine_version = result.get("engine_version", "")

        run.engine = engine
        result = {"findings": findings, "summary": summary}

        MemoryFinding.objects.bulk_create([
            MemoryFinding(
                analysis=run,
                finding_type=f["finding_type"][:255],
                severity=f.get("severity", ""),
                detail=f.get("detail", ""),
                offset=f.get("offset"),
                evidence=f.get("evidence", {}),
            ) for f in result["findings"]
        ])
        # Merge, never assign: the run's own attribution (which worker, which container)
        # was written at start and must survive the analyzer's summary landing.
        run.summary = {**run.summary, **result["summary"]}
        run.status = "completed"
        # Automated hits enter the analyst's triage queue as findings. Without this the
        # results are visible only on the capture panel and never get adjudicated.
        promoted = promotion.promote_memory_findings(run)
        result["summary"]["promoted_findings"] = promoted
        run.finished_at = timezone.now()
        run.save()

        # Adjudication. The toolkit's investigation engine runs on the analyzer's own report folder and
        # decides which processes are true positives; the platform does not make that call itself.
        adjudication = investigation.adjudicate(run, report_dir)
        run.summary["adjudication"] = adjudication
        run.save(update_fields=["summary"])

        audit.custody(capture.run, "analyze", "celery-worker",
                      {"capture_id": capture.id, "analysis_id": run.id,
                       "engine": run.engine, "findings": len(result["findings"])})

        # Retention lifecycle: purge a clean host's capture; retain a compromised one.
        disposition = retention.apply_retention_after_analysis(capture, actor="celery-worker")
        run.summary["retention"] = disposition
        run.save(update_fields=["summary"])
    except Exception as exc:  # analysis failure is recorded, never silently dropped
        run.status = "failed"
        run.error = f"{type(exc).__name__}: {exc}"
        run.finished_at = timezone.now()
        run.save()
        raise
    finally:
        try:
            os.remove(local)
            os.rmdir(tmp_dir)
        except OSError:
            pass
        # The report folder holds the carved regions and the staged collector findings.
        # Both have been persisted by now — regions to the host's bucket, verdicts to the
        # database — and it is sized like the capture, so leaving it behind fills the
        # staging volume and the next analysis fails its capacity preflight.
        if report_dir and os.path.isdir(report_dir):
            shutil.rmtree(os.path.dirname(report_dir), ignore_errors=True)
    return {"analysis_id": run.id, "status": run.status}
