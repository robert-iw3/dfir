"""
Adjudication — running the toolkit's investigation engine, not substituting for it.

A memory pass produces leads. Deciding which of them means the host is compromised is a
separate act, and the toolkit already does it: `investigation/` correlates independent
signals onto a PID, rebuilds process lineage into an attack chain, matches named TTP
patterns, and applies the verdict ladder. That logic is validated offline against real
cases, and it is the reason the workflow says provenance is the verdict rather than the
rule name.

So the platform runs it. This module hands the engine the analyzer's own report folder —
the same directory layout it consumes on an analyst's machine — and reads the report it
writes back. A verdict shown in the UI is the verdict the engine reached, byte for byte,
not a severity mapped through a table here.

Two inputs are added to the folder before the engine runs, because the platform holds
them in the database rather than on disk:

  * `EDR_Report_*.json` — the collector's findings, verbatim as posted. These carry the
    provenance fields the engine weighs most heavily (package ownership, package integrity,
    path trust), which memory findings alone do not have. Without them the engine can still
    run, but almost everything lands Undetermined: memory shows what a process is doing,
    while provenance is what decides whether that is legitimate.
  * `Adjudication_*.json` — the on-host adjudication those findings arrived with. The
    engine compares its own conclusions against it and reports where they disagree, which
    is how a missed detection surfaces.

The engine runs as a subprocess, like the analyzer: it is toolkit code, it is noisy on
stdout, and a failure in it must not take down the worker.
"""
import glob
import json
import os
import re
import shutil
import subprocess
import tempfile

from django.db import transaction
from django.utils import timezone

from . import audit
from .models import Finding, ProcessVerdict

TOOLKIT = os.environ.get("IR_TOOLKIT_DIR", "/opt/toolkit")
ENGINE_MODULE = "playbooks.linux.investigation.live_runner"

PID_IN_TARGET = re.compile(r"\b(?:pid|PID)[\s:=#]*(\d{1,7})\b")

# Findings that report on the analysis rather than on the host. They are attributed to a
# PID like any other, but they assert nothing about it and must never inherit its verdict.
NON_DETECTION_TYPES = (
    "YARA Scan Coverage Incomplete",
    "Unnamed Carved Module",
)

# Engine label -> the platform's verdict vocabulary. This is a rename, not a judgement:
# each engine label has exactly one counterpart on the ladder the collector already uses.
VERDICT_LABEL = {
    "True Positive": "True Positive",
    "Undetermined": "Indeterminate",
    "False Positive": "Likely False Positive",
    "Noise Closed": "Likely False Positive",
}

# How much weight the engine put behind a true positive, expressed as the confidence the
# rest of the platform speaks in. The engine's weight is a sum of independent positive
# dimensions, so these thresholds are "how many things had to agree".
def _confidence(weight):
    if weight >= 6:
        return "High"
    if weight >= 3:
        return "Medium"
    return "Low"


def available():
    """Whether this image carries the investigation engine."""
    return os.path.isdir(os.path.join(TOOLKIT, "playbooks/linux/investigation"))


def stage_collector_context(report_dir, run):
    """Write the collector's findings and prior adjudication into the report folder.

    Returns the number of records staged. The engine treats both files as optional, so a
    run with no collector bundle still adjudicates — on memory evidence alone, which is
    exactly what the engine does when it is handed a capture and nothing else.
    """
    records = [
        f.raw for f in Finding.objects.filter(run=run, source="collector").only("raw")
        if isinstance(f.raw, dict) and f.raw
    ]
    if not records:
        return 0

    stamp = run.stamp or timezone.now().strftime("%Y%m%d_%H%M%S")
    # Written as EDR_Report, which is the file the on-host hunt produces and the name the
    # engine treats as primary evidence. Combined_Findings is only a fallback the engine
    # reads when nothing else is present, so staging under that name would mean the
    # collector's findings were silently ignored on every run that has memory findings —
    # that is, every run.
    with open(os.path.join(report_dir, f"EDR_Report_{stamp}.json"),
              "w", encoding="utf-8") as fh:
        json.dump(records, fh)

    # adjudicate.py enriches the combined findings in place, so the adjudication file is
    # the subset that came back carrying a verdict. Anything without one was never
    # adjudicated on the host and must not be presented as a prior decision.
    adjudicated = [r for r in records if r.get("Verdict") or r.get("verdict")]
    if adjudicated:
        with open(os.path.join(report_dir, f"Adjudication_{stamp}.json"),
                  "w", encoding="utf-8") as fh:
            json.dump(adjudicated, fh)

    return len(records)


def materialize_report_dir(analysis_run, dest):
    """Rebuild a report folder for an analysis from what the database holds.

    The live path adjudicates the analyzer's own output directory, which is deleted with
    the staged capture once the run finishes. This reconstructs an equivalent folder from
    the stored findings, so an analysis can be re-adjudicated later — at a newer engine
    version, or after the collector bundle for the same host arrives — without re-running
    Volatility over a 24 GB image.

    Memory findings are written back in the analyzer's own field names, because that is
    the vocabulary the engine parses. Returns the report directory.
    """
    from .models import MemoryFinding

    run = analysis_run.capture.run
    report_dir = os.path.join(dest, _safe(run.host.hostname) or "unknown-host")
    os.makedirs(report_dir, exist_ok=True)
    stamp = run.stamp or timezone.now().strftime("%Y%m%d_%H%M%S")

    records = []
    for mf in MemoryFinding.objects.filter(analysis=analysis_run).iterator():
        ev = mf.evidence or {}
        # MITRE goes back as the analyzer wrote it: a comma-separated string. The platform
        # stores it as a list because the rest of the API treats techniques as a list, and
        # writing that list back into the report folder hands the engine a shape it does not
        # parse — it splits each entry as text.
        mitre = ev.get("mitre") or []
        if isinstance(mitre, (list, tuple)):
            mitre = ", ".join(str(m) for m in mitre)
        records.append({
            "Type": mf.finding_type,
            "Target": ev.get("target", ""),
            "Details": mf.detail,
            "Severity": mf.severity,
            "MITRE": str(mitre),
            "Timestamp": ev.get("observed_at", ""),
            "Source": "Memory",
        })
    with open(os.path.join(report_dir, f"Memory_Findings_{stamp}.json"),
              "w", encoding="utf-8") as fh:
        json.dump(records, fh)

    stage_collector_context(report_dir, run)
    return report_dir


def _safe(value):
    return re.sub(r"[^A-Za-z0-9._-]", "_", str(value or "")).strip("._-")[:64]


def run_engine(report_dir, timeout=1800):
    """Run the investigation engine over a report folder and return its report dict.

    Returns None when the engine declined to run (no usable findings) — a legitimate
    outcome, not an error.
    """
    if not available():
        raise RuntimeError(f"investigation engine not present under {TOOLKIT}")

    env = dict(os.environ)
    # The engine imports as `playbooks.linux.investigation`; the toolkit root is what makes
    # that package path resolvable.
    env["PYTHONPATH"] = TOOLKIT + os.pathsep + env.get("PYTHONPATH", "")

    proc = subprocess.run(
        ["python3", "-m", ENGINE_MODULE, report_dir],
        capture_output=True, text=True, timeout=timeout, env=env,
        cwd=TOOLKIT, check=False,
    )

    reports = sorted(glob.glob(os.path.join(report_dir, "Investigation_*.json")))
    if not reports:
        tail = (proc.stderr or proc.stdout or "").strip().splitlines()[-3:]
        if proc.returncode == 0:
            # The engine says so explicitly when there is nothing to work with.
            return None
        raise RuntimeError(f"investigation engine produced no report: {' | '.join(tail)}")

    with open(reports[-1], "r", encoding="utf-8") as fh:
        return json.load(fh)


@transaction.atomic
def persist(analysis_run, report):
    """Record the engine's per-PID verdicts and apply them to the findings.

    Re-analysis replaces the previous adjudication for the run rather than accumulating:
    the engine's output is derived from evidence, so a newer pass over the same evidence
    supersedes the older one.
    """
    run = analysis_run.capture.run
    summary = report.get("summary", {}) or {}

    ProcessVerdict.objects.filter(run=run).delete()

    rows = []
    for label, entries in (("True Positive", report.get("true_positives") or []),
                           ("Undetermined", report.get("undetermined") or []),
                           ("Noise Closed", report.get("noise_closed") or [])):
        for e in entries:
            weight = float(e.get("positive_weight") or 0)
            rows.append(ProcessVerdict(
                run=run,
                analysis=analysis_run,
                pid=int(e.get("pid") or 0),
                process=str(e.get("process") or "")[:255],
                engine_label=label,
                verdict=VERDICT_LABEL.get(label, "Indeterminate"),
                confidence=_confidence(weight) if label == "True Positive" else "Low",
                positive_weight=weight,
                rationale=str(e.get("rationale") or "")[:8000],
                sources=e.get("sources") or [],
                mitre=e.get("mitre") or [],
                positive_dims=e.get("positive_dims") or [],
                prior_adjudication=str(e.get("prior_adj") or "")[:64],
            ))
    ProcessVerdict.objects.bulk_create(rows, batch_size=500)

    # The chains, TTP matches and disagreements with the on-host adjudication are the
    # engine's narrative output. They belong to the run as a whole, not to one PID.
    analysis_run.investigation = {
        "summary": summary,
        "attack_chains": report.get("attack_chains") or [],
        "ttp_pattern_matches": report.get("ttp_pattern_matches") or [],
        # Where the engine and the on-host adjudication disagree. A miss is the engine
        # calling something suspicious that the host closed; an unconfirmed prior TP is the
        # reverse. Both are review items, not results.
        "potential_misses": report.get("potential_misses") or [],
        "unconfirmed_prior_tps": report.get("unconfirmed_prior_tps") or [],
        "generated": summary.get("generated", ""),
    }
    analysis_run.save(update_fields=["investigation"])

    applied = _apply_to_findings(run, rows)

    # A host is compromised when the engine says a process on it is a true positive. That
    # decision now comes from the engine rather than from counting rule matches.
    run.tp_count = run.findings.filter(verdict="True Positive").count()
    run.evaluate_compromise()
    run.save(update_fields=["tp_count", "compromised"])

    audit.custody(run, "adjudicate", "investigation-engine", {
        "analysis_id": analysis_run.id,
        "pids": len(rows),
        "true_positive": summary.get("true_positive", 0),
        "undetermined": summary.get("undetermined", 0),
        "noise_closed": summary.get("noise_closed", 0),
        "chains": len(report.get("attack_chains") or []),
        "findings_updated": applied,
    })
    return {"pids": len(rows), "findings_updated": applied, **summary}


def _apply_to_findings(run, verdicts):
    """Carry each process verdict onto the findings attributed to that process.

    The engine judges processes; the triage queue lists findings. A finding belonging to a
    process the engine called a true positive is a true positive — that is the whole point
    of correlating onto a PID. Findings the engine could not attribute to any process keep
    whatever verdict they already had, which for a memory lead is Indeterminate: an
    unattributed rule match is precisely the case the workflow says not to act on alone.
    """
    # `is not None`, not truthiness: PID 0 is the engine's bucket for findings it could not
    # attribute to any process — an unattributed full-image YARA sweep lands there, and on a
    # real capture that is most of them. Treating 0 as absent silently excluded the largest
    # group of findings the engine had actually judged.
    by_pid = {v.pid: v for v in verdicts if v.pid is not None}
    if not by_pid:
        return 0

    updated = []
    for f in Finding.objects.filter(run=run).only(
        "id", "verdict", "confidence", "raw", "target", "finding_type"
    ):
        # Diagnostics describe the analysis, not the host. "YARA Scan Coverage Incomplete"
        # reports that a scan gave up early; inheriting a process's true-positive verdict
        # would assert that an incomplete scan is evidence of compromise.
        #
        # A previously inherited verdict is cleared rather than left alone, so re-running
        # adjudication repairs rows stamped before this rule existed.
        if any(f.finding_type.startswith(p) for p in NON_DETECTION_TYPES):
            raw = f.raw if isinstance(f.raw, dict) else {}
            if raw.pop("adjudication", None) or f.verdict != "Indeterminate":
                f.verdict, f.confidence, f.raw = "Indeterminate", "Low", raw
                updated.append(f)
            continue
        pid = _finding_pid(f)
        # A finding with no PID in it is unattributed, and unattributed is where the engine
        # files it too — under PID 0, its `[host/kernel]` pseudo-process. Matching that
        # convention is what lets the engine's judgement of the unattributed set reach the
        # findings in it, rather than leaving them looking unexamined.
        if pid is None:
            pid = 0
        v = by_pid.get(pid)
        if v is None:
            continue

        stamp = {
            "by": "investigation-engine",
            "engine_label": v.engine_label,
            "pid": v.pid,
            "process": v.process,
            "positive_weight": v.positive_weight,
            "rationale": v.rationale[:1000],
        }
        raw = f.raw if isinstance(f.raw, dict) else {}
        # The stamp is written whenever the engine reached a conclusion about this
        # process, including when that conclusion matches the verdict the finding already
        # carried. Skipping the unchanged case looked like an optimization and was a bug:
        # the engine's most common conclusion is Undetermined, which maps to the same
        # Indeterminate a promoted lead starts at, so every one of those findings ended up
        # indistinguishable from one the engine had never looked at.
        if f.verdict == v.verdict and f.confidence == v.confidence \
           and raw.get("adjudication") == stamp:
            continue

        f.verdict = v.verdict
        f.confidence = v.confidence
        raw["adjudication"] = stamp
        f.raw = raw
        updated.append(f)

    Finding.objects.bulk_update(updated, ["verdict", "confidence", "raw"], batch_size=500)
    return len(updated)


def _finding_pid(finding):
    """The PID a finding is attributed to, using the collector's own convention first."""
    raw = finding.raw if isinstance(finding.raw, dict) else {}
    for key in ("Pid", "PID", "pid"):
        if raw.get(key) not in (None, ""):
            try:
                return int(raw[key])
            except (TypeError, ValueError):
                pass
    # Otherwise the PID is in the text. The engine reads Target first and falls back to
    # Details; matching the same two fields in the same order is what keeps a finding
    # attached to the process the engine attached it to.
    for text in (finding.target, raw.get("Details") or raw.get("detail") or ""):
        m = PID_IN_TARGET.search(str(text))
        if m:
            return int(m.group(1))
    return None


def adjudicate(analysis_run, report_dir=None, timeout=1800):
    """Stage, run and persist — the whole adjudication step for one analysis.

    `report_dir` is the analyzer's own output folder when a Volatility pass produced one.
    Without it — a reduced-depth run, or a re-adjudication long after the fact — the folder
    is rebuilt from stored findings instead. A run still gets adjudicated either way: the
    engine's job is to judge the evidence that exists, and a host analyzed at reduced depth
    is exactly the one an analyst most needs a verdict on.

    Never raises: a failed adjudication leaves the analysis and its findings intact and
    records why. Losing a completed memory pass because the verdict step failed would be a
    worse outcome than an un-adjudicated run someone can re-run.
    """
    tmp = None
    try:
        if not report_dir or not os.path.isdir(report_dir):
            tmp = tempfile.mkdtemp(prefix="ir-adjudicate-")
            report_dir = materialize_report_dir(analysis_run, tmp)
        staged = stage_collector_context(report_dir, analysis_run.capture.run)
        report = run_engine(report_dir, timeout=timeout)
        if report is None:
            return {"ran": False, "reason": "engine found no usable findings",
                    "collector_records": staged}
        result = persist(analysis_run, report)
        return {"ran": True, "collector_records": staged, **result}
    except Exception as exc:  # noqa: BLE001
        return {"ran": False, "reason": f"{type(exc).__name__}: {exc}"[:500]}
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)
