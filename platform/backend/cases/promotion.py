"""
Promoting automated memory-analysis hits into adjudicable findings.

Volatility, YARA and the mwcp parsers produce leads, not conclusions. A YARA rule name is
not evidence that a host is compromised — the analyzer says so itself in the detail text of
an unattributed match. But those hits still belong in the same triage surface as collector
findings, because an analyst working an incident should not have to look in two places to
see what the platform knows about a host.

So each memory finding becomes a Finding with `source="memory"`, and the adjudication step
that follows decides its verdict.

Every lead enters at Indeterminate regardless of the severity the analyzer stamped on it.
Severity is how loud a rule is, not how likely the host is compromised, and promoting a
critical-severity match straight to Likely True Positive would be this module deciding
something it has no evidence for. The investigation engine makes that call afterwards,
from signal convergence and provenance — and a lead it cannot attribute to a process stays
Indeterminate, which is the correct answer for an unattributed rule match.
"""
from django.db import transaction

from .models import Finding, MemoryFinding

# Where every automated hit enters the ladder, before adjudication.
ENTRY_VERDICT = "Indeterminate"
ENTRY_CONFIDENCE = "Low"


def promote_memory_findings(analysis_run, batch_size=500):
    """Create a Finding for every memory finding on this run that does not have one.

    Returns the number promoted. Idempotent: re-running an analysis or re-promoting does
    not duplicate, which matters because re-analysis is a first-class workflow here.
    """
    run = analysis_run.capture.run
    # A synthetic capture's findings are planted content, not observations. They are still
    # promoted so the pipeline is visibly exercised end to end, but every one is labeled at
    # the source so no downstream reader — analyst, engine or export — has to infer it from
    # the capture record two joins away.
    synthetic = bool(analysis_run.capture.is_synthetic)
    pending = list(
        MemoryFinding.objects.filter(analysis=analysis_run, promoted_finding__isnull=True)
    )
    if not pending:
        return 0

    created = []
    with transaction.atomic():
        for mf in pending:
            evidence = mf.evidence or {}
            finding = Finding(
                run=run,
                finding_type=mf.finding_type[:255],
                # The target is what the hit was found in; memory findings carry it in
                # evidence, falling back to the offset so a row is never anonymous.
                target=(str(evidence.get("target") or "")
                        or (f"offset {mf.offset}" if mf.offset else "memory"))[:512],
                verdict=ENTRY_VERDICT,
                confidence=ENTRY_CONFIDENCE,
                mitre=evidence.get("mitre") or [],
                source="memory",
                subject_path="",
                raw={
                    "synthetic": synthetic,
                    "memory_finding_id": mf.id,
                    "analysis_id": analysis_run.id,
                    "engine": analysis_run.engine,
                    "ruleset_version": analysis_run.ruleset_version,
                    "severity": mf.severity,
                    "detail": mf.detail[:4000],
                    "offset": mf.offset,
                },
            )
            created.append((mf, finding))

        Finding.objects.bulk_create([f for _, f in created], batch_size=batch_size)
        for mf, finding in created:
            mf.promoted_finding = finding
        MemoryFinding.objects.bulk_update(
            [mf for mf, _ in created], ["promoted_finding"], batch_size=batch_size
        )

        # Compromise state is derived from verdicts, so it is re-evaluated once the leads
        # are in. A run is not "compromised" because a rule matched, but the evaluation
        # must see the same set the analyst sees.
        run.tp_count = run.findings.filter(verdict="True Positive").count()
        run.evaluate_compromise()
        run.save(update_fields=["tp_count", "compromised"])

    return len(created)
