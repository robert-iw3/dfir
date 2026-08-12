"""
The investigation record — everything asserted about an incident, in one place.

Analytic work is scattered across the platform by necessity: an analyst adjudicates a
finding on the triage screen, writes a note against a host, and a reverse engineer records
a determination about a carved region from a workstation that has no route back here. Each
of those is a claim about the same incident, and each is only meaningful alongside the
others — a downgraded YARA hit reads very differently next to an RE's determination that
the region it fired on was a false positive.

So they are assembled chronologically into one record. Nothing here is derived or inferred:
every entry is something a named person wrote, with the reason they gave and the time they
gave it. That is what makes it usable as a case record rather than as a UI convenience.

Entries carry `occurred_at` where the author supplied one — an incident timeline built from
row-creation times describes the responders' working hours, not the intrusion.
"""
from .models import CarvedRegion, FindingReclassification, Note, RegionAnalysis


def _actor(*candidates):
    for c in candidates:
        if c:
            return c
    return "unknown"


def case_record(investigation, limit=500):
    """Every annotation on this investigation, newest first.

    Returns a list of uniform entries so a caller can render one timeline rather than four
    separate lists that have to be mentally interleaved.
    """
    entries = []

    for n in (Note.objects
              .filter(investigation=investigation)
              .select_related("host", "run")
              .prefetch_related("findings")):
        entries.append({
            "type": "note",
            "id": n.id,
            "at": n.effective_at,
            "recorded_at": n.created_at,
            "actor": _actor(n.author),
            "role": n.author_role,
            "kind": n.kind,
            "host": n.host.hostname if n.host else "",
            "summary": n.summary or n.body[:120],
            "body": n.body,
            "confidence": n.confidence,
            "mitre": n.mitre,
            "tags": n.tags,
            "evidence": [{"finding_id": f.id, "type": f.finding_type, "target": f.target}
                         for f in n.findings.all()[:20]],
            "retracted": n.retracted,
            "retraction_reason": n.retraction_reason,
        })

    # The record is a timeline of what people asserted. An engine pass is already one entry here —
    # the `adjudicate` custody event, carrying how many findings it moved — so its per-finding rows
    # are the detail behind that entry rather than entries themselves.
    for r in (FindingReclassification.objects
              .filter(investigation=investigation)
              .exclude(actor="investigation-engine")
              .select_related("finding", "finding__run__host")):
        entries.append({
            "type": "reclassification",
            "id": r.id,
            "at": r.created_at,
            "recorded_at": r.created_at,
            "actor": _actor(r.actor),
            "role": r.role,
            "kind": "adjudication",
            "host": r.finding.run.host.hostname if r.finding_id else "",
            "summary": (f"{r.finding.finding_type}: {r.from_verdict or 'unset'} "
                        f"→ {r.to_verdict}") if r.finding_id else r.to_verdict,
            "body": r.note,
            "from_verdict": r.from_verdict,
            "to_verdict": r.to_verdict,
            "from_confidence": r.from_confidence,
            "to_confidence": r.to_confidence,
            "evidence": ([{"finding_id": r.finding_id,
                           "type": r.finding.finding_type,
                           "target": r.finding.target}] if r.finding_id else []),
        })

    for a in (RegionAnalysis.objects
              .filter(investigation=investigation)
              .select_related("region", "region__analysis__capture__run__host")):
        host = ""
        if a.region_id:
            host = a.region.analysis.capture.run.host.hostname
        entries.append({
            "type": "region_analysis",
            "id": a.id,
            "at": a.created_at,
            "recorded_at": a.created_at,
            "actor": _actor(a.analyst),
            "role": "reverse_engineer",
            "kind": "reverse_engineering",
            "host": host,
            "summary": (f"region {a.region_id}: {a.verdict}"
                        + (f" — {a.malware_family}" if a.malware_family else "")),
            "body": a.statement or a.notes,
            "verdict": a.verdict,
            "confidence": a.confidence,
            "malware_family": a.malware_family,
            "capability": a.capability,
            "mitre": a.mitre,
            "indicators": a.indicators,
            "network_indicators": a.network_indicators,
            "evidence": ([{"finding_id": a.finding_id}] if a.finding_id else []),
        })

    # A purge destroys evidence. It is the one action in the platform that cannot be undone,
    # so its statement belongs in the record next to the analysis that justified it.
    for reg in (CarvedRegion.objects
                .filter(analysis__capture__run__investigation=investigation,
                        purged_at__isnull=False)
                .select_related("analysis__capture__run__host")):
        entries.append({
            "type": "region_purge",
            "id": reg.id,
            "at": reg.purged_at,
            "recorded_at": reg.purged_at,
            "actor": _actor(reg.purged_by),
            "role": "reverse_engineer",
            "kind": "evidence_disposal",
            "host": reg.analysis.capture.run.host.hostname,
            "summary": f"region {reg.id} purged from object storage",
            "body": reg.purge_statement or reg.purge_reason,
            "reason": reg.purge_reason,
            "pre_purge_sha256": reg.pre_purge_sha256,
            "evidence": [],
        })

    entries.sort(key=lambda e: e["at"], reverse=True)
    return entries[:limit]


def record_summary(entries):
    """Counts by entry type and by author, for the header above the record."""
    by_type, by_actor = {}, {}
    for e in entries:
        by_type[e["type"]] = by_type.get(e["type"], 0) + 1
        by_actor[e["actor"]] = by_actor.get(e["actor"], 0) + 1
    return {"total": len(entries), "by_type": by_type, "contributors": by_actor}
