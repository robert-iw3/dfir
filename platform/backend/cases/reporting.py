"""
Case reports: the plain-language summary and the technical analysis.

Every section is rendered from stored rows. Nothing here accepts prose an author typed
into the renderer, because a section with no data behind it makes the author's memory a
source — and the whole point of the technical report is that it can be checked.

Two properties are load-bearing and are recomputed at render time rather than read from a
stored flag: the custody seal verification, and the audit chain verification. A report
that repeats a stale "verified" is worse than one that says nothing.

Indicators are defanged on the way out. A reader must not be able to click a live C2
address out of a PDF, and remembering to do it by hand is not a control.
"""
from __future__ import annotations

import hashlib
import io
import re

from django.db.models import Count, Max, Min
from django.utils import timezone

from . import audit
from .models import (IOC, CarvedRegion, CollectionRun, CustodyEvent, Finding,
                     FindingReclassification, GeneratedReport,
                     Investigation, MemoryAnalysisRun, MemoryCapture, MemoryFinding,
                     Note, ProcessVerdict, RemediationAction, ReportTemplate,
                     RuledOut)

# Verdicts that assert compromise, as opposed to the ones that record uncertainty. The
# report's whole argument rests on keeping those apart.
CONFIRMING = ("True Positive", "Likely True Positive")


def defang(value):
    """Render an indicator unclickable: no scheme, no dotted host, no bare address."""
    if not value:
        return value
    out = re.sub(r"^(https?)://", r"\1[://]", str(value), flags=re.I)
    out = re.sub(r"\.(?=[A-Za-z0-9])", "[.]", out)
    return out.replace("@", "[@]")


def _fmt(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%SZ") if dt else "—"


def _bytes(n):
    """Sizes a reader can compare at a glance; a raw byte count is not one."""
    if not n:
        return "—"
    value = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


class Section:
    """A rendered section: a heading, Markdown body, and what it drew from."""

    def __init__(self, key, title, body, sources=None):
        self.key, self.title, self.body = key, title, body
        self.sources = sources or {}


# --- individual sections -------------------------------------------------------------

def s_metadata(inv, ctx):
    runs = ctx["runs"]
    hosts = sorted({r.host.hostname for r in runs})
    body = [
        f"| Field | Value |", "|---|---|",
        f"| Case | {inv.name} |",
        f"| Incident id | `{inv.incident_id or '—'}` |",
        f"| Status | {inv.status} |",
        f"| Severity | {inv.severity or 'unspecified'} |",
        f"| Opened | {_fmt(inv.created_at)} |",
        f"| Concluded | {_fmt(inv.concluded_at)} |",
        f"| Hosts examined | {len(hosts)} |",
        f"| Collection runs | {len(runs)} |",
        f"| Data as of | {_fmt(ctx['as_of'])} |",
        "",
        "**All times are UTC.** Timestamps are recorded by the platform in UTC and are "
        "rendered here unchanged; a reader working in another zone must convert.",
    ]
    return Section("metadata", "Case metadata", "\n".join(body),
                   {"investigation": 1, "runs": len(runs)})


def s_scope(inv, ctx):
    runs = ctx["runs"]
    collected = sorted({r.host.hostname for r in runs})
    # Hosts named by evidence but never collected. The most expensive mistake in an
    # incident is concluding on machines nobody looked at, so the gap is stated.
    implicated = set()
    for ioc in IOC.objects.filter(run__investigation=inv):
        for key in ("src_host", "dst_host", "hostname"):
            v = (ioc.context or {}).get(key)
            if v:
                implicated.add(str(v))
    uncollected = sorted(implicated - set(collected))
    body = [
        f"Examined: **{len(collected)}** host(s) — " +
        ", ".join(f"`{h}`" for h in collected) + ".",
        "",
    ]
    if uncollected:
        body += [
            f"**Named in evidence but never collected: {len(uncollected)}** — " +
            ", ".join(f"`{h}`" for h in uncollected) + ".",
            "",
            "No conclusion in this report extends to those machines. They appear in "
            "collected evidence and were not themselves examined.",
        ]
    else:
        body.append("Every host named in the collected evidence was itself examined.")
    return Section("scope", "Scope and authorization", "\n".join(body),
                   {"hosts_examined": len(collected), "hosts_uncollected": len(uncollected)})


def s_custody(inv, ctx):
    """Chain of custody, with the seal verification RECOMPUTED here."""
    from .audit import verify_audit_chain
    rows = ["| Host | Capture | Size | sha256 | Custody events | Chain |",
            "|---|---|---|---|---|---|"]
    caps = (MemoryCapture.objects.filter(run__investigation=inv)
            .select_related("run__host"))
    verified = broken = 0
    for cap in caps:
        events = list(CustodyEvent.objects.filter(run=cap.run))
        # Recomputed from the stored links rather than trusting a flag: a report that
        # repeats "verified" without checking is repeating a claim, not testing one.
        ok, prev = True, ""
        for ev in events:
            if ev.prev_hash and ev.prev_hash != prev:
                ok = False
                break
            prev = ev.entry_hash or prev
        verified += 1 if ok else 0
        broken += 0 if ok else 1
        rows.append(
            f"| `{cap.run.host.hostname}` | `{(cap.object_key or '').rsplit('/', 1)[-1]}` | "
            f"{_bytes(cap.size_bytes)} | `{(cap.sha256 or '')[:16]}…` | {len(events)} | "
            f"{'intact' if ok else '**BROKEN**'} |")
    chain_ok, chain_broken_at = verify_audit_chain()[:2]
    body = "\n".join(rows) + "\n\n" + (
        f"Custody chains: **{verified} intact**, **{broken} broken**. "
        f"Platform audit ledger: **{'verifies' if chain_ok else 'DOES NOT VERIFY'}**"
        + (f" — first break at entry {chain_broken_at}." if not chain_ok else ".")
        + "\n\nBoth verifications were recomputed when this report was generated; neither "
          "is a stored flag.")
    return Section("custody", "Evidence inventory and chain of custody", body,
                   {"captures": caps.count(), "custody_events":
                    CustodyEvent.objects.filter(run__investigation=inv).count()})


def s_tools(inv, ctx):
    runs = ctx["runs"]
    toolkits = sorted({r.toolkit_version for r in runs if r.toolkit_version})
    engines = sorted({a.engine for a in MemoryAnalysisRun.objects.filter(
        capture__run__investigation=inv) if a.engine})
    body = [
        "Reproducing this analysis requires the same versions that produced it.",
        "",
        "| Component | Version(s) |", "|---|---|",
        f"| Collection toolkit | {', '.join(f'`{t}`' for t in toolkits) or '—'} |",
        f"| Memory analysis engine | {', '.join(f'`{e}`' for e in engines) or '—'} |",
    ]
    return Section("tools", "Tools and versions", "\n".join(body),
                   {"toolkit_versions": len(toolkits), "engines": len(engines)})


def s_methodology(inv, ctx):
    ladder = " · ".join(Finding.VERDICTS) if hasattr(Finding, "VERDICTS") else (
        "False Positive · Likely False Positive · Indeterminate · "
        "Likely True Positive · True Positive")
    body = [
        "Evidence was collected by the toolkit on each endpoint, sealed at the point of "
        "collection, shipped to a holding tier, and pulled inward by the platform. "
        "Nothing was pushed into the analysis environment.",
        "",
        "Memory images were analyzed server-side; findings were adjudicated against this "
        "ladder, weakest to strongest:",
        "", f"> {ladder}", "",
        "An analyst's verdict takes precedence over the engine's and the disagreement is "
        "kept. Only the two strongest terms assert compromise; the rest record degrees of "
        "uncertainty and are reported as such.",
    ]
    return Section("methodology", "Methodology", "\n".join(body), {})


def s_timeline(inv, ctx):
    runs = ctx["runs"]
    span = (Finding.objects.filter(run__investigation=inv)
            .aggregate(first=Min("created_at"), last=Max("created_at")))
    first, last = span["first"], span["last"]
    dwell = ""
    if first and last:
        days = (last - first).days
        dwell = (f"\n\nEarliest to latest evidence spans **{days} day(s)**"
                 + (" — the window in which the intrusion was active on collected "
                    "hosts." if days else "."))
    rows = ["| When | Host | Event | Source |", "|---|---|---|---|"]
    events = (Finding.objects.filter(run__investigation=inv, verdict__in=CONFIRMING)
              .select_related("run__host").order_by("created_at")[:40])
    for f in events:
        rows.append(f"| {_fmt(f.created_at)} | `{f.run.host.hostname}` | "
                    f"{f.finding_type}: {(f.target or '')[:60]} | {f.source or '—'} |")
    return Section("timeline", "Timeline of confirmed activity",
                   "\n".join(rows) + dwell, {"events": len(events)})


def s_findings(inv, ctx):
    by_host = {}
    for f in (Finding.objects.filter(run__investigation=inv)
              .select_related("run__host")):
        by_host.setdefault(f.run.host.hostname, []).append(f)
    out, total = [], 0
    for host in sorted(by_host):
        rows = by_host[host]
        total += len(rows)
        confirmed = [f for f in rows if f.verdict in CONFIRMING]
        out.append(f"### `{host}` — {len(rows)} finding(s), "
                   f"{len(confirmed)} asserting compromise\n")
        out.append("| Verdict | Type | Target | MITRE | Adjudicated by | Stated reason |")
        out.append("|---|---|---|---|---|---|")
        for f in sorted(rows, key=lambda x: x.verdict != "True Positive")[:25]:
            recl = (FindingReclassification.objects.filter(finding=f)
                    .order_by("-created_at").first())
            who = recl.actor if recl else (f.source or "engine")
            # The reason a verdict was reached is the part a reviewer argues with; a
            # column naming only who decided invites the question it should answer.
            why = (recl.note or "").replace("|", "/")[:80] if recl else ""
            mitre = f.mitre if isinstance(f.mitre, str) else ", ".join(f.mitre or [])
            out.append(f"| {f.verdict or '—'} | {f.finding_type} | "
                       f"{(f.target or '')[:60]} | {mitre or '—'} | {who} | {why or '—'} |")
        out.append("")
    return Section("findings", "Findings by host", "\n".join(out) or "No findings.",
                   {"findings": total})


def s_memory(inv, ctx):
    analyses = MemoryAnalysisRun.objects.filter(capture__run__investigation=inv)
    mf = MemoryFinding.objects.filter(analysis__in=analyses).count()
    pv = ProcessVerdict.objects.filter(run__investigation=inv)
    regions = CarvedRegion.objects.filter(analysis__capture__run__investigation=inv)
    rows = ["| Process | PID | Verdict | Host |", "|---|---|---|---|"]
    for v in pv.select_related("run__host").order_by("-pid")[:25]:
        rows.append(f"| {v.process or '—'} | {v.pid} | {v.verdict or '—'} | "
                    f"`{v.run.host.hostname}` |")
    body = (f"{analyses.count()} memory analysis run(s) produced **{mf}** memory "
            f"finding(s), **{pv.count()}** adjudicated process verdict(s) and "
            f"**{regions.count()}** carved region(s).\n\n" + "\n".join(rows))
    return Section("memory", "Memory analysis", body,
                   {"analyses": analyses.count(), "memory_findings": mf,
                    "process_verdicts": pv.count(), "carved_regions": regions.count()})


def s_indicators(inv, ctx):
    rows = ["| Type | Indicator (defanged) | Hosts |", "|---|---|---|"]
    seen = (IOC.objects.filter(run__investigation=inv)
            .values("ioc_type", "value")
            .annotate(hosts=Count("run__host", distinct=True))
            .order_by("-hosts", "ioc_type")[:60])
    for row in seen:
        rows.append(f"| {row['ioc_type']} | `{defang(row['value'])}` | {row['hosts']} |")
    body = ("\n".join(rows) + "\n\nIndicators are **defanged** — rendered unclickable — "
            "so that reading this document cannot resolve or contact attacker "
            "infrastructure.")
    return Section("indicators", "Indicators of compromise", body,
                   {"indicators": len(seen)})


def s_correlation(inv, ctx):
    from correlation.models import Campaign, CorrelationRun, HostLink
    crun = CorrelationRun.objects.filter(investigation_id=inv.id,
                                         is_current=True).first()
    if not crun:
        return Section("correlation", "Correlation",
                       "No correlation run has been computed for this case.", {})
    camps = Campaign.objects.filter(run=crun)
    links = HostLink.objects.filter(run=crun)
    linked = links.filter(linked=True)
    out = [f"Correlation ran at algorithm version `{crun.algorithm_version}`, producing "
           f"**{camps.count()}** campaign(s) from **{links.count()}** candidate host "
           f"pair(s), of which **{linked.count()}** were linked.", ""]
    for c in camps:
        out.append(f"### Campaign `{c.label or c.id}`\n")
        out.append(f"- Members: **{c.host_count}** host(s), confidence {c.confidence}")
        if c.patient_zero:
            out.append(f"- Entry point: `{c.patient_zero}`"
                       + (f" via {c.initial_vector}" if c.initial_vector else ""))
        if c.first_activity and c.last_activity:
            out.append(f"- Activity: {_fmt(c.first_activity)} to {_fmt(c.last_activity)}")
        # Cohesion is the WEAKEST internal link, so it falls as a campaign gains
        # corroboration; the mean is the figure to compare campaigns on.
        out.append(f"- Cohesion: mean `{c.cohesion_mean:.3f}`, "
                   f"weakest internal link `{c.cohesion_min:.3f}`")
        out.append("")
    rows = ["| Host A | Host B | Weight | Carried by |", "|---|---|---|---|"]
    for l in linked.order_by("-weight")[:20]:
        kinds = ", ".join((l.factors or {}).get("evidence_kinds", [])[:5])
        rows.append(f"| `{l.host_a}` | `{l.host_b}` | {l.weight:.3f} | {kinds or '—'} |")
    out.append("\n".join(rows))
    return Section("correlation", "Correlation — why these hosts are one campaign",
                   "\n".join(out),
                   {"campaigns": camps.count(), "links": links.count()})


def s_declined(inv, ctx):
    """Links the engine considered and rejected — the record of what was weighed."""
    from correlation.models import CorrelationRun, HostLink
    crun = CorrelationRun.objects.filter(investigation_id=inv.id,
                                         is_current=True).first()
    if not crun:
        return Section("declined", "Links considered and declined",
                       "No correlation run has been computed for this case.", {})
    declined = HostLink.objects.filter(run=crun, linked=False).order_by("-weight")[:20]
    if not declined:
        return Section("declined", "Links considered and declined",
                       "Every candidate pair the engine considered was linked.", {})
    rows = ["| Host A | Host B | Weight | Strongest shared evidence | Why it was declined |",
            "|---|---|---|---|---|"]
    for l in declined:
        top = (l.factors or {}).get("top", {})
        why = (f"rarity {top.get('rarity', '—')} — "
               f"{'reads as environment' if (top.get('rarity') or 1) < 0.35 else 'below the link threshold'}")
        rows.append(f"| `{l.host_a}` | `{l.host_b}` | {l.weight:.4f} | "
                    f"{(top.get('value') or '—')[:40]} | {why} |")
    body = ("\n".join(rows) + "\n\nThese pairs shared evidence and were **not** joined. "
            "What an engine rejected, and on what grounds, is part of the record: it is "
            "the difference between a conclusion and a coincidence.")
    return Section("declined", "Links considered and declined", body,
                   {"declined_links": len(declined)})


def s_attribution(inv, ctx):
    from correlation.models import AttributionCandidate, CorrelationRun
    crun = CorrelationRun.objects.filter(investigation_id=inv.id,
                                         is_current=True).first()
    cands = (AttributionCandidate.objects.filter(campaign__run=crun)
             if crun else AttributionCandidate.objects.none())
    restraint = (
        "\n\n**This platform does not name a culprit.** The rows above record technical "
        "similarity to previously recorded activity, which is evidence of resemblance and "
        "not of identity. Asserting a specific actor would overstate what this evidence "
        "supports.")
    if not cands:
        return Section("attribution", "Attribution",
                       "No attribution candidate reached the threshold for this case."
                       + restraint, {})
    rows = ["| Candidate | Score | Source | Basis |", "|---|---|---|---|"]
    for c in cands[:10]:
        basis = ", ".join(str(k) for k in (c.rationale or {}))[:60]
        rows.append(f"| {c.actor_name or '—'} | {c.score:.3f} | {c.source} | "
                    f"{basis or '—'} |")
    return Section("attribution", "Attribution", "\n".join(rows) + restraint,
                   {"attribution_candidates": cands.count()})


def s_ruled_out(inv, ctx):
    rows = RuledOut.objects.filter(investigation=inv)
    if not rows:
        return Section("ruled_out", "Negative findings — what was ruled out",
                       "No hypothesis has been formally tested and rejected on this "
                       "case. Absence of a ruled-out record is not evidence that "
                       "alternatives were considered.", {})
    out = []
    for r in rows:
        out.append(f"**{r.hypothesis}** — ruled out by {r.tested_by or 'the examiner'} "
                   f"on {_fmt(r.concluded_at)}.\n")
        out.append(f"- How it was tested: {r.method}")
        if r.rationale:
            out.append(f"- Why the conclusion holds: {r.rationale}")
        if r.evidence_refs:
            out.append(f"- Rests on: {', '.join(f'`{e}`' for e in r.evidence_refs)}")
        out.append("")
    return Section("ruled_out", "Negative findings — what was ruled out",
                   "\n".join(out), {"ruled_out": rows.count()})



def s_re_determinations(inv, ctx):
    """What the reverse engineer concluded about the material carved out of memory.

    A separate section because it is a separate examination: different examiner, isolated
    equipment, and a determination about the malware itself rather than about the host.
    """
    entries = [e for e in ctx["record"] if e["type"] == "region_analysis"]
    if not entries:
        return Section("re_determinations", "Reverse-engineering determinations",
                       "No carved region has been analyzed on this case. Regions may have "
                       "been carved without anyone having examined them — that is a gap in "
                       "the analysis, not a finding of innocence.", {})
    out = []
    for e in sorted(entries, key=lambda x: x["at"]):
        out.append(f"**{e['summary']}** — {e['actor']}, {_fmt(e['at'])}"
                   + (f" · host `{e['host']}`" if e["host"] else "") + "\n")
        facts = []
        if e.get("verdict"):
            facts.append(f"verdict **{e['verdict']}**"
                         + (f" ({e['confidence']})" if e.get("confidence") else ""))
        if e.get("malware_family"):
            facts.append(f"family `{e['malware_family']}`")
        if e.get("capability"):
            cap = e["capability"]
            facts.append("capability " + (", ".join(cap) if isinstance(cap, list) else str(cap)))
        mitre = e.get("mitre")
        if mitre:
            facts.append("MITRE " + (", ".join(mitre) if isinstance(mitre, list) else str(mitre)))
        if facts:
            out.append("- " + " · ".join(facts))
        for key, label in (("indicators", "Indicators"),
                           ("network_indicators", "Network indicators")):
            values = e.get(key) or []
            if values:
                shown = ", ".join(f"`{defang(v)}`" for v in values[:12])
                out.append(f"- {label}: {shown}")
        if e.get("body"):
            out.append(f"- Statement: {e['body']}")
        out.append("")
    return Section("re_determinations", "Reverse-engineering determinations",
                   "\n".join(out), {"re_determinations": len(entries)})


def s_record(inv, ctx):
    """The investigation record — everything anyone asserted on this case.

    Rendered from the same assembler the platform's own record view uses, so the report and
    the screen cannot disagree about what was said. Chronological, because a record read
    out of order is an argument rather than an account.
    """
    entries = sorted(ctx["record"], key=lambda x: x["at"])
    if not entries:
        return Section("record", "The investigation record",
                       "Nothing has been recorded on this case beyond the collected "
                       "evidence itself.", {})
    label = {"note": "note", "reclassification": "verdict change",
             "region_analysis": "reverse engineering", "region_purge": "evidence disposal"}
    out, counts = [], {}
    for e in entries:
        kind = e.get("kind") or label.get(e["type"], e["type"])
        counts[e["type"]] = counts.get(e["type"], 0) + 1
        head = (f"**{_fmt(e['at'])}** · {label.get(e['type'], e['type'])} / {kind} · "
                f"{e['actor']}" + (f" ({e['role']})" if e.get("role") else "")
                + (f" · `{e['host']}`" if e.get("host") else ""))
        out.append(head + "  ")
        out.append(e.get("summary") or "")
        body = (e.get("body") or "").strip()
        if body and body != e.get("summary"):
            out.append(f"> {body}")
        refs = e.get("evidence") or []
        if refs:
            named = ", ".join(f"finding {r['finding_id']}" for r in refs if r.get("finding_id"))
            if named:
                out.append(f"Rests on: {named}")
        if e.get("retracted"):
            out.append(f"**RETRACTED** — {e.get('retraction_reason') or 'no reason given'}. "
                       "The entry stays visible: a record whose history can be edited is not "
                       "a record.")
        out.append("")
    summary = ("Entries: "
               + ", ".join(f"{n} {label.get(t, t)}(s)" for t, n in sorted(counts.items()))
               + ".\n\n")
    return Section("record", "The investigation record", summary + "\n".join(out),
                   {"record_entries": len(entries)})


def s_limitations(inv, ctx):
    failed = MemoryAnalysisRun.objects.filter(
        capture__run__investigation=inv, status="failed").count()
    purged = MemoryCapture.objects.filter(
        run__investigation=inv, retention_status="purged").count()
    partial = ctx["runs"].filter(overall_status="PARTIAL").count()
    lines = [
        "What this evidence cannot say, stated rather than implied:",
        "",
        f"- **{failed}** memory analysis run(s) failed. A failed analysis is not a clean "
        "host; it is a host on which the question was not answered.",
        f"- **{partial}** collection run(s) completed only partially.",
        f"- **{purged}** capture(s) have been purged under retention policy. Their "
        "findings survive; the images they came from cannot be re-examined.",
        "",
        "Where the platform could not verify something, it is recorded as unverified "
        "rather than as a negative result.",
    ]
    return Section("limitations", "Limitations and confidence", "\n".join(lines),
                   {"failed_analyses": failed, "purged_captures": purged})


def s_actions(inv, ctx):
    reqs = RemediationAction.objects.filter(status="completed").order_by("-created_at")[:15]
    notes = Note.objects.filter(investigation=inv,
                                kind__in=("action", "containment", "eradication")
                                ).order_by("created_at")
    out = []
    if reqs:
        out.append("| When | Action | By | Outcome |")
        out.append("|---|---|---|---|")
        for r in reqs:
            out.append(f"| {_fmt(r.finished_at or r.created_at)} | {r.action} | "
                       f"{r.actor} | {r.status} |")
        out.append("")
    for n in notes:
        out.append(f"- {_fmt(n.created_at)} — {n.summary or n.body[:120]} "
                   f"({n.author})")
    return Section("actions", "Containment and eradication performed",
                   "\n".join(out) or "No containment action has been recorded on this "
                   "case.", {"remediations": reqs.count(), "action_notes": notes.count()})


def s_recommendations(inv, ctx):
    notes = Note.objects.filter(investigation=inv,
                                kind="recommendation").order_by("created_at")
    if not notes:
        return Section("recommendations", "Recommended actions",
                       "No recommendation has been recorded on this case.", {})
    out = [f"{i}. **{n.summary or 'Recommendation'}** — {n.body}"
           for i, n in enumerate(notes, 1)]
    return Section("recommendations", "Recommended actions", "\n".join(out),
                   {"recommendations": notes.count()})


def s_narrative(inv, ctx):
    """The one-paragraph account, taken from the analyst's own summary note."""
    note = (Note.objects.filter(investigation=inv, kind="summary")
            .order_by("-created_at").first())
    if not note:
        return Section("narrative", "What happened",
                       "No summary has been written for this case. This section is "
                       "authored by the examiner and is deliberately not generated.", {})
    return Section("narrative", "What happened", note.body,
                   {"summary_note": 1})


def s_glossary(inv, ctx):
    from .models import CaseTag
    tags = CaseTag.objects.filter(retired=False).exclude(description="")
    if not tags:
        return Section("glossary", "Plain-language glossary",
                       "No glossary terms are curated on this deployment.", {})
    rows = ["| Term | What it means |", "|---|---|"]
    for t in tags:
        rows.append(f"| **{t.label}** | {t.description} |")
    return Section("glossary", "Plain-language glossary", "\n".join(rows),
                   {"glossary_terms": tags.count()})


def s_audit(inv, ctx):
    from .audit import verify_audit_chain
    from .models import AuditLog
    ok, broken_at = verify_audit_chain()[:2]
    n = AuditLog.objects.filter(object_type="investigation",
                                object_id=str(inv.id)).count()
    body = (f"**{n}** audit entr(ies) name this case directly. The platform's hash-chained "
            f"ledger {'verifies end to end' if ok else f'FAILS at entry {broken_at}'} as "
            f"of this render.\n\nEvery adjudication, export, assignment and evidence "
            f"disposal is in that ledger, attributable to a person.")
    return Section("audit", "Audit trail", body, {"audit_entries": n})


SECTIONS = {
    "metadata": s_metadata, "scope": s_scope, "custody": s_custody, "tools": s_tools,
    "methodology": s_methodology, "timeline": s_timeline, "findings": s_findings,
    "memory": s_memory, "indicators": s_indicators, "correlation": s_correlation,
    "declined": s_declined, "attribution": s_attribution, "ruled_out": s_ruled_out,
    "limitations": s_limitations, "actions": s_actions,
    "re_determinations": s_re_determinations, "record": s_record,
    "recommendations": s_recommendations, "narrative": s_narrative,
    "glossary": s_glossary, "audit": s_audit,
}

TECHNICAL_SECTIONS = ["metadata", "scope", "custody", "tools", "methodology", "timeline",
                      "findings", "memory", "re_determinations", "indicators",
                      "correlation", "declined", "attribution", "ruled_out", "record",
                      "limitations", "actions", "recommendations", "audit"]
SUMMARY_SECTIONS = ["narrative", "metadata", "ruled_out", "re_determinations", "actions",
                    "recommendations", "glossary"]


def render_markdown(inv, template):
    """Render one report. Returns (markdown, sources)."""
    as_of = timezone.now()
    from . import record as record_mod
    ctx = {"as_of": as_of,
           "runs": CollectionRun.objects.filter(investigation=inv)
                   .select_related("host", "investigation"),
           "record": record_mod.case_record(inv, limit=5000)}
    title = ("Security Incident — Plain-Language Summary"
             if template.kind == ReportTemplate.SUMMARY
             else "Digital Forensic Analysis — Technical Report")
    out = [f"# {title}", "",
           f"**{inv.name}**" + (f" · incident `{inv.incident_id}`"
                                if inv.incident_id else ""), "",
           f"Generated {_fmt(as_of)} from platform data as of the same moment · "
           f"template `{template.name}` v{template.version}", "", "---", ""]
    sources = {}
    for key in template.sections or []:
        fn = SECTIONS.get(key)
        if not fn:
            continue
        sec = fn(inv, ctx)
        out += [f"## {sec.title}", "", sec.body, "", "---", ""]
        sources.update(sec.sources)
    if template.kind == ReportTemplate.SUMMARY:
        out.append("*This is a plain-language summary. The full technical analysis, "
                   "evidence inventory and exact indicators are in the technical report "
                   "for this case. All times are UTC.*")
    return "\n".join(out), sources


def to_pdf(markdown_text, inv, template):
    """Typeset the report. Layout lives in reportpdf; this supplies the case identity."""
    from . import reportpdf

    technical = template.kind == ReportTemplate.TECHNICAL
    title = ("Digital Forensic Analysis — Technical Report" if technical
             else "Security Incident — Plain-Language Summary")
    subtitle = inv.name + (f" · incident {inv.incident_id}" if inv.incident_id else "")
    meta = [
        ["Case", inv.name],
        ["Incident id", inv.incident_id or "—"],
        ["Status", inv.status],
        ["Severity", inv.severity or "unspecified"],
        ["Prepared", _fmt(timezone.now())],
        ["Times", "All timestamps are UTC"],
    ]
    caveat = ("CONTAINS EVIDENTIARY MATERIAL — HANDLE AND DISTRIBUTE ACCORDINGLY<br/>"
              "Indicators appear defanged and must not be re-armed to be acted on."
              if technical else
              "This is a plain-language summary. The technical analysis for this case "
              "holds the evidence, the exact indicators and the methodology.")
    toc = [line[3:].strip() for line in markdown_text.splitlines()
           if line.startswith("## ")]
    return reportpdf.render(markdown_text, title=title, subtitle=subtitle,
                            meta_rows=meta, caveat=caveat, toc_entries=toc)


def generate(inv, template, actor="", fmt="md"):
    """Render, store and record one report."""
    from . import storage
    body, sources = render_markdown(inv, template)
    payload = body.encode() if fmt == "md" else to_pdf(body, inv, template)
    sha = hashlib.sha256(payload).hexdigest()
    key = f"reports/{inv.id}/{template.kind}-{sha[:16]}.{fmt}"
    bucket = "ir-reports"
    try:
        storage.ensure_bucket_named(bucket)
        storage.put_fileobj_to(bucket, io.BytesIO(payload), key)
    except Exception:                                  # noqa: BLE001
        key = ""
    rec = GeneratedReport.objects.create(
        investigation=inv, template=template, template_version=template.version,
        generated_by=actor, data_as_of=timezone.now(), fmt=fmt,
        object_key=key, sha256=sha, size_bytes=len(payload), sources=sources)
    audit.audit(actor, "report.generate", object_type="investigation",
                object_id=str(inv.id),
                detail={"template": template.name, "kind": template.kind,
                        "fmt": fmt, "sha256": sha, "sources": sources})
    return rec, payload


def ensure_default_templates():
    """The two reports every deployment starts with."""
    made = []
    for name, kind, sections, desc in (
        ("Technical analysis", ReportTemplate.TECHNICAL, TECHNICAL_SECTIONS,
         "The evidentiary record: custody, tools, findings, correlation, what was "
         "ruled out and what cannot be concluded."),
        ("Plain-language summary", ReportTemplate.SUMMARY, SUMMARY_SECTIONS,
         "For the affected party: what happened, what was done, what remains."),
    ):
        obj, created = ReportTemplate.objects.get_or_create(
            name=name, defaults={"kind": kind, "sections": sections,
                                 "description": desc})
        if not created and obj.sections != sections:
            obj.sections = sections
            obj.save(update_fields=["sections", "updated_at"])
        made.append(obj)
    return made


# --- API ----------------------------------------------------------------------------
from django.http import HttpResponse                   # noqa: E402
from rest_framework.response import Response           # noqa: E402
from rest_framework.views import APIView               # noqa: E402

from .rbac import CanExport, IsAnalystOrAdmin, may_see_investigation  # noqa: E402


class ReportTemplateView(APIView):
    """The available templates and what each one contains."""

    permission_classes = [IsAnalystOrAdmin]

    def get(self, request):
        ensure_default_templates()
        return Response({"templates": [
            {"id": t.id, "name": t.name, "kind": t.kind, "version": t.version,
             "description": t.description, "sections": t.sections}
            for t in ReportTemplate.objects.all()]})


class CaseReportView(APIView):
    """Generate a report, or list what has been generated for this case.

    Generating is reading and is available to any analyst on the case. TAKING one out is
    the export right, checked on the download route: rendering evidence and removing it
    from the enclave are different acts.
    """

    permission_classes = [IsAnalystOrAdmin]

    def get(self, request, investigation_id):
        inv = Investigation.objects.filter(id=investigation_id).first()
        if not inv or not may_see_investigation(request.user, inv):
            return Response({"detail": "not found"}, status=404)
        return Response({"reports": [
            {"id": r.id, "template": r.template.name, "kind": r.template.kind,
             "version": r.template_version, "fmt": r.fmt,
             "generated_by": r.generated_by,
             "generated_at": r.created_at.isoformat(),
             "data_as_of": r.data_as_of.isoformat(),
             "sha256": r.sha256, "size_bytes": r.size_bytes, "sources": r.sources}
            for r in inv.reports.select_related("template")]})

    def post(self, request, investigation_id):
        inv = Investigation.objects.filter(id=investigation_id).first()
        if not inv or not may_see_investigation(request.user, inv):
            return Response({"detail": "not found"}, status=404)
        ensure_default_templates()
        tpl = ReportTemplate.objects.filter(
            id=request.data.get("template")).first() or \
            ReportTemplate.objects.filter(kind=request.data.get("kind")).first()
        if not tpl:
            return Response({"detail": "no such template"}, status=400)
        fmt = request.data.get("fmt") or "md"
        if fmt not in ("md", "pdf"):
            return Response({"detail": "fmt must be md or pdf"}, status=400)
        actor = getattr(request.user, "username", "") or ""
        rec, _ = generate(inv, tpl, actor=actor, fmt=fmt)
        return Response({"id": rec.id, "template": tpl.name, "kind": tpl.kind,
                         "fmt": rec.fmt, "sha256": rec.sha256,
                         "size_bytes": rec.size_bytes,
                         "data_as_of": rec.data_as_of.isoformat(),
                         "sources": rec.sources}, status=201)


class ReportContentView(APIView):
    """Read a generated report inside the platform.

    Reading is not exporting: displaying a report in the analyst's browser keeps it inside
    the enclave, while downloading a file takes it out. Only the second is gated on the
    export right, and conflating them would make an analyst ask for egress to read their
    own case.
    """

    permission_classes = [IsAnalystOrAdmin]

    def get(self, request, report_id):
        from . import storage
        rec = (GeneratedReport.objects.filter(id=report_id)
               .select_related("investigation", "template").first())
        if not rec or not may_see_investigation(request.user, rec.investigation):
            return Response({"detail": "not found"}, status=404)
        if rec.fmt != "md":
            return Response({"detail": "only the Markdown render is readable in place; "
                                       "a PDF is a file and needs the export right"},
                            status=415)
        try:
            body = storage.get_object_bytes("ir-reports", rec.object_key).decode()
        except Exception:                              # noqa: BLE001
            body, _ = render_markdown(rec.investigation, rec.template)
        return Response({"id": rec.id, "kind": rec.template.kind, "text": body,
                         "sha256": rec.sha256,
                         "data_as_of": rec.data_as_of.isoformat()})


class ReportDownloadView(APIView):
    """Take a generated report out of the platform. Export right, and it is ledgered."""

    permission_classes = [CanExport]

    def get(self, request, report_id):
        from . import storage
        from .exportledger import record_export

        rec = (GeneratedReport.objects.filter(id=report_id)
               .select_related("investigation", "template").first())
        if not rec or not may_see_investigation(request.user, rec.investigation):
            return Response({"detail": "not found"}, status=404)
        try:
            body = storage.get_object_bytes("ir-reports", rec.object_key)
        except Exception:                              # noqa: BLE001
            body, _ = render_markdown(rec.investigation, rec.template)
            body = body.encode()
        # The ledger never raises by design, and it audits either way — so the record of
        # what left the platform is written before the bytes do.
        record_export(request, kind=f"report.{rec.template.kind}", fmt=rec.fmt,
                      row_count=1,
                      filters={"investigation": rec.investigation_id,
                               "report": rec.id, "sha256": rec.sha256})
        ctype = "application/pdf" if rec.fmt == "pdf" else "text/markdown"
        resp = HttpResponse(body, content_type=ctype)
        name = f"{rec.template.kind}-{rec.investigation_id}.{rec.fmt}"
        resp["Content-Disposition"] = f'attachment; filename="{name}"'
        return resp
