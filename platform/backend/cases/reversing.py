"""
Reverse-engineering workflow over carved memory regions.

A reverse engineer works on extracted bytes, not on cases. This module gives that role
exactly what it needs — the regions, their provenance, and somewhere to record what each
one turned out to be — and nothing else.

The important connection is the last step: when a region is identified as malicious, the
determination is raised as a Finding on the run the capture came from. That is how RE
work reaches the incident, gets adjudicated alongside collector findings, feeds IOC
correlation across hosts, and lands in the audit trail. Without it the analysis would sit
in a silo that the analyst never sees.
"""
import io
import os
import re
import tarfile

from django.db import transaction
from django.db.models import Count
from django.http import HttpResponse
from django.utils import timezone
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from . import audit as audit_mod
from .models import (CarvedRegion, Finding, Host, IOC, Investigation, RegionAnalysis,
                     ReWorkset, ReWorksetRegion)
from .pagination import StandardPagination
from .rbac import IsReverseEngineerOrAdmin, may_see_investigation, role_of, scope_by_investigation
from .serializers import (CarvedRegionSerializer, RegionAnalysisSerializer,
                          ReWorksetSerializer)

# The compartment path from a carved region up to its case. Quoted once: a wrong path does
# not raise, it silently scopes nothing.
REGION_INVESTIGATION = "analysis__capture__run__investigation_id"

# A verdict that means "this is hostile" — only these raise a finding on the incident.
ESCALATING = {"malicious", "suspicious"}

# What a determination must carry before it can be recorded. A verdict is an opinion; the
# investigation needs the reasoning behind it, and a sample identified beyond doubt has to
# be evidenced well enough that someone else could reach the same conclusion.
MIN_STATEMENT = 40


def _evidence_gaps(verdict, confidence, data):
    """Missing evidence for this verdict, as human-readable reasons."""
    gaps = []
    statement = str(data.get("statement", "")).strip()

    if verdict in ESCALATING:
        if len(statement) < MIN_STATEMENT:
            gaps.append(
                f"a written statement of at least {MIN_STATEMENT} characters explaining "
                "how the region was identified"
            )
        if not (data.get("capabilities") or data.get("capability")):
            gaps.append("at least one observed capability")

        # Something concrete the reader can check for themselves.
        corroboration = any(data.get(k) for k in (
            "strings_of_interest", "yara_matches", "network_indicators",
            "indicators", "crypto_material", "config_extracted", "related_hashes",
        ))
        if not corroboration:
            gaps.append(
                "at least one piece of corroborating evidence — strings, a YARA match, "
                "network indicators, extracted configuration or a related hash"
            )

    # "Beyond doubt" carries more weight in the incident, so it is held to more.
    if confidence == "definitive":
        if not data.get("malware_family"):
            gaps.append("a malware family (a definitive verdict must say what it is)")
        if not data.get("file_characteristics"):
            gaps.append(
                "file characteristics — entropy, packer, sections or imports that support "
                "a definitive identification"
            )
    return gaps

VERDICT_TO_FINDING = {
    "malicious": ("True Positive", "High"),
    "suspicious": ("Likely True Positive", "Medium"),
}


class CarvedRegionViewSet(viewsets.ReadOnlyModelViewSet):
    """Carved regions, filtered to the work in front of the reverse engineer."""

    queryset = CarvedRegion.objects.select_related(
        "analysis__capture__run__host", "analysis__capture__run__investigation"
    )
    serializer_class = CarvedRegionSerializer
    permission_classes = [IsReverseEngineerOrAdmin]
    pagination_class = StandardPagination

    def get_queryset(self):
        # Scoped like every other view of case data. Memory findings from a capture are
        # compartment-scoped; the bytes carved out of that same capture were not, so a
        # restricted case's malware was listable by anyone holding the RE role.
        qs = scope_by_investigation(super().get_queryset(), self.request.user,
                                    REGION_INVESTIGATION)
        params = self.request.query_params
        if params.get("status"):
            qs = qs.filter(triage_status=params["status"])
        if params.get("host"):
            qs = qs.filter(analysis__capture__run__host__hostname=params["host"])
        if params.get("investigation"):
            qs = qs.filter(analysis__capture__run__investigation_id=params["investigation"])
        return qs

    @action(detail=True, methods=["post"])
    def claim(self, request, pk=None):
        """Take a region for analysis, so two people do not duplicate the work."""
        region = self.get_object()
        region.triage_status = "in_progress"
        region.save(update_fields="triage_status".split())
        audit_mod.audit(getattr(request.user, "username", "?"), "region.claim",
                        role=role_of(request.user), method="POST", path=request.path,
                        object_type="CarvedRegion", object_id=region.id)
        return Response(CarvedRegionSerializer(region).data)

    @action(detail=True, methods=["post"])
    def analyze(self, request, pk=None):
        """Record what this region turned out to be.

        A malicious or suspicious verdict raises a Finding on the owning run, which is how
        the determination reaches the incident the analyst is working.
        """
        if role_of(request.user) not in ("reverse_engineer", "admin"):
            return Response({"detail": "reverse engineer role required"}, status=403)

        region = self.get_object()
        data = request.data or {}
        verdict = data.get("verdict", "")
        if verdict not in dict(RegionAnalysis.VERDICT):
            return Response(
                {"detail": f"verdict must be one of {[v for v, _ in RegionAnalysis.VERDICT]}"},
                status=400,
            )

        confidence = data.get("confidence", "medium")
        gaps = _evidence_gaps(verdict, confidence, data)
        if gaps:
            # Refused rather than stored incomplete: a finding on an incident should not
            # rest on a verdict nobody can evaluate.
            return Response({
                "detail": "the determination is missing evidence",
                "missing": gaps,
            }, status=400)

        actor = getattr(request.user, "username", "?")
        run = region.analysis.capture.run
        # A determination made while this region was staged for a session belongs to that
        # session. Staged before assembled: if the region sits in two, the one an operator
        # actually pulled is the one someone is looking at.
        # A STAGED workset is one an operator actually pulled, so it wins outright over any
        # number of assembled ones holding the same region. Stated as two lookups rather than
        # one sort: ordering by a nullable timestamp made this depend on how the database
        # sorts NULLs, and it named the wrong session when it got that wrong.
        def _session_for(region_obj, states):
            return (ReWorksetRegion.objects
                    .filter(region=region_obj, workset__state__in=states)
                    .select_related("workset")
                    .order_by("-workset__staged_at", "-workset__created_at")
                    .first())

        session = (_session_for(region, (ReWorkset.STAGED,))
                   or _session_for(region, (ReWorkset.ASSEMBLED,)))

        with transaction.atomic():
            analysis = RegionAnalysis.objects.create(
                region=region,
                workset=session.workset if session else None,
                analyst=actor,
                verdict=verdict,
                confidence=confidence,
                malware_family=str(data.get("malware_family", ""))[:128],
                variant=str(data.get("variant", ""))[:128],
                capability=str(data.get("capability", ""))[:255],
                statement=str(data.get("statement", ""))[:16000],
                capabilities=data.get("capabilities") or [],
                strings_of_interest=data.get("strings_of_interest") or [],
                yara_matches=data.get("yara_matches") or [],
                file_characteristics=data.get("file_characteristics") or {},
                network_indicators=data.get("network_indicators") or [],
                crypto_material=data.get("crypto_material") or [],
                config_extracted=data.get("config_extracted") or {},
                related_hashes=data.get("related_hashes") or [],
                indicators=data.get("indicators") or [],
                mitre=data.get("mitre") or [],
                notes=str(data.get("notes", ""))[:8000],
            )

            finding = None
            if verdict in ESCALATING:
                # Named apart from the reverse engineer's own confidence: this is the
                # finding's confidence on the incident, not their attribution certainty.
                fverdict, fconfidence = VERDICT_TO_FINDING[verdict]
                family = analysis.malware_family or "unattributed"
                finding = Finding.objects.create(
                    run=run,
                    finding_type=f"Reverse Engineering: {family}",
                    target=region.object_key,
                    verdict=fverdict,
                    confidence=fconfidence,
                    mitre=analysis.mitre,
                    # The source is what tells an analyst this came from a person examining
                    # the bytes, not from an automated pass.
                    source="reverse-engineering",
                    subject_path=region.source_process or "",
                    raw={
                        "region_id": region.id,
                        "sha256": region.sha256,
                        "analyst": actor,
                        "confidence": analysis.confidence,
                        "malware_family": analysis.malware_family,
                        "variant": analysis.variant,
                        "capabilities": analysis.capabilities or [analysis.capability],
                        "statement": analysis.statement,
                        "strings_of_interest": analysis.strings_of_interest[:50],
                        "yara_matches": analysis.yara_matches,
                        "file_characteristics": analysis.file_characteristics,
                        "config_extracted": analysis.config_extracted,
                        "related_hashes": analysis.related_hashes,
                        # Recovered infrastructure and key material travel with the finding.
                        # Held only on the RegionAnalysis row, they reached no indicator
                        # index and no correlation — yet a C2 address a reverse engineer
                        # pulled out of an implant is among the strongest cross-host links
                        # the platform can hold, and it was the one thing not leaving the
                        # table it was written in.
                        "network_indicators": analysis.network_indicators,
                        "crypto_material": analysis.crypto_material,
                        "indicators": analysis.indicators,
                        "carved_by": region.carved_by,
                    },
                )
                analysis.finding = finding
                analysis.save(update_fields=["finding"])

                # Indicators recovered by hand join the corpus, so they correlate across
                # hosts exactly like collector-derived ones.
                for ind in list(analysis.indicators) + list(analysis.network_indicators):
                    if isinstance(ind, dict) and ind.get("value"):
                        IOC.objects.create(
                            run=run,
                            ioc_type=str(ind.get("type", "unknown"))[:64],
                            value=str(ind["value"])[:1024],
                            context={"source": "reverse-engineering",
                                     "region_id": region.id, "analyst": actor},
                        )

                run.tp_count = run.findings.filter(verdict="True Positive").count()
                run.evaluate_compromise()
                run.save(update_fields=["tp_count", "compromised"])

            region.triage_status = "analyzed" if verdict in ESCALATING else "benign"
            region.save(update_fields=["triage_status"])

            audit_mod.audit(actor, "region.analyze",
                            role=role_of(request.user), method="POST", path=request.path,
                            object_type="CarvedRegion", object_id=region.id,
                            detail={"verdict": verdict,
                                    "malware_family": analysis.malware_family,
                                    "raised_finding": finding.id if finding else None,
                                    "indicators": len(analysis.indicators)})

        return Response({
            "region": CarvedRegionSerializer(region).data,
            "analysis": RegionAnalysisSerializer(analysis).data,
            "raised_finding": finding.id if finding else None,
        }, status=201)

    @action(detail=True, methods=["post"])
    def purge(self, request, pk=None):
        """Delete a benign region's bytes, keeping the determination that justified it.

        Only regions examined and found benign can be purged: something assessed hostile is
        evidence and stays. The row, its analyses and the pre-purge hash are all retained,
        so the deletion remains provable and the reasoning remains readable long after the
        sample is gone.

        A reason and a written statement are required. Deleting evidence without a record
        of who decided, when, and why is not something the platform should make easy.
        """
        if role_of(request.user) not in ("reverse_engineer", "admin"):
            return Response({"detail": "reverse engineer role required"}, status=403)

        region = self.get_object()
        data = request.data or {}
        reason = str(data.get("reason", "")).strip()
        statement = str(data.get("statement", "")).strip()

        if region.triage_status == "purged":
            return Response({"detail": "already purged",
                             "purged_at": region.purged_at}, status=409)
        if region.triage_status != "benign":
            return Response({
                "detail": "only a region examined and found benign can be purged",
                "triage_status": region.triage_status,
            }, status=409)
        if not reason or len(statement) < MIN_STATEMENT:
            return Response({
                "detail": "a reason and a written statement are required to delete a region",
                "missing": [
                    *([] if reason else ["reason"]),
                    *([] if len(statement) >= MIN_STATEMENT
                      else [f"statement of at least {MIN_STATEMENT} characters"]),
                ],
            }, status=400)

        actor = getattr(request.user, "username", "?")
        pre_purge_sha = region.sha256
        hostname = region.analysis.capture.run.host.hostname

        from django.utils import timezone

        from . import storage

        try:
            client = storage.client()
            client.delete_object(Bucket=region.bucket, Key=region.object_key)
        except Exception as exc:  # noqa: BLE001
            return Response({"detail": f"object store refused the delete: {exc}"}, status=502)

        with transaction.atomic():
            region.triage_status = "purged"
            region.purged_at = timezone.now()
            region.purged_by = actor
            region.purge_reason = reason[:500]
            region.purge_statement = statement[:16000]
            region.pre_purge_sha256 = pre_purge_sha
            region.save(update_fields=["triage_status", "purged_at", "purged_by",
                                       "purge_reason", "purge_statement",
                                       "pre_purge_sha256"])

            # Custody continues in the ledger: the bytes are gone, the record of what they
            # were and who removed them is not.
            audit_mod.custody(region.analysis.capture.run, "region.purge", actor, {
                "region_id": region.id,
                "object_key": region.object_key,
                "bucket": region.bucket,
                "pre_purge_sha256": pre_purge_sha,
                "reason": reason,
                "statement": statement,
                "host": hostname,
            })
            audit_mod.audit(actor, "region.purge",
                            role=role_of(request.user), method="POST", path=request.path,
                            object_type="CarvedRegion", object_id=region.id,
                            detail={"pre_purge_sha256": pre_purge_sha,
                                    "reason": reason,
                                    "statement": statement,
                                    "object_key": region.object_key,
                                    "host": hostname})

        return Response({
            "purged": True,
            "region": CarvedRegionSerializer(region).data,
            "pre_purge_sha256": pre_purge_sha,
            "purged_by": actor,
            "purged_at": region.purged_at,
        })

    @action(detail=False, methods=["get"])
    def queue(self, request):
        """Work summary for the reverse-engineering view."""
        base = self.get_queryset()
        return Response({
            "unanalyzed": base.filter(triage_status="unanalyzed").count(),
            "in_progress": base.filter(triage_status="in_progress").count(),
            "analyzed": base.filter(triage_status="analyzed").count(),
            "benign": base.filter(triage_status="benign").count(),
            "hosts": sorted(set(
                base.values_list("analysis__capture__run__host__hostname", flat=True)
            )),
        })


class RegionAnalysisViewSet(viewsets.ReadOnlyModelViewSet):
    """Determinations already recorded — visible to every role that can see the case."""

    queryset = RegionAnalysis.objects.select_related("region", "finding")
    serializer_class = RegionAnalysisSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = StandardPagination

    def get_queryset(self):
        # RegionAnalysis carries its own investigation id, backfilled on save.
        qs = scope_by_investigation(super().get_queryset(), self.request.user,
                                    "investigation_id")
        if self.request.query_params.get("region"):
            qs = qs.filter(region_id=self.request.query_params["region"])
        return qs


# ---------------------------------------------------------------------------------------
# Worksets: which regions a reverse-engineering session is for.
# ---------------------------------------------------------------------------------------

# The analyzer records its own severity on the YARA hit that caused the carve.
SEVERITY_RANK = {"critical": 4.0, "high": 3.0, "medium": 2.0, "low": 1.0}

# Examined regions sink rather than disappear: a second opinion is legitimate, re-staging the
# same bytes by accident is not.
TRIAGE_WEIGHT = {"unanalyzed": 1.0, "in_progress": -1.0, "analyzed": -3.0, "benign": -4.0}


def _rank_regions(regions, host_counts, promoted=()):
    """Score regions so the few worth a person's time surface out of the pile.

    Every signal here is already recorded at carve time. Ranking proposes and the analyst
    disposes, so the reasons travel with the score — a number nobody can question is worse
    than no number.
    """
    ranked = []
    for r in regions:
        score, why = 0.0, []
        hits = (r.trigger or {}).get("hits") or []

        if (r.analysis_id, r.source_pid) in promoted:
            score += 2.5
            why.append("promoted to triage")

        worst = max((SEVERITY_RANK.get(str(h.get("severity", "")).lower(), 0.0)
                     for h in hits), default=0.0)
        if worst:
            score += worst * 1.5
            why.append(f"severity {max(hits, key=lambda h: SEVERITY_RANK.get(str(h.get('severity','')).lower(), 0.0)).get('severity')}")

        # Private RWX is where injected code lives; it is the difference between a region
        # that is merely mapped and one that had no business being executable.
        if any("rwx" in str(h.get("memory", "")).lower() for h in hits):
            score += 2.0
            why.append("rwx memory")

        named = [h.get("rule") for h in hits
                 if h.get("rule") and h.get("rule") != "unnamed rule"]
        if named:
            score += 1.5
            why.append(f"rule {named[0]}")

        distinct = {m.get("id") for h in hits for m in (h.get("matches") or []) if m.get("id")}
        if distinct:
            score += min(len(distinct), 5) * 0.3
            why.append(f"{len(distinct)} matched string(s)")

        # Confined to one host is the interesting case; the same bytes on thirty hosts are
        # the environment, not the intrusion.
        seen_on = host_counts.get(r.sha256, 0) if r.sha256 else 0
        if seen_on == 1:
            score += 2.0
            why.append("seen on one host")
        elif seen_on == 2:
            score += 1.0
            why.append("seen on two hosts")
        elif seen_on > 5:
            score -= 1.0
            why.append(f"seen on {seen_on} hosts")

        score += TRIAGE_WEIGHT.get(r.triage_status, 0.0)
        if r.triage_status not in ("unanalyzed",):
            why.append(r.triage_status)

        ranked.append({"region": r, "score": round(score, 2), "why": why})
    ranked.sort(key=lambda x: (-x["score"], -(x["region"].size_bytes or 0), x["region"].id))
    return ranked


def _promoted_pids(regions):
    """(analysis, pid) pairs whose YARA hit was promoted into the triage queue.

    Promotion is the platform having already said this hit is worth adjudicating, which is a
    stronger statement than the rule firing at all.
    """
    from .models import MemoryFinding

    analyses = {r.analysis_id for r in regions}
    if not analyses:
        return set()
    promoted = set()
    for mf in MemoryFinding.objects.filter(
            analysis_id__in=analyses, promoted_finding__isnull=False,
            finding_type__startswith="YARA Memory").only("analysis_id", "detail", "evidence"):
        target = (mf.evidence or {}).get("target", "") if isinstance(mf.evidence, dict) else ""
        hit = re.search(r"PID\s+(\d+)", str(target)) or re.search(r"PID\s+(\d+)", mf.detail or "")
        if hit:
            promoted.add((mf.analysis_id, int(hit.group(1))))
    return promoted


def _host_counts(regions):
    """How many distinct hosts each of these regions' hashes has been seen on."""
    hashes = {r.sha256 for r in regions if r.sha256}
    if not hashes:
        return {}
    rows = (CarvedRegion.objects.filter(sha256__in=hashes)
            .values("sha256")
            .annotate(hosts=Count("analysis__capture__run__host_id", distinct=True)))
    return {row["sha256"]: row["hosts"] for row in rows}


def _safe_host(ws):
    """A hostname fit to appear in generated text.

    The hostname originates as the bundle's top-level tar directory name and is stored on a
    bare CharField, so an adversary who controls the memory image controls it — newlines
    included. `_run_script` writes it into a shell script the kit tells an analyst to run on
    the machine that owns the platform runtime, which turned a passive image into execution
    in the operator's context. Sanitised on the way OUT rather than trusted on the way in,
    because the raw value still has to match what was collected.
    """
    raw = ws.host.hostname if ws.host else "?"
    safe = "".join(c if (c.isalnum() or c in "-._") else "-" for c in raw)[:64]
    return safe or "?"


def _next_slug(investigation_id, hostname):
    """ws-<case>-<host>-<n>, bounded to the audit column that has to carry it."""
    safe = "".join(c if c.isalnum() else "-" for c in hostname.lower()).strip("-")[:24] or "host"
    base = f"ws-{investigation_id}-{safe}"
    n = ReWorkset.objects.filter(slug__startswith=f"{base}-").count() + 1
    while ReWorkset.objects.filter(slug=f"{base}-{n}").exists():
        n += 1
    return f"{base}-{n}"[:64]


# Where the mediator and launcher live on the host that runs the platform. Mounted into the
# backend so a kit can carry them; a kit that only names them would still leave the operator
# hunting for the scripts.
RE_SCRIPT_DIR = os.environ.get("IR_RE_SCRIPT_DIR", "/opt/re-workstation")


def _session_steps(ws, tool):
    """The procedure, in the order someone actually performs it.

    Written out rather than assumed: the two commands alone presume a shell already sitting
    in the right directory with the scripts present, which is never where anyone starts.
    """
    session = f"./session-{ws.slug}"
    kit = f"re-session-{ws.slug}"
    return [
        {
            "step": 1,
            "where": "on the machine running the platform runtime",
            "why": "staging reads the enclave's object store, so it runs where the platform "
                   "runs — the workstation has no route to it",
            "commands": [
                f"tar -xzf {kit}.tar.gz",
                f"cd {kit}",
                "./run.sh",
            ],
        },
        {
            "step": 2,
            "where": "what run.sh does, if you would rather type it",
            "why": "the same two commands the kit runs for you",
            "commands": [
                f"./stage_regions.sh --workset {ws.slug} --out {session}",
                f"./launch.sh --regions {session} --tool {tool}",
            ],
        },
    ]


def _run_script(ws, tool):
    """The kit's automated path: stage this workset, then open it."""
    session = f"./session-{ws.slug}"
    return f"""#!/usr/bin/env sh
# Reverse-engineering session for workset {ws.slug}
#   host {_safe_host(ws)} · case {ws.investigation_id} · """ f"""{ws.members.count()} region(s)
#
# Run this from the directory it was unpacked into, on the machine that runs the platform
# runtime. It stages exactly this workset's regions and opens them in {tool}.
set -eu
# --stage-only pulls the regions and stops. Opening the tool blocks until a person closes
# it, which is right for a session and wrong for anything that has to finish on its own.
STAGE_ONLY=0
[ "${{1:-}}" = "--stage-only" ] && STAGE_ONLY=1
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "${{HERE}}"
chmod +x ./stage_regions.sh ./launch.sh 2>/dev/null || true
# Staged malware is wiped when the session ends. Left behind it accumulates on the host,
# unencrypted, until somebody remembers — set IR_KEEP_SESSION=1 to keep it deliberately.
cleanup() {{
    if [ "${{IR_KEEP_SESSION:-0}}" = "1" ]; then
        echo "[session] keeping {session} (IR_KEEP_SESSION=1)"
    else
        chmod -R u+w "{session}" 2>/dev/null || true
        rm -rf "{session}"
        echo "[session] staged regions wiped"
    fi
}}
trap cleanup EXIT INT TERM

echo "[session] staging {ws.members.count()} region(s) for workset {ws.slug}"
./stage_regions.sh --workset {ws.slug} --out "{session}"
if [ "$STAGE_ONLY" = "1" ]; then
    echo "[session] staged only; {tool} not opened"
    exit 0
fi
echo "[session] opening {tool}"
./launch.sh --regions "{session}" --tool {tool}
"""


def _kit_readme(ws, tool, requested_by="", requested_at=None):
    return f"""Reverse-engineering session kit
===============================

Workset : {ws.slug}
Host    : {_safe_host(ws)}
Case    : {ws.investigation_id}
Regions : {ws.members.count()}
Tool    : {tool}
For     : {requested_by or "?"}
Issued  : {requested_at.isoformat() if requested_at else "?"}

This kit was issued to the person named above. Found later, it says whose session it was
for; it is not a credential and grants nothing on its own.

This archive contains NO EVIDENCE. The carved regions are not in it and never travel
through a browser: they are pulled from the enclave's object store by stage_regions.sh,
which is the only step holding credentials for it.

To run the session:

    tar -xzf re-session-{ws.slug}.tar.gz
    cd re-session-{ws.slug}
    ./run.sh

run.sh stages this workset's regions into ./session-{ws.slug}, verifies each against the
hash recorded when it was carved, opens them in {tool} with no network namespace at all,
and WIPES the staged bytes when the session ends. Staging must run on the machine with the
platform runtime; the regions are mounted read-only into the session.

Set IR_KEEP_SESSION=1 to keep the staged regions after the tool exits.

When the determination is written up, record it against the region in the platform so it
reaches the investigation — a conclusion left in the disassembler is not part of the case.
"""


class ReWorksetViewSet(viewsets.ModelViewSet):
    """Worksets — the unit a reverse-engineering session is granted.

    The platform cannot deploy the workstation: it is air-gapped, launched by an operator on
    its own hardware, and reaching into it would defeat the reason it exists. What it can do
    is name exactly which regions a session is for and mint the command that stages them.
    """

    queryset = ReWorkset.objects.select_related("investigation", "host")
    serializer_class = ReWorksetSerializer
    permission_classes = [IsReverseEngineerOrAdmin]
    pagination_class = StandardPagination
    lookup_field = "slug"

    def get_queryset(self):
        return scope_by_investigation(super().get_queryset(), self.request.user,
                                      "investigation_id")

    def create(self, request, *args, **kwargs):
        data = request.data or {}
        region_ids = data.get("region_ids") or []
        if not isinstance(region_ids, list) or not region_ids:
            return Response({"detail": "region_ids must be a non-empty list"}, status=400)
        if len(region_ids) > ReWorkset.MAX_REGIONS:
            return Response({"detail": f"a workset holds at most {ReWorkset.MAX_REGIONS} "
                                       f"regions; assemble more than one",
                             "requested": len(region_ids)}, status=400)

        # Read the regions THROUGH the scope, so a restricted case's region cannot be pulled
        # into a workset by id alone.
        regions = list(scope_by_investigation(
            CarvedRegion.objects.select_related("analysis__capture__run__host",
                                                "analysis__capture__run__investigation"),
            request.user, REGION_INVESTIGATION).filter(id__in=region_ids))
        missing = set(region_ids) - {r.id for r in regions}
        if missing:
            return Response({"detail": "some regions do not exist or are not visible to you",
                             "missing": sorted(missing)}, status=404)

        purged = [r.id for r in regions if r.triage_status == "purged"]
        if purged:
            return Response({"detail": "purged regions have no bytes to open",
                             "purged": purged}, status=409)

        cases = {r.analysis.capture.run.investigation_id for r in regions}
        hosts = {r.analysis.capture.run.host_id for r in regions}
        if len(cases) != 1 or len(hosts) != 1:
            return Response({"detail": "a workset is one investigation and one host — the "
                                       "per-host bucket is the wall a session sees",
                             "investigations": sorted(cases), "hosts": sorted(hosts)},
                            status=400)

        investigation_id, host_id = cases.pop(), hosts.pop()
        inv = Investigation.objects.filter(id=investigation_id).first()
        if not may_see_investigation(request.user, inv):
            return Response({"detail": "not found"}, status=404)
        host = Host.objects.filter(id=host_id).first()

        counts = _host_counts(regions)
        order = {x["region"].id: i
                 for i, x in enumerate(_rank_regions(regions, counts, _promoted_pids(regions)))}
        actor = getattr(request.user, "username", "?")
        with transaction.atomic():
            ws = ReWorkset.objects.create(
                slug=_next_slug(investigation_id, host.hostname if host else "host"),
                investigation_id=investigation_id, host_id=host_id,
                created_by=actor, note=str(data.get("note", ""))[:2000])
            ReWorksetRegion.objects.bulk_create([
                ReWorksetRegion(workset=ws, region=r, rank=order.get(r.id, 0), added_by=actor)
                for r in regions])
        audit_mod.audit(actor, "workset.create", role=role_of(request.user),
                        method="POST", path=request.path, object_type="ReWorkset",
                        object_id=ws.slug,
                        detail={"investigation": investigation_id, "host": host_id,
                                "regions": len(regions)})
        return Response(ReWorksetSerializer(ws).data, status=201)

    @action(detail=False, methods=["get"])
    def propose(self, request):
        """The ranked shortlist for one host — what a session SHOULD probably hold."""
        hostname = request.query_params.get("host")
        if not hostname:
            return Response({"detail": "host is required"}, status=400)
        try:
            limit = min(int(request.query_params.get("limit", 20)), ReWorkset.MAX_REGIONS)
        except (TypeError, ValueError):
            return Response({"detail": "limit must be a number"}, status=400)

        qs = scope_by_investigation(
            CarvedRegion.objects.select_related("analysis__capture__run__host"),
            request.user, REGION_INVESTIGATION).filter(
                analysis__capture__run__host__hostname=hostname).exclude(
                triage_status="purged")

        # A hostname outlives an incident: the same machine collected again under a new case
        # carries regions from both. A proposal spanning two cases is one a workset can never
        # accept, so the proposal picks ONE — the newest, unless told otherwise — and names
        # the others rather than quietly folding them in.
        available = sorted({r[REGION_INVESTIGATION] for r in qs.values(REGION_INVESTIGATION)})
        wanted = request.query_params.get("investigation")
        if wanted:
            if not str(wanted).isdigit() or int(wanted) not in available:
                return Response({"detail": "that investigation has no regions for this host",
                                 "investigations": available}, status=404)
            chosen = int(wanted)
        else:
            newest = qs.order_by("-created_at", "-id").values(REGION_INVESTIGATION).first()
            chosen = newest[REGION_INVESTIGATION] if newest else None
        qs = qs.filter(**{REGION_INVESTIGATION: chosen}) if chosen else qs.none()

        regions = list(qs[:500])
        ranked = _rank_regions(regions, _host_counts(regions),
                               _promoted_pids(regions))[:limit]
        return Response({
            "host": hostname,
            "investigation": chosen,
            "other_investigations": [i for i in available if i != chosen],
            "considered": len(regions),
            "proposed": [{"region": CarvedRegionSerializer(x["region"]).data,
                          "score": x["score"], "why": x["why"]} for x in ranked],
        })

    @action(detail=True, methods=["post"], url_path="stage-command")
    def stage_command(self, request, slug=None):
        """Mint the commands that stage this workset on a reverse-engineering workstation."""
        ws = self.get_object()
        tool = request.data.get("tool", "binja") if request.data else "binja"
        if tool not in ("binja", "ghidra"):
            return Response({"detail": "tool must be binja or ghidra"}, status=400)
        count = ws.members.count()
        steps = _session_steps(ws, tool)
        commands = [c for step in steps for c in step["commands"]]
        audit_mod.audit(getattr(request.user, "username", "?"), "workset.stage-command",
                        role=role_of(request.user), method="POST", path=request.path,
                        object_type="ReWorkset", object_id=ws.slug,
                        detail={"tool": tool, "regions": count})
        return Response({
            "workset": ws.slug,
            "investigation": ws.investigation_id,
            "host": ws.host.hostname if ws.host else "",
            "regions": count,
            "tool": tool,
            "steps": steps,
            "commands": commands,
            "kit": f"/api/worksets/{ws.slug}/kit/?tool={tool}",
            # Said plainly because it is the design, not an omission: the platform does not
            # start the disassembler, an operator does.
            "note": "the kit runs these for you; the commands are here for a machine "
                    "that cannot take the download",
        })

    @action(detail=True, methods=["get"])
    def kit(self, request, slug=None):
        """A session kit: the scripts and one run.sh, pinned to this workset.

        NO EVIDENCE TRAVELS IN THIS FILE. Regions are pulled by the mediator, which is the
        only step holding object-store credentials — carrying malware out through a browser
        would undo the reason the reverse-engineering workstation is separate at all.
        """
        ws = self.get_object()
        tool = request.query_params.get("tool", "binja")
        if tool not in ("binja", "ghidra"):
            return Response({"detail": "tool must be binja or ghidra"}, status=400)

        mediator = os.path.join(RE_SCRIPT_DIR, "stage_regions.sh")
        if not os.path.exists(mediator):
            # Without the mediator the kit cannot stage anything, and an archive that looks
            # complete but is not would be discovered on the workstation, out of reach.
            return Response({"detail": "this deployment cannot build a session kit — the "
                                       "mediator scripts are not in the image",
                             "expected": RE_SCRIPT_DIR}, status=503)

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            def add(name, body, mode=0o644):
                data = body.encode()
                info = tarfile.TarInfo(f"re-session-{ws.slug}/{name}")
                info.size, info.mode, info.mtime = len(data), mode, 0
                tar.addfile(info, io.BytesIO(data))

            who = getattr(request.user, "username", "?")
            add("run.sh", _run_script(ws, tool), mode=0o755)
            add("README.txt", _kit_readme(ws, tool, who, timezone.now()))
            for name in ("stage_regions.sh", "launch.sh", "binja-settings.json",
                         "ghidra-session.sh"):
                src = os.path.join(RE_SCRIPT_DIR, name)
                if os.path.exists(src):
                    with open(src) as fh:
                        add(name, fh.read(), mode=0o755 if name.endswith(".sh") else 0o644)

        audit_mod.audit(getattr(request.user, "username", "?"), "workset.kit",
                        role=role_of(request.user), method="GET", path=request.path,
                        object_type="ReWorkset", object_id=ws.slug,
                        detail={"tool": tool, "regions": ws.members.count()})
        resp = HttpResponse(buf.getvalue(), content_type="application/gzip")
        resp["Content-Disposition"] = f'attachment; filename="re-session-{ws.slug}.tar.gz"'
        return resp

    @action(detail=True, methods=["post"])
    def close(self, request, slug=None):
        """Close a workset. Determinations stay on the regions; this ends the session."""
        ws = self.get_object()
        ws.state, ws.closed_at = ReWorkset.CLOSED, timezone.now()
        ws.save(update_fields=["state", "closed_at", "updated_at"])
        audit_mod.audit(getattr(request.user, "username", "?"), "workset.close",
                        role=role_of(request.user), method="POST", path=request.path,
                        object_type="ReWorkset", object_id=ws.slug, detail={})
        return Response(ReWorksetSerializer(ws).data)
