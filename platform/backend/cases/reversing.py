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
from django.db import transaction
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from . import audit as audit_mod
from .models import CarvedRegion, Finding, IOC, RegionAnalysis
from .pagination import StandardPagination
from .rbac import IsReverseEngineerOrAdmin, role_of
from .serializers import CarvedRegionSerializer, RegionAnalysisSerializer

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
        qs = super().get_queryset()
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

        with transaction.atomic():
            analysis = RegionAnalysis.objects.create(
                region=region,
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
        qs = super().get_queryset()
        if self.request.query_params.get("region"):
            qs = qs.filter(region_id=self.request.query_params["region"])
        return qs
