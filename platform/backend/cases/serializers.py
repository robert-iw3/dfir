"""DRF serializers for the read API consumed by the React frontend."""
from rest_framework import serializers

from .models import (
    CarvedRegion,
    RegionAnalysis,
    AuditLog,
    CollectionRun,
    CustodyEvent,
    Finding,
    Host,
    HostIdentityChange,
    IOC,
    Investigation,
    MemoryAnalysisRun,
    MemoryCapture,
    MemoryFinding,
    Note,
    Principal,
    ProcessVerdict,
    RescanRequest,
)


class FindingSerializer(serializers.ModelSerializer):
    # Host and investigation are carried so a finding listed outside its run still says
    # where it came from; the cross-investigation view is otherwise unreadable.
    hostname = serializers.CharField(source="run.host.hostname", read_only=True)
    investigation = serializers.CharField(source="run.investigation.name", read_only=True)

    class Meta:
        model = Finding
        # `adjudicated_by` and `adjudication_conflict` are carried so the queue can show who
        # owns a verdict and where an engine pass disagreed with an analyst. A conflict that
        # exists only in the database is not review; it has to reach the person deciding.
        fields = ["id", "run", "hostname", "investigation", "finding_type", "target",
                  "verdict", "confidence", "mitre", "tier", "subject_path", "source", "raw",
                  "adjudicated_by", "adjudication_conflict"]


class IOCSerializer(serializers.ModelSerializer):
    class Meta:
        model = IOC
        fields = ["id", "ioc_type", "value", "context"]


class PrincipalSerializer(serializers.ModelSerializer):
    class Meta:
        model = Principal
        fields = ["id", "name", "context"]


class MemoryFindingSerializer(serializers.ModelSerializer):
    class Meta:
        model = MemoryFinding
        fields = ["id", "finding_type", "severity", "detail", "offset", "evidence"]


class ProcessVerdictSerializer(serializers.ModelSerializer):
    """One process as the investigation engine judged it.

    `rationale`, `sources` and `positive_dims` are the engine's own reasoning, carried
    through verbatim: an analyst reviewing a verdict has to see what it rests on, and a
    verdict without its rationale is an assertion.
    """

    class Meta:
        model = ProcessVerdict
        fields = ["id", "pid", "process", "engine_label", "verdict", "confidence",
                  "positive_weight", "rationale", "sources", "mitre", "positive_dims",
                  "prior_adjudication"]


class MemoryAnalysisRunSerializer(serializers.ModelSerializer):
    """An analysis run and what it produced, by shape rather than in full.

    A Volatility pass over a real capture yields thousands of findings. Embedding them made
    the run page a multi-megabyte response that the browser then rendered in one go. The
    detail is fetched on demand from the paginated endpoint instead.
    """

    finding_count = serializers.SerializerMethodField()
    severity_counts = serializers.SerializerMethodField()
    top_findings = serializers.SerializerMethodField()

    class Meta:
        model = MemoryAnalysisRun
        fields = ["id", "engine", "engine_version", "ruleset_version", "status",
                  "started_at", "finished_at", "summary", "error",
                  "finding_count", "severity_counts", "top_findings"]

    def get_finding_count(self, obj):
        return obj.findings.count()

    def get_severity_counts(self, obj):
        from django.db.models import Count
        return {row["severity"] or "Unknown": row["n"] for row in
                obj.findings.values("severity").annotate(n=Count("id")).order_by("-n")}

    def get_top_findings(self, obj):
        # Enough to show what the pass found without shipping the whole set. Severity
        # ordering puts the ones an analyst should look at first at the top.
        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        rows = sorted(obj.findings.all()[:400],
                      key=lambda f: order.get(f.severity, 4))[:15]
        return MemoryFindingSerializer(rows, many=True).data


class MemoryCaptureSerializer(serializers.ModelSerializer):
    analyses = MemoryAnalysisRunSerializer(many=True, read_only=True)

    class Meta:
        model = MemoryCapture
        fields = ["id", "store_backend", "bucket", "object_key", "size_bytes",
                  "sha256", "image_format", "capture_tool", "is_synthetic",
                  "symbol_context", "retention_status", "retention_reason",
                  "purged_at", "analyses"]


class CustodyEventSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustodyEvent
        fields = ["id", "action", "actor", "detail", "entry_hash", "created_at"]


class HostIdentityChangeSerializer(serializers.ModelSerializer):
    class Meta:
        model = HostIdentityChange
        fields = ["id", "field", "from_value", "to_value", "observed_at",
                  "source_stamp", "actor", "created_at"]


class HostSerializer(serializers.ModelSerializer):
    # Former identities travel with the host, so a run collected under an older name can be
    # read correctly. `machine_id` is exposed alongside them because it is what makes a rename
    # traceable at all — a name history with no stable key behind it cannot be distinguished
    # from two different machines.
    identity_changes = HostIdentityChangeSerializer(many=True, read_only=True)

    class Meta:
        model = Host
        fields = ["id", "hostname", "platform", "machine_id", "clock_context",
                  "identity_changes"]


class CollectionRunSerializer(serializers.ModelSerializer):
    host = HostSerializer(read_only=True)
    finding_count = serializers.IntegerField(source="findings.count", read_only=True)
    ioc_count = serializers.IntegerField(source="iocs.count", read_only=True)

    class Meta:
        model = CollectionRun
        fields = ["id", "host", "stamp", "toolkit_version", "overall_status",
                  "tp_count", "custody_verified", "collected_at", "run_kind",
                  "compromised", "finding_count", "ioc_count", "created_at"]


class CollectionRunDetailSerializer(CollectionRunSerializer):
    """One run, sized for a page load.

    Findings are summarized, not embedded. A host with a memory capture routinely produces
    thousands, and adjudication does not happen by scrolling all of them — it happens by
    looking at what converged. The full set is paginated at `/findings/?run=<id>`.
    """

    finding_summary = serializers.SerializerMethodField()
    top_findings = serializers.SerializerMethodField()
    iocs = IOCSerializer(many=True, read_only=True)
    principals = PrincipalSerializer(many=True, read_only=True)
    captures = MemoryCaptureSerializer(many=True, read_only=True)
    custody_events = CustodyEventSerializer(many=True, read_only=True)

    class Meta(CollectionRunSerializer.Meta):
        fields = CollectionRunSerializer.Meta.fields + [
            "status_json", "custody_summary",
            "finding_summary", "top_findings",
            "iocs", "principals", "captures", "custody_events",
        ]

    def get_finding_summary(self, obj):
        from django.db.models import Count
        qs = obj.findings.all()
        by = lambda field: {r[field] or "Unknown": r["n"] for r in
                            qs.values(field).annotate(n=Count("id")).order_by("-n")}
        # Two different states hide behind a single Indeterminate verdict, and telling them apart is the
        # difference between a number that moves and one that never does. The engine's most frequent
        # conclusion is Undetermined — a real conclusion, drawn from evidence that did not converge —
        # and it maps to the same Indeterminate a promoted lead starts at.
        indeterminate = qs.filter(verdict="Indeterminate")
        judged = indeterminate.filter(raw__adjudication__isnull=False).count()
        return {
            "total": qs.count(),
            "by_verdict": by("verdict"),
            "by_source": by("source"),
            "by_confidence": by("confidence"),
            # Nothing has looked at these yet.
            "needs_adjudication": indeterminate.count() - judged,
            # The engine looked and could not decide: real leads, but not actionable
            # without corroboration the capture alone does not carry.
            "awaiting_corroboration": judged,
            "engine_adjudicated": qs.filter(raw__adjudication__isnull=False).count(),
        }

    def get_top_findings(self, obj):
        # The findings an analyst should see first: confirmed, then probable. Everything
        # else is reached through the paginated view.
        rank = ["True Positive", "Likely True Positive", "Indeterminate"]
        rows = sorted(
            obj.findings.exclude(verdict__in=["False Positive", "Likely False Positive"])[:400],
            key=lambda f: rank.index(f.verdict) if f.verdict in rank else len(rank),
        )[:20]
        return FindingSerializer(rows, many=True).data


class NoteSerializer(serializers.ModelSerializer):
    """An entry in the investigation record.

    `occurred_at` is when the described event happened; `created_at` is when it was written
    down. Both are returned because a reviewer needs to tell them apart.
    """

    hostname = serializers.CharField(source="host.hostname", read_only=True)
    evidence = serializers.SerializerMethodField()

    class Meta:
        model = Note
        fields = ["id", "investigation", "run", "host", "hostname", "author", "author_role",
                  "kind", "summary", "body", "occurred_at", "confidence", "mitre", "tags",
                  "findings", "evidence", "retracted", "retracted_by", "retracted_at",
                  "retraction_reason", "created_at"]
        read_only_fields = ["author", "author_role", "retracted", "retracted_by",
                            "retracted_at", "retraction_reason"]

    def get_evidence(self, obj):
        """The findings this entry cites, named rather than as bare ids."""
        return [{"id": f.id, "finding_type": f.finding_type, "target": f.target,
                 "verdict": f.verdict} for f in obj.findings.all()[:20]]


class RescanRequestSerializer(serializers.ModelSerializer):
    hostname = serializers.CharField(source="host.hostname", read_only=True)

    class Meta:
        model = RescanRequest
        fields = ["id", "host", "hostname", "investigation", "baseline_run", "kind",
                  "status", "requested_by", "resulting_run", "result", "created_at"]


class AuditLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = AuditLog
        fields = ["id", "actor", "role", "action", "method", "path", "object_type",
                  "object_id", "detail", "entry_hash", "signature", "created_at"]


class InvestigationSerializer(serializers.ModelSerializer):
    run_count = serializers.IntegerField(source="runs.count", read_only=True)

    class Meta:
        model = Investigation
        fields = ["id", "name", "incident_id", "operator", "severity", "status",
                  "notes", "run_count", "created_at"]


class InvestigationDetailSerializer(InvestigationSerializer):
    runs = CollectionRunSerializer(many=True, read_only=True)
    case_notes = NoteSerializer(many=True, read_only=True)

    class Meta(InvestigationSerializer.Meta):
        fields = InvestigationSerializer.Meta.fields + ["runs", "case_notes"]


class CarvedRegionSerializer(serializers.ModelSerializer):
    """A region plus the context a reverse engineer needs to work on it."""

    hostname = serializers.CharField(source="analysis.capture.run.host.hostname", read_only=True)
    investigation = serializers.CharField(
        source="analysis.capture.run.investigation.name", read_only=True)
    investigation_id = serializers.IntegerField(
        source="analysis.capture.run.investigation_id", read_only=True)
    run_id = serializers.IntegerField(source="analysis.capture.run_id", read_only=True)
    analysis_count = serializers.SerializerMethodField()

    class Meta:
        model = CarvedRegion
        fields = ["id", "bucket", "object_key", "size_bytes", "sha256", "carved_by",
                  "trigger", "source_pid", "source_process", "triage_status", "hostname",
                  "investigation", "investigation_id", "run_id", "analysis_count",
                  "created_at",
                  # Retained after deletion so the record stays readable without the bytes.
                  "purged_at", "purged_by", "purge_reason", "purge_statement",
                  "pre_purge_sha256"]

    def get_analysis_count(self, obj):
        return obj.analyses.count()


class RegionAnalysisSerializer(serializers.ModelSerializer):
    region_key = serializers.CharField(source="region.object_key", read_only=True)
    hostname = serializers.CharField(
        source="region.analysis.capture.run.host.hostname", read_only=True)

    class Meta:
        model = RegionAnalysis
        fields = ["id", "region", "region_key", "hostname", "analyst", "verdict",
                  "confidence", "malware_family", "variant", "capability", "statement",
                  "capabilities", "strings_of_interest", "yara_matches",
                  "file_characteristics", "network_indicators", "crypto_material",
                  "config_extracted", "related_hashes", "indicators", "mitre", "notes",
                  "finding", "created_at"]
