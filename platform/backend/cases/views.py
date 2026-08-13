"""
REST API.

Read endpoints feed the React SPA; the ingest endpoint (service token only) receives
bundles from the store-and-forward broker; IOC-search is the cross-investigation
historical-lookup payoff; rescan re-runs collection to validate eradication/baseline;
retention/purge + audit endpoints serve maintenance and the tamper-proof trail.

RBAC (cases/rbac.py): admin=full incl. delete; analyst=work cases/notes/rescans;
auditor=read investigations + audit trail. Every mutation is audit-logged.
"""
import csv
import io
import json
import os

from django.db.models import Count, Q, Sum
from django.utils import timezone
from rest_framework import filters, status, viewsets
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from . import brokeredsessions
from . import collab
from . import componenthealth
from . import remediation
from . import meshhealth
from . import opsmetrics
from . import symbols as symbols_mod
from .pagination import StandardPagination
from . import audit as audit_mod
from .killchain import TECHNIQUE_TACTICS
from . import ingest as ingest_mod
from . import record as record_mod
from . import retention as retention_mod
from .models import (
    AuditLog,
    CollectionRun,
    ExportLedger,
    Finding,
    Host,
    IOC,
    Investigation,
    MemoryAnalysisRun,
    MemoryCapture,
    MemoryFinding,
    Note,
    ProcessVerdict,
    RemediationAction,
    RescanRequest,
    SymbolRequest,
)
from .exportledger import record_export
from .rbac import (
    CanExport,
    may_export,
    IsAdmin,
    scope_by_investigation,
    scope_investigations,
    IsAnalystOrAdmin,
    IsAuditorOrAdmin,
    IsService,
    role_of,
)
from .serializers import (
    AuditLogSerializer,
    CollectionRunDetailSerializer,
    CollectionRunSerializer,
    FindingSerializer,
    HostSerializer,
    InvestigationDetailSerializer,
    InvestigationSerializer,
    MemoryCaptureSerializer,
    MemoryFindingSerializer,
    NoteSerializer,
    ProcessVerdictSerializer,
    RescanRequestSerializer,
)
from .tasks import analyze_capture
from .triage import _attachment


@api_view(["GET"])
@permission_classes([])  # health is unauthenticated for load-balancer probes
def health(request):
    return Response({"status": "ok"})


# When this process started. A restart changes it, which is how a browser tab that has been
# open across a redeployment finds out that the thing it is talking to is not the thing it
# started talking to.
_STARTED_AT = timezone.now()


@api_view(["GET"])
@permission_classes([])   # polled by every open tab, including a login screen
def version(request):
    """What is running right now.

    The SPA polls this so an analyst working a case finds out that the backend was
    redeployed, rather than discovering it through a request that fails oddly. An admin
    restarting a service mid-shift is routine; a stale tab silently calling an endpoint
    that no longer exists is what makes it look like a fault.
    """
    return Response({
        "build": os.environ.get("IR_BUILD_ID", ""),
        "started_at": _STARTED_AT,
        "status": "ok",
    })


@api_view(["GET"])
def me(request):
    """Who am I + what can I do — drives the SPA's role-aware UI."""
    return Response({
        "username": request.user.username,
        "email": getattr(request.user, "email", ""),
        "role": role_of(request.user),
        # Export is a right held alongside a role, so the UI cannot derive it from the
        # role alone — offering a button that will be refused is worse than not offering it.
        "may_export": may_export(request.user),
    })


class UsersView(APIView):
    """Admin-only user administration. Creating a user provisions the account in
    Keycloak (for SSO) in the group matching the chosen role, and mirrors it locally."""

    permission_classes = [IsAdmin]

    def get(self, request):
        from . import keycloak_admin
        try:
            return Response({"users": keycloak_admin.list_users()})
        except Exception as exc:  # noqa: BLE001
            return Response({"error": str(exc)}, status=502)

    def post(self, request):
        from django.contrib.auth.models import Group, User
        from . import keycloak_admin

        data = request.data
        username = (data.get("username") or "").strip()
        email = (data.get("email") or "").strip()
        role = (data.get("role") or "").strip()
        password = data.get("password") or ""
        if not (username and email and role and password):
            return Response({"error": "username, email, role, password required"}, status=400)
        if role not in ("admin", "analyst", "auditor"):
            return Response({"error": "role must be admin|analyst|auditor"}, status=400)

        try:
            kc_id = keycloak_admin.create_user(
                username, email, role, password,
                temporary=bool(data.get("temporary", True)))
        except Exception as exc:  # noqa: BLE001 — provisioning failure must not create a half-user
            return Response({"error": f"Keycloak provisioning failed: {exc}"}, status=502)

        # Mirror locally so the user + role exist even before first SSO login.
        user, _ = User.objects.get_or_create(username=username, defaults={"email": email})
        user.email = email
        user.is_staff = user.is_superuser = (role == "admin")
        user.save()
        grp, _ = Group.objects.get_or_create(name=role)
        user.groups.set([grp])

        audit_mod.audit(request.user.username, "user.create", role="admin",
                        method="POST", path=request.path, object_type="User",
                        object_id=username,
                        detail={"email": email, "role": role, "keycloak_id": kc_id})
        return Response({"username": username, "email": email, "role": role,
                         "keycloak_id": kc_id, "provisioned": True}, status=201)


class InvestigationViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Investigation.objects.all()
    # Scoping is applied in get_queryset, so retrieve() 404s a compartment an identity
    # is not assigned to rather than answering it.
    permission_classes = [IsAuthenticated]
    pagination_class = StandardPagination
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["name", "incident_id", "operator", "severity", "status"]
    ordering_fields = ["created_at", "name", "severity", "status"]
    ordering = ["-created_at"]

    def get_queryset(self):
        return scope_investigations(super().get_queryset(), self.request.user)

    def get_serializer_class(self):
        return (InvestigationDetailSerializer if self.action == "retrieve"
                else InvestigationSerializer)

    @action(detail=True, methods=["get"])
    def record(self, request, pk=None):
        """Everything asserted about this incident, chronologically.

        Analyst notes, verdict changes and their stated reasons, reverse-engineering
        determinations, and evidence disposals — one record rather than four screens. The
        reverse engineer works on an isolated workstation and the analyst works here, but
        both are writing into the same case, and this is where that shows.
        """
        entries = record_mod.case_record(self.get_object(),
                                         limit=int(request.query_params.get("limit", 500)))
        kind = request.query_params.get("type")
        if kind:
            entries = [e for e in entries if e["type"] == kind]
        return Response({"summary": record_mod.record_summary(entries), "entries": entries})

    def destroy(self, request, *args, **kwargs):  # admin-only deletion
        return _admin_delete(request, self.get_object(), "Investigation")


class CollectionRunViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = CollectionRun.objects.select_related("host", "investigation")
    permission_classes = [IsAuthenticated]
    pagination_class = StandardPagination
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["host__hostname", "investigation__name", "stamp", "overall_status"]
    ordering_fields = ["collected_at", "created_at", "tp_count", "host__hostname"]
    ordering = ["-created_at"]

    def get_queryset(self):
        qs = scope_by_investigation(super().get_queryset(), self.request.user)
        params = self.request.query_params
        if params.get("investigation"):
            qs = qs.filter(investigation_id=params["investigation"])
        if params.get("host"):
            qs = qs.filter(host_id=params["host"])
        if params.get("compromised") in ("true", "false"):
            qs = qs.filter(compromised=params["compromised"] == "true")
        if params.get("run_kind"):
            qs = qs.filter(run_kind=params["run_kind"])
        return qs

    def get_serializer_class(self):
        return (CollectionRunDetailSerializer if self.action == "retrieve"
                else CollectionRunSerializer)

    @action(detail=True, methods=["get"])
    def adjudication(self, request, pk=None):
        """What the investigation engine concluded about this host.

        The adjudication surface: a thousand findings sorted by nothing is not reviewable,
        whereas the handful of processes the engine judged — with the rationale it judged
        them on, the attack chains it reconstructed, and any disagreement with the on-host
        adjudication — is what an analyst works from.

        Everything here is the engine's output. The platform ranks and paginates it; it
        does not decide any of it.
        """
        run = self.get_object()
        # The CURRENT pass only. Superseded verdicts are kept as history — a reviewer needs
        # to see what the engine concluded before it changed its mind — but showing them
        # beside the live ones would present one PID twice carrying two verdicts.
        verdicts = run.process_verdicts.filter(is_current=True)
        if request.query_params.get("verdict"):
            verdicts = verdicts.filter(engine_label=request.query_params["verdict"])

        latest = (MemoryAnalysisRun.objects
                  .filter(capture__run=run, status="completed")
                  .exclude(investigation={})
                  .order_by("-finished_at").first())
        narrative = (latest.investigation if latest else {}) or {}

        return Response({
            "summary": narrative.get("summary", {}),
            "generated": narrative.get("generated", ""),
            # Full detail per process is a drill-down; the list surface stays bounded no
            # matter how much the memory pass produced.
            "processes": ProcessVerdictSerializer(verdicts[:200], many=True).data,
            "process_count": verdicts.count(),
            "attack_chains": _chain_headers(narrative.get("attack_chains", [])),
            "ttp_pattern_matches": narrative.get("ttp_pattern_matches", []),
            "potential_misses": narrative.get("potential_misses", []),
            "unconfirmed_prior_tps": narrative.get("unconfirmed_prior_tps", []),
            "adjudicated": bool(latest),
        })

    @action(detail=True, methods=["get"], url_path="adjudication/chain")
    def adjudication_chain(self, request, pk=None):
        """The full event sequence for one attack chain.

        Split out from the adjudication response because chains carry every correlated
        event: on a real capture one chain held over a thousand, and shipping them all
        made the summary a half-megabyte payload to render a table of verdicts. An analyst
        opens one chain at a time.
        """
        run = self.get_object()
        try:
            root_pid = int(request.query_params.get("root_pid", ""))
        except ValueError:
            return Response({"error": "root_pid is required"}, status=400)

        latest = (MemoryAnalysisRun.objects
                  .filter(capture__run=run, status="completed")
                  .exclude(investigation={})
                  .order_by("-finished_at").first())
        for chain in ((latest.investigation if latest else {}) or {}).get("attack_chains", []):
            if chain.get("root_pid") == root_pid:
                return Response(chain)
        return Response({"error": f"no chain rooted at pid {root_pid}"}, status=404)

    @action(detail=True, methods=["get"])
    def captures(self, request, pk=None):
        return Response(MemoryCaptureSerializer(self.get_object().captures.all(), many=True).data)


class HostViewSet(viewsets.ReadOnlyModelViewSet):
    """Host history — the 'have we seen this box before?' view."""

    queryset = Host.objects.all()
    serializer_class = HostSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = StandardPagination
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["hostname", "platform"]
    ordering_fields = ["hostname", "platform", "created_at"]
    ordering = ["hostname"]

    @action(detail=True, methods=["get"])
    def runs(self, request, pk=None):
        runs = CollectionRun.objects.filter(host=self.get_object()).select_related("investigation")
        return Response(CollectionRunSerializer(runs, many=True).data)


class MemoryFindingViewSet(viewsets.ReadOnlyModelViewSet):
    """Memory-analysis results, paged. The drill-down behind an analysis summary."""

    queryset = MemoryFinding.objects.select_related("analysis__capture__run__host")
    serializer_class = MemoryFindingSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = StandardPagination
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["finding_type", "detail", "severity"]
    ordering_fields = ["severity", "finding_type", "offset", "created_at"]
    ordering = ["-severity"]

    def get_queryset(self):
        qs = scope_by_investigation(super().get_queryset(), self.request.user,
                                    "analysis__capture__run__investigation_id")
        params = self.request.query_params
        if params.get("analysis"):
            qs = qs.filter(analysis_id=params["analysis"])
        if params.get("run"):
            qs = qs.filter(analysis__capture__run_id=params["run"])
        if params.get("severity"):
            qs = qs.filter(severity__in=params["severity"].split(","))
        return qs


class FindingViewSet(viewsets.ReadOnlyModelViewSet):
    """Findings, paged and filtered at the database.

    Severity-style triage order is expressed over verdict and confidence rather than a
    stored rank, so the ordering reflects adjudication rather than collection order.
    """

    queryset = Finding.objects.select_related("run", "run__host", "run__investigation")
    serializer_class = FindingSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = StandardPagination
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["finding_type", "target", "subject_path", "verdict", "confidence"]
    ordering_fields = ["created_at", "finding_type", "verdict", "confidence", "target",
                       "run__host__hostname"]
    ordering = ["-created_at"]

    def get_queryset(self):
        qs = scope_by_investigation(super().get_queryset(), self.request.user,
                                    "run__investigation_id")
        params = self.request.query_params
        if params.get("run"):
            qs = qs.filter(run_id=params["run"])
        if params.get("investigation"):
            qs = qs.filter(run__investigation_id=params["investigation"])
        if params.get("host"):
            qs = qs.filter(run__host_id=params["host"])
        if params.get("verdict"):
            qs = qs.filter(verdict__in=params["verdict"].split(","))
        if params.get("source"):
            qs = qs.filter(source=params["source"])
        if params.get("finding_type"):
            qs = qs.filter(finding_type=params["finding_type"])
        if params.get("cells"):
            # Heatmap multi-select: pipe-separated `finding_type::verdict` pairs, OR'd as EXACT pairs.
            # Separate sets per dimension would be the cross product — selecting (A, TP) and (B,
            # Indeterminate) would silently include A's Indeterminate rows, a set no cell on screen claims.
            match = Q(pk__in=[])
            for part in params["cells"].split("|"):
                ft, sep, v = part.partition("::")
                if not sep or not ft:
                    continue
                match |= Q(finding_type=ft, verdict="" if v == "unset" else v)
            qs = qs.filter(match)
        if params.get("day"):
            # The same derivation the aggregates use: the intrusion's own timestamp when the
            # finding carries one, ingest time otherwise. A day-shaped chart mark drills
            # here, so both sides must read the same clock.
            day = params["day"]
            qs = qs.filter(
                Q(raw__Timestamp__startswith=day)
                | (
                    (Q(raw__Timestamp__isnull=True) | Q(raw__Timestamp=""))
                    & Q(created_at__date=day)
                )
            )
        if params.get("adjudicated"):
            # Adjudicated means PAST THE ENTRY STATE, the same composite the funnel
            # aggregate counts: the engine marked it, or a verdict was set beyond the
            # Indeterminate every promoted lead enters at. Seeded and analyst-set verdicts
            # carry no engine marker, and reading only that marker reported zero adjudicated
            # beneath a non-zero confirmed.
            entry_state = Q(adjudicated_by="") & Q(verdict__in=["", "Indeterminate"])
            if params["adjudicated"] == "yes":
                qs = qs.exclude(entry_state)
            else:
                qs = qs.filter(entry_state)
        if params.get("tactic"):
            # A stage's drill. The tactic maps to the base techniques that serve it, so the
            # table reproduces exactly what the progression counted — the chart cannot claim
            # a set the table has no way to express.
            want = params["tactic"]
            if want == "unmapped":
                qs = qs.filter(Q(mitre=[]) | Q(mitre__isnull=True))
            else:
                bases = [b for b, tacs in TECHNIQUE_TACTICS.items() if want in tacs]
                match = Q(pk__in=[])
                for b in bases:
                    match |= Q(mitre__icontains=b)
                qs = qs.filter(match)
        if params.get("technique"):
            # "unmapped" is the aggregate's name for findings carrying NO technique, and it
            # must be a filter the table can express: a chart mark for those findings has to
            # drill somewhere real. It matches no technique id, so the sentinel is safe.
            if params["technique"] == "unmapped":
                qs = qs.filter(Q(mitre=[]) | Q(mitre__isnull=True))
            else:
                qs = qs.filter(mitre__contains=[params["technique"]])
        return qs


class NoteViewSet(viewsets.ModelViewSet):
    """Entries in the investigation record. Analysts + admins write; auditors read.

    Append-only by design: an entry is retracted with a stated reason rather than edited or
    removed, because a case record that can be rewritten after the fact is not a record.
    """

    queryset = Note.objects.select_related("host", "run", "investigation")
    serializer_class = NoteSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        qs = scope_by_investigation(super().get_queryset(), self.request.user)
        params = self.request.query_params
        for field in ("investigation", "run", "host", "kind"):
            if params.get(field):
                qs = qs.filter(**{f"{field}_id" if field != "kind" else "kind":
                                  params[field]})
        return qs

    def get_permissions(self):
        if self.request.method in ("POST", "PUT", "PATCH"):
            return [IsAnalystOrAdmin()]
        if self.request.method == "DELETE":
            return [IsAdmin()]
        return [IsAuthenticated()]

    def perform_create(self, serializer):
        note = serializer.save(author=self.request.user.username,
                               author_role=role_of(self.request.user))
        mentioned = collab.notify_mentions(
            f"{note.summary or ''} {note.body or ''}", self.request.user.username,
            note.investigation, ref_type="note", ref_id=note.id)
        audit_mod.audit(self.request.user.username, "note.create",
                        role=role_of(self.request.user), method="POST",
                        path=self.request.path, object_type="Note", object_id=note.id,
                        detail={"investigation": note.investigation_id, "run": note.run_id,
                                "host": note.host_id, "kind": note.kind,
                                "mentioned": mentioned})

    @action(detail=True, methods=["post"])
    def retract(self, request, pk=None):
        """Withdraw an entry without erasing it.

        The entry stays in the record, marked and with the reason given. Deleting it would
        remove the fact that someone once asserted it, which is itself part of the history.
        """
        if role_of(request.user) not in ("analyst", "admin"):
            return Response({"error": "analyst or admin only"},
                            status=status.HTTP_403_FORBIDDEN)
        note = self.get_object()
        reason = (request.data.get("reason") or "").strip()
        if len(reason) < 10:
            return Response({"error": "a retraction needs a stated reason (10+ characters)"},
                            status=400)
        if note.retracted:
            return Response({"error": "already retracted"}, status=400)

        note.retracted = True
        note.retracted_by = request.user.username
        note.retracted_at = timezone.now()
        note.retraction_reason = reason
        note.save(update_fields=["retracted", "retracted_by", "retracted_at",
                                 "retraction_reason"])
        audit_mod.audit(request.user.username, "note.retract",
                        role=role_of(request.user), method="POST", path=request.path,
                        object_type="Note", object_id=note.id, detail={"reason": reason})
        return Response(NoteSerializer(note).data)

    def destroy(self, request, *args, **kwargs):
        return _admin_delete(request, self.get_object(), "Note")


class IngestView(APIView):
    """Store-and-forward broker POSTs a verified bundle here (service token only)."""

    permission_classes = [IsService]

    def post(self, request):
        actor = request.user.username
        run, created = ingest_mod.ingest_bundle(request.data, actor=actor)
        audit_mod.audit(actor, "ingest", role="service", method="POST",
                        path=request.path, object_type="CollectionRun", object_id=run.id,
                        detail={"created": created, "host": run.host.hostname,
                                "custody_verified": run.custody_verified})
        analyses = []
        if created:
            for cap in getattr(run, "_captures", []) or run.captures.all():
                res = analyze_capture.delay(cap.id)
                analyses.append({"capture_id": cap.id, "task_id": res.id})
        return Response({
            "run_id": run.id, "investigation_id": run.investigation_id,
            "created": created, "analyses_enqueued": analyses,
        }, status=201 if created else 200)


class ReAnalyzeView(APIView):
    """Re-run memory analysis on an existing capture at the current detection version."""

    permission_classes = [IsAnalystOrAdmin]

    def post(self, request, capture_id):
        cap = MemoryCapture.objects.get(pk=capture_id)
        if cap.retention_status == "purged":
            return Response({"error": "capture was purged; object no longer in storage"},
                            status=status.HTTP_409_CONFLICT)
        version = request.data.get("ruleset_version", "current")
        res = analyze_capture.delay(cap.id, ruleset_version=version)
        audit_mod.audit(request.user.username, "capture.reanalyze",
                        role=role_of(request.user), method="POST", path=request.path,
                        object_type="MemoryCapture", object_id=cap.id,
                        detail={"ruleset_version": version})
        return Response({"capture_id": cap.id, "task_id": res.id}, status=202)


class CapturePurgeView(APIView):
    """Admin-initiated manual purge of a capture object (metadata/results kept)."""

    permission_classes = [IsAdmin]

    def post(self, request, capture_id):
        cap = MemoryCapture.objects.get(pk=capture_id)
        result = retention_mod.purge_capture(cap, actor=request.user.username,
                                              reason=request.data.get("reason", "admin manual purge"))
        return Response({"capture_id": cap.id, "retention_status": result})


class LegalHoldView(APIView):
    """Admin sets/clears a legal hold so a capture is never auto-purged."""

    permission_classes = [IsAdmin]

    def post(self, request, capture_id):
        cap = MemoryCapture.objects.get(pk=capture_id)
        hold = bool(request.data.get("hold", True))
        cap.retention_status = "legal_hold" if hold else "retained"
        cap.retention_reason = request.data.get("reason", "legal hold") if hold else ""
        cap.save(update_fields=["retention_status", "retention_reason"])
        audit_mod.audit(request.user.username, "capture.legal_hold",
                        role="admin", object_type="MemoryCapture", object_id=cap.id,
                        detail={"hold": hold})
        return Response({"capture_id": cap.id, "retention_status": cap.retention_status})


class RescanRequestView(APIView):
    """Analyst/admin initiates a rescan to validate eradication or a restored baseline.
    Creates a pending request the broker fulfills with a follow-up collection run."""

    def get_permissions(self):
        return [IsAuthenticated()] if self.request.method == "GET" else [IsAnalystOrAdmin()]

    def get(self, request):
        pending = RescanRequest.objects.filter(status="pending")
        return Response(RescanRequestSerializer(pending, many=True).data)

    def post(self, request):
        host = Host.objects.get(pk=request.data["host"])
        baseline = None
        if request.data.get("baseline_run"):
            baseline = CollectionRun.objects.get(pk=request.data["baseline_run"])
        req = RescanRequest.objects.create(
            host=host,
            investigation_id=request.data.get("investigation"),
            baseline_run=baseline,
            kind=request.data.get("kind", "baseline"),
            requested_by=request.user.username,
        )
        audit_mod.audit(request.user.username, "rescan.request",
                        role=role_of(request.user), method="POST", path=request.path,
                        object_type="RescanRequest", object_id=req.id,
                        detail={"host": host.hostname, "kind": req.kind})
        return Response(RescanRequestSerializer(req).data, status=201)


@api_view(["GET"])
def ioc_search(request):
    """Cross-investigation IOC lookup (the historical-analysis payoff)."""
    q = request.query_params.get("q", "").strip()
    if not q:
        return Response({"results": []})
    matches = (IOC.objects.filter(Q(value__icontains=q))
               .select_related("run__host", "run__investigation")[:200])
    results = [{
        "ioc_type": m.ioc_type, "value": m.value,
        "hostname": m.run.host.hostname, "investigation": m.run.investigation.name,
        "investigation_id": m.run.investigation_id, "run_id": m.run_id,
        "collected_at": m.run.collected_at,
    } for m in matches]
    by_value = {}
    for r in results:
        by_value.setdefault(r["value"], set()).add(r["hostname"])
    for r in results:
        r["host_count"] = len(by_value[r["value"]])
    results.sort(key=lambda r: -r["host_count"])
    return Response({"query": q, "count": len(results), "results": results})


class AuditLogView(APIView):
    """The tamper-proof audit trail — visible to auditors and admins. Also reports
    whether the hash chain still verifies."""

    permission_classes = [IsAuditorOrAdmin]

    def get(self, request):
        # The chain is verified over the whole ledger, not the page: a page-local check
        # would miss tampering outside the window being viewed.
        ok, broken = audit_mod.verify_audit_chain()

        rows = AuditLog.objects.order_by("-id")
        if request.query_params.get("q"):
            q = request.query_params["q"]
            rows = rows.filter(
                Q(actor__icontains=q) | Q(action__icontains=q)
                | Q(object_type__icontains=q) | Q(path__icontains=q)
            )
        if request.query_params.get("action"):
            rows = rows.filter(action=request.query_params["action"])
        if request.query_params.get("actor"):
            rows = rows.filter(actor=request.query_params["actor"])

        paginator = StandardPagination()
        page = paginator.paginate_queryset(rows, request, view=self)
        payload = paginator.get_paginated_response(
            AuditLogSerializer(page, many=True).data
        ).data
        payload.update({"chain_intact": ok, "first_broken_id": broken,
                        "entries": payload["results"]})
        return Response(payload)


class AuditExportView(APIView):
    """Export the audit trail as CSV or JSON, for auditors and admins.

    The export carries the hash-chain verification alongside the entries. An audit trail
    handed over without evidence that it verifies is a list of claims, so the JSON form
    states whether the chain is intact and where it first breaks, and the CSV form is
    accompanied by the same result in its headers.

    Taking an export is itself an auditable act and is recorded before the file is sent.

    Reading the trail and REMOVING it are separate rights. An auditor's remit is to see
    everything, which says nothing about carrying it out of the platform, so both permissions
    are required rather than one implying the other.
    """

    permission_classes = [IsAuditorOrAdmin, CanExport]
    # Read by cases.denials, so a refusal lands in the ledger under the same kind a success
    # would have.
    export_kind = "audit"

    def get(self, request):
        # `fmt`, not `format`: DRF reserves the latter for content negotiation.
        fmt = request.query_params.get("fmt", "csv")
        ok, broken = audit_mod.verify_audit_chain()

        rows = AuditLog.objects.order_by("id")
        params = request.query_params
        if params.get("q"):
            q = params["q"]
            rows = rows.filter(
                Q(actor__icontains=q) | Q(action__icontains=q)
                | Q(object_type__icontains=q) | Q(path__icontains=q)
            )
        for field in ("action", "actor", "object_type"):
            if params.get(field):
                rows = rows.filter(**{field: params[field]})
        if params.get("since"):
            rows = rows.filter(created_at__gte=params["since"])
        if params.get("until"):
            rows = rows.filter(created_at__lte=params["until"])

        limit = min(int(params.get("limit", 50000)), 200000)
        entries = [{
            "id": r.id,
            "at": r.created_at.isoformat(),
            "actor": r.actor,
            "role": r.role,
            "action": r.action,
            "object_type": r.object_type,
            "object_id": r.object_id,
            "method": r.method,
            "path": r.path,
            "detail": json.dumps(r.detail, sort_keys=True) if r.detail else "",
            "hash": r.entry_hash,
            "prev_hash": r.prev_hash,
        } for r in rows[:limit]]

        record_export(request, kind="audit", fmt=fmt, row_count=len(entries),
                      filters={k: params.get(k) for k in
                               ("q", "action", "actor", "object_type", "since", "until")})
        # The chain's own verification stays on the audit trail: it describes the trail's
        # integrity at the moment of export, not what left, and the ledger is a list of
        # what left.
        audit_mod.audit(getattr(request.user, "username", "?"), "audit.export.verification",
                        role=role_of(request.user), method="GET", path=request.path,
                        object_type="AuditLog",
                        detail={"chain_intact": ok, "first_broken_id": broken})

        stamp = timezone.now().strftime("%Y%m%d_%H%M%S")
        if fmt == "json":
            payload = {
                "exported_at": timezone.now().isoformat(),
                "exported_by": getattr(request.user, "username", "?"),
                "chain_intact": ok,
                "first_broken_id": broken,
                "count": len(entries),
                "entries": entries,
            }
            return _attachment(json.dumps(payload, indent=2), "application/json",
                               f"audit-trail_{stamp}.json")

        fields = ["id", "at", "actor", "role", "action", "object_type", "object_id",
                  "method", "path", "detail", "hash", "prev_hash"]
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fields)
        writer.writeheader()
        writer.writerows(entries)
        response = _attachment(buf.getvalue(), "text/csv", f"audit-trail_{stamp}.csv")
        # CSV carries no place for the verification result, so it travels in the headers
        # rather than being dropped.
        response["X-Audit-Chain-Intact"] = "true" if ok else "false"
        if broken:
            response["X-Audit-First-Broken-Id"] = str(broken)
        return response


class ExportLedgerView(APIView):
    """What has left the platform — and what was refused.

    Readable by auditors and admins. Reading the ledger is NOT gated on the export right:
    the people who need to know what left are rarely the people permitted to take it, and
    requiring the second to see the first would hide the record from its audience.

    Totals are computed over the filtered set rather than the returned page, because the
    question is "how much has gone out", and a count that silently means "of the fifty rows
    you are looking at" answers a different one.
    """

    permission_classes = [IsAuditorOrAdmin]

    def get(self, request):
        params = request.query_params
        rows = ExportLedger.objects.all()
        for field in ("actor", "kind", "outcome"):
            if params.get(field):
                rows = rows.filter(**{field: params[field]})
        if params.get("since"):
            rows = rows.filter(created_at__gte=params["since"])
        if params.get("until"):
            rows = rows.filter(created_at__lte=params["until"])

        totals = rows.aggregate(exports=Count("id"), rows_taken=Sum("row_count"))
        limit = min(int(params.get("limit", 200)), 2000)
        entries = [{
            "id": r.id,
            "at": r.created_at.isoformat(),
            "actor": r.actor,
            "role": r.role,
            "kind": r.kind,
            "fmt": r.fmt,
            "filters": r.filters,
            "row_count": r.row_count,
            "destination": r.destination,
            "outcome": r.outcome,
            "denied_reason": r.denied_reason,
            "path": r.path,
        } for r in rows[:limit]]

        return Response({
            "entries": entries,
            "count": len(entries),
            "total_exports": totals["exports"] or 0,
            # Denials are counted separately: a rising refusal count is a finding in its own
            # right, and averaged into one total it disappears.
            "denied": rows.filter(outcome="denied").count(),
            "total_rows_taken": totals["rows_taken"] or 0,
        })


class PlatformMetricsView(APIView):
    """Platform health and performance — admin only.

    Measured live on every request: a cached health panel can report healthy while the
    thing it describes is down.
    """

    permission_classes = [IsAdmin]

    def get(self, request):
        return Response(opsmetrics.collect_all())


class ComponentHealthReportView(APIView):
    """A component POSTs its own resource report here (service token only).

    Reported rather than probed: the figures that predict a failed collection — a volume's
    free space, a container's memory ceiling, a link's drop counter — are only visible from
    inside the container they describe. The DMZ receiver has no route inward, so its report
    arrives the way its bundles do, carried outbound by the puller.
    """

    permission_classes = [IsService]

    def post(self, request):
        # One reporter may forward several components: the puller carries the receiver's
        # report alongside its own, because the receiver cannot reach in here itself.
        reports = request.data.get("reports") or [request.data]
        stored = []
        for r in reports:
            name = (r.get("component") or "").strip()
            if not name:
                continue
            componenthealth.report_component(
                name, r.get("tier", ""), r.get("metrics") or r, r.get("note", ""))
            stored.append(name)
        return Response({"stored": stored})


class ComponentHealthView(APIView):
    """Per-component resources, environment and log counts — admin only.

    Separate from the platform metrics panel: that one answers whether each service is
    reachable, which is what gets asked once something has already broken. This answers
    whether the next collection will fit, which is worth asking beforehand.
    """

    permission_classes = [IsAdmin]

    def get(self, request):
        return Response(componenthealth.overview())


class MeshHealthView(APIView):
    """The service mesh as Consul reports it — admin only.

    Distinct from component health: that says whether each service is up, this says whether it
    is IN THE MESH and which pairs the policy authorizes. A service can be perfectly healthy
    and unproxied, in which case its traffic bypasses every intention — the exact condition
    this platform once shipped, and the reason `proxied` is a field rather than an assumption.
    """

    permission_classes = [IsAdmin]

    def get(self, request):
        return Response(meshhealth.overview())


class BrokeredSessionsView(APIView):
    """Every analyst session Boundary has brokered — admin and auditor.

    Auditors can read it because it IS the access record: analysts reach this platform only
    through a brokered session, so who connected, from where and for how long cannot be
    answered anywhere else. Read-only by construction — the credential behind it can list and
    read sessions, and cannot authorize or cancel one.
    """

    permission_classes = [IsAuditorOrAdmin]

    def get(self, request):
        return Response(brokeredsessions.overview())


class RemediationView(APIView):
    """Request a named repair, and read the history of them.

    The platform records the request and executes NOTHING. `troubleshooting/remediation-agent.sh`
    runs on the enclave host, polls for queued rows and matches the action name against its own
    allow-list. Giving this container the runtime socket instead would put a container-escape
    path in a request-serving service, which is the boundary the whole tier split defends.

    The action name is validated here too — not as the security control, which is the agent's
    list, but so an admin gets an immediate, clear rejection instead of a row that sits queued
    forever because nothing will ever claim it.
    """

    permission_classes = [IsAdmin]

    def get(self, request):
        qs = RemediationAction.objects.all()
        state = request.query_params.get("status")
        if state:
            qs = qs.filter(status=state)
        return Response({
            "catalog": remediation.catalog(),
            "requests": [
                {"id": r.id, "action": r.action, "actor": r.actor, "reason": r.reason,
                 "status": r.status, "exit_code": r.exit_code, "output": r.output,
                 "agent_host": r.agent_host, "created_at": r.created_at,
                 "finished_at": r.finished_at}
                for r in qs[:100]
            ],
        })

    def post(self, request):
        action_name = (request.data or {}).get("action", "")
        if not remediation.is_known(action_name):
            return Response({"detail": f"unknown action '{action_name}'"},
                            status=status.HTTP_400_BAD_REQUEST)
        row = RemediationAction.objects.create(
            action=action_name,
            actor=getattr(request.user, "username", "unknown"),
            reason=(request.data or {}).get("reason", "")[:2000],
        )
        audit_mod.audit(getattr(request.user, "username", "unknown"), "remediation.request",
                        role="admin", object_type="RemediationAction", object_id=str(row.id),
                        detail=f"action={action_name}")
        return Response({"id": row.id, "action": row.action, "status": row.status},
                        status=status.HTTP_201_CREATED)


class RemediationQueueView(APIView):
    """What the agent polls: queued requests, nothing else.

    Service credential — the admin GET above carries the catalog and full history, which the
    agent has no business reading, and IsAdmin refuses its token anyway. This returns the
    minimum a claim needs: id and action name.
    """

    permission_classes = [IsService]

    def get(self, request):
        return Response({
            "requests": [
                {"id": r.id, "action": r.action}
                for r in RemediationAction.objects.filter(status="queued")[:20]
            ],
        })


class RemediationDetailView(APIView):
    """The agent reporting back on a repair it claimed.

    Service credential, not an admin one: this is written by the host agent, and an admin
    session must not be able to forge the OUTCOME of a repair it requested — that is the
    difference between an audit record and a note.

    Transitions are guarded: `running` claims atomically from `queued`, terminal states apply
    only from `queued` or `running`. Two agents polling the same platform then race on the
    claim and exactly one wins; the loser gets 409 and moves on, instead of both running the
    same repair.
    """

    permission_classes = [IsService]

    def patch(self, request, pk):
        try:
            row = RemediationAction.objects.get(pk=pk)
        except RemediationAction.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)
        data = request.data or {}
        new_status = data.get("status")
        if new_status in dict(RemediationAction.STATUS_CHOICES):
            if new_status == "running":
                claimed = RemediationAction.objects.filter(
                    pk=pk, status="queued").update(status="running",
                                                  claimed_at=timezone.now())
                if not claimed:
                    return Response({"detail": f"not queued (status={row.status})"},
                                    status=status.HTTP_409_CONFLICT)
                row.refresh_from_db()
            elif new_status in ("succeeded", "failed", "rejected"):
                if row.status not in ("queued", "running"):
                    return Response({"detail": f"already finished (status={row.status})"},
                                    status=status.HTTP_409_CONFLICT)
                row.status = new_status
                row.finished_at = timezone.now()
        if "output" in data:
            row.output = (data.get("output") or "")[:8000]
        if "exit_code" in data:
            row.exit_code = data.get("exit_code")
        if "agent_host" in data:
            row.agent_host = (data.get("agent_host") or "")[:128]
        row.save()
        return Response({"id": row.id, "status": row.status})


class SymbolRequestView(APIView):
    """Kernels whose symbol tables the enclave is missing.

    Neither the collector nor the enclave may reach the internet, so acquiring debug
    symbols is an administrator's job. This is how they learn what to fetch, and it
    exports only kernel identity — no evidence, hostnames or case context leaves with it.

    Symbols are perishable: distributions prune debug packages for superseded kernel ABIs,
    so an ageing request can become impossible to satisfy. `age_days` is surfaced for that
    reason, not as decoration.
    """

    permission_classes = [IsAdmin]

    def get(self, request):
        from django.utils import timezone

        rows = []
        for r in SymbolRequest.objects.all():
            age = None
            if r.first_needed_at:
                age = (timezone.now() - r.first_needed_at).days
            rows.append({
                "symbol_key": r.symbol_key,
                "kernel_release": r.kernel_release,
                "arch": r.arch,
                "build_id": r.build_id,
                "os_release": r.os_release,
                "status": r.status,
                "waiting_captures": r.waiting_captures,
                "first_needed_at": r.first_needed_at,
                "fulfilled_at": r.fulfilled_at,
                "age_days": age,
                "isf_sha256": r.isf_sha256,
            })
        return Response({
            "requests": rows,
            "outstanding": sum(1 for r in rows if r["status"] == "needed"),
        })


class SymbolRequisitesView(APIView):
    """The requisites an administrator carries out to acquire symbols.

    It leaves the enclave on removable media, so it is an export and is ledgered as one —
    even though it carries kernel identity rather than evidence. What crossed the boundary
    is the question the ledger answers, not how sensitive it was.
    """

    permission_classes = [IsAdmin, CanExport]
    export_kind = "symbol_requisites"

    def get(self, request):
        payload = symbols_mod.requisites_export()
        record_export(request, kind="symbol_requisites", fmt="json",
                      row_count=len(payload["requests"]),
                      destination="removable media (administrator, out of band)")
        response = Response(payload)
        response["Content-Disposition"] = 'attachment; filename="symbol-requisites.json"'
        return response


class TaskStatusView(APIView):
    """State of long-running analysis work, so the UI can show progress rather than
    leaving a queued job indistinguishable from a stuck one."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        recent = MemoryAnalysisRun.objects.select_related("capture__run__host").order_by("-id")[:20]
        return Response({"analyses": [{
            "id": a.id,
            "capture_id": a.capture_id,
            "hostname": a.capture.run.host.hostname,
            "status": a.status,
            "engine": a.engine,
            "ruleset_version": a.ruleset_version,
            "started_at": a.started_at,
            "finished_at": a.finished_at,
            "finding_count": (a.summary or {}).get("finding_count"),
            "error": a.error[:300] if a.error else "",
        } for a in recent],
            "pending": MemoryAnalysisRun.objects.filter(
                status__in=("queued", "running")).count(),
            "failed": MemoryAnalysisRun.objects.filter(status="failed").count(),
        })


@api_view(["GET"])
def facets(request):
    """Selectable drill-down dimensions for the dashboard panels."""
    verdicts = (Finding.objects.exclude(verdict="")
                .values("verdict").annotate(count=Count("id")).order_by("-count"))
    retention = (MemoryCapture.objects.values("retention_status")
                 .annotate(count=Count("id")).order_by("-count"))
    hosts = [{"id": h.id, "hostname": h.hostname,
              "compromised": h.runs.filter(compromised=True).exists()}
             for h in Host.objects.all()]
    invs = [{"id": i.id, "name": i.name, "run_count": i.runs.count()}
            for i in Investigation.objects.all()]
    return Response({
        "investigations": invs,
        "hosts": hosts,
        "verdicts": [{"value": v["verdict"], "count": v["count"]} for v in verdicts],
        "retention": [{"value": r["retention_status"], "count": r["count"]} for r in retention],
    })


def _csv(request, name):
    raw = request.query_params.get(name, "").strip()
    return [x for x in raw.split(",") if x] if raw else []


@api_view(["GET"])
def summary(request):
    """Aggregate summary for the current cross-panel selection (intersection).

    Query params (comma-separated): investigations, hosts, verdicts, retention.
    Empty selection => whole corpus. Powers the dashboard's drill-down summary."""
    inv_ids = _csv(request, "investigations")
    host_ids = _csv(request, "hosts")
    verdicts = _csv(request, "verdicts")
    retention = _csv(request, "retention")

    runs = CollectionRun.objects.select_related("host", "investigation")
    if inv_ids:
        runs = runs.filter(investigation_id__in=inv_ids)
    if host_ids:
        runs = runs.filter(host_id__in=host_ids)
    if retention:
        runs = runs.filter(captures__retention_status__in=retention)
    if verdicts:
        runs = runs.filter(findings__verdict__in=verdicts)
    runs = runs.distinct()

    findings = Finding.objects.filter(run__in=runs)
    if verdicts:
        findings = findings.filter(verdict__in=verdicts)

    return Response({
        "selection": {"investigations": inv_ids, "hosts": host_ids,
                      "verdicts": verdicts, "retention": retention},
        "totals": {
            "runs": runs.count(),
            "hosts": runs.values("host").distinct().count(),
            "findings": findings.count(),
            "true_positives": findings.filter(verdict="True Positive").count(),
            "compromised_runs": runs.filter(compromised=True).count(),
            "iocs": IOC.objects.filter(run__in=runs).count(),
            "captures": MemoryCapture.objects.filter(run__in=runs).count(),
        },
        "runs": [{
            "id": r.id, "hostname": r.host.hostname, "platform": r.host.platform,
            "investigation": r.investigation.name, "investigation_id": r.investigation_id,
            "run_kind": r.run_kind, "compromised": r.compromised,
            "tp_count": r.tp_count, "overall_status": r.overall_status,
        } for r in runs[:200]],
    })


@api_view(["GET"])
def stats(request):
    return Response({
        "investigations": Investigation.objects.count(),
        "hosts": Host.objects.count(),
        "runs": CollectionRun.objects.count(),
        "findings": Finding.objects.count(),
        "true_positives": Finding.objects.filter(verdict="True Positive").count(),
        "captures": MemoryCapture.objects.count(),
        "captures_retained": MemoryCapture.objects.filter(retention_status="retained").count(),
        "captures_purged": MemoryCapture.objects.filter(retention_status="purged").count(),
        "compromised_hosts": CollectionRun.objects.filter(compromised=True)
                             .values("host").distinct().count(),
        "recurring_hosts": Host.objects.annotate(n=Count("runs")).filter(n__gt=1).count(),
    })


def _chain_headers(chains, limit=50):
    """Attack chains without their event lists.

    A chain's value on a summary screen is its shape — what it is rooted at, what stages
    it reached, and the engine's one-line narrative. The events behind it are the
    drill-down, and there can be over a thousand in a single chain.
    """
    return [{
        "root_pid": c.get("root_pid"),
        "root_process": c.get("root_process", ""),
        "verdict": c.get("verdict", ""),
        "stages_present": c.get("stages_present", []),
        "narrative": c.get("narrative", ""),
        "related_pids": (c.get("related_pids") or [])[:20],
        "event_count": len(c.get("events") or []),
    } for c in chains[:limit]]


def _admin_delete(request, obj, obj_type):
    """Shared admin-only delete with an audit entry recording what was removed."""
    if role_of(request.user) != "admin":
        return Response({"error": "deletion is admin-only"}, status=status.HTTP_403_FORBIDDEN)
    obj_id = obj.pk
    audit_mod.audit(request.user.username, f"{obj_type.lower()}.delete", role="admin",
                    method="DELETE", path=request.path, object_type=obj_type,
                    object_id=obj_id, detail={"repr": str(obj)})
    # Correlation for a deleted investigation is dropped by the post_delete signal in
    # cases/signals.py, which covers every deletion path rather than this one alone.
    obj.delete()
    return Response(status=status.HTTP_204_NO_CONTENT)
