from django.urls import include, path
from rest_framework.authtoken.views import obtain_auth_token
from rest_framework.routers import DefaultRouter

from . import aggregates, reversing, triage, views

router = DefaultRouter()
router.register("investigations", views.InvestigationViewSet, basename="investigation")
router.register("runs", views.CollectionRunViewSet, basename="run")
router.register("hosts", views.HostViewSet, basename="host")
router.register("findings", views.FindingViewSet, basename="finding")
router.register("memory-findings", views.MemoryFindingViewSet, basename="memoryfinding")
router.register("notes", views.NoteViewSet, basename="note")
# Reverse-engineering workflow over carved regions.
router.register("regions", reversing.CarvedRegionViewSet, basename="region")
router.register("region-analyses", reversing.RegionAnalysisViewSet, basename="regionanalysis")

urlpatterns = [
    path("health/", views.health),
    path("version/", views.version),
    path("stats/", views.stats),
    path("facets/", views.facets),
    path("summary/", views.summary),
    path("auth/token/", obtain_auth_token),           # username+password -> API token
    path("me/", views.me),
    path("users/", views.UsersView.as_view()),
    path("ingest/", views.IngestView.as_view()),
    path("captures/<int:capture_id>/reanalyze/", views.ReAnalyzeView.as_view()),
    path("captures/<int:capture_id>/purge/", views.CapturePurgeView.as_view()),
    path("captures/<int:capture_id>/legal-hold/", views.LegalHoldView.as_view()),
    path("rescans/", views.RescanRequestView.as_view()),
    path("ioc-search/", views.ioc_search),
    path("audit/", views.AuditLogView.as_view()),
    path("audit/export/", views.AuditExportView.as_view()),
    path("admin/metrics/", views.PlatformMetricsView.as_view()),
    path("admin/component-health/", views.ComponentHealthView.as_view()),
    path("admin/mesh-health/", views.MeshHealthView.as_view()),
    path("admin/remediation/", views.RemediationView.as_view()),
    path("admin/remediation/queue/", views.RemediationQueueView.as_view()),
    path("admin/remediation/<int:pk>/", views.RemediationDetailView.as_view()),
    path("brokered-sessions/", views.BrokeredSessionsView.as_view()),
    path("component-health/report/", views.ComponentHealthReportView.as_view()),
    path("tasks/", views.TaskStatusView.as_view()),
    path("admin/symbols/", views.SymbolRequestView.as_view()),
    path("admin/symbols/requisites/", views.SymbolRequisitesView.as_view()),
    path("captures/<int:capture_id>/diff/", triage.AnalysisDiffView.as_view()),
    path("findings/bulk-verdict/", triage.BulkVerdictView.as_view()),
    path("findings/export/", triage.FindingExportView.as_view()),
    path("findings/<int:finding_id>/reclassify/", triage.ReclassifyView.as_view()),
    # Server-side aggregates. Charts read these instead of summing a page of rows.
    path("investigations/<int:investigation_id>/stats/", aggregates.investigation_stats),
    path("investigations/<int:investigation_id>/coverage/", aggregates.investigation_coverage),
    path("investigations/<int:investigation_id>/transition/",
         aggregates.InvestigationTransitionView.as_view()),
    path("investigations/stalled/", aggregates.stalled_investigations),
    path("runs/<int:run_id>/timeline/", aggregates.run_timeline),
    path("runs/<int:run_id>/custody/", aggregates.run_custody),
    path("iocs/<str:ioc_type>/<path:value>/spread/", aggregates.ioc_spread),
    path("admin/queue-depth/", aggregates.QueueDepthView.as_view()),
    # Derived multi-host correlation, served from its own database.
    path("correlation/", include("correlation.urls")),
    path("", include(router.urls)),
]
