from django.urls import include, path
from rest_framework.authtoken.views import obtain_auth_token
from rest_framework.routers import DefaultRouter

from . import (aggregates, authviews, casework, collab, handover, reporting, reversing,
               scoping, search, tiering, triage, views)

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
router.register("worksets", reversing.ReWorksetViewSet, basename="workset")

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
    # Sign-on lifecycle. Stateless SSO leaves no login or logout to observe, so both are
    # recorded here rather than inferred from activity.
    path("auth/logout/", authviews.SignOutView.as_view()),
    path("auth/sessions/", authviews.SessionsView.as_view()),
    path("audit/", views.AuditLogView.as_view()),
    path("audit/export/", views.AuditExportView.as_view()),
    # What has left the platform, as a table rather than as a filter over the audit chain.
    path("exports/", views.ExportLedgerView.as_view()),
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
    path("investigations/archive-due/", tiering.ArchiveDueView.as_view()),
    path("investigations/<int:investigation_id>/tree/",
         casework.CaseTreeView.as_view()),
    path("investigations/<int:investigation_id>/tags/",
         casework.CaseTagAssignView.as_view()),
    path("investigations/<int:investigation_id>/tasks/",
         casework.CaseTaskView.as_view()),
    path("tags/", casework.CaseTagView.as_view()),
    path("report-templates/", reporting.ReportTemplateView.as_view()),
    path("investigations/<int:investigation_id>/reports/",
         reporting.CaseReportView.as_view()),
    path("reports/<int:report_id>/", reporting.ReportContentView.as_view()),
    path("reports/<int:report_id>/download/",
         reporting.ReportDownloadView.as_view()),
    path("hosts/<int:host_id>/overview/", casework.HostOverviewView.as_view()),
    path("tasks/board/", casework.TaskBoardView.as_view()),
    path("tasks/<int:task_id>/", casework.CaseTaskDetailView.as_view()),
    path("tasks/<int:task_id>/notes/", casework.CaseTaskNoteView.as_view()),
    path("tasks/<int:task_id>/attachments/", casework.CaseTaskAttachmentView.as_view()),
    path("tasks/<int:task_id>/attachments/<int:attachment_id>/",
         casework.CaseTaskAttachmentDownloadView.as_view()),
    path("investigations/<int:investigation_id>/assignments/",
         scoping.CaseAssignmentView.as_view()),
    path("investigations/<int:investigation_id>/compartment/",
         scoping.CaseCompartmentView.as_view()),
    path("investigations/<int:investigation_id>/restore/", tiering.RestoreView.as_view()),
    path("investigations/activity/", aggregates.investigations_activity),
    path("findings/funnel/", aggregates.findings_funnel),
    path("findings/backlog/", aggregates.findings_backlog),
    path("findings/matrix/", aggregates.findings_matrix),
    path("runs/<int:run_id>/timeline/", aggregates.run_timeline),
    path("runs/<int:run_id>/custody/", aggregates.run_custody),
    path("iocs/<str:ioc_type>/<path:value>/spread/", aggregates.ioc_spread),
    path("admin/queue-depth/", aggregates.QueueDepthView.as_view()),
    path("admin/storage-allocation/", aggregates.StorageAllocationView.as_view()),
    path("presence/", collab.PresenceView.as_view()),
    path("locks/", collab.LockView.as_view()),
    path("notifications/", collab.NotificationView.as_view()),
    path("me/here/", collab.WhoAmIHereView.as_view()),
    path("investigations/<int:investigation_id>/activity/",
         collab.ActivityFeedView.as_view()),
    path("search/", search.GlobalSearchView.as_view()),
    path("handover/", handover.HandoverView.as_view()),
    # Derived multi-host correlation, served from its own database.
    path("correlation/", include("correlation.urls")),
    path("", include(router.urls)),
]
