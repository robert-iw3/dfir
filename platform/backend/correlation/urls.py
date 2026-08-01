from django.urls import path

from . import views

urlpatterns = [
    path("investigations/<int:investigation_id>/", views.investigation_correlation),
    path("campaigns/<int:campaign_id>/graph/", views.campaign_graph),
    path("campaigns/<int:campaign_id>/timeline/", views.campaign_timeline),
    path("indicators/", views.shared_indicators),
    path("recompute/", views.RecomputeView.as_view()),
]
