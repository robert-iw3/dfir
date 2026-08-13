from django.urls import path

from . import logstore, views

urlpatterns = [
    path("client-errors/", views.ClientErrorView.as_view()),   # the browser reporting itself
    path("client-errors/list/", views.client_errors),
    path("requests/", views.RequestLogView.as_view()),
    path("logs/sources/", logstore.LogSourceView.as_view()),
    path("logs/objects/", logstore.LogObjectView.as_view()),
    path("logs/download/", logstore.LogDownloadView.as_view()),
]
