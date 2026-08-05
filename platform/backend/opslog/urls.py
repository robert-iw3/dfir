from django.urls import path

from . import views

urlpatterns = [
    path("client-errors/", views.ClientErrorView.as_view()),   # the browser reporting itself
    path("client-errors/list/", views.client_errors),
    path("requests/", views.RequestLogView.as_view()),
]
