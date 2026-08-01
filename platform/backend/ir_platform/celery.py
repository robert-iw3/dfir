"""Celery entrypoint for the IR platform.

Server-side memory analysis runs here: a worker pulls a stored capture
from the object store and analyzes it, so captures can be re-analyzed later as
detections improve.
"""
import os

from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ir_platform.settings")

app = Celery("ir_platform")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()
