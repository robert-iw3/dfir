"""IR Platform Django project.

Loads the Celery app so ``@shared_task`` is bound when Django starts.
"""
from .celery import app as celery_app

__all__ = ("celery_app",)
