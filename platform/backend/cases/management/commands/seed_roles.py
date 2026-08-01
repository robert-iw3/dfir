"""
Seed the three roles (admin/analyst/auditor) as Django groups, a broker service
account, and — in dev/UAT — one demo user per role with a stable API token printed to
stdout so the E2E test can authenticate as each role.
"""
import os

from django.conf import settings
from django.contrib.auth.models import Group, User
from django.core.management.base import BaseCommand
from rest_framework.authtoken.models import Token

from cases.rbac import ROLES, SERVICE_GROUP


class Command(BaseCommand):
    help = "Create RBAC groups, a broker service account, and demo users."

    def handle(self, *args, **opts):
        for name in (*ROLES, SERVICE_GROUP):
            Group.objects.get_or_create(name=name)
        self.stdout.write(f"groups: {', '.join((*ROLES, SERVICE_GROUP))}")

        # Broker service account (ingest only) — token from env or generated.
        svc, _ = User.objects.get_or_create(username="ir-broker",
                                            defaults={"is_active": True})
        svc.groups.set([Group.objects.get(name=SERVICE_GROUP)])
        svc.save()
        svc_token = os.environ.get("IR_BROKER_TOKEN")
        if svc_token:
            Token.objects.filter(user=svc).delete()
            Token.objects.create(user=svc, key=svc_token[:40])
        tok, _ = Token.objects.get_or_create(user=svc)
        self.stdout.write(f"service ir-broker token: {tok.key}")

        if not settings.SEED_DEMO_USERS:
            return

        demo = {
            "admin": os.environ.get("IR_ADMIN_PASSWORD", "admin-demo-pw"),
            "analyst": os.environ.get("IR_ANALYST_PASSWORD", "analyst-demo-pw"),
            "auditor": os.environ.get("IR_AUDITOR_PASSWORD", "auditor-demo-pw"),
        }
        for role, pw in demo.items():
            user, _ = User.objects.get_or_create(
                username=role, defaults={"is_active": True})
            user.set_password(pw)
            user.is_superuser = user.is_staff = (role == "admin")
            user.groups.set([Group.objects.get(name=role)])
            user.save()
            t, _ = Token.objects.get_or_create(user=user)
            self.stdout.write(f"user {role} token: {t.key}")
