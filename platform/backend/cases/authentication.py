"""
SSO header authentication.

The frontend sits behind Traefik + oauth2-proxy (OIDC → Keycloak). On a valid session,
oauth2-proxy returns the identity, Traefik forwards it as Remote-* headers, and nginx passes
them to the backend along with a shared proxy secret. This authentication class trusts
those headers ONLY when the shared secret matches (so the identity cannot be spoofed by a
client that reaches the backend directly), then just-in-time provisions the Django user
and syncs their role from the Keycloak groups claim the SSO gate forwards.

Kept alongside TokenAuthentication: the store-and-forward broker still authenticates with
its service token (it does not pass through the SSO gate).
"""
from django.conf import settings
from django.contrib.auth.models import Group, User
from rest_framework import authentication, exceptions

from .rbac import ROLES


def _header(request, name):
    return request.META.get("HTTP_" + name.upper().replace("-", "_"), "")


class SSOHeaderAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        secret = getattr(settings, "SSO_PROXY_SECRET", "")
        # Only engage when SSO is enabled and the trusted-proxy secret is present+correct.
        if not secret:
            return None
        if _header(request, "X-Proxy-Auth") != secret:
            return None
        # oauth2-proxy forwards X-Auth-Request-*; Remote-* is accepted as a fallback.
        email = (_header(request, "X-Forwarded-Email")
                 or _header(request, "X-Auth-Request-Email")
                 or _header(request, "Remote-Email")
                 or _header(request, "X-Auth-Request-User")
                 or _header(request, "Remote-User"))
        if not email:
            return None

        username = (_header(request, "X-Forwarded-Preferred-Username")
                    or _header(request, "X-Auth-Request-Preferred-Username")
                    or _header(request, "X-Auth-Request-User")
                    or _header(request, "Remote-User")
                    or email).split("@")[0]
        user, _ = User.objects.get_or_create(
            username=username, defaults={"email": email, "is_active": True})
        if email and user.email != email:
            user.email = email
            user.save(update_fields=["email"])

        # Role is authoritative from the Keycloak groups claim; highest privilege wins.
        raw_groups = (_header(request, "X-Forwarded-Groups")
                      or _header(request, "X-Auth-Request-Groups")
                      or _header(request, "Remote-Groups"))
        groups = [g.strip().lstrip("/") for g in raw_groups.split(",") if g.strip()]
        role = next((r for r in ("admin", "analyst", "auditor") if r in groups), None)
        if role:
            _sync_role(user, role)
        elif not user.groups.exists():
            raise exceptions.AuthenticationFailed("SSO user has no platform role group")
        return (user, None)


def _sync_role(user, role):
    current = set(user.groups.values_list("name", flat=True))
    if current == {role}:
        return
    grp, _ = Group.objects.get_or_create(name=role)
    user.groups.set([grp])
    # admin role implies Django staff/superuser for the admin site + delete rights.
    is_admin = role == "admin"
    if user.is_superuser != is_admin or user.is_staff != is_admin:
        user.is_superuser = user.is_staff = is_admin
        user.save(update_fields=["is_superuser", "is_staff"])
