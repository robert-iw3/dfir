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

from . import authevents
from .rbac import GRANT_GROUPS, ROLES


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
        # ONLY the X-Forwarded-* set, which oauth2-proxy replaces on the request it makes to
        # the upstream. The X-Auth-Request-* form belongs to the RESPONSE side of an
        # auth_request subrequest, and Remote-* is set by nothing in this deployment — so on
        # the request path both are whatever the client sent, and accepting them as fallbacks
        # let a caller name their own identity to a backend that had already decided to trust
        # the hop because the shared secret was present.
        email = _header(request, "X-Forwarded-Email")
        if not email:
            return None

        username = (_header(request, "X-Forwarded-Preferred-Username")
                    or _header(request, "X-Forwarded-User")
                    or email).split("@")[0]
        user, _ = User.objects.get_or_create(
            username=username, defaults={"email": email, "is_active": True})
        if email and user.email != email:
            user.email = email
            user.save(update_fields=["email"])

        # Role is authoritative from the Keycloak groups claim; highest privilege wins.
        # ROLES rather than a literal tuple, so a role added there cannot be silently absent
        # here — `reverse_engineer` was, which sent every RE session down the no-sync path.
        raw_groups = _header(request, "X-Forwarded-Groups")
        groups = [g.strip().lstrip("/") for g in raw_groups.split(",") if g.strip()]
        role = next((r for r in ROLES if r in groups), None)
        # Rights that compose with the role rather than replacing it. Read from the same
        # claim, so Keycloak stays authoritative in BOTH directions: withdrawing the group
        # there withdraws the right here on the next request.
        grants = [g for g in GRANT_GROUPS if g in groups]
        if role:
            _sync_role(user, role, grants)
        else:
            # An absent role is a REVOCATION, not "keep whatever this account had". Treating
            # it as the latter made withdrawing someone's group in Keycloak a no-op — the
            # platform's documented answer to a suspect insider, withdrawing nothing, while a
            # stale local admin stayed admin across fresh logins.
            _revoke(user)
            raise exceptions.AuthenticationFailed("SSO user has no platform role group")

        # Attribute the request to a sign-on, opening one on first sight. Stateless auth has
        # no login call to hook, so this is the point at which a login becomes observable.
        authevents.note_request(request, user, role or "")
        return (user, None)


def _revoke(user):
    """Strip every local right when the claim carries no role.

    Refusing the request alone is not enough: the groups and the staff/superuser flags persist
    on the account, so any other path that reads them — the Django admin site, a token, a
    later request whose claim is momentarily present — still sees the old privilege.
    """
    if user.groups.exists():
        user.groups.clear()
    if user.is_superuser or user.is_staff:
        user.is_superuser = user.is_staff = False
        user.save(update_fields=["is_superuser", "is_staff"])


def _sync_role(user, role, grants=()):
    """Reconcile the local groups to exactly what the claim carries.

    The whole set is replaced rather than merged. A grant removed in Keycloak has to be
    removed here, and a merge would leave it in place for the life of the account — which is
    the failure mode that matters, since the reason a right gets withdrawn mid-incident is
    usually that someone is under suspicion.
    """
    desired = {role, *grants}
    current = set(user.groups.values_list("name", flat=True))
    if current == desired:
        return
    user.groups.set([Group.objects.get_or_create(name=name)[0] for name in sorted(desired)])
    # admin role implies Django staff/superuser for the admin site + delete rights.
    is_admin = role == "admin"
    if user.is_superuser != is_admin or user.is_staff != is_admin:
        user.is_superuser = user.is_staff = is_admin
        user.save(update_fields=["is_superuser", "is_staff"])
