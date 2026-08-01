"""
Keycloak Admin API client — provisions platform users in Keycloak for SSO.

When an admin creates a user in the platform, the account is created in Keycloak (so the
user can sign in via SSO) and placed in the group that maps to their platform role. Uses
the bootstrap admin credentials against the master realm to obtain an admin token, then
manages the platform realm. (A scoped service-account client is the production hardening.)

Stdlib only (urllib) so the backend image needs no extra dependency.
"""
import json
import os
import urllib.error
import urllib.parse
import urllib.request

from django.conf import settings


def _cfg(key, default=""):
    return getattr(settings, "KEYCLOAK", {}).get(key, default) or default


def _url():
    return _cfg("URL", os.environ.get("KEYCLOAK_URL", "http://keycloak:8080")).rstrip("/")


def _realm():
    return _cfg("REALM", "irplatform")


class KeycloakError(RuntimeError):
    pass


def _post_form(path, data, token=None):
    body = urllib.parse.urlencode(data).encode()
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(_url() + path, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


def _admin_token():
    data = {
        "grant_type": "password",
        "client_id": "admin-cli",
        "username": _cfg("ADMIN_USER", os.environ.get("KEYCLOAK_ADMIN", "admin")),
        "password": _cfg("ADMIN_PASSWORD", os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "admin")),
    }
    return _post_form("/realms/master/protocol/openid-connect/token", data)["access_token"]


def _api(method, path, token, payload=None):
    url = f"{_url()}/admin/realms/{_realm()}{path}"
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode()
            return json.loads(raw) if raw else None, dict(resp.headers)
    except urllib.error.HTTPError as exc:
        raise KeycloakError(f"{method} {path} -> {exc.code}: {exc.read().decode()[:300]}") from exc


def _group_id(token, name):
    groups, _ = _api("GET", "/groups", token)
    for g in groups or []:
        if g["name"] == name:
            return g["id"]
    raise KeycloakError(f"group '{name}' not found in realm {_realm()}")


def create_user(username, email, role, password, temporary=True):
    """Create a Keycloak user in the group matching `role`. Returns the KC user id.
    Idempotent-ish: if the user exists, updates group membership + password."""
    token = _admin_token()
    # Create (or find existing) user.
    payload = {"username": username, "email": email, "enabled": True,
               "emailVerified": True, "firstName": username, "lastName": role}
    try:
        _, headers = _api("POST", "/users", token, payload)
        location = headers.get("Location", "")
        user_id = location.rstrip("/").split("/")[-1]
    except KeycloakError as exc:
        if "409" not in str(exc):
            raise
        found, _ = _api("GET", f"/users?username={urllib.parse.quote(username)}&exact=true", token)
        if not found:
            raise
        user_id = found[0]["id"]

    _api("PUT", f"/users/{user_id}/reset-password", token,
         {"type": "password", "value": password, "temporary": temporary})
    _api("PUT", f"/users/{user_id}/groups/{_group_id(token, role)}", token, {})
    return user_id


def list_users():
    token = _admin_token()
    users, _ = _api("GET", "/users?max=500", token)
    out = []
    for u in users or []:
        groups, _ = _api("GET", f"/users/{u['id']}/groups", token)
        out.append({"username": u.get("username"), "email": u.get("email"),
                    "enabled": u.get("enabled"),
                    "roles": [g["name"] for g in (groups or [])]})
    return out
