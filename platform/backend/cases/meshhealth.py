"""
The service mesh, as the platform can observe it.

Two questions an admin asks about a mesh, and they are not the same one:

  REGISTERED  which services are in the catalog, and is each one's proxy healthy — the
              shape of the mesh as it actually is right now
  AUTHORIZED  which service may reach which — the policy, which is the half that decides
              whether a compromised container can reach the evidence

A page showing only the first looks reassuring while the policy is empty. Both are read here,
over the mesh's TLS control plane with a token that can read and nothing else: the platform
must never be able to edit the intentions that govern it, and a read-only credential is what
makes "the UI shows the policy" safe to say.

Consul is the authority; nothing here is cached or inferred from configuration files. A file
in the repository is what the policy SHOULD be — this is what it IS.
"""
from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request

CONSUL_ADDR = os.environ.get("IR_CONSUL_ADDR", "https://consul:8501")
CONSUL_CACERT = os.environ.get("IR_CONSUL_CACERT") or None
CONSUL_TOKEN_FILE = os.environ.get("IR_CONSUL_TOKEN_FILE", "/consul/tls/ui-token")

# The mesh's own services, in the order the deployment builds them up: data tier, then the
# secrets store that issues its credentials, then the application, then the ingress edge. The
# page reads as the enclave is assembled rather than alphabetically.
MESH_ORDER = ["ir-postgres", "ir-minio", "ir-vault", "ir-backend", "ir-worker",
              "ir-frontend", "ir-puller"]


def _token():
    try:
        with open(CONSUL_TOKEN_FILE) as fh:
            return fh.read().strip()
    except OSError:
        return ""


def _get(path, timeout=5):
    """One Consul read. Returns parsed JSON, or None when the control plane cannot be reached."""
    ctx = ssl.create_default_context(cafile=CONSUL_CACERT) if CONSUL_CACERT else None
    req = urllib.request.Request(f"{CONSUL_ADDR}/v1{path}",
                                 headers={"X-Consul-Token": _token()})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return json.loads(r.read() or "null")
    except (urllib.error.HTTPError, urllib.error.URLError, OSError, ValueError):
        return None


def _intentions():
    """Every service-intentions entry, flattened to (source, destination) -> action.

    Read from Consul rather than from hashicorp/consul/config-entries/: those files are the
    intended policy, and the whole reason this exists is that the two can differ.
    """
    entries = _get("/config/service-intentions")
    if entries is None:
        return None
    rules = []
    for entry in entries:
        dest = entry.get("Name")
        for src in entry.get("Sources") or []:
            rules.append({
                "source": src.get("Name"),
                "destination": dest,
                "action": (src.get("Action") or "").lower(),
            })
    return rules


def overview():
    """Everything the mesh page needs, in one read of the control plane."""
    services = _get("/catalog/services")
    if services is None:
        # Distinguished from an empty mesh on purpose. "Cannot reach Consul" and "Consul says
        # nothing is registered" look identical on a page that renders both as no rows, and
        # they call for opposite responses.
        return {
            "reachable": False,
            "error": "the mesh control plane did not answer — Consul, its TLS material or the read-only token",
            "services": [], "intentions": [], "proxies": 0, "registered": 0,
        }

    names = sorted(services.keys())
    proxies = [n for n in names if n.endswith("-sidecar-proxy")]
    real = [n for n in names if not n.endswith("-sidecar-proxy") and n != "consul"]

    out = []
    for name in sorted(real, key=lambda n: (MESH_ORDER.index(n) if n in MESH_ORDER else 99, n)):
        health = _get(f"/health/service/{name}") or []
        inst = health[0] if health else {}
        checks = inst.get("Checks") or []
        # Consul's own serf check is about the NODE, not this service; counting it as a service
        # check makes every service look healthy whenever the agent is alive.
        svc_checks = [c for c in checks if c.get("ServiceName") == name or c.get("ServiceID")]
        statuses = {c.get("Status") for c in svc_checks}
        if not statuses:
            # No check DEFINED is not the same as a check that has not reported. These
            # registrations declare none — liveness is the platform health page's job — so the
            # honest answer is that the mesh is not watching, not that something is wrong.
            # Rendering it as "unknown" put a grey dot beside seven healthy services.
            status = "unchecked"
        else:
            status = ("critical" if "critical" in statuses
                      else "warning" if "warning" in statuses
                      else "passing" if statuses == {"passing"} else "unknown")

        svc = inst.get("Service") or {}
        out.append({
            "name": name,
            "address": svc.get("Address") or "",
            "port": svc.get("Port") or 0,
            "status": status,
            # A service in the catalog without a proxy is NOT in the mesh: its traffic bypasses
            # every intention. That is the failure this platform already shipped once, so it is
            # surfaced as a property of each service rather than left to be inferred.
            "proxied": f"{name}-sidecar-proxy" in proxies,
            "checks": [
                {"name": c.get("Name"), "status": c.get("Status"), "output": (c.get("Output") or "")[:200]}
                for c in svc_checks
            ],
        })

    rules = _intentions()
    return {
        "reachable": True,
        "datacenter": (_get("/agent/self") or {}).get("Config", {}).get("Datacenter", "dc1"),
        "registered": len(real),
        "proxies": len(proxies),
        "unproxied": [s["name"] for s in out if not s["proxied"]],
        "services": out,
        "intentions": rules if rules is not None else [],
        "intentions_readable": rules is not None,
    }
