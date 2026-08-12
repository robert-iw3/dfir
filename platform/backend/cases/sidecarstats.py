"""What this component's OWN Envoy sidecar has observed about its upstreams.

The mesh's policy view (Consul intentions) says who MAY reach whom; only the proxies know
who actually tried and what happened. Every proxied service shares its network namespace
with its sidecar, whose admin interface binds loopback inside that namespace — so a
component can read its own sidecar's counters and nobody else's. That boundary is the
design, not a limitation: the observations reported here are first-person, and the mesh
health view labels its coverage accordingly instead of pretending to a fleet-wide wiretap.
"""
import json
import os
import re
import urllib.request

ADMIN = os.environ.get("IR_SIDECAR_ADMIN", "http://127.0.0.1:19000")

# cluster.<service>.default.<dc>.internal.<trust-domain>.consul.<metric>
_CLUSTER = re.compile(r"^cluster\.([a-z0-9-]+)\.[a-z0-9-]+\..*\.consul\.(.+)$")

_METRICS = {
    "upstream_cx_connect_fail": "connect_fail",
    "upstream_cx_total": "cx_total",
    "upstream_cx_active": "cx_active",
}


def upstream_observations(timeout=4):
    """Per-upstream connection counters, or None when this component has no sidecar.

    None and {} are different answers: None means "nothing could observe" (unproxied, or
    the admin endpoint is down) and the caller must not render it as "no failures".
    """
    try:
        with urllib.request.urlopen(
                f"{ADMIN}/stats?filter=upstream_cx&format=json", timeout=timeout) as r:
            stats = json.load(r).get("stats", [])
    except Exception:                                 # noqa: BLE001
        return None

    out = {}
    for s in stats:
        m = _CLUSTER.match(s.get("name", ""))
        if not m:
            continue
        dest, metric = m.group(1), m.group(2)
        if metric in _METRICS:
            out.setdefault(dest, {})[_METRICS[metric]] = int(s.get("value", 0))
    return out
