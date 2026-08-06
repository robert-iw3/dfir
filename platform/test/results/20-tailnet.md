## Analyst tunnel — WireGuard reachability

*What passing proves:* An analyst workstation reaches the platform only over an authenticated WireGuard tunnel to the bastion, with no route to any internal host.

- Run: `uat_tailnet.sh` — 2026-08-06 16:25:51Z

**Control plane**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | headscale answers (headscale version v0.29.3) |
| ✅ PASS | user analyst exists (the ACL grants from it) |
| ✅ PASS | user bastion exists (the ACL grants from it) |

**Nodes**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | bastion is enrolled in the tailnet |
| ✅ PASS | analyst is enrolled in the tailnet |

**Tunnel — a real interface, not userspace**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | bastion has a tailscale interface |
| ✅ PASS | bastion holds tailnet address 100.64.0.1 |
| ✅ PASS | analyst has a tailscale interface |
| ✅ PASS | analyst holds tailnet address 100.64.0.2 |

**Confinement — the tunnel belongs to the container, not the host**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the host has no tailnet interface (the tunnel is namespaced to its container) |
| ✅ PASS | browser shares the tailnet namespace — its traffic leaves over WireGuard |
| ✅ PASS | no default route in the analyst namespace (no egress, no internal reach) |

**Traffic — the analyst reaches the platform THROUGH the tunnel**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | analyst opened TCP to 100.64.0.1:8443 over the tunnel |

**Broker — the forwarder binds the tunnel, not a network beside it**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the brokered port is bound in the bastion's namespace |
| · | listeners in the bastion namespace: 3 (tailscaled's own sockets included) |

**DERP — the tunnel has a relay to fall back on**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | bastion relays through the embedded DERP region (bastion) |
| ✅ PASS | bastion reports no tunnel health warnings |
| ✅ PASS | analyst relays through the embedded DERP region (bastion) |
| ✅ PASS | analyst reports no tunnel health warnings |
| ✅ PASS | control plane advertises https://headscale:8080 (TLS — required for DERP) |

**Bounds — the tunnel is not a route to the enclave**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | analyst cannot reach the bastion on 8090 |
| ✅ PASS | analyst cannot reach the bastion on 22 |
| ✅ PASS | analyst cannot reach the bastion on 9090 |
| ✅ PASS | no approved subnet routes (workstations cannot address internal hosts) |

**Bounds — internal services stay unreachable**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | analyst cannot reach db:5432 |
| ✅ PASS | analyst cannot reach minio:9000 |
| ✅ PASS | analyst cannot reach backend:8000 |
| ✅ PASS | analyst cannot reach keycloak:8080 |

**Tailnet**

| Result | Assertion — with evidence |
|---|---|

**Verdict: PROVEN** — 27 assertions passed, 0 failed.
