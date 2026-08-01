# Administrative access

Management interfaces — MinIO console, Keycloak administration, Consul, PostgreSQL, the
evidence receiver, headscale — are **not published**. They are reachable only while an
admin has opened a forwarder for one tier, and unreachable the rest of the time.

An admin logs into the host that owns a tier, opens access, does the work, and closes it.

```bash
./adminctl.sh up enclave --ttl 30m
./adminctl.sh status
./adminctl.sh down enclave
```

## Why two forwarders

One per tier, each joined only to that tier's network:

| Tier | Network | Reaches |
|---|---|---|
| `enclave` | `ir-enclave_internal` | MinIO console `19001`, Keycloak admin `18080`, Consul `18500`, PostgreSQL `15432` |
| `dmz` | `ir-edge` | Evidence receiver `18090`, headscale `18081` |

The DMZ forwarder has no route to an enclave service and the enclave forwarder has no
route into the DMZ. That containment is the **network membership**, not the target list —
an admin working on the DMZ cannot pivot inward from here, which is the same property the
evidence path depends on.

The DMZ forwarder deliberately does not join `ir-dmzlink`: that network is the DMZ↔enclave
link and carries enclave services (Traefik, Keycloak), so joining it would hand the DMZ
side reach into the enclave.

## What keeps it bounded

- **Off by default.** Nothing here runs as part of a deployment. `deploy.sh` never starts it.
- **Explicit allow-list.** A service with no entry in `adminctl.sh` has no forwarder. There
  is no wildcard and no default route.
- **Management address only.** Host ports bind `IR_MGMT_BIND`, default `127.0.0.1`. Set it
  to the management-VLAN interface in a split deployment. It is never `0.0.0.0` — an admin
  path on every interface is an admin path reachable from the analyst side.
- **Optional TTL.** `--ttl 30m` closes the forwarder on its own. A session left open is the
  realistic failure, so the tool can close itself.
- **Separate from the analyst path.** Analysts reach one SSO-gated origin through the
  bastion broker. Admins reach management interfaces from the management network. The two
  never share a path, and the broker is not an admin target.

## Targets are resolved on the host

`adminctl.sh` resolves each target to its container address **on that tier's network**, and
passes the resolved list in. Two reasons:

- `ir-edge` runs with DNS disabled as an anti-exfil control, so names do not resolve there.
- Binding a target to a named network makes the reachable path explicit. A container that
  is not on that network yields no address and is skipped with a warning, rather than
  silently resolving somewhere else.

Addresses are assigned by podman and change when the stack is recreated; they are resolved
fresh each time access is opened, which suits a forwarder that only exists for one task.

## Credentials

Read from `deploy/.env` (`S3_ACCESS_KEY`/`S3_SECRET_KEY` for MinIO,
`KEYCLOAK_ADMIN_PASSWORD` for Keycloak, `POSTGRES_*` for the databases). Every default is
a `CHANGE_ME`-class value and must be changed before production.

## Verifying containment

With both open, each forwarder must fail to reach the other tier:

```bash
podman exec ir-dmz_adminfwd_1 nc -z -w2 <enclave-service-ip> 5432   # must fail
podman exec ir-enclave_adminfwd_1 nc -z -w2 <dmz-service-ip> 8090   # must fail
```

A forwarder that *can* reach the other tier is a regression in the segmentation model, not
a convenience.
