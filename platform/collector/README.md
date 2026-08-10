# Collection on a suspect endpoint

The host under investigation is assumed compromised and network-isolated. Collection runs
there in two containers, split so that no single component holds both root and network
reach.

| | Privilege | Host access | Network |
|---|---|---|---|
| **collect** | root, `--privileged`, `--pid=host` | `/proc`, `/dev/mem`, filesystem | **none** |
| **ship** | unprivileged, no host mounts | the evidence volume only | **one** outbound target |

Collection genuinely needs root: `avml` reads kernel memory, and the toolkit's hunts read
other processes' `/proc` entries. What it does not need is a network, and it has none —
`--network none` gives it no namespace to reach anything through. Everything it produces
lands on a mounted volume as a custody-sealed bundle.

Shipping is then a separate, unprivileged container whose entire view of the world is that
sealed tarball and one URL. A compromise of either container yields materially less than
one container holding both.

## Collect

```bash
podman run --rm \
  --privileged --pid=host --network none \
  -v /proc:/host/proc:ro -v /:/host/root:ro \
  -v "$PWD/evidence:/evidence:z" \
  -e IR_INCIDENT_ID=INC-0001 \
  -e IR_CUSTODY_HMAC_KEY="<same as the platform>" \
  ir-collector:latest
```

`--network none` is not optional hardening; it is the containment. A privileged container
on a compromised host with a network namespace is an exfiltration path.

Collection performs the toolkit's static analysis (EDR/fileless hunt, remote-access triage,
container hunt, journal analysis, thread inventory), captures memory with `avml`, records
the requisites needed to build a Volatility symbol table later, and seals the whole folder.

**Memory analysis does not happen here.** Volatility needs a symbol table matching the
kernel, and building one requires downloading debug symbols — which an isolated host
cannot do and should not be able to do. Analysis happens in the enclave; see
[`../symbols/README.md`](../symbols/README.md) for how the symbol table gets there.

## Ship

```bash
podman run --rm \
  -v "$PWD/evidence:/evidence:ro,z" \
  -e RECEIVER_URL=https://<dmz-receiver>:8090 \
  -e CA_BUNDLE=/evidence/ca.crt \
  ir-collector:latest sh /opt/collector/ship.sh
```

One outbound destination, no host mounts, no privilege. The receiver terminates the
connection on receipt, so there is no channel back. A failed transfer leaves the bundle on
the volume to be re-sent.

Restrict egress at the runtime as well as by convention — the container should be able to
reach the receiver and nothing else, whether by a dedicated network with a single route or
by the host's own containment rules
([`playbooks/linux/01_contain_host.sh`](../../toolkit/playbooks/linux/01_contain_host.sh) drops all
traffic except management access).

## What is captured for symbols

`symbol_requisites.py` records the kernel identity needed to build an ISF later: release,
architecture, `/proc/version` banner, the `NT_GNU_BUILD_ID` from `/sys/kernel/notes`, and
`os-release`. It reads only local kernel metadata and makes no network calls.

The build-id matters most — it identifies a kernel build across distributions and is what
`debuginfod` resolves against. `os-release` matters nearly as much: debug-symbol packages
are published per distribution *release*, so the acquisition step needs to know which one.

**Symbols are perishable.** Distributions prune debug packages for superseded kernel ABIs,
so a kernel captured today may have no obtainable symbols in a few weeks. Acquire them
promptly, and prefer maintaining a symbol store for the fleet's kernel inventory ahead of
any incident.
