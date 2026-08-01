# Network design — VLANs, routing, firewall and IDPS placement

The platform's application-layer controls (SSO, RBAC, custody verification, pull-only
ingest, sandboxed analysis) are only as strong as the network underneath them. A L7 rule
that says "the DMZ must not reach the database" is a *statement of intent*; the firewall
and VLAN design below is what makes it **true**. This document is the L2/L3 counterpart to
[`README.md`](../README.md)'s architecture.

Design rule throughout: **the network enforces the same claim the application makes.** If a
flow isn't listed here, it is denied — there is no implicit any-any anywhere.

---

## 1. Segments (VLANs)

| VLAN | Name | Holds | Trust |
|---:|---|---|---|
| 10 | `IR-MGMT` | out-of-band management: switch/router/firewall mgmt, IPMI, jump access for admins | highest — never routable from any other VLAN |
| 20 | `IR-ENCLAVE` | PostgreSQL, MinIO, Redis, API, **analysis sandbox**, Keycloak, Vault, Consul, ingest **puller**, SSO ingress | high — the system of record |
| 30 | `IR-DMZ` | ir-ingest **receiver**, bastion broker, headscale, CoreDNS | low — untrusted parties touch this |
| 40 | `IR-ANALYST` | analyst workstations (kiosk browser) | low |
| 50 | `IR-COLLECT` | *transit only* — where endpoints shipping evidence appear (often an existing corporate/field VLAN, not one you own) | untrusted |

Two segments carry no client traffic and exist to make the boundary explicit:

- **`IR-DMZLINK` (VLAN 25)** — the only routed adjacency between DMZ and enclave. A /30 or
  /29 point-to-point transit between the firewall and each tier. Nothing else lives on it.
- **`IR-SPAN` (VLAN 99)** — the monitoring/TAP segment carrying mirrored traffic to the IDPS
  sensors. Sensors have **no IP on the monitored VLANs**.

> **Why VLANs and not one flat subnet with host firewalls.** Host firewalls are part of the
> defense (they are — see S1/S2), but a compromised host can disable its own rules. A VLAN
> boundary enforced on a separate device cannot be turned off by the compromised host.

---

## 2. Physical placement

```
                        ┌──────────────── INTERNET / CORP WAN ────────────────┐
                        │                                                     │
                   ┌────┴─────┐                                               │
                   │  ROUTER  │  edge router — default route, BGP/static,     │
                   │  (edge)  │  anti-spoof (uRPF), no inbound to platform    │
                   └────┬─────┘                                               │
                        │                                                     │
                ┌───────┴────────┐                                            │
                │   FIREWALL     │  ◄── THE policy enforcement point.         │
                │  (L3 / NGFW)   │      All inter-VLAN traffic transits here. │
                │   + IDPS inline│      Inter-VLAN routing happens HERE, not  │
                └──┬────┬────┬───┘      on the switch (no SVI shortcuts).     │
                   │    │    │
        ┌──────────┘    │    └───────────┐
        │               │                │
   ┌────┴────┐    ┌─────┴─────┐    ┌─────┴─────┐
   │ SWITCH  │    │  SWITCH   │    │  SWITCH   │   L2 only in each segment:
   │ VLAN 30 │    │  VLAN 20  │    │ VLAN 40   │   port security, DHCP snooping,
   │  (DMZ)  │    │ (ENCLAVE) │    │ (ANALYST) │   dynamic ARP inspection, BPDU guard
   └────┬────┘    └─────┬─────┘    └─────┬─────┘
        │               │                │
   DMZ hardware    Enclave hardware   Analyst workstations
   (receiver,      (DB, MinIO, API,   (kiosk browser)
    broker, DNS)    sandbox, IdP)
```

**Where each device goes and why**

- **Router (edge).** Owns the default route and the WAN. It must **not** have a path into
  `IR-ENCLAVE`; the platform publishes nothing to the internet. Enable uRPF (anti-spoofing)
  and drop bogons/martians inbound.
- **Firewall (the policy enforcement point).** All inter-VLAN routing is done **on the
  firewall**, not by switch SVIs. This is the single most important placement decision: if
  the switch routes between VLANs, traffic never passes a policy device and the segmentation
  is cosmetic. Every flow in §3 is an explicit rule here; the last rule is `deny any any log`.
- **Switches.** Pure L2 per segment. No inter-VLAN SVIs. Harden the access layer: port
  security (sticky MAC), DHCP snooping, dynamic ARP inspection, BPDU guard, disable DTP/auto-
  trunking, put unused ports in an unused VLAN and shut them.
- **IDPS.** Two placements, deliberately (see §4).

---

## 3. Firewall policy (the allowed flows — everything else denied)

Read this next to the architecture diagram; each row is a claim the application makes.

| # | Source | Destination | Port | Purpose | Notes |
|---|---|---|---|---|---|
| 1 | `IR-COLLECT` (endpoints) | DMZ **receiver** | 8090/tcp (mTLS) | ship sealed evidence | **Only** flow from endpoint space. Rate-limit; cap session duration. |
| 2 | `IR-ANALYST` | DMZ **broker** | 8443/tcp | analyst reaches the SSO app | Only the broker port. |
| 3 | `IR-ANALYST` | DMZ **CoreDNS** | 53/udp+tcp | resolve the one platform name | **No other DNS destination permitted from VLAN 40** (see §5). |
| 4 | `IR-ANALYST` | DMZ **headscale** | 8080/tcp, 3478/udp | tailnet control plane + DERP | Enrollment only. |
| 5 | **ENCLAVE puller** | DMZ **receiver** | 8090/tcp | **enclave pulls** verified evidence | Direction is the whole point: *enclave → DMZ*, established/related back only. |
| 6 | DMZ **broker** | ENCLAVE ingress (Traefik) | 443/tcp | brokered analyst session | The only DMZ→enclave flow, and it terminates at the SSO ingress. |
| 7 | `IR-MGMT` | all tiers | 22/tcp (+ mgmt) | administration | From MGMT only; MFA; jump host; logged. |
| 8 | all tiers | `IR-MGMT` log collector | 6514/tcp (syslog-TLS) | audit/telemetry off-box | One-way; see §6. |

**Explicitly denied (and logged):**

- `IR-DMZ` → `IR-ENCLAVE` **anything except row 6**. The receiver must never reach the DB,
  object store, or API — this is the rule that contains a compromised receiver.
- `IR-ANALYST` → `IR-ENCLAVE` **anything**. Analysts reach the app only through row 2.
- `IR-COLLECT` → anything except row 1.
- `IR-ENCLAVE` → **internet**: denied. The enclave, including the malware-analysis sandbox,
  has no egress. This is what stops C2 from a detonated sample.
- Any → `IR-MGMT` except row 8's collector.
- Inter-workstation traffic within VLAN 40 (use private VLANs / port isolation) — stops an
  infected workstation pivoting sideways.

**Stateful direction matters.** Rows 5 and 6 must be written so only the initiating side may
open the connection (`established,related` for the return path). A "permit tcp DMZ→ENCLAVE
8090" rule written symmetrically would silently undo the pull-only design.

---

## 4. IDPS placement

Two sensors, two jobs:

1. **Inline (IPS) at the firewall, on the DMZ boundary** — inspects rows 1, 2, 5, 6. This is
   where hostile traffic from a compromised endpoint or workstation first appears, so it is
   where blocking has the most value. Tune for: exploit attempts against the receiver,
   protocol abuse on the brokered port, oversized/malformed uploads.
2. **Out-of-band (IDS) on a SPAN/TAP of `IR-ENCLAVE`** — detection only, no blocking, because
   this segment carries *evidence*: memory images full of real malware signatures. Inline
   blocking here would drop legitimate evidence transfers and corrupt captures. Sensors sit
   on VLAN 99 with **no IP on the monitored segment**, so they cannot be reached or pivoted to.

**Critical tuning note.** The enclave legitimately moves malware bytes between MinIO and the
sandbox. Signature-based alerts will fire constantly on that path. Suppress *known-evidence
paths* by 5-tuple (MinIO↔sandbox) rather than by signature — you want those signatures still
live everywhere else. Never disable a rule globally to quiet an evidence path.

The highest-value alerts to build, because they mean the design has been violated:

- any packet `IR-ENCLAVE → internet` (sandbox egress attempt / C2)
- any connection **initiated** DMZ→ENCLAVE outside row 6
- DNS from `IR-ANALYST` to anything but the DMZ resolver, or high-entropy/large-volume
  queries to the resolver (tunneling attempt)
- authentication anomalies at the SSO gate (spray, impossible travel)

---

## 5. DNS design

DNS is a covert channel; treat it as a controlled service, not plumbing.

- `IR-ANALYST` uses **only** the DMZ CoreDNS (firewall row 3 denies all other resolvers).
- That resolver answers exactly one name — the platform — and **REFUSES** everything else. It
  has **no forwarders and no recursion**, so there is no upstream to tunnel through.
- The name resolves to the **broker**, never to an internal address: the workstation never
  learns the enclave's addressing.
- `IR-ENCLAVE` resolves internally (Consul/host records) and has no external resolver.

## 5a. Mesh addressing — IP assignment and its caveats

The address each mesh service is registered at is **configuration, never discovery**. A
discovered container address is stale the moment the runtime recreates the container, and a
stale Connect registration surfaces far from its cause: a proxy binding an address that no
longer exists, or an application refused by a database that is healthy.

Two variables per service, one precedence rule:

| Variable | Scope | What it is |
|---|---|---|
| `IR_MESH_ADDR_<SERVICE>` | multi-host | The **routable host address** remote proxies dial. Set it per service when tiers run on separate VMs or bare metal. Takes precedence. |
| `IR_IP_<SVC>` | single host | The **static container address** on `ENCLAVE_SUBNET`. Places the container on the local bridge; what local proxies dial when no `IR_MESH_ADDR_*` is set. |

To move a service: edit its value in [`.env`](.env.example) and redeploy. `deploy.sh` validates
the whole set — inside the subnet, no duplicates, no collision with the resolver — **before
starting anything**, so a bad edit fails at the top of the deploy instead of as an unreachable
container.

Caveats, each of which has bitten:

- `IR_IP_*` must lie inside `ENCLAVE_SUBNET`. The subnet itself is free — `192.168.50.0/24`
  works exactly as well as the `10.89.1.0/24` default; `ipv4_address` is standard compose and
  behaves the same on podman and docker. Change them **together**; the validator refuses a
  mismatch.
- Do not choose a range that overlaps the host's own LAN (home networks are usually
  `192.168.x`): the bridge would shadow the real network on that host.
- Keep static addresses in a high block (`.201+` here). The runtime's allocator hands out
  dynamic addresses from the bottom of the subnet, and a static address inside the dynamic
  range can be claimed by an unrelated container while the pinned one is down.
- On multiple hosts, `IR_MESH_ADDR_*` is the value that matters and the sidecar's public port
  (21000) must be reachable on that host address — publish it only in that deployment shape,
  never on a single host, where the enclave bridge already carries it.
- The resolver's address (`ENCLAVE_DNS_IP`) follows the same rule and predates the rest:
  resolv.conf holds literals, so it is the one address that can never be discovered by asking
  a resolver.
- **Switching shapes is a teardown, not a redeploy.** Loading or unloading the multi-host
  overlay changes every mesh service's definition at once, and compose recreates them all
  mid-deploy — churn no health gate should have to survive. `deploy.sh down enclave` first;
  a fresh create carries the shape from the start, exactly as a real host does.
- **The firewall must allow the mesh ports inbound.** A deny-all-inbound host (the correct
  default) silently blocks every remote proxy: sessions authorize, then carry nothing. Add an
  allow row per enclave host for `IR_MESH_PORT_*` (21001-21007 by default), source-limited to
  the other enclave hosts — these ports speak Connect mTLS, so the firewall is layered on the
  certificate check, not substituting for it.

## 6. Logging and time

- Every device (router, firewall, switches, IDPS) and every tier ships to a log collector in
  `IR-MGMT` over syslog-TLS, **one-way** (row 8). A collector reachable *from* a compromised
  segment is a collector an attacker can tamper with.
- The platform's own tamper-proof audit chain is application-level; this is the network-level
  complement. Keep both.
- NTP from `IR-MGMT` only. Correlating an incident across tiers requires a common clock, and
  forensic timelines are worthless if hosts disagree.

## 7. Deployment mapping

The tiers in [`deploy/`](.) map onto the segments above:

| Tier | Hardware | VLAN | Reaches |
|---|---|---|---|
| [`enclave/`](enclave) | enclave host(s) | 20 | DMZ receiver (outbound pull) only |
| [`dmz/`](dmz) | DMZ host | 30 (+25 link) | enclave ingress (row 6) only |
| [`workstation/`](workstation) | analyst machine | 40 | broker + DMZ DNS only |
| [`../collector/`](../collector) | the endpoint under investigation | 50 | DMZ receiver only |

`RECEIVER_URL` and `ENCLAVE_INGRESS` in [`.env`](.env.example) are the only cross-hardware
couplings — set them to the routed addresses of rows 5 and 6.

> **Validation.** The single-host UATs model these boundaries with container networks
> (`ir-edge` has no gateway; the enclave network is `internal`), and assert the denials
> directly. On real hardware, re-run [`../troubleshooting/diagnose.sh`](../troubleshooting/diagnose.sh)
> after deployment: it probes the same allowed/denied flows against the live segments.
