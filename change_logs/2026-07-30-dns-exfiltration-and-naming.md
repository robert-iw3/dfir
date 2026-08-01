# DNS exfiltration was open on the DMZ link, and services were addressed by pinned IP

**Date:** 2026-07-30

**Area:** `platform/deploy/deploy.sh`, `platform/deploy/*/docker-compose.yml`, `platform/hashicorp/access/Corefile*.tmpl`

**Status:** fixed

## Defect

`ir-dmzlink` — the network carrying the puller, the ingress and the IdP — was not `internal`.
The container runtime's resolver there forwarded anything it could not answer to the **host's**
resolvers, so the puller resolved `example.com` to a live internet address (`104.20.23.154`).
That is the enclave's only outbound bridge, and DNS is a covert exfiltration channel out of the
tier holding the evidence. The enclave's own network was already `internal`, which is precisely
why the leak was invisible from inside it.

Separately, `ir-edge` was created `--disable-dns`. With no resolver on that segment, every
service on it needed a pinned address in `.env` (`BROKER_EDGE_IP`, `HEADSCALE_EDGE_IP`,
`DNS_EDGE_IP`), which breaks on any network recreate and prevents a second analyst workstation.

## Changes

**Every network is `internal`.** `ir-edge`, `ir-dmzlink` and the enclave network all have no
route off the host. Nothing on the link needs egress: the puller dials the receiver, the ingress
serves the broker, and the IdP's outbound calls are telemetry.

**Runtime DNS enabled, so names are dynamic.** `--disable-dns` was gratuitous — an `internal`
network still gets a gateway and supports resolution. Services now address each other by name;
the runtime tracks where each one currently is. `BROKER_EDGE_IP` and `HEADSCALE_EDGE_IP` are
removed. The only addresses still written down are the two resolvers' own, because `resolv.conf`
holds literals and a resolver cannot be found by asking a resolver.

**Two CoreDNS instances as egress backstops.** Each refuses out-of-zone names with no
forwarders and no recursion; the enclave's permits exactly one cross-tier name, the receiver.
Their real role is stated honestly in the Corefiles: while the networks are `internal` they
carry no traffic, because podman overrides a container's `dns:` when its own resolver is enabled
and makes CoreDNS the *upstream* instead. They arm the moment a network gains a route out —
which is exactly how the DMZ-link leak was caught.

**Gateways are discovered, not configured.** `deploy.sh` reads them from the runtime, so a
stale hand-written copy cannot send every lookup into a black hole.

## Verification

`platform/test/uat_dns.sh` (new) asserts, from the running services rather than a probe: all
three networks are `internal`; enclave services resolve each other by name; the platform name
resolves to the bastion's *current* address; the puller resolves `receiver` and nothing else in
the DMZ; six containers including the puller cannot resolve any outside name; both CoreDNS
instances refuse outside names and still answer in-zone ones when queried directly; and no
service pins an address.

A purpose-built probe started with `--dns <resolver>` does **not** get that resolver — podman
overrides it — so the first version of this test silently exercised a different resolution path
than the platform uses. Every query is now made from a running service.
