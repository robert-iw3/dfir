# Deploying the DFIR Framework

The platform deploys as **four tiers on separate hardware**. Each tier is its own compose
project; the only coupling between them is the addressing in [`.env`](.env.example).

| Tier | Hardware | VLAN | Contains |
|---|---|---|---|
| [`enclave/`](enclave) | enclave host | 20 | PostgreSQL, MinIO, Redis, API, analysis sandbox, Keycloak, oauth2-proxy, Traefik, Consul, ingest puller |
| [`dmz/`](dmz) | DMZ host | 30 | ingest receiver, bastion broker, headscale, CoreDNS |
| [`workstation/`](workstation) | analyst machine | 40 | STIG-hardened Firefox kiosk |
| [`../collector/`](../collector) | the endpoint under investigation | 50 | collection container (run per incident) |

> **Automation.** Compose is the deployment interface. Any orchestration layer drives these
> same compose files rather than replacing them.

---

## 1. Prerequisites

- Podman (rootless is fine) + `podman-compose` on every host.
- Network segmentation per [`NETWORKING.md`](NETWORKING.md) — VLANs, the firewall allow-list,
  and IDPS placement. **The application controls assume those boundaries exist.**
- DNS: analyst workstations must resolve the platform name via the DMZ CoreDNS only.

## 2. Configure

```bash
cp .env.example .env
```

Set at minimum — everything marked `CHANGE_ME` is a secret:

| Variable | Meaning |
|---|---|
| `PLATFORM_PUBLIC_URL` | the single public origin analysts use (also Keycloak's issuer) |
| `RECEIVER_URL` | where the **enclave puller** reaches the DMZ receiver (enclave → DMZ) |
| `ENCLAVE_INGRESS` | where the **DMZ broker** forwards analyst sessions (DMZ → enclave) |
| `EDGE_SUBNET`, `BROKER_EDGE_IP`, `DNS_EDGE_IP` | analyst-side addressing (fixed, so DNS and the broker are stable) |
| `POSTGRES_PASSWORD`, `S3_SECRET_KEY` | data-tier credentials |
| `DJANGO_SECRET_KEY`, `IR_AUDIT_HMAC_KEY`, `IR_CUSTODY_HMAC_KEY` | app secrets — Vault supplies these in a hardened deployment |
| `IR_BROKER_TOKEN`, `IR_SSO_PROXY_SECRET`, `OAUTH2_COOKIE_SECRET` | service + gate secrets |
| `KEYCLOAK_ADMIN_PASSWORD` | IdP bootstrap admin (admin console is MGMT-VLAN only) |

`RECEIVER_URL` and `ENCLAVE_INGRESS` are the **only cross-hardware couplings** — set them to
the routed addresses of firewall rows 5 and 6 in [`NETWORKING.md`](NETWORKING.md).

**Before production:** change every default password, and disable the realm's per-role
break-glass logins you don't need (see the pinned note in
[`../hashicorp/keycloak/realm-irplatform.json`](../hashicorp/keycloak/realm-irplatform.json)).

## 3. Deploy

Run on the host that owns each tier:

```bash
./deploy.sh dmz            # DMZ host
./deploy.sh enclave        # enclave host
./deploy.sh workstation    # analyst machine (needs: xhost +local:)
./deploy.sh all            # single-host validation — all tiers together
./deploy.sh down all       # tear down (removes volumes)
```

Order matters on a single host: the DMZ owns the analyst-side network the workstation joins,
and the enclave's puller expects the receiver to exist. Keycloak takes 30–60s to become ready;
a `502` from the ingress during that window is expected.

## 4. Verify

```bash
../test/uat_full_stack.sh        # capstone: all tiers, real data flow + segmentation
../troubleshooting/diagnose.sh   # hop-by-hop health + boundary assertions
```

Then confirm by hand: browse `PLATFORM_PUBLIC_URL` from the workstation, log in as a role, and
check the dashboard renders ingested evidence.

Segment UATs, when you want to isolate one property:

```bash
../test/uat_vault.sh     # dynamic secrets
../test/uat_dmz.sh       # evidence-ingress containment
../test/uat_access.sh    # brokered analyst path, DNS containment, browser hardening
../test/uat_consul.sh    # mesh intentions
```

## 5. Run a collection

The endpoint is the machine under suspicion. It is deliberately separate from every other tier,
has no route to a registry, and is the least trustworthy place in the deployment — so
everything it needs travels to it, and one command does the rest.

**Take to the endpoint:** the collector image as a tar, and `collector/respond.sh`.

```bash
# on a machine that can build (not the endpoint)
../collector/build.sh
podman save localhost/ir-collector:latest -o ir-collector.tar
```

**On the endpoint, as root:**

```bash
sudo ./respond.sh --receiver https://<dmz-receiver>:8090 --incident INC-0001 \
                  --hmac-key <same IR_CUSTODY_HMAC_KEY as .env>
```

That is the whole procedure. It checks the host can do the job, collects, captures memory,
seals the chain of custody, ships the bundle, and removes the local copy once the receiver has
confirmed it. Nothing is reported back to the endpoint beyond that confirmation: analysis runs
in the enclave, and a machine under investigation is told no more about the platform than the
address it uploads to.

### Parameters

| Option | Required | Meaning |
|---|---|---|
| `--receiver <URL>` | yes¹ | The DMZ receiver's address **as reachable from this endpoint** |
| `--incident <ID>` | yes | Investigation this collection belongs to |
| `--hmac-key <KEY>` | no | Custody signing key; must match `IR_CUSTODY_HMAC_KEY` in `deploy/.env` |
| `--evidence <DIR>` | no | Where to write evidence. Default `/var/tmp/ir-evidence-<incident>` |
| `--hostname <NAME>` | no | Override the detected name when `/etc/hostname` is wrong or unset |
| `--collect-only` | no | Seal without shipping — endpoint has no path to the receiver |
| `--ship-only` | no | Ship evidence collected earlier, without repeating the capture |
| `--keep` | no | Retain the local copy after a successful ship |

¹ Not required with `--collect-only`.

**`--receiver` is the receiver's routable address, not `localhost`.** The upload runs inside a
container, where `127.0.0.1` is the container itself — pointing there fails with a connection
refusal that looks like the receiver being down. Use the DMZ host's DNS name, or its IP on the
network the endpoint can actually reach. The receiver publishes port 8090.

**Without `--hmac-key` the bundle is sealed but unsigned.** The receiver can still verify it is
internally consistent, but not that it came from you. The script warns and continues, because a
collection from a host that is actively being attacked is worth more than a refusal over a
missing key.

**Omitting `--keep` deletes the local evidence once the receiver confirms acceptance.** That is
the intended default: the endpoint is the least trustworthy place the evidence could sit, and a
copy left behind is one nobody is tracking. Pass `--keep` when a re-ship is plausible and the
capture was expensive to take — re-collecting a large host is not a cheap retry.

### Shipping separately

A collection that sealed but did not ship is not lost. The evidence stays where it was written
and goes out with `--ship-only`, which repeats nothing:

```bash
sudo ./respond.sh --ship-only \
     --receiver https://<dmz-receiver>:8090 \
     --incident INC-0001 \
     --evidence /var/tmp/ir-evidence-INC-0001 \
     --keep
```

`--incident` and `--evidence` must match what was collected — the incident because it keys the
investigation the run files under, and the evidence path because a non-default location is not
rediscoverable. On a failure the script prints this command back with the values already filled
in, so the retry is a paste rather than a reconstruction.

This is also the path for an endpoint with no route to the DMZ: `--collect-only` on the host,
move the evidence directory out on removable media, then `--ship-only` from a machine that can
reach the receiver.

### Why root, and why one script

**Memory acquisition needs `CAP_SYS_ADMIN` over the host's `/proc/iomem`.** A rootless container
cannot hold it however privileged it is declared, and the collector's fallback in that case is a
synthetic sample — flagged as such, but a completed collection that contains no real memory.
`respond.sh` refuses to run rootless and says why, rather than producing that quietly.

**The capture is written `0400` by root; every other artifact is world-readable.** `respond.sh`
hands the evidence to whoever invoked sudo — not because its own ship needs that (it runs as
root throughout), but so the evidence is usable afterwards without root: reading the manifest,
re-sending by hand, copying to removable media. Anyone who ships these files unprivileged
without doing so reads a few hundred artifacts and fails on the single one that counts, which
presents as a transfer fault rather than a permissions one.

**Space is checked before the capture, not discovered during it.** A memory image is the size of
the host's RAM and the bundle is written beside it, so the collection needs roughly 1.5× RAM
free. Filling the endpoint's disk mid-capture is a worse outcome than a refusal.

### The two containers are separate on purpose

Collection runs **privileged, with the host filesystem and `/proc` mounted, and no network**.
Shipping runs with **a network and no view of the host**, reading the evidence read-only.

Neither capability sits beside the other. A single container with both would be one parser
exploit away from reading the host and calling out. If you run the steps by hand, keep them
apart — `--network none` on the collection is load-bearing, not decoration.

### What happens next

The receiver verifies custody and holds the bundle as an opaque blob. The **enclave pulls it
inward** on its next poll; nothing is ever pushed into the enclave. Memory analysis, adjudication
and correlation all happen there. The endpoint's involvement ends when the receiver confirms
acceptance.

## What the deployment enforces

- **One brokered port.** Analysts reach a single origin; app, IdP login, and the SSO callback
  are path-routed behind it. Everything else has no forwarder and no route.
- **Pull-only ingest.** The enclave initiates every internal-bound transfer; a compromised
  endpoint or DMZ host has no inbound path to ride.
- **Sandboxed analysis.** The malware-facing worker has no egress, no capabilities, a read-only
  root filesystem, and is non-root.
- **SSO + RBAC + tamper-proof audit.** Every session authenticates at the gate; roles come from
  Keycloak groups; every mutation is hash-chained.
