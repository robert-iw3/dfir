# Admin workflow

The admin deploys the platform, provisions accounts, collects from endpoints under suspicion,
supplies symbol tables the enclave cannot fetch, and manages evidence retention.

Management interfaces are not published. They are opened on demand from the management
network and closed when the task is done.

Related: [`troubleshooting/RUNBOOK.md`](troubleshooting/RUNBOOK.md),
[`troubleshooting/MEMORY-ANALYSIS.md`](troubleshooting/MEMORY-ANALYSIS.md),
[`symbols/README.md`](symbols/README.md).

---

## 1. Deploy

Each tier runs on the hardware it belongs to. Bring-up is staged: a service starts only
once its dependency answers.

```bash
cd platform/deploy
./deploy.sh enclave        # internal enclave host
./deploy.sh dmz            # DMZ host
./deploy.sh workstation    # analyst machine
./deploy.sh all            # single-host validation
./deploy.sh status
./deploy.sh down <tier|all>
```

`deploy.sh` replaces containers running a superseded image and verifies each is running an
image built no earlier than its source. It refuses to replace the worker while an analysis
is in progress; `IR_FORCE_RECREATE=1` overrides that and discards the analysis.

## 2. Open management access

```bash
cd platform/admin
./adminctl.sh up enclave              # MinIO console, Keycloak admin, Consul, Postgres
./adminctl.sh up dmz                  # receiver, headscale
./adminctl.sh up enclave --ttl 30m
./adminctl.sh status
./adminctl.sh down enclave|dmz|all
```

Forwarders bind the management address only, never `0.0.0.0`. One forwarder per tier, each
joined only to that tier's network: the DMZ forwarder has no route to an enclave service.

Enclave ports:

| Port | Interface |
|---|---|
| 19001 | MinIO console |
| 18080 | Keycloak admin |
| 18500 | Consul |
| 15432 | Postgres |

Close the forwarder when finished.

## 3. Provision accounts

**Users** creates an account in Keycloak in the group matching the chosen role and mirrors
it locally. Roles: `admin`, `analyst`, `auditor`, `reverse_engineer`.

## 4. Collect from an endpoint

Collection happens on the machine under suspicion, which is separate from every other tier and
has no route to a registry. Take the collector image as a tar and `collector/respond.sh` to it,
then run one command as root:

```bash
sudo ./respond.sh --receiver https://<dmz-receiver>:8090 --incident INC-0001 --hmac-key <key>
```

It checks the host, collects, captures memory, seals custody, ships to the receiver, and removes
the local copy once acceptance is confirmed. `--collect-only` seals without shipping when the
endpoint cannot reach the receiver; `--ship-only` retries a failed transfer without repeating
the capture.

**It must run as root.** Memory acquisition needs `CAP_SYS_ADMIN` over the host's `/proc/iomem`,
and a rootless container cannot hold it — the collector's fallback is a synthetic sample, which
is flagged but still yields a completed collection containing no real memory. The script refuses
rootless rather than producing that quietly.

Full procedure, including why the collecting and shipping containers are deliberately separate:
[`deploy/README.md` §5](deploy/README.md).

## 5. Supply symbol tables

Volatility needs an ISF matching the captured kernel. The enclave has no internet, so it
cannot build one. When a capture arrives with no matching table, the platform records a
symbol request and analyzes at reduced depth, labelled as such.

**Platform Health → Symbol requests** lists outstanding kernels. The requisites export
carries kernel identity only.

Acquisition runs on an internet-connected machine and the result travels into the enclave
the same way evidence does:

The input is the requisites file the collector wrote beside the capture — kernel release, build
id, banner and the host's distribution. It is read from the collection bundle rather than typed,
because the builder has to match the *collected host's* release, and that is a property of the
evidence rather than something to remember:

```bash
cd platform/symbols
./provision.sh --requisites <bundle>/reports/<host>/_symbols.json --store ~/ir-symbols/store
```

| Option | Meaning |
|---|---|
| `--requisites <file>` | `_symbols.json` from the collection bundle |
| `--store <dir>` | Keep a local copy of the built ISF |
| `--acquire-only` | Build the ISF without shipping it |
| `--isf <file> --key <k>` | Ship an ISF acquired earlier |

This builds the ISF from DWARF debug symbols, seals it, ships it through the DMZ receiver,
and verifies the enclave installed it read-only.

## 6. Manage evidence retention

Retention is applied automatically when an analysis completes: a clean host's capture is
purged, a compromised host's is retained.

Manual controls, on a capture:

- **Purge** — delete the image from object storage. The custody record remains.
- **Legal hold** — retain regardless of disposition.

## 7. Monitor

**Platform Health** reports service state, queue depth, analysis throughput and storage
use, measured live on each request.

**Component Health** reports what each component says about its own resources every 15
minutes: free space per volume, container memory and process ceilings, load, interface
errors, and errors counted since the previous report. It also shows what each collected
endpoint declared it will need — computed from that endpoint's RAM before its capture ran —
against the space each hop actually has. Act on it before the collection rather than after:
a memory image is the size of the endpoint's RAM, and a shortfall found at the far end of a
multi-hour transfer wastes the whole collection. Every alert names the volume to expand.

The version endpoint (`/api/version/`) reports the running build and process start time.
Open browser tabs poll it and surface a redeployment or restart rather than failing oddly.

---

## Operational notes

**A memory analysis runs for over an hour.** The broker's visibility timeout is derived
from `IR_VOL3_TIMEOUT` so a running analysis is never redelivered as a duplicate. Raising
the analysis timeout without raising the visibility timeout reintroduces duplicate runs.

**Staging is disk-backed and sized like the capture.** Budget the capture size again on
local disk on top of the object store's copy. A preflight check refuses a run when the
staging area is too small.

**MinIO and the worker staging volume may share a disk.** Object transfers use limited
concurrency for that reason; `IR_S3_CONCURRENCY` raises it when the object store is on its
own hardware.

---

## Adding an analyst workstation

Each workstation is its own tailnet node. Two sharing a node name are one node to the control
plane, and the tunnel then works only for whichever registered last.

1. Add its id to `IR_WS_IDS` in `deploy/.env`.
2. `./deploy/deploy.sh dmz` — mints that workstation's own pre-auth key.
3. `./deploy/deploy.sh workstation <id>` — its own compose project, containers and tailnet
   state volume, all named from the id.

Revoking one workstation's key does not unenroll the others. `test/uat_tailnet.sh` asserts that
every configured workstation is a distinct node with its own machine key, address and state
volume, and that each reaches the platform through its own tunnel.
