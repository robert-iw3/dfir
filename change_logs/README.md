# Change logs

Defects found in the public baseline and what was done about them.

## Scope

In scope: bugs in shipped detection logic, collection, or the analysis platform — defects that
exist in this repository and affect anyone running it.

Out of scope: new capability, roadmap items, and anything developed privately. Entries here
describe corrections to what already ships, not extensions of it.

## Format

One file per change, named `YYYY-MM-DD-<subject>.md`. Each states the defect, the evidence it
was measured with, the change, and the verification. Issues found but not fixed are listed in
the entry that found them, so the open set is always visible next to the work that surfaced it.

## Entries

| Date | Subject | Status |
|---|---|---|
| 2026-07-29 | [mwcp parser false positives on ordinary content](2026-07-29-mwcp-parser-false-positives.md) | 9 fixed, 7 open |
| 2026-07-29 | [Hostname, incident and synthetic-capture attribution](2026-07-29-collection-attribution.md) | 4 fixed |
| 2026-07-29 | [Host identity for correlating collection with memory analysis](2026-07-29-host-identity-correlation.md) | fixed |
| 2026-07-29 | [Memory capture never succeeded, and the fallback was silent](2026-07-29-memory-capture-never-succeeded.md) | fixed, 1 open |
| 2026-07-29 | [The DMZ transport could not carry a real capture](2026-07-29-dmz-transport-scale.md) | fixed |
| 2026-07-29 | [Capacity was only discoverable after a collection failed](2026-07-29-component-health.md) | fixed |
| 2026-07-29 | [Component Health figures were unreadable at the values that matter](2026-07-29-component-health-rendering.md) | fixed |
| 2026-07-30 | [Evidence crossed the wire in cleartext](2026-07-30-evidence-transport-plaintext.md) | fixed |
| 2026-07-30 | [DNS exfiltration was open on the DMZ link, and services were addressed by pinned IP](2026-07-30-dns-exfiltration-and-naming.md) | fixed |
| 2026-07-30 | [The backend image could never be rebuilt, so backend fixes never deployed](2026-07-30-backend-could-not-be-rebuilt.md) | fixed |
| 2026-07-30 | [Teardown deleted all ingested evidence without warning](2026-07-30-teardown-destroyed-evidence.md) | fixed |
| 2026-07-30 | [Four components reported healthy while doing nothing](2026-07-30-components-reported-healthy.md) | fixed |
| 2026-07-30 | [Tailnet nodes could not register, and the DERP relay was never used](2026-07-30-tailnet-registration-and-derp.md) | fixed |
| 2026-07-30 | [Pinned images had drifted, unnoticed](2026-07-30-stale-pinned-images.md) | fixed |
| 2026-07-31 | [The HashiCorp zero-trust enclave: from declared to enforced](2026-07-31-zero-trust-enclave-closure.md) | closed |

## Reading order

The 29 July entries are one investigation, not seven unrelated fixes. A single defect — the
collector's `avml` invocation being wrong for its installed version — kept every collection
synthetic and 24 MB, which held the whole transport and capacity path in a regime where its
own limits were unreachable. Fixing it surfaced the rest within hours:

1. **[Memory capture never succeeded](2026-07-29-memory-capture-never-succeeded.md)** — the
   root cause, and the silent fallback that hid it.
2. **[The DMZ transport could not carry a real capture](2026-07-29-dmz-transport-scale.md)** —
   what the first real 6.87 GiB bundle immediately broke.
3. **[Capacity was only discoverable after a collection failed](2026-07-29-component-health.md)**
   — making the limits visible before the next one.

The other three stand alone: the parser false positives were found by measuring the catalog
against ordinary host content, and the two attribution entries by asking where a finding was
actually filed.

The 30 July entries share a different root cause: **components that report success while doing
nothing.** A build that failed and left the previous image running, a broker that logged its
forwarding table and forwarded nothing, a resolver no query reached, a readiness check that was
literally `true`, a bind-mounted theme detached from its own files. None is visible in container
status and none is findable by reading code — the code is correct and only the running system
disagrees.

1. **[The backend image could never be rebuilt](2026-07-30-backend-could-not-be-rebuilt.md)** —
   the widest-reaching, because it made every other backend fix appear to deploy.
2. **[Four components reported healthy while doing nothing](2026-07-30-components-reported-healthy.md)**
   — the same pattern in four more places.
3. **[Evidence crossed the wire in cleartext](2026-07-30-evidence-transport-plaintext.md)** and
   **[DNS exfiltration was open on the DMZ link](2026-07-30-dns-exfiltration-and-naming.md)** —
   two confidentiality defects on the evidence path, the second found only by closing the first.
4. **[Teardown deleted all ingested evidence](2026-07-30-teardown-destroyed-evidence.md)** —
   found by losing a 9.4 GiB ingest to a routine redeploy.

`platform/troubleshooting/diagnose.sh` gained a `--silent` section covering this class, and
`platform/ci/image-currency.sh` was added for the one defect a running system cannot show at
all.
