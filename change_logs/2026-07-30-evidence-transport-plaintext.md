# Evidence crossed the wire in cleartext

**Date:** 2026-07-30

**Area:** `platform/dmz/receiver.py`, `platform/dmz/puller.py`, `platform/collector/ship.sh`, `platform/collector/respond.sh`

**Status:** fixed

## Defect

The receiver was a plain `ThreadingHTTPServer` with no TLS path of any kind. `ship.sh` already
documented `RECEIVER_URL` as `https://dmz.example:8090` and supported `--cacert`, so the client
was half-prepared for a server that could not speak TLS at all; that documented URL would simply
have failed.

What crosses this connection is a memory image — every credential, key, token and open file the
host had in RAM. The custody seal proves the bundle was not *altered*; it does nothing to stop
it being *read*. An endpoint under suspicion is routinely on a segment the responder neither
controls nor trusts.

## Changes

**Receiver serves TLS and refuses to start without it.** `RECEIVER_TLS_CERT` /
`RECEIVER_TLS_KEY`, TLS 1.2 floor, optional client certificates via `RECEIVER_CLIENT_CA`.
Starting without a certificate requires an explicit `RECEIVER_ALLOW_PLAINTEXT=1`; a receiver
that silently downgrades produces collections that look successful while the evidence was
readable in transit.

**Client verifies, and will not fall back.** `ship.sh` refuses a non-`https` receiver unless
`SHIP_ALLOW_PLAINTEXT=1` is set explicitly. `respond.sh` gained `--ca-cert`, defaulting to the
certificate this checkout generates, and mounts it into the shipping container.

**Puller verifies the same certificate.** `RECEIVER_CA_BUNDLE` is pinned as the trust anchor
for all three receiver calls. Verification is never disabled: a puller that skipped it would
accept evidence from anything answering on that address.

**Dedicated certificate.** `dmz/gen-receiver-cert.sh`, separate from the platform's web
certificate — different trust anchors, different lifetimes, different blast radii. Generated
during `deploy.sh dmz`, so a fresh deployment is encrypted rather than encrypted once someone
remembers. `dmz/certs/` is gitignored.

Client certificates are deliberately not claimed as protection against a hostile endpoint: the
host is presumed compromised, so a key stored on it is presumed adversary-readable. They keep
third parties from filling the holding volume or planting bundles.

## Verification

A 9.4 GiB bundle from a 25.4 GB capture shipped over TLS 1.3 with the certificate pinned, was
custody-verified, pulled inward and ingested. `platform/test/uat_baseline.sh` asserts the
configured URL is `https`, that the receiver completes a TLS handshake, that its certificate
verifies against the pinned CA, and that a client *without* the pinned CA is rejected — the last
being what distinguishes verification from encryption.
