# Pinned images had drifted, unnoticed

**Date:** 2026-07-30

**Area:** `platform/deploy/*/docker-compose.yml`, `platform/ci/image-currency.sh`

**Status:** fixed

## Defect

Six of eleven pinned upstream images were behind or unpinned. A pinned tag freezes a
vulnerability set: the image does not change, so anything unpatched at pin time stays unpatched
for as long as the pin survives, and a pin nobody revisits is indistinguishable from one chosen
deliberately.

| Image | Was | Now |
|---|---|---|
| oauth2-proxy | v7.7.1 | v7.15.3 |
| consul | 1.20 | 2.0.2 |
| coredns | 1.13.1 | 1.14.6 |
| traefik | v3.6 | v3.7 |
| headscale | v0.29.2 | v0.29.3 |
| minio | `:latest` | `RELEASE.2025-09-07T16-13-09Z` |

oauth2-proxy is the SSO gate and was eight minor versions behind. CoreDNS is queried by every
enclave service. `minio:latest` was not stale but unpinned, which trades a known vulnerability
set for an unknown one and makes the deployed artifact unreproducible after an incident.

Reading the compose files does not surface this: the tags look deliberate and the stack comes up
green either way.

## Changes

All six updated. `platform/ci/image-currency.sh` (new) queries the registry for every pinned
image and reports stale pins, newer majors, and floating tags. Track precision is respected —
`postgres:18` is current while no 19 exists, whereas `coredns:1.13.1` is stale the moment 1.13.2
ships. Date-stamped releases (MinIO) are compared chronologically rather than skipped, since
skipping is the same silent rot.

`--strict` exits non-zero for use as a CI gate.

## Verification

`ci/image-currency.sh` reports all eleven pinned images current. `diagnose.sh` runs it as part
of its sweep.
