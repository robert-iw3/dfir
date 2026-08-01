# Teardown deleted all ingested evidence without warning

**Date:** 2026-07-30

**Area:** `platform/deploy/deploy.sh`

**Status:** fixed

## Defect

`deploy.sh down <tier|all>` ran `compose down -v` unconditionally. `-v` deletes the tier's
volumes: the database, the object store and the receiver's holding area — every collected
capture, its custody record and its analysis. No warning, no confirmation.

`down` is used to restart a service far more often than to reset state, so the common operation
destroyed evidence as a side effect. On a forensic platform that is evidence destruction: the
bundles are gone and the endpoints they came from have usually been rebuilt by then.

The teardown also reported `torn down` unconditionally. A compose file that failed to parse left
every container running behind a success message, and the next bring-up inherited containers
built from the previous configuration.

## Changes

**Volumes are kept by default.** Deleting them now requires `deploy.sh down <tier> --purge`,
which warns that all ingested evidence, captures and analyses are being deleted. Documented in
the usage banner.

**Teardown reports what happened.** Compose failures are surfaced instead of discarded, network
removal failures are reported, and the final verdict is drawn from the runtime — if any `ir-`
container is still running, `down` says so and exits non-zero.

## Verification

`down all` followed by `podman volume ls` shows `ir-enclave_pgdata`, `ir-enclave_miniodata` and
`ir-dmz_receiver-holding` intact. `diagnose.sh` asserts their presence, so their absence is
reported as destroyed evidence rather than discovered as an empty platform.
