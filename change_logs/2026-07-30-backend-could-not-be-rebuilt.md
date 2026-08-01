# The backend image could never be rebuilt, so backend fixes never deployed

**Date:** 2026-07-30

**Area:** `platform/deploy/enclave/docker-compose.yml`

**Status:** fixed

## Defect

The backend service declared `build: ../../backend`, making the build context `platform/backend`.
Its Dockerfile copies `backend/requirements.txt`, `backend/` and `shared/sysstats.py` — all
relative to `platform/`. Every build therefore failed with
`COPY backend/requirements.txt: no such file or directory`.

`deploy.sh` discarded the error, so the previous image kept running and the deployment reported
success. Any change to backend code appeared to deploy and none of them did. This is the most
expensive failure mode in the set: the symptom is "my fix did nothing", and the code being
correct makes it unfindable by reading.

It was discovered only because a new management command was added and never appeared in the
container.

## Changes

Context corrected to `../..` with an explicit `dockerfile: backend/Dockerfile`.

## Verification

`platform/troubleshooting/diagnose.sh` now checks every compose service: that the referenced
Dockerfile exists, and that each `COPY` source resolves under the declared context — catching a
build that cannot succeed before it is run. It also compares each running container's image ID
against the current `localhost/ir-<svc>:latest` and reports any container still serving a
superseded image, which is the second half of the same failure.
