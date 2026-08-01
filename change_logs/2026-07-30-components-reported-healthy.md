# Four components reported healthy while doing nothing

**Date:** 2026-07-30

**Area:** `platform/hashicorp/access/broker.sh`, `platform/dmz/Dockerfile.broker`, `platform/keycloak/`, `platform/re-workstation/Dockerfile.ghidra`, `platform/deploy/enclave/docker-compose.yml`

**Status:** fixed

## Defect

Four independent components started, passed their checks, and performed no function.

**The broker forwarded nothing.** `broker.sh` ran `apk add --no-cache socat >/dev/null 2>&1 || true`
at startup. Closing egress on the DMZ link (see
[DNS exfiltration](2026-07-30-dns-exfiltration-and-naming.md)) made the install fail; `|| true`
swallowed it. The container logged its forwarding table, held the port, and forwarded nothing —
the analyst path was dead while every gate read green. `deploy.sh`'s readiness check for it was
literally `true`, which passes for any process that has not exited.

**Keycloak served the stock login page.** The custom theme was bind-mounted from the working
tree. A bind mount tracks the directory *inode*, so when the theme tree was rewritten the
container kept a stale, unlinked inode and saw an empty directory while the host plainly had the
files. Keycloak logged one line — `Failed to find LOGIN theme dfir` — and served a working,
unbranded page.

**Ghidra's GUI could not start.** `Dockerfile.ghidra` installed `openjdk-21-jdk-headless`, which
omits the AWT/Swing native libraries. Headless analysis worked, so the import step gave no
warning that the interactive half of the tool was missing; the error — "Unable to launch Ghidra
GUI application in headless environment" — reads as a missing X socket and sends you to the host.

**Re-login dead-ended at 403.** oauth2-proxy used one fixed CSRF cookie. Signing out and back in
replays a callback whose cookie was already consumed or expired, giving
`CSRF cookie with name '_oauth2_proxy_csrf' was not found` and a 403 that no retry clears.

## Changes

- Broker built as `localhost/ir-broker:latest` with socat baked in; `broker.sh` refuses to start
  without it; the build fails if socat is not runnable. `deploy.sh` now gates on the listener
  being bound in the bastion's namespace, not on the container being up.
- Keycloak built as `localhost/ir-keycloak:latest` with the theme baked in; the build asserts
  every theme file is present. A theme change is now a rebuild rather than invisible drift.
- `Dockerfile.ghidra` installs the full `openjdk-21-jdk`.
- oauth2-proxy gains `--cookie-csrf-per-request=true` and `--cookie-csrf-expire=15m`.

## Verification

`uat_baseline.sh` asserts the login page serves `/login/dfir`, carries the wordmark, and that the
identity provider logged no theme-load failures. `uat_tailnet.sh` asserts the brokered port is
bound inside the bastion's namespace. `diagnose.sh` checks all four: the broker's listener,
CSRF failures in the oauth2-proxy log, and that the Ghidra image contains `libawt_xawt.so`.

## Note

None of these is visible in container status, and none is findable by reading code — the code is
correct and only the running system disagrees. `diagnose.sh` gained a `--silent` section for
this class specifically.
