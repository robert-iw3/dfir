# Analyst cannot get in

Failures on the path an analyst actually uses: the kiosk browser, the SSO gate, Keycloak.
Each entry is a symptom as it appears at the workstation, then what it actually is.

The kiosk has no address bar, no history, no settings and no way to clear cookies. Any
instruction that begins "clear your browser state" is not a remedy here — it is a remedy that
does not exist, and the platform has to recover on its own.

---

## "Invalid username or password" for a credential that is correct

**Check whether the account exists at all before assuming the password is wrong.**

```bash
platform/admin/kc-userctl.sh status default-admin
```

`no user '<name>' in realm irplatform` means exactly that — the account is gone, and every
password fails identically because there is nothing to authenticate against.

**Why it happens.** Keycloak's database lives inside its container: there is no volume on
`/opt/keycloak/data`. Recreating Keycloak — which `deploy.sh enclave` does deliberately when
the realm file changes — destroys every account, including passwords analysts set through the
forced-change flow. Accounts are recreated afterwards by
`hashicorp/keycloak/provision-demo-users.sh`, so a completed deploy converges; a deploy that
was interrupted, or that ran while the realm was still importing, leaves nothing behind.

**Fix:**

```bash
platform/hashicorp/keycloak/provision-demo-users.sh
```

Idempotent — present accounts are untouched, missing ones are created and their single-use
initial credential printed. `deploy.sh` now *verifies* the accounts exist afterwards and fails
the deploy rather than warning, so this cannot pass silently again.

Persisting analyst-chosen passwords across a recreate needs Keycloak moved onto the platform
Postgres; that is tracked work, not something to improvise during an incident.

## Locked out after repeated attempts

Brute-force protection is on (`failureFactor 5`, not permanent). Keycloak reports a locked
account as "invalid username or password" — it does not reveal the lockout, so it looks
identical to a wrong password.

```bash
platform/admin/kc-userctl.sh status default-analyst    # numFailures, disabled
platform/admin/kc-userctl.sh unlock default-analyst
platform/admin/kc-userctl.sh reset  default-analyst    # single-use temporary password
```

Host-bound by design: these work only where Keycloak runs, because recovering an account
should take the same access as recovering the identity store.

## "400 Request Header Or Cookie Too Large"

Served by nginx, before the request reaches the application. The SSO gate issues a CSRF
cookie per login attempt; without a ceiling those accumulate until the Cookie header exceeds
what the server accepts, and retrying cannot help because every retry resends the same header.

Capped at the gate (`--cookie-csrf-per-request-limit`), not absorbed by a larger buffer —
header buffers are per-connection memory and every analyst arrives through the broker from
one source address, so widening them would weaken a shared resource bound to hide a fixable
defect. If this recurs, confirm the cap is still present rather than raising the buffer:

```bash
podman inspect ir-enclave_oauth2-proxy_1 --format '{{range .Config.Cmd}}{{println .}}{{end}}' | grep csrf
```

## Keycloak "We are sorry — an error occurred, please login again"

A callback the identity provider no longer recognizes: the flow's CSRF cookie expired, was
evicted by the per-request cap, or Keycloak was recreated mid-flow. **Refreshing cannot fix
it** — F5 resubmits the same dead callback — and the page carries no link back.

Recovery is to start a fresh flow at the platform root. In the kiosk the analyst cannot
navigate there, so the browser has to do it:

```bash
podman restart ir-workstation_browser_1
```

`workstation/launch.sh` discards the Firefox profile before every start and supervises rather
than `exec`s, so a restart always opens a clean login and a crash self-heals. In-session
recovery — the error page routing itself back — is tracked work; until it lands, a browser
restart is the remedy and it is an administrator action.

## A change to launch.sh or policies.json appears to do nothing

Both are baked into `localhost/ir-browser:latest` (`COPY launch.sh /usr/local/bin/`). A
deploy reuses an existing container, so neither a rebuild nor `deploy.sh workstation` alone
puts new content in front of the analyst:

```bash
podman build -t localhost/ir-browser:latest -f platform/workstation/Dockerfile platform/workstation
podman rm -f ir-workstation_browser_1
platform/deploy/deploy.sh workstation
```

Confirm what is actually running rather than what was built:

```bash
podman exec ir-workstation_browser_1 grep -c "clean profile" /usr/local/bin/launch.sh
```

Removing the browser is safe; it shares the tailnet container's network namespace as a
consumer. Removing `ir-workstation_tailnet_1` — the namespace **owner** — while the browser
holds it can hang while holding the storage lock.
