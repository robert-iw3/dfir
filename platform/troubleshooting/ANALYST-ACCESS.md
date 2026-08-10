# Analyst cannot get in

Failures on the path an analyst actually uses: the kiosk browser, the SSO gate, Keycloak.
Each entry is a symptom as it appears at the workstation, then what it actually is.

The kiosk has no address bar, no history, no settings and no way to clear cookies. Any
instruction that begins "clear your browser state" is not a remedy here — it is a remedy that
does not exist, and the platform has to recover on its own.

---

## "We can't connect to the server at ir-platform.local"

Firefox's connection-failure page, on one workstation or all of them. Before treating it as a
workstation fault, ask whether the enclave is being redeployed: `deploy.sh down enclave` drops
the analyst path end to end — controller, egress workers, ingress — and every kiosk shows this
page until the enclave is back and the brokered sessions re-establish, about a minute after
`deploy.sh enclave` completes. Try Again is the whole remedy.

If the stack is up and stable, distinguish the workstation's tunnel from its browser. The
browser shares the tailnet container's network namespace, so the diagnostics probe (same
namespace) answers for both:

```bash
podman exec ir-workstation-<id>_probe_1 python3 -c "
import socket; print(socket.gethostbyname('ir-platform.local'))"
```

- **Resolution fails** → the workstation's resolver or tunnel; see the tailnet entries below.
- **Resolves and a request answers 200** → the path is fine and the page is stale; Try Again.
  A kiosk has no other state to clear.

`test/uat_tailnet.sh` asserts per-workstation reachability — reachability for the first
workstation proves nothing about the second.

## Password refused after a UAT run — neither the initial nor the changed one

A test walked the forced-password-change flow on a demo account and left it rotated to a
value only that run knew. Restore it — **with the deploy environment sourced**:

```bash
set -a; . deploy/.env; set +a; bash hashicorp/keycloak/provision-demo-users.sh --force default-admin
```

The account returns to its initial password with a new password demanded at first login.

The sourcing matters: initial passwords come from `IR_DEMO_<ROLE>_PASSWORD` in `deploy/.env`,
falling back to documented defaults only when unset. Run without the env and the account is
provisioned with the DEFAULT — a different credential than every other provisioning of the
same account, and the printed password is the only statement of which one applies. When a
restored account "still refuses the initial password", the value in `deploy/.env` is the
truth; the counter at `attack-detection/brute-force/users/<id>` says whether attempts are
even reaching password validation.

Tests are not supposed to put an account in this state. `uat_audit.sh` drives an EPHEMERAL
`uat-audit-probe` account it creates and deletes itself; `uat_srg_webtier.sh` still drives
`default-admin` — its assertions are about that account's provisioned state specifically —
and restores it on every exit via trap. If the symptom appears anyway, a test was killed
hard enough to skip its trap; the command above is the remedy either way.

## The password change form refuses the new password

The form re-presents with small red text under the field — easy to miss on the kiosk, so the
attempt reads as "the change does not work" rather than as a refusal with a reason. The realm
policy the new password must satisfy:

| Rule | Refusal it causes |
|---|---|
| `length(15)` | anything shorter than 15 characters — the common one |
| `upperCase(1) lowerCase(1) digits(1) specialChars(1)` | all four classes required |
| `passwordHistory(5)` | any of the last 5 passwords used on this account |
| `passwordBlacklist` | dictionary/known-breached values |
| not the username or email | self-referential passwords |

The account is not harmed by refusals — the credential is unchanged and the form can be
resubmitted. Failed POLICY checks are not failed LOGINS and do not count toward brute-force
lockout. Read the policy live with:

```bash
podman exec ir-enclave_keycloak_1 sh -c '/opt/keycloak/bin/kcadm.sh config credentials \
  --server http://127.0.0.1:8080 --realm master --user "${KC_BOOTSTRAP_ADMIN_USERNAME:-admin}" \
  --password "${KC_BOOTSTRAP_ADMIN_PASSWORD:-admin}" >/dev/null 2>&1 && \
  /opt/keycloak/bin/kcadm.sh get realms/irplatform --fields passwordPolicy'
```

## "We are sorry — an internal server error" mid password-change

Keycloak's 500 page while submitting the new password, with `UPDATE_PASSWORD_ERROR`,
`userId="null"` and a `NullPointerException: ... UserModel.getUsername()` in its log. The
account was DELETED AND RECREATED while the form was open — the browser's login attempt
references a user id that no longer exists. `provision-demo-users.sh --force` does exactly
that, which is why tests must not drive shared accounts: a re-provision racing a person's
login invalidates it mid-flight.

Nothing is broken. The error page returns to sign-in on its own; the fresh attempt
authenticates against the recreated account with its printed initial password.

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

## "403 Forbidden" from the SSO gate after a long login

Served by oauth2-proxy, not Keycloak, and typically at the end of a forced password change —
credentials accepted, password updated, then a bare 403 with Go Back as the only control. Go
Back returns to the app, which starts a fresh flow, so it can look intermittent.

The gate's own log names it:

```bash
podman logs ir-enclave_oauth2-proxy_1 | grep -i "csrf cookie"
```

`unable to obtain CSRF cookie: ... was not found` means the attempt's cookie was gone before
its callback arrived. Eviction is **oldest-first** against `--cookie-csrf-per-request-limit`,
and the oldest attempt is the one already in progress — so competing attempts do not queue
behind the analyst's, they displace it. Count the starts in a one-second window:

```bash
podman logs ir-enclave_oauth2-proxy_1 | grep -c "302.*oauth2/start"
```

With `--skip-provider-button=true` every unauthenticated request that is not classified as a
data call redirects to the identity provider and mints one. Three settings keep them apart:

- `--api-route=^/(api/|index\.html)` on the gate — those paths are answered `401`, never
  redirected. **`index.html` is in there deliberately**: DeployWatch re-fetches it every 30
  seconds, so while it was treated as navigation a single idle tab minted an attempt every
  half minute and exhausted the ceiling in ninety seconds. Any path the app POLLS belongs in
  this pattern, whatever serves it.
- the single-flight guard in `frontend/src/api.js` — however many 401s a page load produces,
  one sign-in happens.
- `--cookie-csrf-per-request-limit=6` — headroom for legitimate re-navigation (a retry, a
  kiosk reopening, a restored tab). It bounds the cookie header; it is not what protects the
  flow.

To see whether a path is minting, look for `302` on anything that is not a navigation:

```bash
podman logs --since 15m ir-enclave_oauth2-proxy_1 | grep -E '" (302|401) ' | tail -30
```

A polled path answering `302` is the bug; answering `401` is correct.

A missing `Accept` header is not the mechanism here: the gate also 401s anything sending
`Accept: application/json`, but the app's fetch sends `*/*`, so classification is by path.

Both halves, and the 403 itself, are asserted by `test/uat_srg_webtier.sh` ("Login flow" —
including a control that reproduces the eviction over unclassified paths). If this recurs,
run that section before changing anything; it distinguishes a gate regression from a bundle
that shipped without the guard.

### Two different 403s — read the log line, not the page

The page is identical either way. The gate's message is not:

| Log message | What happened |
|---|---|
| `unable to obtain CSRF cookie: ... was not found` | The attempt's cookie was **evicted** — competing attempts, above. |
| `No cookies were found in OAuth callback` | The browser sent **no cookies at all**. |

The second is not eviction, and tuning `--cookie-csrf-per-request-limit` will not touch it.
Nothing was displaced; the cookie jar was empty when the callback arrived. Confirm with the
request headers the gate logs alongside it:

```bash
podman logs --since 30m ir-enclave_oauth2-proxy_1 | grep -A2 "No cookies were found"
```

`Sec-Fetch-Site: none` on that callback is the tell. Keycloak is served from the same origin
as the app, so a redirect back from it is `same-origin`; `none` means the browser treated the
callback as a fresh navigation with no initiator — a restored tab, a reopened kiosk, or a
profile whose cookies were cleared between the login starting and the code coming back.

The login itself is fine. Only that attempt is unrecoverable, which is why going back and
signing in again works.

The gate no longer dead-ends on it. `deploy/enclave/oauth2-templates/error.html` replaces the
built-in error page and restarts the flow once, bounded by a `sessionStorage` flag so a
persistent fault surfaces instead of looping. The manual control stays for scripting-off
kiosks, and `frontend/src/auth.jsx` clears the flag on a successful load so the next failure
gets its own retry.

If the retry itself 403s, the cause is not a stale attempt — stop and read the log line
above before changing gate settings.

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
