## Evidence pipeline — collection to enclave

*What passing proves:* Sealed evidence ships from a collector over pinned TLS, is held opaque in the DMZ, and is pulled inward by the enclave with custody intact.

- Run: `uat_full_stack.sh` — 2026-08-12 18:10:56Z

**1/9  Deploy all tiers (enclave + DMZ + workstation)**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | enclave API healthy |
| ✅ PASS | ir-dmz_receiver_1 running |
| ✅ PASS | ir-dmz_broker_1 running |
| ✅ PASS | ir-dmz_coredns_1 running |
| ✅ PASS | ir-enclave_puller_1 running |
| ✅ PASS | ir-enclave_worker_1 running |
| ✅ PASS | ir-enclave_traefik_1 running |

**2/9  Tier isolation: the DMZ cannot reach into the enclave**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | DMZ receiver → enclave API: BLOCKED |
| ✅ PASS | DMZ receiver → database : BLOCKED |
| ✅ PASS | DMZ receiver → object store: BLOCKED |
| ✅ PASS | edge endpoint → DMZ receiver: reachable (the ONE permitted flow) |
| ✅ PASS | edge endpoint → enclave backend:8000: BLOCKED |
| ✅ PASS | edge endpoint → enclave db:5432: BLOCKED |
| ✅ PASS | edge endpoint → enclave minio:9000: BLOCKED |

**3/9  Endpoint ships evidence to the DMZ (the only thing it can reach)**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | DMZ receiver accepted + custody-verified the bundle over pinned TLS (202) |
| ✅ PASS | tampered bundle quarantined (400) |
| ✅ PASS | the receiver refuses plaintext — evidence cannot be shipped unencrypted |

**4/9  The enclave PULLS it in (nothing pushed inward)**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | enclave pulled and ingested the evidence |
| ✅ PASS | DMZ holding drained after the pull |

**5/9  DATA FLOW: evidence is stored, analyzed and renderable**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | data flow: collection run ingested (runs=117) |
| ✅ PASS | data flow: findings stored (findings=1417) |
| ✅ PASS | data flow: capture recorded in object store (captures=103) |
| ✅ PASS | data flow: true-positive adjudication preserved (tp=234) |
| ✅ PASS | sandboxed memory analysis produced 18 finding(s) from the stored capture |

**6/9  The analysis sandbox has no egress; the enclave cannot phone home**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | analysis sandbox → internet: BLOCKED (no C2 egress) |

**7/9  Analyst path: brokered to the SSO app, blind to everything else**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | workstation → SSO-gated web app via the broker (HTTP 302) |
| ✅ PASS | workstation → API : BLOCKED |
| ✅ PASS | workstation → database : BLOCKED |
| ✅ PASS | workstation → object store: BLOCKED |
| ✅ PASS | platform name resolves to the broker (10.89.30.90) |
| ✅ PASS | no out-of-zone name resolves from the analyst segment (no DNS exfil) |
| ✅ PASS | the DMZ resolver REFUSES out-of-zone queries (in-zone answers only) |

**8/9  All roles complete the REAL browser OIDC flow**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | admin: browser OIDC login end to end (forced first-login change completed) |
| ✅ PASS | admin: sign-out ends app + IdP session |
| ✅ PASS | analyst: browser OIDC login end to end (forced first-login change completed) |
| ✅ PASS | analyst: sign-out ends app + IdP session |
| ✅ PASS | auditor: browser OIDC login end to end (forced first-login change completed) |
| ✅ PASS | auditor: sign-out ends app + IdP session |
| ✅ PASS | the deployed accounts are still present and untouched (4 users) — this suite set no analyst password |

**8a/9  A dead sign-in callback offers the analyst a way back**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the error page carries a return link — the analyst is not stranded |
| ✅ PASS | it returns to a fresh sign-in on its own, for a kiosk nobody is sitting at |
| ✅ PASS | the automatic return is bounded — it stops rather than looping on a persistent fault |

**8b/9  The kiosk can SAVE an export without the dialog that aborts it**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the kiosk has a writable fixed download directory (/home/analyst/downloads) |
| ✅ PASS | the download directory resolves to a path on the host, not inside the container |
| ✅ PASS | a file written in the kiosk IS readable on the host — the handoff completes |
| ✅ PASS | the running kiosk saves to that directory and cannot be redirected (True /home/analyst/downloads) |
| ✅ PASS | Firefox did not abort handling a download (rc=0) |

**9/9  Identity + audit are enforced across the consolidated stack**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | Keycloak serving (SSO identity source) |
| ✅ PASS | tamper-proof audit chain present (service token scope: denied) |

**Result**

| Result | Assertion — with evidence |
|---|---|
| · | Web app (via broker): https://ir-platform.local:8443/   ·  tiers: ir-enclave / ir-dmz / ir-workstation |

**Verdict: PROVEN** — 49 assertions passed, 0 failed.
