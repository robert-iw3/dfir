## Identity store — separated, leased, persistent

*What passing proves:* The identity store is a separate database the application is refused the CONNECTION to; both sides run on Vault leases with no static secret in any environment; accounts survive a Keycloak recreate through the deploy path; the realm file is enforced on existing realms; the database hop rides the mesh.

- Run: `uat_keycloak_db.sh` — 2026-08-13 20:26:39Z

**Preconditions**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | ir-enclave_db_1 running |
| ✅ PASS | ir-enclave_backend_1 running |
| ✅ PASS | ir-enclave_keycloak_1 running |
| ✅ PASS | ir-enclave_vault-agent_1 running |
| ✅ PASS | ir-enclave_kc-vault-agent_1 running |
| ✅ PASS | static admin credential opens the maintenance database (control for admin checks) |

**The application's LIVE credential — what it sources, not what compose says**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | read the application's rendered credential (v-approle-ir-platf-uzjS0VPVjlNzrhg2arNH-1786652143) |
| ✅ PASS | the credential is Vault-issued (username shape v-…) |
| ✅ PASS | control: that credential DOES open the evidence database over TCP |

**The application is refused the identity store**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the application's credential is REFUSED the connection to the keycloak database |
| ✅ PASS | ir_app holds no CONNECT privilege on keycloak |

**The reciprocal — the identity role reaches no evidence**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | kc_app holds no CONNECT on ir_platform |
| ✅ PASS | kc_app holds no CONNECT on ir_correlation |

**Ownership and schema**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the keycloak database is owned by kc_app, not by the application's role |
| ✅ PASS | PUBLIC cannot create objects in the identity store's schema |

**No superuser, no static secret, in the app tier**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | ir-enclave_backend_1 carries no POSTGRES_PASSWORD in its environment |
| ✅ PASS | ir-enclave_worker_1 carries no POSTGRES_PASSWORD in its environment |
| ✅ PASS | control: the application holds 21 live connection(s) to assert against |
| ✅ PASS | every live application connection is a Vault-issued non-superuser |
| ✅ PASS | the only non-Vault-issued session is the credential broker's own (static admin, as vault) |

**Keycloak's credential — a lease, not a static secret wearing a dynamic name**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | Keycloak's rendered credential is Vault-issued (v-approle-keycloak-fhj2eIoGBAe8LH1blxJY-1786651515) |
| ✅ PASS | that user EXPIRES (VALID UNTIL set) — it is a lease |
| ✅ PASS | the leased user acts as kc_app — objects survive rotation |
| ✅ PASS | Keycloak is CONNECTED to its store with that lease (2 connection(s)) |
| ✅ PASS | the running process holds the CURRENT credential — no superseded user in its pool |
| · | superseded keycloak roles still present in the cluster: 1 |
| ✅ PASS | no KC_DB_PASSWORD in Keycloak's configured environment |
| ✅ PASS | no KC_DB_PASSWORD in compose or .env |

**The database hop rides the mesh**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | intention permits ir-keycloak -> ir-postgres |
| ✅ PASS | control: a pair with no business (ir-frontend -> ir-postgres) is Denied |

**Realm converge — the file governs an EXISTING realm**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | a drifted brute-force threshold (99) was converged back to the file's value (5) |

**Persistence — the defect that started this (destructive, runs last)**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | probe account created |
| ✅ PASS | control: the probe credential authenticates BEFORE the recreate |
| ✅ PASS | Keycloak container removed |
| ✅ PASS | enclave redeployed through deploy.sh |
| ✅ PASS | the credential set BEFORE the recreate authenticates AFTER it — accounts persist |
| ✅ PASS | control: a wrong password is still refused |

**Result**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | identity is separated by privilege, leased by Vault, and survives a recreate |

**Verdict: PROVEN** — 37 assertions passed, 0 failed.
