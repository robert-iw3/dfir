## Secrets — Vault dynamic credentials

*What passing proves:* The platform holds no static application credential: Vault issues short-lived database users the app provably runs on, the custody key is Vault-sourced, the store is audited with its root revoked, and a full rotation converges the platform onto fresh credentials while it stays up.

- Run: `uat_vault.sh` — 2026-08-17 13:06:08Z

**Placement — the secrets authority is in the enclave**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | Vault server is running in the enclave |
| ✅ PASS | Vault agent is running in the enclave |
| ✅ PASS | Vault sits on the internal network and nothing else |

**Vault is initialized and unsealed**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | initialized |
| ✅ PASS | unsealed |

**The signing keys survive provisioning — rotation is never a side effect of deploying**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | re-running provisioning left the audit and custody signing keys UNCHANGED (0964dd605074) — every signature and seal already written still verifies against them |

**Vault recovers from a restart on its own**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | a restart nothing deploy-related caused came back UNSEALED — recovery is a property of the server, not of the deployment |
| ✅ PASS | and its mesh proxy was reattached to the new namespace, so the stack is left serving |

**Hardening — audit on, root revoked**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | audit device is recording (11770023 bytes) |
| ✅ PASS | initial root token revoked and removed from state |

**The app tier runs on Vault-issued credentials**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | agent rendered a Vault-minted database user (v-approle-ir-platf-MEcQT4eHMlHzBU1fcjfu-1786969099) |
| ✅ PASS | it is not the static admin |
| ✅ PASS | the custody HMAC key is Vault-sourced |
| ✅ PASS | Django key + remaining app secrets are Vault-sourced |
| ✅ PASS | Django logs in as the Vault dynamic user (v-approle-ir-platf-MEcQT4eHMlHzBU1fcjfu-1786969099) |
| ✅ PASS | and acts as the stable owner role ir_app (rotation-safe) |

**Both databases answer the dynamic user**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | ir_platform: django_migrations readable (58 rows) |
| ✅ PASS | ir_correlation: django_migrations readable (58 rows) |
| ✅ PASS | API healthy over the issued credentials |

**Rotation — executed, not assumed**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | rotation procedure completed (rotation complete: v-approle-ir-platf-MEcQT4eHMlHzBU1fcjfu-1786969099 -> v-approle-ir-platf-wuKvHY9B9y1tpZixEejI-1786971984) |
| ✅ PASS | a NEW credential was issued (v-approle-ir-platf-MEcQT4eHMlHzBU1fcjfu-1786969099 -> v-approle-ir-platf-wuKvHY9B9y1tpZixEejI-1786971984) |
| ✅ PASS | the old user was dropped from Postgres at rotation (v-approle-ir-platf-MEcQT4eHMlHzBU1fcjfu-1786969099) |
| ✅ PASS | Django's live connection is on the new user (v-approle-ir-platf-wuKvHY9B9y1tpZixEejI-1786971984) |
| ✅ PASS | KV secrets (custody/Django keys) unchanged by rotation, as they must be |
| ✅ PASS | platform healthy on the rotated credential |

**Setup credentials — an admin retrieves what the deployment generated**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | platform-admin logs in to Vault with userpass (no dependency on Keycloak) |
| ✅ PASS | platform-admin reads ir/setup (10 field(s)) |
| ✅ PASS | every credential the deploy generates is in the store — nothing is recoverable only from the host that ran it |
| ✅ PASS | the password stored in Vault is the one Keycloak accepts — the store tracks the deployment rather than a past one |
| ✅ PASS | the same admin CANNOT mint the app tier's AppRole secret-id — read access is not impersonation |

**Result**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | Vault holds: enclave-placed, audited, root revoked, app on issued credentials, rotation proven live |

**Verdict: PROVEN** — 31 assertions passed, 0 failed.
