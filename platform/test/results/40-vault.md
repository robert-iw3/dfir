## Secrets — Vault dynamic credentials

*What passing proves:* The platform holds no static application credential: Vault issues short-lived database users the app provably runs on, the custody key is Vault-sourced, the store is audited with its root revoked, and a full rotation converges the platform onto fresh credentials while it stays up.

- Run: `uat_vault.sh` — 2026-08-05 16:02:54Z

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

**Hardening — audit on, root revoked**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | audit device is recording (7644015 bytes) |
| ✅ PASS | initial root token revoked and removed from state |

**The app tier runs on Vault-issued credentials**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | agent rendered a Vault-minted database user (v-approle-ir-platf-SmLtV0VoDFRi0xcyDZVJ-1785942231) |
| ✅ PASS | it is not the static admin |
| ✅ PASS | the custody HMAC key is Vault-sourced |
| ✅ PASS | Django key + remaining app secrets are Vault-sourced |
| ✅ PASS | Django logs in as the Vault dynamic user (v-approle-ir-platf-SmLtV0VoDFRi0xcyDZVJ-1785942231) |
| ✅ PASS | and acts as the stable owner role ir_app (rotation-safe) |

**Both databases answer the dynamic user**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | ir_platform: django_migrations readable (43 rows) |
| ✅ PASS | ir_correlation: django_migrations readable (43 rows) |
| ✅ PASS | API healthy over the issued credentials |

**Rotation — executed, not assumed**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | rotation procedure completed (rotation complete: v-approle-ir-platf-SmLtV0VoDFRi0xcyDZVJ-1785942231 -> v-approle-ir-platf-jNWt9YoWPpuC8Xme1Dlu-1785945778) |
| ✅ PASS | a NEW credential was issued (v-approle-ir-platf-SmLtV0VoDFRi0xcyDZVJ-1785942231 -> v-approle-ir-platf-jNWt9YoWPpuC8Xme1Dlu-1785945778) |
| ✅ PASS | the old user was dropped from Postgres at rotation (v-approle-ir-platf-SmLtV0VoDFRi0xcyDZVJ-1785942231) |
| ✅ PASS | Django's live connection is on the new user (v-approle-ir-platf-jNWt9YoWPpuC8Xme1Dlu-1785945778) |
| ✅ PASS | KV secrets (custody/Django keys) unchanged by rotation, as they must be |
| ✅ PASS | platform healthy on the rotated credential |

**Result**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | Vault holds: enclave-placed, audited, root revoked, app on issued credentials, rotation proven live |

**Verdict: PROVEN** — 23 assertions passed, 0 failed.
