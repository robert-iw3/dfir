## Secrets — Vault dynamic credentials

*What passing proves:* The platform holds no static application credential: Vault issues short-lived database users the app provably runs on, the custody key is Vault-sourced, the store is audited with its root revoked, and a full rotation converges the platform onto fresh credentials while it stays up.

- Run: `uat_vault.sh` — 2026-08-06 16:26:43Z

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
| ✅ PASS | audit device is recording (10241630 bytes) |
| ✅ PASS | initial root token revoked and removed from state |

**The app tier runs on Vault-issued credentials**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | agent rendered a Vault-minted database user (v-approle-ir-platf-ihfrUkeqtaZTXg7zg0Dw-1786033162) |
| ✅ PASS | it is not the static admin |
| ✅ PASS | the custody HMAC key is Vault-sourced |
| ✅ PASS | Django key + remaining app secrets are Vault-sourced |
| ✅ PASS | Django logs in as the Vault dynamic user (v-approle-ir-platf-ihfrUkeqtaZTXg7zg0Dw-1786033162) |
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
| ✅ PASS | rotation procedure completed (rotation complete: v-approle-ir-platf-ihfrUkeqtaZTXg7zg0Dw-1786033162 -> v-approle-ir-platf-LqBg5XD7ALwaDGARquWP-1786033607) |
| ✅ PASS | a NEW credential was issued (v-approle-ir-platf-ihfrUkeqtaZTXg7zg0Dw-1786033162 -> v-approle-ir-platf-LqBg5XD7ALwaDGARquWP-1786033607) |
| ✅ PASS | the old user was dropped from Postgres at rotation (v-approle-ir-platf-ihfrUkeqtaZTXg7zg0Dw-1786033162) |
| ✅ PASS | Django's live connection is on the new user (v-approle-ir-platf-LqBg5XD7ALwaDGARquWP-1786033607) |
| ✅ PASS | KV secrets (custody/Django keys) unchanged by rotation, as they must be |
| ✅ PASS | platform healthy on the rotated credential |

**Result**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | Vault holds: enclave-placed, audited, root revoked, app on issued credentials, rotation proven live |

**Verdict: PROVEN** — 23 assertions passed, 0 failed.
