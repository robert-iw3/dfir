## Service mesh — default-deny authorization, on a hardened control plane

*What passing proves:* Which service may reach which is stated explicitly, denied by default, and enforced on the wire — and the policy itself is protected by TLS and ACLs, so the services it governs cannot read or rewrite it.

- Run: `uat_consul.sh` — 2026-07-31 19:13:17Z

**Consul is running in the enclave with Connect enabled**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | Consul is running in the enclave |
| ✅ PASS | on the internal network only — the mesh control plane is exposed to no other tier |
| ✅ PASS | management token present on the deploy host (gen-consul-secrets.sh ran) |
| ✅ PASS | a leader is elected — the catalog and mesh are serving |

**The control plane is TLS-only, with the enclave's own CA**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | consul:8500 (cleartext HTTP API) is closed |
| ✅ PASS | consul:8502 (cleartext gRPC (xDS)) is closed |
| ✅ PASS | HTTPS on 8501 serves and its certificate chains to the enclave CA (HTTP 200) |
| ✅ PASS | a client without the enclave CA cannot complete the handshake |

**Gossip traffic is encrypted**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the gossip keyring is loaded — membership and health traffic is encrypted |

**The API is default-deny and the policy is not writable by the services it governs**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | an untokened request for the ACL store is refused (HTTP 403) |
| ✅ PASS | an untokened request to READ the intentions is refused (HTTP 403) |
| ✅ PASS | the frontend's own token is valid and reads the catalog (HTTP 200) |
| ✅ PASS | that same token CANNOT delete the intention denying it Postgres (HTTP 403) |

**Bootstrapped intentions are loaded**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | intentions present for ir-postgres |
| ✅ PASS | intentions present for ir-minio |
| ✅ PASS | intentions present for ir-backend |

**The pairs the platform needs are allowed**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | ir-backend → ir-postgres: ALLOWED |
| ✅ PASS | ir-worker → ir-postgres: ALLOWED |
| ✅ PASS | ir-backend → ir-minio: ALLOWED |
| ✅ PASS | ir-worker → ir-minio: ALLOWED |
| ✅ PASS | ir-frontend → ir-backend: ALLOWED |
| ✅ PASS | ir-puller → ir-postgres: ALLOWED |
| ✅ PASS | ir-puller → ir-minio: ALLOWED |
| ✅ PASS | ir-puller → ir-backend: ALLOWED |
| ✅ PASS | ir-vault → ir-postgres: ALLOWED |

**Everything else is denied — lateral movement is refused by rule**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | ir-frontend → ir-postgres: DENIED |
| ✅ PASS | ir-frontend → ir-minio: DENIED |
| ✅ PASS | ir-receiver → ir-postgres: DENIED |
| ✅ PASS | unknown-svc → ir-minio: DENIED |

**The policy is ENFORCED on the wire, not merely evaluated**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | platform services are registered in the catalog (15 entries) |
| ✅ PASS | ir-frontend → ir-postgres: the connection to db:5432 is actually refused |
| ✅ PASS | ir-frontend → ir-minio: the connection to minio:9000 is actually refused |
| ✅ PASS | ir-backend → ir-postgres: the allowed upstream carries traffic through its sidecar |
| ✅ PASS | ir-vault → ir-postgres: minted a live credential through the mesh (v-approle-ir-platf-UwHGDI6B69xuvhWJpTsx-1785525202) |

**Every sidecar authenticated to the hardened control plane**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | db-sidecar is up and stable (0 restarts) |
| ✅ PASS | db-sidecar shares its service's live network namespace (net:[4026534383]) |
| ✅ PASS | minio-sidecar is up and stable (0 restarts) |
| ✅ PASS | minio-sidecar shares its service's live network namespace (net:[4026534457]) |
| ✅ PASS | vault-sidecar is up and stable (0 restarts) |
| ✅ PASS | vault-sidecar shares its service's live network namespace (net:[4026534126]) |
| ✅ PASS | backend-sidecar is up and stable (0 restarts) |
| ✅ PASS | backend-sidecar shares its service's live network namespace (net:[4026534243]) |
| ✅ PASS | worker-sidecar is up and stable (0 restarts) |
| ✅ PASS | worker-sidecar shares its service's live network namespace (net:[4026534809]) |
| ✅ PASS | frontend-sidecar is up and stable (0 restarts) |
| ✅ PASS | frontend-sidecar shares its service's live network namespace (net:[4026534359]) |
| ✅ PASS | puller-sidecar is up and stable (0 restarts) |
| ✅ PASS | puller-sidecar shares its service's live network namespace (net:[4026534949]) |

**Result**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | mesh authorization holds: explicit allow-list, default-deny, enforced on the wire, on a TLS control plane the services cannot rewrite |

**Verdict: PROVEN** — 49 assertions passed, 0 failed.
