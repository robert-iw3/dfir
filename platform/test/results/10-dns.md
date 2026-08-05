## Network policy — name resolution and egress control

*What passing proves:* Services address each other by dynamic name, and no tier can resolve anything outside its zone — closing DNS as an exfiltration channel from the tier that parses hostile memory.

- Run: `uat_dns.sh` — 2026-08-05 20:34:03Z

**Resolvers**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | DMZ resolver is running |
| ✅ PASS | enclave resolver is running |

**Segmentation — no network has a route off the host**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | ir-edge is internal (no egress) |
| ✅ PASS | ir-dmzlink is internal (no egress) |
| ✅ PASS | ir-enclave_internal is internal (no egress) |

**Analyst segment — the platform name resolves to the BASTION, live**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | ir-platform.local resolves to 10.89.30.37 from the analyst browser |
| ✅ PASS | the answer is the bastion's CURRENT address (resolved, not pinned) |
| ✅ PASS | bastion resolves by name (10.89.0.10) |
| ✅ PASS | headscale resolves by name (10.89.0.9) |
| ✅ PASS | receiver resolves by name (10.89.0.8) |

**Enclave — services resolve each other by name**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | db resolves (10.89.1.201) |
| ✅ PASS | redis resolves (10.89.1.208) |
| ✅ PASS | minio resolves (10.89.1.202) |
| ✅ PASS | keycloak resolves (10.89.1.211) |
| ✅ PASS | backend resolves (10.89.1.204) |
| ✅ PASS | worker resolves (10.89.1.205) |
| ✅ PASS | traefik resolves (10.89.1.12) |

**Enclave — exactly ONE cross-tier name: the receiver**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | receiver resolves from the puller (10.89.0.8) — the evidence path inward |
| ✅ PASS | bastion is NOT resolvable from the enclave (only receiver is) |
| ✅ PASS | headscale is NOT resolvable from the enclave (only receiver is) |

**Exfiltration — no service can resolve an outside name**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | enclave_puller_1 cannot resolve any outside name |
| ✅ PASS | enclave_backend_1 cannot resolve any outside name |
| ✅ PASS | enclave_worker_1 cannot resolve any outside name |
| ✅ PASS | enclave_traefik_1 cannot resolve any outside name |
| ✅ PASS | enclave_keycloak_1 cannot resolve any outside name |
| ✅ PASS | workstation_browser_1 cannot resolve any outside name |

**Backstop — CoreDNS refuses when it is the one asked**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | DMZ CoreDNS refuses outside names when queried directly |
| ✅ PASS | DMZ CoreDNS still resolves in-zone names (forwarding works) |
| ✅ PASS | enclave CoreDNS refuses outside names when queried directly |
| ✅ PASS | enclave CoreDNS still resolves in-zone names (forwarding works) |

**Addressing — every address is declared configuration, never a literal**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | every pinned address is a declared variable, none hard-coded |
| ✅ PASS | pins are the resolvers and IR_IP_* mesh participants, nothing else |

**DNS**

| Result | Assertion — with evidence |
|---|---|

**Verdict: PROVEN** — 32 assertions passed, 0 failed.
