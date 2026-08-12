## Enclave repairs — admin-requested, agent-executed

*What passing proves:* A repair is requested in the web tier and executed only by the isolated agent's own allow-list; the outcome is recorded once and cannot be forged or replayed.

- Run: `uat_repairs.sh` — 2026-08-12 13:57:55Z

**The catalog and the allow-list**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the UI catalog and the agent allow-list name the same 6 repairs |

**The deployed agent and its posture**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the agent container is running (deployed by deploy.sh agent) |
| ✅ PASS | network_mode is none — the executor has no address and accepts nothing |
| ✅ PASS | no published ports |
| ✅ PASS | pid: host — the deploy scripts' /proc namespace checks see host pids |
| ✅ PASS | the runtime socket is mounted — the agent's one authority |

**Requesting a repair**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | a principal without the admin role cannot request a repair (403) |
| ✅ PASS | an unknown action is refused at the API (400) |
| ✅ PASS | the queue endpoint answers the service credential with a requests list |
| ✅ PASS | admin queued consul-converge-policy (request 1) |

**The deployed agent claims and executes**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | request 1 landed succeeded — claimed and executed by the deployed agent |
| ✅ PASS | the agent's own log records the claim |
| ✅ PASS | the record carries the executing host, the output, and exit 0 |

**The repair restored the policy**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | Consul holds 8 intention set(s) for 8 declared — the policy converged |

**The outcome cannot be rewritten**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | a second claim on the finished request is refused (409) |
| ✅ PASS | an outcome cannot be rewritten after the fact (409) |
| ✅ PASS | the request is in the audit ledger |

**Result**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | enclave repairs hold: named requests, an isolated executor, recorded outcomes, and a repair that actually repairs |

**Verdict: PROVEN** — 18 assertions passed, 0 failed.
