## Load — measured

_50 agents · 60s sustained activity · arrivals paced at 2/s — a fleet · generated 2026-08-12 14:16:47Z_

### Provisioning (through the platform's own admin API, arrivals paced at 2/s)

| Attempted | Created | p50 ms | p95 ms |
|---|---|---|---|
| 50 | 50 | 319 | 439 |

### Login storm (full OIDC, forced credential change included)

| Attempted | Completed | Failed | p50 ms | p95 ms | max ms |
|---|---|---|---|---|---|
| 50 | 50 | 0 | 772 | 2469 | 2939 |

**1 login(s) had to retry through a refused connection** — the brokered session turned over mid-run; the availability figure below covers the same window.

### Sustained activity, with writes colliding on one investigation

| Operation | n | ok | 5xx | resets | p50 ms | p95 ms | p99 ms |
|---|---|---|---|---|---|---|---|
| export | 151 | 149 | 2 | 0 | 92 | 250 | 492 |
| me | 857 | 848 | 9 | 0 | 31 | 830 | 1920 |
| poll | 857 | 846 | 11 | 0 | 9 | 67 | 116 |
| rbac_refusal | 186 | 185 | 1 | 0 | 60 | 378 | 2165 |
| read_findings | 857 | 844 | 13 | 0 | 43 | 134 | 206 |
| read_stats | 857 | 836 | 21 | 0 | 72 | 188 | 288 |
| write_note | 671 | 661 | 10 | 0 | 88 | 403 | 517 |
| write_verdict | 671 | 662 | 9 | 0 | 79 | 747 | 1444 |

### Ramp

- **Knee (largest concurrency that held): 50**
- Read-p95 ceiling used: 3000 ms · steps attempted: [10, 20, 30, 40, 50]

### Availability, database, and what was written

| Measure | Value |
|---|---|
| Availability (independent 1 Hz sampler) | 100.00% over 215 samples |
| Health-probe p95 | 3 ms |
| Peak DB connections | 0 of 100 |
| Deadlocks / rollbacks during contention | 0 / 0 |
| Notes written (agent ledger) | 1021 |
| Adjudications written | 1022 |
| Exports completed / refused | 40 / 259 |
| RBAC refusals counted as correct | 275 |
| Confidentiality violations | 0 |
