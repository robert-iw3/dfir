## Load — measured

_50 agents · 60s sustained activity · arrivals paced at 2/s — a fleet · generated 2026-08-18 00:01:52Z_

### Provisioning (through the platform's own admin API, arrivals paced at 2/s)

| Attempted | Created | p50 ms | p95 ms |
|---|---|---|---|
| 50 | 50 | 348 | 801 |

### Login storm (full OIDC, forced credential change included)

| Attempted | Completed | Failed | p50 ms | p95 ms | max ms |
|---|---|---|---|---|---|
| 50 | 50 | 0 | 761 | 823 | 873 |

### Sustained activity, with writes colliding on one investigation

| Operation | n | ok | 5xx | resets | p50 ms | p95 ms | p99 ms |
|---|---|---|---|---|---|---|---|
| export | 133 | 132 | 1 | 0 | 90 | 452 | 746 |
| me | 759 | 741 | 14 | 4 | 35 | 3012 | 7305 |
| poll | 759 | 735 | 24 | 0 | 8 | 102 | 166 |
| rbac_refusal | 157 | 155 | 2 | 0 | 66 | 343 | 488 |
| read_findings | 759 | 732 | 27 | 0 | 46 | 192 | 369 |
| read_stats | 759 | 744 | 14 | 1 | 117 | 443 | 702 |
| write_note | 602 | 581 | 16 | 5 | 98 | 338 | 519 |
| write_verdict | 602 | 587 | 14 | 1 | 95 | 848 | 1488 |

### Ramp

- **Knee (largest concurrency that held): 10**
- Read-p95 ceiling used: 3000 ms · steps attempted: [10, 20, 30, 40, 50]
- First degradation at 20 agents — read p95 1038 ms, 6 error(s)

### Availability, database, and what was written

| Measure | Value |
|---|---|
| Availability (independent 1 Hz sampler) | 99.44% over 177 samples |
| Health-probe p95 | 3 ms |
| Peak DB connections | 0 of 100 |
| Deadlocks / rollbacks during contention | 0 / 0 |
| Notes written (agent ledger) | 656 |
| Adjudications written | 662 |
| Exports completed / refused | 23 / 139 |
| RBAC refusals counted as correct | 170 |
| Confidentiality violations | 0 |
