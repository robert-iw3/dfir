## Load — measured

_50 agents · 60s sustained activity · arrivals paced at 2/s — a fleet · generated 2026-08-15 01:21:21Z_

### Provisioning (through the platform's own admin API, arrivals paced at 2/s)

| Attempted | Created | p50 ms | p95 ms |
|---|---|---|---|
| 50 | 50 | 352 | 786 |

### Login storm (full OIDC, forced credential change included)

| Attempted | Completed | Failed | p50 ms | p95 ms | max ms |
|---|---|---|---|---|---|
| 50 | 50 | 0 | 775 | 1849 | 2270 |

### Sustained activity, with writes colliding on one investigation

| Operation | n | ok | 5xx | resets | p50 ms | p95 ms | p99 ms |
|---|---|---|---|---|---|---|---|
| export | 141 | 140 | 1 | 0 | 45 | 286 | 346 |
| me | 791 | 786 | 4 | 1 | 28 | 3354 | 10427 |
| poll | 791 | 786 | 5 | 0 | 8 | 50 | 152 |
| rbac_refusal | 159 | 157 | 2 | 0 | 43 | 216 | 345 |
| read_findings | 791 | 787 | 4 | 0 | 36 | 135 | 245 |
| read_stats | 791 | 787 | 4 | 0 | 82 | 225 | 412 |
| write_note | 632 | 622 | 9 | 1 | 57 | 298 | 449 |
| write_verdict | 632 | 626 | 6 | 0 | 51 | 581 | 1409 |

### Ramp

- **Knee (largest concurrency that held): 50**
- Read-p95 ceiling used: 3000 ms · steps attempted: [10, 20, 30, 40, 50]

### Availability, database, and what was written

| Measure | Value |
|---|---|
| Availability (independent 1 Hz sampler) | 99.54% over 216 samples |
| Health-probe p95 | 5 ms |
| Peak DB connections | 0 of 100 |
| Deadlocks / rollbacks during contention | 0 / 0 |
| Notes written (agent ledger) | 981 |
| Adjudications written | 986 |
| Exports completed / refused | 40 / 250 |
| RBAC refusals counted as correct | 247 |
| Confidentiality violations | 0 |
