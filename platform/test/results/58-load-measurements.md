## Load — measured

_50 agents · 60s sustained activity · arrivals paced at 2/s — a fleet · generated 2026-08-13 20:43:03Z_

### Provisioning (through the platform's own admin API, arrivals paced at 2/s)

| Attempted | Created | p50 ms | p95 ms |
|---|---|---|---|
| 50 | 50 | 316 | 338 |

### Login storm (full OIDC, forced credential change included)

| Attempted | Completed | Failed | p50 ms | p95 ms | max ms |
|---|---|---|---|---|---|
| 50 | 50 | 0 | 723 | 748 | 771 |

### Sustained activity, with writes colliding on one investigation

| Operation | n | ok | 5xx | resets | p50 ms | p95 ms | p99 ms |
|---|---|---|---|---|---|---|---|
| export | 149 | 143 | 6 | 0 | 57 | 469 | 557 |
| me | 842 | 828 | 14 | 0 | 32 | 1222 | 2716 |
| poll | 842 | 830 | 12 | 0 | 7 | 115 | 213 |
| rbac_refusal | 179 | 177 | 2 | 0 | 50 | 422 | 639 |
| read_findings | 842 | 830 | 12 | 0 | 40 | 176 | 285 |
| read_stats | 842 | 830 | 12 | 0 | 53 | 239 | 345 |
| write_note | 663 | 653 | 10 | 0 | 82 | 442 | 568 |
| write_verdict | 663 | 653 | 10 | 0 | 68 | 1159 | 2422 |

### Ramp

- **Knee (largest concurrency that held): 50**
- Read-p95 ceiling used: 3000 ms · steps attempted: [10, 20, 30, 40, 50]

### Availability, database, and what was written

| Measure | Value |
|---|---|
| Availability (independent 1 Hz sampler) | 100.00% over 214 samples |
| Health-probe p95 | 3 ms |
| Peak DB connections | 0 of 100 |
| Deadlocks / rollbacks during contention | 0 / 0 |
| Notes written (agent ledger) | 1013 |
| Adjudications written | 1013 |
| Exports completed / refused | 40 / 253 |
| RBAC refusals counted as correct | 267 |
| Confidentiality violations | 0 |
