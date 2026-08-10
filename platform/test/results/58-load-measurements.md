## Load — measured

_50 agents · 60s sustained activity · arrivals paced at 2/s — a fleet · generated 2026-08-10 02:28:05Z_

### Provisioning (through the platform's own admin API, arrivals paced at 2/s)

| Attempted | Created | p50 ms | p95 ms |
|---|---|---|---|
| 50 | 50 | 321 | 399 |

### Login storm (full OIDC, forced credential change included)

| Attempted | Completed | Failed | p50 ms | p95 ms | max ms |
|---|---|---|---|---|---|
| 50 | 50 | 0 | 748 | 795 | 918 |

### Sustained activity, with writes colliding on one investigation

| Operation | n | ok | 5xx | resets | p50 ms | p95 ms | p99 ms |
|---|---|---|---|---|---|---|---|
| export | 150 | 150 | 0 | 0 | 44 | 243 | 352 |
| me | 890 | 879 | 1 | 10 | 15 | 954 | 3902 |
| poll | 890 | 890 | 0 | 0 | 8 | 27 | 164 |
| rbac_refusal | 179 | 179 | 0 | 0 | 24 | 194 | 319 |
| read_findings | 890 | 888 | 0 | 2 | 26 | 115 | 238 |
| read_stats | 890 | 889 | 0 | 1 | 28 | 155 | 1162 |
| write_note | 711 | 711 | 0 | 0 | 38 | 266 | 439 |
| write_verdict | 711 | 711 | 0 | 0 | 36 | 317 | 1142 |

### Ramp

- **Knee (largest concurrency that held): 50**
- Read-p95 ceiling used: 3000 ms · steps attempted: [10, 20, 30, 40, 50]

### Availability, database, and what was written

| Measure | Value |
|---|---|
| Availability (independent 1 Hz sampler) | 100.00% over 221 samples |
| Health-probe p95 | 3 ms |
| Peak DB connections | 0 of 100 |
| Deadlocks / rollbacks during contention | 0 / 0 |
| Notes written (agent ledger) | 1071 |
| Adjudications written | 1071 |
| Exports completed / refused | 40 / 260 |
| RBAC refusals counted as correct | 269 |
| Confidentiality violations | 0 |
