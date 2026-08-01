#!/usr/bin/env bash
# Derive Postgres settings from the resources this container actually has, then start it.
#
# Every value below can still be overridden explicitly (IR_PG_*), because a site that has
# measured its own workload knows better than a ratio.
#
# The ratios are the standard ones for a host dedicated to Postgres, which the enclave's database
# is — nothing else runs in this namespace but its own sidecar.
set -euo pipefail

# Memory the container may actually use. The cgroup limit is what matters when one is set: the
# host's total is a lie inside a limited container, and sizing shared_buffers against it is how a
# database gets OOM-killed under load rather than at start-up, when it would be obvious.
mem_bytes() {
    local v
    for f in /sys/fs/cgroup/memory.max /sys/fs/cgroup/memory/memory.limit_in_bytes; do
        [[ -r "$f" ]] || continue
        v="$(cat "$f")"
        # "max" means unlimited; the sentinel on cgroup v1 is an implausibly large number.
        [[ "$v" == "max" ]] && continue
        [[ "$v" =~ ^[0-9]+$ ]] || continue
        (( v > 0 && v < 2**62 )) && { printf '%s' "$v"; return; }
    done
    awk '/^MemTotal:/ {print $2 * 1024; exit}' /proc/meminfo
}

TOTAL_B="$(mem_bytes)"
TOTAL_MB=$(( TOTAL_B / 1024 / 1024 ))
CPUS="$(nproc 2>/dev/null || echo 2)"

mb() { printf '%sMB' "$1"; }
pct() { echo $(( TOTAL_MB * $1 / 100 )); }

# 25% of RAM is the long-standing starting point; above ~8GB the returns flatten and the memory
# is better left to the page cache, so it is capped.
SHARED=$(pct 25); (( SHARED > 8192 )) && SHARED=8192; (( SHARED < 128 )) && SHARED=128

# What the planner BELIEVES is cached, including the OS page cache — not an allocation. Too low
# and it refuses index scans that would be free.
CACHE=$(pct 70); (( CACHE < 256 )) && CACHE=256

# Per sort/hash node, and there can be several per query across many connections — hence the
# division. Generous here is how a host runs out of memory under concurrency.
MAXCONN="${IR_PG_MAX_CONNECTIONS:-100}"
WORK=$(( TOTAL_MB / 4 / MAXCONN )); (( WORK < 4 )) && WORK=4; (( WORK > 256 )) && WORK=256

# Index builds and VACUUM. This platform bulk-loads findings, so it is worth more than the default.
MAINT=$(pct 5); (( MAINT > 2048 )) && MAINT=2048; (( MAINT < 64 )) && MAINT=64

# Ingest is write-heavy in bursts — a capture lands and the worker writes thousands of rows.
# Larger WAL between checkpoints turns a stall into a smooth spread.
MAXWAL="${IR_PG_MAX_WAL:-4GB}"
MINWAL="${IR_PG_MIN_WAL:-1GB}"

# Parallelism, bounded by the cores actually present.
PAR=$(( CPUS > 8 ? 8 : CPUS )); (( PAR < 1 )) && PAR=1

# SSD/NVMe assumptions. Spinning disks would want random_page_cost 4 and io_concurrency 2 —
# override IR_PG_RANDOM_PAGE_COST if the enclave stores on rust.
RPC="${IR_PG_RANDOM_PAGE_COST:-1.1}"
IOC="${IR_PG_IO_CONCURRENCY:-200}"

echo "[pg-tune] ${TOTAL_MB}MB / ${CPUS} cpu -> shared_buffers=$(mb ${SHARED}) effective_cache_size=$(mb ${CACHE}) work_mem=$(mb ${WORK}) maintenance_work_mem=$(mb ${MAINT}) parallel=${PAR}"

exec docker-entrypoint.sh postgres \
    -c "listen_addresses=${IR_DB_LISTEN:-0.0.0.0}" \
    -c "shared_buffers=${IR_PG_SHARED_BUFFERS:-$(mb ${SHARED})}" \
    -c "effective_cache_size=${IR_PG_CACHE_SIZE:-$(mb ${CACHE})}" \
    -c "work_mem=${IR_PG_WORK_MEM:-$(mb ${WORK})}" \
    -c "maintenance_work_mem=${IR_PG_MAINT_MEM:-$(mb ${MAINT})}" \
    -c "max_connections=${MAXCONN}" \
    -c "max_wal_size=${MAXWAL}" \
    -c "min_wal_size=${MINWAL}" \
    -c "checkpoint_completion_target=0.9" \
    -c "wal_compression=on" \
    -c "random_page_cost=${RPC}" \
    -c "effective_io_concurrency=${IOC}" \
    -c "max_worker_processes=${PAR}" \
    -c "max_parallel_workers=${PAR}" \
    -c "max_parallel_workers_per_gather=$(( PAR / 2 > 0 ? PAR / 2 : 1 ))" \
    -c "jit=off" \
    "$@"
