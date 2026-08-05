#!/usr/bin/env bash
# ==============================================================================
# Run the UAT suite against the RUNNING deployment, one at a time, in stage order.
#
#   ./test/run_uats.sh                 # everything whose tiers are up
#   ./test/run_uats.sh --only corpus,ui
#   ./test/run_uats.sh --list
#
# SEQUENTIAL BY DESIGN. These act on a live deployment — they rotate credentials,
# recreate containers, register services and open brokered sessions. Two of them at
# once do not merely interleave output: one reaps the workers another is using, and
# the failure surfaces in whichever happened to look second.
#
# A UAT whose tiers are absent is SKIPPED and named, never silently passed. "17 of 17
# green" is only worth something if the ones that did not run are visible.
# ==============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"
RUNTIME="${IR_RUNTIME:-podman}"

# Stage order, cheapest and most foundational first: a resolver fault explains a mesh
# fault, so finding it second wastes the run. Each entry is `name:required-containers`.
SUITE=(
    "dns:ir-dmz_coredns_1 ir-enclave_coredns_1"
    "tailnet:ir-dmz_headscale_1 ir-workstation_tailnet_1"
    "boundary:ir-enclave_boundary_1 ir-dmz_broker_1"
    "consul:ir-enclave_consul_1"
    "mesh_multihost:ir-enclave_consul_1"
    "vault:ir-enclave_vault_1"
    "repairs:ir-agent_remediation-agent_1"
    "schema:ir-enclave_backend_1"
    "keycloak_db:ir-enclave_keycloak_1"
    "baseline:ir-enclave_backend_1 ir-dmz_receiver_1"
    "srg_webtier:ir-enclave_traefik_1"
    "corpus:ir-enclave_worker_1 ir-dmz_receiver_1"
    "ui:ir-enclave_backend_1"
    "re_workstation:ir-enclave_backend_1"
    "memory_analysis:ir-enclave_worker_1"
    "full_stack:ir-workstation_browser_1 ir-dmz_receiver_1"
    "e2e:ir-enclave_worker_1 ir-dmz_receiver_1"
)

ONLY=""
LIST=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --only) ONLY="$2"; shift 2 ;;
        --list) LIST=1; shift ;;
        *) echo "unknown option $1" >&2; exit 2 ;;
    esac
done

if (( LIST )); then
    printf '%s\n' "${SUITE[@]}" | cut -d: -f1
    exit 0
fi

say() { printf '\n\033[1;36m========== %s\033[0m\n' "$*"; }
LOGDIR="${PLATFORM}/test/logs"; mkdir -p "${LOGDIR}"

PASSED=(); FAILED=(); SKIPPED=()
START_ALL=$(date +%s)

for entry in "${SUITE[@]}"; do
    name="${entry%%:*}"; needs="${entry#*:}"
    script="${PLATFORM}/test/uat_${name}.sh"

    if [[ -n "${ONLY}" ]] && [[ ",${ONLY}," != *",${name},"* ]]; then continue; fi
    [[ -x "${script}" || -f "${script}" ]] || { SKIPPED+=("${name} (no script)"); continue; }

    missing=""
    for c in ${needs}; do
        [[ "$(${RUNTIME} inspect "$c" --format '{{.State.Status}}' 2>/dev/null)" == "running" ]] \
            || missing="${missing} ${c}"
    done
    if [[ -n "${missing}" ]]; then
        SKIPPED+=("${name} — not running:${missing}")
        printf '\033[1;33m  SKIP %s — not running:%s\033[0m\n' "${name}" "${missing}"
        continue
    fi

    say "uat_${name}.sh"
    t0=$(date +%s)
    # KEEP_UP so a suite run leaves the deployment standing for the next UAT. Without it
    # uat_full_stack tears the stack down and everything after it skips on absent tiers.
    KEEP_UP=1 bash "${script}" > "${LOGDIR}/uat_${name}.log" 2>&1
    rc=$?
    took=$(( $(date +%s) - t0 ))
    # `grep -c` already prints 0 when nothing matches AND exits 1, so a `|| echo 0`
    # fallback appends a SECOND line and every later comparison sees "0\n0". `tail -1`
    # keeps one line and masks the exit status, which is the only failure mode here.
    p="$(grep -c '^  .*PASS' "${LOGDIR}/uat_${name}.log" 2>/dev/null | tail -1)"
    f="$(grep -c '^  .*FAIL' "${LOGDIR}/uat_${name}.log" 2>/dev/null | tail -1)"
    if [[ "${p:-0}" -eq 0 ]]; then
        # A run that asserted NOTHING neither passed nor failed, whatever it exited with, and
        # both directions of that mistake are misleading. `uat_mesh_multihost` exits 0 on a
        # single-host deployment and would inflate the green count; `uat_memory_analysis`
        # exits non-zero without a capture to analyze and would inflate the red one. Neither
        # measured anything. The reason line is carried so "did not run" stays distinguishable
        # from "ran and was fine".
        why="$(sed -e 's/\x1b\[[0-9;]*m//g' "${LOGDIR}/uat_${name}.log" \
               | grep -vE '^\s*$|^!!|^\s{3}' | tail -3 | head -1 || true)"
        SKIPPED+=("${name} — asserted nothing: ${why:-no output}")
        printf '\033[1;33m  N/A  %s — 0 assertions (rc=%s): %s\033[0m\n' "${name}" "${rc}" "${why}"
    elif [[ "$rc" -eq 0 ]]; then
        PASSED+=("${name} (${p} assertions, ${took}s)")
        printf '\033[1;32m  PASS %s — %s assertions in %ss\033[0m\n' "${name}" "${p}" "${took}"
    else
        FAILED+=("${name} (${f} failed, ${took}s)")
        printf '\033[1;31m  FAIL %s — %s failed in %ss\033[0m\n' "${name}" "${f}" "${took}"
        grep '^  .*FAIL' "${LOGDIR}/uat_${name}.log" 2>/dev/null | head -6 | sed 's/^/       /'
    fi
done

say "Suite result — $(( $(date +%s) - START_ALL ))s"
printf '\033[1;32mPASSED (%s)\033[0m\n' "${#PASSED[@]}";  printf '  %s\n' "${PASSED[@]:-none}"
printf '\033[1;33mSKIPPED (%s)\033[0m\n' "${#SKIPPED[@]}"; printf '  %s\n' "${SKIPPED[@]:-none}"
printf '\033[1;31mFAILED (%s)\033[0m\n' "${#FAILED[@]}";  printf '  %s\n' "${FAILED[@]:-none}"
printf '\nReports: test/results/UAT-REPORT.md   Logs: test/logs/\n'
[[ "${#FAILED[@]}" -eq 0 ]]
