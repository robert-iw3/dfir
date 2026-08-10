#!/usr/bin/env bash
# ==============================================================================
# CLOCK SYNCHRONIZATION — SRG-APP-000920-WSR-000320, SRG-APP-000925-WSR-000330.
#
# Containers inherit the host clock; there is no per-container time source and none should be
# added. So the web tier's clock is the HOST's clock, and the control is satisfied by the host
# being synchronized to an authoritative source — which the platform previously assumed and
# never asserted.
#
# It matters here more than on an ordinary web tier. Every custody seal, audit row, correlation
# window and certificate lifetime is a timestamp, and `temporal_coherence` compares instants
# ACROSS hosts: a collector whose clock is wrong does not produce a wrong-looking record, it
# produces a plausible one in the wrong place on the timeline.
#
#   ci/clock-sync-check.sh            # assert and report
#   ci/clock-sync-check.sh --quiet    # exit status only
#
# ENCLAVE NOTE. The enclave has no egress, so a public pool is unreachable by design. The
# authoritative source there is an internal stratum server, named by IR_NTP_SERVER, and host
# preparation points systemd-timesyncd or chrony at it. This script asserts the RESULT —
# synchronized, and agreeing with the containers — rather than the mechanism, so it holds for
# either daemon and for an internal source as readily as a public one.
# ==============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"
RUNTIME="${IR_RUNTIME:-podman}"
QUIET=0
[[ "${1:-}" == "--quiet" ]] && QUIET=1

# Seconds of drift between host and container that still counts as agreement. Generous: the
# check is for a clock that is WRONG, not one that is a scheduling quantum behind.
TOLERANCE="${IR_CLOCK_TOLERANCE:-5}"

RC=0
ok()   { (( QUIET )) || printf '  \033[1;32m✔\033[0m %s\n' "$*"; }
bad()  { (( QUIET )) || printf '  \033[1;31m✘\033[0m %s\n' "$*"; RC=1; }
info() { (( QUIET )) || printf '  \033[0;37m%s\033[0m\n' "$*"; }
say()  { (( QUIET )) || printf '\n\033[1;36m== %s\033[0m\n' "$*"; }

say "Host clock is synchronized to an authoritative source"

if command -v timedatectl >/dev/null 2>&1; then
    NTP_ENABLED="$(timedatectl show -p NTP --value 2>/dev/null)"
    NTP_SYNCED="$(timedatectl show -p NTPSynchronized --value 2>/dev/null)"
    [[ "${NTP_ENABLED}" == "yes" ]] \
        && ok "time synchronization is enabled on the host" \
        || bad "time synchronization is DISABLED — every custody seal and audit timestamp is unanchored"
    # Enabled and synchronized are different claims: a daemon that is running but has never
    # reached a server reports the first and not the second, and the clock is still free-running.
    [[ "${NTP_SYNCED}" == "yes" ]] \
        && ok "the host clock has actually synchronized (not merely configured to)" \
        || bad "the host clock is NOT synchronized — the daemon is enabled but has not reached a source"

    # The source is reported by NAME and stratum. The address it resolved to is deliberately
    # not recorded: these reports are published.
    SRC="$(timedatectl timesync-status 2>/dev/null | awk -F'[()]' '/Server:/ {print $2}')"
    STRATUM="$(timedatectl timesync-status 2>/dev/null | awk -F': *' '/Stratum:/ {print $2}')"
    [[ -n "${SRC}" ]] && info "source: ${SRC}${STRATUM:+ (stratum ${STRATUM})}" \
                      || info "source: not reported by timesync-status (chrony or ntpd may be in use)"
elif command -v chronyc >/dev/null 2>&1; then
    LEAP="$(chronyc tracking 2>/dev/null | awk -F': *' '/Leap status/ {print $2}')"
    [[ "${LEAP}" == "Normal" ]] \
        && ok "chrony reports the clock synchronized (leap status normal)" \
        || bad "chrony leap status is '${LEAP:-unknown}' — the clock is not disciplined"
    info "source: $(chronyc tracking 2>/dev/null | awk -F': *' '/Reference ID/ {print $2}' | cut -d' ' -f2-)"
else
    bad "no time-synchronization daemon found (timedatectl, chronyc) — cannot establish clock provenance"
fi

# ---------------------------------------------------------------------------------------
say "Containers agree with the host they inherit it from"

# The claim "containers inherit the host clock" is the reason a per-container time source is
# not configured. It is cheap to test and has never been tested; a container started with a
# frozen or offset clock would timestamp evidence wrongly while every host-level check passed.
CONTAINER="$(${RUNTIME} ps --format '{{.Names}}' 2>/dev/null | grep -m1 '^ir-enclave_backend_1$' || true)"
if [[ -z "${CONTAINER}" ]]; then
    info "no running enclave backend — container clock agreement not evaluated"
else
    HOST_EPOCH="$(date +%s)"
    CONT_EPOCH="$(${RUNTIME} exec "${CONTAINER}" date +%s 2>/dev/null)"
    if [[ -z "${CONT_EPOCH}" ]]; then
        bad "could not read the clock inside ${CONTAINER}"
    else
        DRIFT=$(( HOST_EPOCH > CONT_EPOCH ? HOST_EPOCH - CONT_EPOCH : CONT_EPOCH - HOST_EPOCH ))
        [[ "${DRIFT}" -le "${TOLERANCE}" ]] \
            && ok "${CONTAINER} is within ${DRIFT}s of the host (tolerance ${TOLERANCE}s)" \
            || bad "${CONTAINER} is ${DRIFT}s from the host — containers are NOT inheriting the clock"
    fi
fi

# ---------------------------------------------------------------------------------------
say "The enclave serves its own time"

# `internal: true` installs no route off the host, so a public pool is unreachable by design.
# The enclave runs its own chrony, and the enclave HOSTS discipline against it.
NTPC="$(${RUNTIME} ps --format '{{.Names}}' 2>/dev/null | grep -m1 'ir-enclave_ntp_1' || true)"
if [[ -z "${NTPC}" ]]; then
    info "enclave time service not running — not evaluated"
else
    TRACK="$(${RUNTIME} exec "${NTPC}" chronyc -n tracking 2>/dev/null)"
    STRAT="$(printf '%s' "${TRACK}" | awk -F': *' '/^Stratum/ {print $2}')"
    if [[ -z "${STRAT}" ]]; then
        bad "${NTPC} is running but does not answer chronyc — it is not serving"
    elif [[ "${STRAT}" == "10" ]]; then
        # Serving, but from its own local reference. The segment agrees with itself and is not
        # traceable to anything. Reported rather than failed: an air-gapped enclave is the
        # designed case, and a check that fails on it would be turned off.
        info "serving at stratum 10 — LOCAL reference, no traceable source (IR_NTP_UPSTREAM unset)"
        ok "the enclave has a time authority, so its hosts can agree with each other"
    else
        ok "serving at stratum ${STRAT} — disciplined by a traceable upstream"
    fi

    # SRG-APP-000925 asks for comparison against an authoritative source. When a deployment
    # names one, reaching it is the claim, and an unreachable upstream must not read the same
    # as a deliberate air gap.
    if [[ -n "${IR_NTP_UPSTREAM:-}" ]]; then
        [[ -n "${STRAT}" && "${STRAT}" != "10" ]] \
            && ok "the configured upstream (${IR_NTP_UPSTREAM}) is being reached" \
            || bad "IR_NTP_UPSTREAM names ${IR_NTP_UPSTREAM} but the service is not disciplined by it"
    fi
fi

(( QUIET )) || { say "Result"; [[ ${RC} -eq 0 ]] \
    && printf '  \033[1;32mclock provenance established\033[0m\n\n' \
    || printf '  \033[1;31mclock provenance NOT established\033[0m\n\n'; }
exit ${RC}
