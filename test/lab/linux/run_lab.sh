#!/usr/bin/env bash
# ==============================================================================
# Linux endpoint lab — run the REAL collection against planted artifacts.
#
#   ./run_lab.sh                        every scenario, the profile that SHIPS
#   ./run_lab.sh novice_persistence     one scenario
#   ./run_lab.sh --shallow              without --deep, the profile that shipped before
#   ./run_lab.sh --compare              each scenario BOTH ways, side by side
#   ./run_lab.sh --distro=fedora        run against an RPM endpoint
#
# The endpoint is a disposable container. The toolkit is mounted read-only from the working
# tree, so the lab always exercises the code being edited and never a copy baked into an
# image. The host is not touched: every artifact is planted inside the container, and the
# container is removed when the run ends.
#
# --compare is the measurement that decided the collection profile. Running the same scenario
# both ways prints exactly which evidence `--deep` is responsible for — a number rather than an
# argument. It is kept after the fix, not retired with it: it is the regression evidence, and
# the day someone drops --deep again this is what says what it cost.
# ==============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLKIT="$(cd "${HERE}/../../.." && pwd)"
RUNTIME="${IR_RUNTIME:-podman}"
# The endpoint's distro. The toolkit's trust anchor is package ownership and integrity, and
# `pkg_modified()` branches per package manager — debsums, `rpm -Vf`, `pacman -Qkk`. A branch
# that never runs is a trust anchor nobody has weighed, so the distro is a dimension of the
# lab rather than a fixed choice.
DISTRO="${IR_LAB_DISTRO:-debian}"

say()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '    \033[1;32m✔\033[0m %s\n' "$*"; }
bad()  { printf '    \033[1;31m✘\033[0m %s\n' "$*"; }
die()  { bad "$*"; exit 1; }

# Default is the profile the platform's collector actually passes. The lab measures what
# ships, not a configuration nobody runs.
DEEP=1; COMPARE=0; ONLY=""
for a in "$@"; do
    case "$a" in
        --shallow)   DEEP=0 ;;
        --compare)   COMPARE=1 ;;
        --distro=*)  DISTRO="${a#*=}" ;;
        -*)          die "unknown option $a" ;;
        *)           ONLY="$a" ;;
    esac
done
DOCKERFILE="${HERE}/Dockerfile.${DISTRO}"
[[ -f "${DOCKERFILE}" ]] || die "no endpoint image for distro '${DISTRO}' (${DOCKERFILE})"
IMAGE="localhost/ir-lab-linux-${DISTRO}:latest"

SCENARIOS=()
if [[ -n "${ONLY}" ]]; then
    f="${HERE}/scenarios/${ONLY}.json"
    [[ -f "$f" ]] || die "no scenario ${ONLY} (looked for $f)"
    SCENARIOS=("$f")
else
    while IFS= read -r f; do SCENARIOS+=("$f"); done \
        < <(find "${HERE}/scenarios" -name '*.json' | sort)
fi
(( ${#SCENARIOS[@]} )) || die "no scenarios found"

say "Building the endpoint image (${DISTRO})"
${RUNTIME} build -q -f "${DOCKERFILE}" -t "${IMAGE}" "${HERE}" >/dev/null 2>&1 \
    && ok "endpoint image ready (${DISTRO})" || die "could not build the ${DISTRO} endpoint image"

# One scenario, one profile, in a fresh container.
#
# --cap-add is deliberately narrow rather than --privileged: the lab should reflect what a
# collector can see with the privileges it is actually given, and a plant that cannot run
# under them is reported SKIPPED rather than quietly passing.
run_one() {  # scenario-file  deep(0|1)
    local scen="$1" deep="$2" name profile args=()
    name="$(basename "${scen}" .json)"
    profile=$([[ "$deep" == "1" ]] && echo "ships today" || echo "without --deep")
    [[ "$deep" == "1" ]] && args=(--deep)

    printf '\n\033[1;35m--- %s [%s profile] ---\033[0m\n' "${name}" "${profile}"
    ${RUNTIME} run --rm \
        --cap-add LINUX_IMMUTABLE --cap-add SYS_PTRACE --cap-add DAC_READ_SEARCH \
        --security-opt label=disable \
        -v "${TOOLKIT}:/toolkit:ro" \
        -e IR_TOOLKIT=/toolkit \
        -e IR_HOSTNAME="ir-lab-${name}" \
        "${IMAGE}" bash -c "
            set -u
            python3 /toolkit/test/lab/linux/lab.py plant   '/toolkit/test/lab/linux/scenarios/$(basename "${scen}")'
            python3 /toolkit/test/lab/linux/lab.py collect '/toolkit/test/lab/linux/scenarios/$(basename "${scen}")' /out ${args[*]:-} >/dev/null
            echo
            python3 /toolkit/test/lab/linux/lab.py verify  '/toolkit/test/lab/linux/scenarios/$(basename "${scen}")' /out
        "
    return $?
}

FAILED=0
for scen in "${SCENARIOS[@]}"; do
    if [[ "${COMPARE}" == "1" ]]; then
        run_one "${scen}" 0 || FAILED=1
        run_one "${scen}" 1 || FAILED=1
    else
        run_one "${scen}" "${DEEP}" || FAILED=1
    fi
done

say "Result"
if [[ "${FAILED}" == "0" ]]; then
    ok "every planted artifact was recovered by the collection"
else
    bad "the collection did not recover everything planted — see the FAIL lines above"
    printf '    \033[0;37mA FAIL here is a collection gap, not a broken test: the artifact was\n'
    printf '    demonstrably on the endpoint and the collection did not bring it back.\033[0m\n'
fi
exit "${FAILED}"
