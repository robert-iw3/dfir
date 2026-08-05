#!/usr/bin/env bash
# ==============================================================================
# Build the field collector and place the artifact on this host.
#
#   ./build.sh              build and export to dist/ir-collect
#   ./build.sh --check      typecheck and lint; produces no artifact
#   ./build.sh --lock       resolve dependencies and write Cargo.lock here
#   ./build.sh --verify     rebuild and require the hash to match dist/ir-collect.sha256
#
# Built in a container because the toolchain is not a host dependency — the same rule the
# platform applies to every other build. The OUTPUT is what lands on the host: a single
# statically linked binary with no runtime, because the endpoints this is deployed to have
# no container runtime and no interpreter.
#
# The hash is recorded beside the artifact. It is what an operator checks before pushing to an
# endpoint, and what the platform records against the collection — the endpoint cannot vouch
# for what ran on it, so the verification happens here.
# ==============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNTIME="${IR_RUNTIME:-podman}"
IMAGE="localhost/ir-collect-build:latest"
DIST="${HERE}/dist"
ART="${DIST}/ir-collect"
LOCK="${HERE}/Cargo.lock"
MODE="${1:-build}"

say()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '    \033[1;32m✔\033[0m %s\n' "$*"; }
warn() { printf '    \033[1;33m!\033[0m %s\n' "$*"; }
die()  { printf '    \033[1;31m✘\033[0m %s\n' "$*" >&2; exit 1; }

# rust-toolchain.toml is the single source of truth for the compiler version. Passing it as the
# base image tag means the container cannot be built with anything else.
CHANNEL="$(sed -n 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' \
    "${HERE}/rust-toolchain.toml")"
[[ -n "${CHANNEL}" ]] || die "no [toolchain].channel in rust-toolchain.toml"

# --locked only once a lockfile exists; the run that creates it cannot demand it.
LOCKED=""
[[ -f "${LOCK}" ]] && LOCKED="--locked"

build_stage() {  # stage, output-dest ("" for none)
    local stage="$1" dest="${2:-}"
    local -a cmd=("${RUNTIME}" build --target "${stage}"
        --build-arg "RUST_VERSION=${CHANNEL}"
        --build-arg "CARGO_LOCKED=${LOCKED}")
    [[ -n "${dest}" ]] && cmd+=(-o "type=local,dest=${dest}")
    cmd+=(-t "${IMAGE}" "${HERE}")
    "${cmd[@]}"
}

case "${MODE}" in
--lock)
    say "Resolving dependencies with Rust ${CHANNEL}"
    TMP="$(mktemp -d)"
    trap 'rm -rf "${TMP}"' EXIT
    # Resolution is what produces the lockfile, so it cannot be asked to honor one.
    LOCKED=""
    build_stage lock "${TMP}" || die "dependency resolution failed"
    [[ -f "${TMP}/Cargo.lock" ]] || die "no Cargo.lock produced"
    if [[ -f "${LOCK}" ]] && cmp -s "${TMP}/Cargo.lock" "${LOCK}"; then
        ok "Cargo.lock unchanged"
    else
        cp "${TMP}/Cargo.lock" "${LOCK}"
        ok "wrote ${LOCK} — commit it; the recorded artifact hash means nothing without it"
    fi
    exit 0
    ;;
--check)
    say "Typechecking and linting with Rust ${CHANNEL}"
    build_stage check || die "check failed"
    ok "cargo check, clippy and rustfmt all clean"
    exit 0
    ;;
--verify|build) ;;
*) die "unknown mode: ${MODE}" ;;
esac

[[ -f "${LOCK}" ]] || warn "no Cargo.lock — run ./build.sh --lock first, or this build is not reproducible"

mkdir -p "${DIST}"

say "Building the field collector (static, musl, Rust ${CHANNEL})"
build_stage artifact "${DIST}" || die "build failed"
[[ -f "${ART}" ]] || die "no artifact at ${ART}"
chmod 0755 "${ART}"

# Proven, not assumed: a dynamically linked artifact would fail on the endpoints this exists
# for, and the failure would land mid-incident on a machine we do not control.
if command -v file >/dev/null 2>&1; then
    file "${ART}" | grep -q 'statically linked' \
        && ok "statically linked — no loader needed on the endpoint" \
        || die "artifact is NOT statically linked"
fi
if command -v ldd >/dev/null 2>&1; then
    ldd "${ART}" 2>&1 | grep -qE 'not a dynamic executable|statically linked' \
        && ok "no dynamic dependencies" \
        || die "artifact reports dynamic dependencies"
fi

SIZE="$(stat -c %s "${ART}")"
HASH="$(sha256sum "${ART}" | cut -d' ' -f1)"

if [[ "${MODE}" == "--verify" ]]; then
    PRIOR="$(cut -d' ' -f1 < "${ART}.sha256" 2>/dev/null || true)"
    [[ -n "${PRIOR}" ]] || die "no recorded hash to verify against"
    [[ "${HASH}" == "${PRIOR}" ]] \
        && ok "reproducible — hash matches the recorded artifact" \
        || die "hash CHANGED: recorded ${PRIOR}, built ${HASH}"
else
    printf '%s  ir-collect\n' "${HASH}" > "${ART}.sha256"
fi

ok "artifact: ${ART} ($(numfmt --to=iec "${SIZE}" 2>/dev/null || echo "${SIZE} bytes"))"
ok "sha256:   ${HASH}"
printf '\n    Check this hash before deploying. The endpoint cannot vouch for what ran on it.\n\n'
