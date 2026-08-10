#!/usr/bin/env bash
# ==============================================================================
# BASE IMAGE PINNING — every FROM names a digest, and the digest is recorded.
#
# SRG-APP-000131-WSR-000051. A tag is a mutable pointer: `alpine:3.24` is whatever the
# registry decides it is on the day of the build, so two builds of the same source produce
# different images and neither can be said to be the one that was reviewed. A digest is the
# content, so pulling by digest IS the integrity check — podman refuses content that does not
# hash to the name it was asked for. There is nothing further to verify at build time.
#
# The lock is the record the control asks for: what each tag resolved to, and when.
#
#   ci/pin-base-images.sh --check    # every external FROM carries a digest, and it matches
#   ci/pin-base-images.sh --update   # re-resolve each tag and rewrite the lock
#   ci/pin-base-images.sh --apply    # rewrite the Dockerfiles to the locked digests
#
# `--update` reaches the registry and MOVES THE PINS. It is the deliberate act of accepting
# new upstream content; run it when `ci/image-currency.sh` reports drift, then rebuild and run
# the suite. `--check` reaches nothing and is safe in CI.
#
# Deliberately NOT pinned, and why:
#   symbols/Dockerfile.debian   BASE_IMAGE is the distro whose symbols are being fetched. The
#                               parameter is the feature; pinning it would defeat it.
# ==============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"
LOCK="${HERE}/base-images.lock"
RUNTIME="${IR_RUNTIME:-podman}"

MODE="${1:---check}"

ok()   { printf '  \033[1;32m✔\033[0m %s\n' "$*"; }
bad()  { printf '  \033[1;31m✘\033[0m %s\n' "$*"; }
info() { printf '  \033[0;37m%s\033[0m\n' "$*"; }
say()  { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }

# Every external base this tree builds on. Stage references (`FROM deps`), `scratch` and the
# parameterized distro base are not upstream content and carry no digest.
#
# Listed rather than scraped: a scrape reads what the Dockerfiles SAY, and the point of the
# check is to catch a Dockerfile that says something new. The list is the intent; the scrape
# below is the reality; `--check` compares them and a base added without being declared is a
# finding rather than a silent pass.
BASES=(
    docker.io/library/alpine:3.24
    docker.io/library/debian:12
    docker.io/library/debian:13
    docker.io/library/node:lts-slim
    docker.io/hashicorp/consul:2.0.2
    docker.io/envoyproxy/envoy:v1.38.0
    quay.io/keycloak/keycloak:26.7.0
    quay.io/podman/stable:latest
)

# Bases whose tag is assembled from build arguments. They are RECORDED in the lock — the
# control asks for a manifest, and "what did the toolchain resolve to" is part of it — but not
# rewritten inline, because the argument is the point: `build.sh` passes RUST_VERSION from
# rust-toolchain.toml so the two cannot drift, and hard-coding a digest here would silently
# win over that file.
RECORDED=(
    docker.io/library/rust:1.97.1-alpine3.24
)

# Reads the index digest — what the registry returned for the TAG — not the per-architecture
# manifest under it. `.Digest` gives the latter and would pin this build to this machine's
# architecture.
resolve() {
    local ref="$1" d
    d="$(${RUNTIME} image inspect "$ref" --format '{{index .RepoDigests 0}}' 2>/dev/null)"
    if [[ -z "$d" ]]; then
        ${RUNTIME} pull -q "$ref" >/dev/null 2>&1 || return 1
        d="$(${RUNTIME} image inspect "$ref" --format '{{index .RepoDigests 0}}' 2>/dev/null)"
    fi
    [[ -n "$d" ]] || return 1
    printf '%s' "${d##*@}"
}

# Every FROM that names upstream content, as (file:line, ref) — stage aliases and scratch
# excluded. `${BASE_IMAGE}` is the parameterized distro base and is excluded by name.
scrape() {
    grep -rn '^FROM ' --include='Dockerfile*' "${PLATFORM}" 2>/dev/null \
      | sed 's|^'"${PLATFORM}"'/||' \
      | awk '{ loc=$1; sub(/^[^:]*:[^:]*:/,"",$0); ref=$2;
               if (ref ~ /^scratch$/ || ref ~ /\$\{/) next;
               print loc, ref }' \
      | while read -r loc ref; do
            # A bare stage alias (FROM deps, FROM toolchain) has no registry component.
            [[ "$ref" == *.*/* || "$ref" == *:* ]] || continue
            printf '%s %s\n' "$loc" "$ref"
        done
}

lock_digest() { awk -v r="$1" '$1==r {print $2}' "$LOCK" 2>/dev/null; }

case "$MODE" in
--update)
    say "Resolving $(( ${#BASES[@]} + ${#RECORDED[@]} )) base images from the registry"
    tmp="$(mktemp)"
    {   printf '# Base image manifest — SRG-APP-000131-WSR-000051.\n'
        printf '# What each tag resolved to, and when. Regenerate with:\n'
        printf '#   ci/pin-base-images.sh --update && ci/pin-base-images.sh --apply\n'
        printf '# Resolved: %s\n\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    } > "$tmp"
    rc=0
    for ref in "${BASES[@]}" "${RECORDED[@]}"; do
        if d="$(resolve "$ref")"; then
            printf '%s %s\n' "$ref" "$d" >> "$tmp"
            ok "${ref}  ${d}"
        else
            bad "${ref} — could not resolve"
            rc=1
        fi
    done
    [[ $rc -eq 0 ]] && mv "$tmp" "$LOCK" && ok "wrote ${LOCK#"${PLATFORM}/"}" || rm -f "$tmp"
    exit $rc
    ;;

--apply)
    [[ -f "$LOCK" ]] || { bad "no lock — run --update first"; exit 1; }
    say "Rewriting FROM lines to the locked digests"
    changed=0
    while read -r ref d; do
        [[ "$ref" == \#* || -z "$ref" ]] && continue
        # Match the ref with or without an existing digest, keeping any `AS stage` suffix.
        while IFS= read -r f; do
            python3 - "$f" "$ref" "$d" <<'PY'
import re, sys
path, ref, digest = sys.argv[1], sys.argv[2], sys.argv[3]
src = open(path).read()
pat = re.compile(r'^(FROM\s+)' + re.escape(ref) + r'(@sha256:[0-9a-f]{64})?(\s.*)?$', re.M)
new, n = pat.subn(lambda m: f"{m.group(1)}{ref}@{digest}{m.group(3) or ''}", src)
if n and new != src:
    open(path, 'w').write(new)
    print(f"  updated {path} ({n})")
PY
        done < <(grep -rl "^FROM ${ref}" --include='Dockerfile*' "${PLATFORM}" 2>/dev/null)
        changed=$((changed+1))
    done < "$LOCK"
    ok "applied ${changed} pin(s)"
    exit 0
    ;;

--check)
    [[ -f "$LOCK" ]] || { bad "no lock at ${LOCK#"${PLATFORM}/"} — run --update"; exit 1; }
    say "Base images are pinned by digest, and the digest matches the lock"
    rc=0
    # Resolved ONCE. `scrape | grep -q` closes the pipe on the first match, the writer takes
    # SIGPIPE, and `set -o pipefail` turns that into a failed pipeline — which reads exactly
    # like "no match". Every base then reports as unused. Same defect as the one corrected in
    # `uat_consul.sh`; capture, then match.
    FOUND="$(scrape)"

    # 1. Every scraped FROM carries a digest and it is the locked one.
    while read -r loc ref; do
        base="${ref%@*}"
        want="$(lock_digest "$base")"
        if [[ "$ref" != *@sha256:* ]]; then
            bad "${loc}: ${ref} is pinned by TAG — the content it names can change under it"
            rc=1
        elif [[ -z "$want" ]]; then
            bad "${loc}: ${base} carries a digest but is not in the lock — undeclared base"
            rc=1
        elif [[ "${ref##*@}" != "$want" ]]; then
            bad "${loc}: ${base} pinned to ${ref##*@}, lock says ${want}"
            rc=1
        fi
    done <<< "$FOUND"

    # 2. Every declared base is actually used — a lock entry nobody builds on is a stale
    #    record, and a record describing something absent is worse than no record.
    for ref in "${BASES[@]}"; do
        case "$FOUND" in
            *" ${ref}@"*) ;;
            *) bad "${ref} is declared and locked but no Dockerfile builds on it"; rc=1 ;;
        esac
    done

    [[ $rc -eq 0 ]] && ok "$(printf '%s\n' "$FOUND" | wc -l) FROM line(s) pinned by digest against ${#BASES[@]} locked base(s), ${#RECORDED[@]} recorded"
    exit $rc
    ;;
*)
    bad "usage: $0 [--check|--update|--apply]"; exit 2 ;;
esac
