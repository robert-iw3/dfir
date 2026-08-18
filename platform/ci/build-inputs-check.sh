#!/usr/bin/env bash
# Verify every image build's inputs resolve, without building anything. A path that stopped
# resolving after a tree move is otherwise found by starting a multi-minute build and watching
# it die part-way.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"

rc=0
for build in "${PLATFORM}/collector/build.sh" "${PLATFORM}/backend/build_worker.sh"; do
    if IR_BUILD_CHECK_ONLY=1 bash "${build}"; then
        :
    else
        rc=1
    fi
done

# A network fetch inside a Dockerfile must verify what it received. The enclave has no egress
# at run time, so everything an image carries was decided at BUILD time on a machine that did
# — which makes the build the supply chain, and an unverified download the way something else
# gets in. Checked here rather than trusted, because the last one was closed with `|| true`
# and silently shipped an image with the tool missing.
echo
echo "== Network fetches in Dockerfiles verify what they download"
unverified=0
while IFS= read -r df; do
    [[ -f "${df}" ]] || continue
    # A fetching RUN block is a finding unless the same block also checks a digest.
    awk -v file="${df##*/}" '
        /^[[:space:]]*RUN/ { blk = ""; inblk = 1 }
        inblk { blk = blk $0 }
        inblk && !/\\[[:space:]]*$/ {
            inblk = 0
            if (blk ~ /(curl|wget)[^|]*https?:\/\// &&
                blk !~ /sha256sum|sha512sum|gpg --verify|--require-hashes/) {
                print "  UNVERIFIED  " file ": " substr(blk, 1, 90)
                bad = 1
            }
        }
        END { exit bad ? 1 : 0 }' "${df}" || unverified=1
done < <(find "${PLATFORM}" -name 'Dockerfile*' -not -path '*/node_modules/*' 2>/dev/null)
if (( unverified )); then
    echo "  a Dockerfile downloads something it does not verify"
    rc=1
else
    echo "  every network fetch checks a digest"
fi

exit "${rc}"
