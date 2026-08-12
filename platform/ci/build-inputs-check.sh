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
exit "${rc}"
