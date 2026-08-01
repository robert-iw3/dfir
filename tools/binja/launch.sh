#!/usr/bin/env bash
# Binary Ninja launcher — kept as the path people and docs already know.
#
# The launcher itself lives one level up, at tools/re-launch.sh, and drives BOTH frameworks. The
# isolation flags are the part that must not drift between them, and they are the part nobody
# re-reads; two copies would diverge exactly there.
#
#   ./launch.sh [args]                 identical to before
#   ../re-launch.sh --tool ghidra      the same regions, in Ghidra
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/re-launch.sh" --tool binja "$@"
