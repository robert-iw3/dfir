#!/usr/bin/env bash
# Fails when CODE_GRAPH.md / code_graph.json are stale — new logic must regenerate them:
#   python3 gen_code_graph.py
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# The generator sits at the TREE ROOT, above platform/, because it walks the platform and the
# toolkit together. `${HERE}/..` is platform/ and resolved to a path that has never existed, so
# this gate reported "can't open file" and exited non-zero on every run — a check that fails
# identically whether the graph is stale or the checker is broken proves nothing either way.
GEN="${HERE}/../../gen_code_graph.py"
[[ -f "${GEN}" ]] || { echo "code graph generator not found at ${GEN}" >&2; exit 2; }
exec python3 "${GEN}" --check
