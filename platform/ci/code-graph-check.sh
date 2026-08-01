#!/usr/bin/env bash
# Fails when CODE_GRAPH.md / code_graph.json are stale — new logic must regenerate them:
#   python3 gen_code_graph.py
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "${HERE}/../gen_code_graph.py" --check
