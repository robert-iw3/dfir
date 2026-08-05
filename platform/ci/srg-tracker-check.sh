#!/usr/bin/env bash
# Fails when the SRG tracker is stale, or a control has no determination — an unassessed
# requirement must never read as "nothing to do".
#   python3 platform/artifacts/gen_srg_tracker.py
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "${HERE}/../artifacts/gen_srg_tracker.py" --check
