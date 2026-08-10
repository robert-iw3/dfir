#!/usr/bin/env bash
# ==============================================================================
# DOCUMENTATION INTEGRITY — the references in the docs still resolve, and every
# document is accounted for in the change-management inventory.
#
# Documentation drift is silent: nothing fails and no gate turns red. The only symptom is a
# reader following a link that goes nowhere, or trusting a diagram of a hop the system no
# longer takes.
#
#   BROKEN LINK        a relative link whose target does not exist — what a tree move leaves
#                      behind in every document that referenced the moved file.
#
#   UNINVENTORIED DOC  a document absent from CHANGE-MANAGEMENT.md §4. That inventory is the
#                      list a change is reconciled against, so a document missing from it is
#                      invisible to the process meant to keep it current.
#
#   ci/docs-check.sh            # report
#   ci/docs-check.sh --strict   # non-zero exit on any finding (CI gate)
# ==============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"
ROOT="$(cd "${PLATFORM}/.." && pwd)"
STRICT=0
[[ "${1:-}" == "--strict" ]] && STRICT=1
FINDINGS=0

C_OK=$'\033[1;32m'; C_BAD=$'\033[1;31m'; C_HD=$'\033[1;36m'; C_OFF=$'\033[0m'
finding() { echo "  ${C_BAD}BROKEN${C_OFF}   $*"; FINDINGS=$((FINDINGS + 1)); }

# Docs live in three places and all three are in scope: the platform tree, the tree root
# (where the split left the cross-cutting references), and planning/.
mapfile -t DOCS < <(
    find "${PLATFORM}" -name '*.md' \
        -not -path '*/node_modules/*' -not -path '*/test/results/*' -not -path '*/archive/*' \
        -not -path '*/change_logs/*' 2>/dev/null
    find "${ROOT}" -maxdepth 1 -name '*.md' 2>/dev/null
)

echo
echo "${C_HD}== Link resolution (${#DOCS[@]} documents)${C_OFF}"

# Relative links only. An http(s) target is not this script's business — reaching the network
# to validate it would make the gate fail when the network is down, which trains everyone to
# ignore it. Anchors are stripped: the file is what must exist.
for doc in "${DOCS[@]}"; do
    dir="$(dirname "${doc}")"
    rel="${doc#"${ROOT}"/}"
    # Markdown inline links and images: ](target)
    while IFS= read -r target; do
        [[ -z "${target}" ]] && continue
        case "${target}" in
            http://*|https://*|mailto:*|'#'*) continue ;;
        esac
        target="${target%%#*}"
        [[ -z "${target}" ]] && continue
        # Strip a title: [text](path "Title")
        target="${target%% *}"
        if [[ ! -e "${dir}/${target}" ]]; then
            finding "${rel} -> ${target}"
        fi
    done < <(grep -oE '\]\([^)]+\)' "${doc}" 2>/dev/null | sed -E 's/^\]\(//; s/\)$//')
done
[[ "${FINDINGS}" -eq 0 ]] && echo "  ${C_OK}every relative link resolves${C_OFF}"

# ---------------------------------------------------------------------------
# Inventory coverage. CHANGE-MANAGEMENT.md §4 is the list a change is reconciled against;
# anything absent from it is a document the process cannot see.
INV="${PLATFORM}/CHANGE-MANAGEMENT.md"
echo
echo "${C_HD}== Inventory coverage (CHANGE-MANAGEMENT.md)${C_OFF}"
if [[ ! -f "${INV}" ]]; then
    finding "CHANGE-MANAGEMENT.md is missing — nothing defines what a change must reconcile"
else
    missing=0
    for doc in "${DOCS[@]}"; do
        rel="${doc#"${ROOT}"/}"
        base="$(basename "${doc}")"
        # Listed either by its path from the root or by its own file name; both are
        # unambiguous enough to find, and requiring one exact form would make the inventory
        # brittle rather than useful.
        grep -qF "${rel}" "${INV}" || grep -qF "${base}" "${INV}" || {
            echo "  ${C_BAD}UNLISTED${C_OFF} ${rel}"
            missing=$((missing + 1)); FINDINGS=$((FINDINGS + 1))
        }
    done
    [[ "${missing}" -eq 0 ]] && echo "  ${C_OK}every document appears in the inventory${C_OFF}"
fi

# ---------------------------------------------------------------------------
# Diagram freshness, reported not enforced. An SVG cannot be diffed against the deployment, so
# this only names diagrams older than the compose files they depict: a prompt to look, not a
# verdict.
echo
echo "${C_HD}== Diagrams older than the deployment they depict${C_OFF}"
newest_compose=0
for f in "${PLATFORM}"/deploy/*/docker-compose.yml; do
    [[ -f "$f" ]] || continue
    t="$(stat -c %Y "$f" 2>/dev/null || echo 0)"
    [[ "$t" -gt "${newest_compose}" ]] && newest_compose="$t"
done
stale_img=0
for svg in "${PLATFORM}"/img/*.svg; do
    [[ -f "${svg}" ]] || continue
    t="$(stat -c %Y "${svg}" 2>/dev/null || echo 0)"
    if [[ "${t}" -lt "${newest_compose}" ]]; then
        echo "  ${C_BAD}REVIEW${C_OFF}   $(basename "${svg}") predates the current compose definition"
        stale_img=$((stale_img + 1))
    fi
done
[[ "${stale_img}" -eq 0 ]] && echo "  ${C_OK}diagrams are newer than the compose files${C_OFF}"

echo
if [[ "${FINDINGS}" -eq 0 ]]; then
    echo "${C_HD}== Documentation${C_OFF}"
    echo "  ${C_OK}no findings${C_OFF}"
    exit 0
fi
echo "${C_HD}== Documentation${C_OFF}"
echo "  ${C_BAD}${FINDINGS} finding(s)${C_OFF}"
[[ "${STRICT}" -eq 1 ]] && exit 1
exit 0
