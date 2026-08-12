#!/usr/bin/env bash
# ==============================================================================
# BANNED PASSWORD LIST — SRG-APP-000835-WSR-000200, SRG-APP-000840-WSR-000210.
#
# Two controls, one mechanism, distinguished only by what triggers an update: a schedule (835)
# and a suspicion of compromise (840). So the list is not the interesting part — the RECORD is.
#
#   ci/password-blacklist-check.sh                    # assert list, policy and record
#   ci/password-blacklist-check.sh --record "reason"  # stamp a review
#
# The reason is required for a reason. An out-of-cycle update under 840 and a scheduled one
# under 835 are the same file edit and different events, and a record that cannot tell them
# apart satisfies neither control.
# ==============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"

LIST="${PLATFORM}/keycloak/password-blacklists/dfir-platform.txt"
REALM="${PLATFORM}/hashicorp/keycloak/realm-irplatform.json"
RECORD="${HERE}/password-blacklist.record"
REVIEW_DAYS="${IR_BLACKLIST_REVIEW_DAYS:-90}"

RC=0
ok()  { printf '  \033[1;32m✔\033[0m %s\n' "$*"; }
bad() { printf '  \033[1;31m✘\033[0m %s\n' "$*"; RC=1; }
say() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }

if [[ "${1:-}" == "--record" ]]; then
    reason="${2:-}"
    [[ -n "${reason}" ]] || { bad "a reason is required: --record \"scheduled review\" | \"suspected compromise: <what>\""; exit 2; }
    entries="$(grep -cvE '^\s*#|^\s*$' "${LIST}" 2>/dev/null || echo 0)"
    {   printf '# Banned password list review — SRG-APP-000835-WSR-000200 / -000840-WSR-000210.\n'
        printf '# Written by ci/password-blacklist-check.sh --record.\n'
        printf 'reviewed = "%s"\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        printf 'reason = "%s"\n' "${reason}"
        printf 'entries = %s\n' "${entries}"
        printf 'interval_days = %d\n' "${REVIEW_DAYS}"
    } > "${RECORD}"
    ok "recorded: ${reason} (${entries} entries)"
    exit 0
fi

say "The list exists and says something"
if [[ -s "${LIST}" ]]; then
    ENTRIES="$(grep -cvE '^\s*#|^\s*$' "${LIST}")"
    [[ "${ENTRIES}" -gt 0 ]] \
        && ok "${ENTRIES} banned entries" \
        || bad "the list is all comments — the policy would accept every password"
else
    bad "no list at ${LIST#"${PLATFORM}/"} — the policy names a file that does not exist"
fi

# Lowercase only: Keycloak lowercases the candidate before comparing, so a capitalized entry
# is one that can never match. Silent, and it makes the list look larger than it is.
if [[ -s "${LIST}" ]]; then
    UPPER="$(grep -vE '^\s*#|^\s*$' "${LIST}" | grep -c '[A-Z]' || true)"
    [[ "${UPPER}" -eq 0 ]] \
        && ok "every entry is lowercase, so every entry can actually match" \
        || bad "${UPPER} entr(y|ies) contain uppercase and can never match a lowercased candidate"
fi

say "The realm policy names it"
POLICY="$(python3 -c "import json,sys;print(json.load(open(sys.argv[1])).get('passwordPolicy',''))" "${REALM}" 2>/dev/null)"
case "${POLICY}" in
    *"passwordBlacklist(dfir-platform.txt)"*)
        ok "passwordPolicy references dfir-platform.txt" ;;
    *)  bad "the realm password policy does not reference the blacklist — the file is inert" ;;
esac

say "The review is on record and current"
if [[ ! -f "${RECORD}" ]]; then
    bad "never reviewed — run --record \"initial\""
else
    last="$(awk -F'= *' '/^reviewed/ {print $2}' "${RECORD}" | tr -d '"')"
    why="$(awk -F'= *' '/^reason/ {print $2}' "${RECORD}" | tr -d '"')"
    if last_s="$(date -d "${last}" +%s 2>/dev/null)"; then
        age=$(( ( $(date +%s) - last_s ) / 86400 ))
        [[ "${age}" -le "${REVIEW_DAYS}" ]] \
            && ok "reviewed ${age}d ago (ceiling ${REVIEW_DAYS}d): ${why}" \
            || bad "OVERDUE — reviewed ${age}d ago, ceiling ${REVIEW_DAYS}d"
    else
        bad "unreadable review date: ${last}"
    fi
fi

say "Result"
[[ ${RC} -eq 0 ]] && printf '  \033[1;32mbanned password list enforced and reviewed\033[0m\n\n' \
                  || printf '  \033[1;31mbanned password list NOT proven\033[0m\n\n'
exit ${RC}
