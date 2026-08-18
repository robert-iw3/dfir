# Shared UAT output + evidence reporting. Sourced by every test/uat_*.sh:
#
#     . "${HERE}/lib/report.sh"
#     report_begin <order> <slug> "<title>" "<what passing PROVES about the platform>"
#     ... say / ok / bad / info ...
#     report_finish        # then: exit "${FAILED}"
#
# Each ok/bad is one ASSERTION, and its message is written to carry the EVIDENCE inline — a
# live user name, a session id, a row count — because "PASS" alone proves that a check ran,
# not that the platform is in the claimed state. Anyone reading the report should be able to
# dispute an assertion from what is printed next to it.
#
# Every run rewrites its own fragment in test/results/ and regenerates UAT-REPORT.md from all
# fragments, ordered by the <order> prefix — which follows the platform's own dependency
# order, so the report reads as the end state being built up: network policy, then brokered
# access, then secrets, then the evidence pipeline, then analysis on top of all of it.

REPORT_DIR="${PLATFORM}/test/results"
_R_LOCK=""
REPORT_FRAG=""
REPORT_TITLE=""
_R_PASS=0; _R_FAIL=0
# Guards the verdict against being written twice when a suite calls report_finish and the
# exit trap fires after it.
_R_DONE=0
FAILED=0

say()  { printf '\n\033[1;36m== %s\033[0m\n' "$*"; _r_section "$*"; }
ok()   { printf '  \033[1;32mPASS\033[0m %s\n' "$*"; _r_line PASS "$*"; }
bad()  { printf '  \033[1;31mFAIL\033[0m %s\n' "$*"; FAILED=1; _r_line FAIL "$*"; }
info() { printf '  \033[0;37m%s\033[0m\n' "$*"; _r_line note "$*"; }

_r_esc() { printf '%s' "$1" | sed 's/|/\\|/g'; }

_r_section() {
    [[ -n "${REPORT_FRAG}" ]] || return 0
    {   printf '\n**%s**\n\n' "$(_r_esc "$1")"
        printf '| Result | Assertion — with evidence |\n|---|---|\n'
    } >> "${REPORT_FRAG}"
}

_r_line() {
    [[ -n "${REPORT_FRAG}" ]] || return 0
    local mark
    case "$1" in
        PASS) mark="✅ PASS" ;;
        FAIL) mark="❌ **FAIL**" ;;
        *)    mark="·" ;;
    esac
    printf '| %s | %s |\n' "${mark}" "$(_r_esc "$2")" >> "${REPORT_FRAG}"
}

# One suite at a time. Two sharing an ingress, a queue and a database are not two
# experiments: a suite run beside another scored 18/17 where it scores 34/1 alone, and those
# failures are indistinguishable from real ones. run_uats.sh sequences; this stops a second
# run started by hand from silently invalidating both.
_r_claim_lock() {  # <slug>
    local lock="${IR_UAT_LOCK:-${TMPDIR:-/tmp}/ir-uat-suite.lock}"
    if ! mkdir "${lock}" 2>/dev/null; then
        local who pid
        who="$(cat "${lock}/slug" 2>/dev/null || echo "another suite")"
        pid="$(cat "${lock}/pid" 2>/dev/null || echo 0)"
        if [[ "${pid}" =~ ^[0-9]+$ ]] && [[ "${pid}" -gt 0 ]] && kill -0 "${pid}" 2>/dev/null; then
            printf '\033[1;31m✘\033[0m %s is already running (pid %s) — refusing to start %s beside it\n' \
                "${who}" "${pid}" "$1" >&2
            exit 2
        fi
        # The holder is gone; its lock is not evidence of anything.
        rm -rf "${lock}" 2>/dev/null
        mkdir "${lock}" 2>/dev/null || { printf 'could not take the suite lock\n' >&2; exit 2; }
    fi
    printf '%s' "$1" > "${lock}/slug"
    printf '%s' "$$" > "${lock}/pid"
    _R_LOCK="${lock}"
    trap _r_at_exit EXIT
}

# A suite that exits early — a failed precondition, its own `exit 1` on a verdict it printed
# itself — must still PUBLISH what it measured. Left to the suite, a run that failed keeps the
# last successful fragment standing and the report reads green for a suite that just failed,
# which is the one error a reader cannot catch by reading the report.
#
# The documented exception is preserved: a run that asserted NOTHING leaves the previous
# fragment alone rather than replacing proof with an empty section.
_r_at_exit() {
    if [[ -n "${REPORT_FRAG:-}" && "${_R_DONE}" != "1" ]] \
       && grep -qE '^\| (✅|❌)' "${REPORT_FRAG}" 2>/dev/null; then
        report_finish
    fi
    [[ -n "${_R_LOCK:-}" ]] && rm -rf "${_R_LOCK}"
}

report_begin() {  # <order> <slug> <title> <claim>
    local order="$1" slug="$2"; REPORT_TITLE="$3"; local claim="$4"
    [[ "${IR_UAT_NO_LOCK:-0}" == "1" ]] || _r_claim_lock "${slug}"
    mkdir -p "${REPORT_DIR}"
    # The run writes a .part file and the published fragment is replaced only at report_finish, when
    # there is a verdict to replace it with. Writing the fragment directly meant a suite that bailed
    # on a precondition — before its first assertion — destroyed the previous run's proof and
    # published a header over empty tables, which reads as sections that ran and asserted nothing.
    REPORT_FINAL="${REPORT_DIR}/${order}-${slug}.md"
    REPORT_FRAG="${REPORT_FINAL}.part"
    rm -f "${REPORT_FRAG}"
    # Unconditionally, not only where the lock was claimed: IR_UAT_NO_LOCK skips that path,
    # and a suite run without the lock must still publish the verdict it measured.
    trap _r_at_exit EXIT
    printf '\033[1;33m!! These tests act on the RUNNING deployment.\033[0m\n'
    printf '\033[0;37m   Intended use: bring the stack up, run these to VALIDATE it, then rebuild.\n'
    printf '     deploy.sh enclave  ->  test/uat_*.sh  ->  deploy.sh down enclave && deploy.sh enclave\n'
    printf '   They rotate live credentials, register services and open real sessions, so the\n'
    printf '   stack they leave behind is a tested one, not a clean one. Reports under\n'
    printf '   test/results/ are PUBLISHED — the identifiers in them belong to a throwaway\n'
    printf '   deployment, but nothing an operator would not publish may reach an assertion.\033[0m\n'
    {   printf '## %s\n\n' "${REPORT_TITLE}"
        printf '*What passing proves:* %s\n\n' "${claim}"
        printf -- '- Run: `%s` — %s\n' "uat_${slug}.sh" "$(date -u '+%Y-%m-%d %H:%M:%SZ')"
    } > "${REPORT_FRAG}"
}

report_finish() {
    [[ -n "${REPORT_FRAG}" ]] || return 0
    [[ "${_R_DONE}" == "1" ]] && return 0
    _R_DONE=1
    _R_PASS="$(grep -c '^| ✅' "${REPORT_FRAG}" || true)"
    _R_FAIL="$(grep -c '^| ❌' "${REPORT_FRAG}" || true)"
    local verdict="PROVEN"
    [[ "${FAILED}" != "0" ]] && verdict="NOT PROVEN"
    printf '\n**Verdict: %s** — %s assertions passed, %s failed.\n' \
        "${verdict}" "${_R_PASS}" "${_R_FAIL}" >> "${REPORT_FRAG}"
    # Reaching here IS the verdict — including NOT PROVEN, which replaces the old proof
    # honestly. Only a run that never got this far leaves the previous fragment standing.
    mv "${REPORT_FRAG}" "${REPORT_FINAL}"
    REPORT_FRAG="${REPORT_FINAL}"

    # Regenerate the collective report from every fragment present. Order is the filename's
    # numeric prefix, so the document builds the platform up the way the deployment does.
    local out="${REPORT_DIR}/UAT-REPORT.md" f
    {   printf '# IR Platform — UAT results\n\n'
        printf 'Generated by `test/uat_*.sh` against the RUNNING deployment; each run rewrites its own section.\n'
        printf 'Last update: %s.\n\n' "$(date -u '+%Y-%m-%d %H:%M:%SZ')"
        printf '> **These tests act on the running deployment.** Bring the stack up, run them to\n'
        printf '> validate it, then rebuild:\n'
        printf '>\n'
        printf '> ```\n'
        printf '> deploy.sh enclave\n'
        printf '> test/uat_consul.sh   # and the rest\n'
        printf '> deploy.sh down enclave && deploy.sh enclave\n'
        printf '> ```\n'
        printf '>\n'
        printf '> They rotate live database credentials, register services into the mesh and open\n'
        printf '> real brokered sessions — so the stack they leave behind is a tested one, not a\n'
        printf '> clean one.\n'
        printf '>\n'
        printf '> The evidence below is deliberately specific — dynamic user names, session and\n'
        printf '> worker identifiers, container addresses, row counts — because "PASS" alone\n'
        printf '> proves that a check ran, not that the platform is in the claimed state. An\n'
        printf '> assertion nobody can dispute from what is printed beside it is not evidence.\n'
        printf '>\n'
        printf '> These reports are published. Every identifier in them is issued fresh by a\n'
        printf '> deployment that is torn down and rebuilt — container-bridge and tailnet\n'
        printf '> addresses, generated account names, session ids. The operator running it is\n'
        printf '> not named, and the sync gate refuses any file that would name them.\n\n'
        printf '## Summary\n\n| # | UAT | Verdict | Pass | Fail |\n|---|---|---|---|---|\n'
        for f in "${REPORT_DIR}"/[0-9]*-*.md; do
            [[ -f "$f" ]] || continue
            # A SUITE is a section that names the run which produced it. Other files sit here
            # too — `58-load-measurements.md` is a table, not a claim — and handing those a
            # verdict invents a failure out of something that never asserted anything. A suite
            # that died cannot reach this state: it leaves its `.part` behind and the previous
            # fragment standing, so no run line means "not a suite", never "a suite that died".
            grep -q '^- Run: ' "$f" || continue
            local t v p x n
            n="$(basename "$f")"; n="${n%%-*}"
            t="$(sed -n 's/^## //p' "$f" | head -1)"
            v="$(sed -n 's/^\*\*Verdict: \([A-Z ]*\)\*\*.*/\1/p' "$f" | tail -1)"
            p="$(grep -c '^| ✅' "$f" || true)"; x="$(grep -c '^| ❌' "$f" || true)"
            [[ "${v}" == "PROVEN" ]] && v="✅ PROVEN" || v="❌ ${v:-INCOMPLETE}"
            printf '| %s | %s | %s | %s | %s |\n' "${n}" "${t}" "${v}" "${p}" "${x}"
        done
        printf '\n---\n'
        for f in "${REPORT_DIR}"/[0-9]*-*.md; do
            [[ -f "$f" ]] || continue
            printf '\n'
            # Everything is published, including what the summary above will not score. A file
            # that names no run is labeled here rather than dropped, because a block of
            # assertions concatenated behind a titled section reads as part of it.
            if ! grep -q '^- Run: ' "$f"; then
                grep -q '^## ' "$f" \
                    || printf '## %s — no run recorded\n\n*Left by an earlier report format: it names no run and no date, so the summary does not score it. It is rewritten the next time its suite completes.*\n\n' \
                             "$(basename "${f%.md}")"
            fi
            cat "$f"; printf '\n---\n'
        done
    } > "${out}"
    printf '\n  \033[0;37mreport: %s (section) -> %s\033[0m\n' \
        "$(basename "${REPORT_FRAG}")" "${out}"
}
