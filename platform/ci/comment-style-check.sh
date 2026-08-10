#!/usr/bin/env bash
# ==============================================================================
# COMMENT STYLE — comments state what the code does and the constraint that shapes it.
#
# Two things are checked, both defined in CHANGE-MANAGEMENT.md §2 rule 6:
#
#   NARRATIVE   dates, measurements, and past-tense accounts of what went wrong. That
#               material belongs in change_logs/ and planning/. A comment may point at a
#               change log; it may not retell it.
#
#   DENSITY     a file that is more comment than code. The constraint stops being readable
#               when it is buried in prose, and the prose is what goes stale.
#
#   ci/comment-style-check.sh            # report
#   ci/comment-style-check.sh --strict   # non-zero exit on any finding (CI gate)
# ==============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"
STRICT=0
[[ "${1:-}" == "--strict" ]] && STRICT=1

# Ratio of comment lines to non-blank lines, measured BELOW the header block. A file may
# document itself at the top; what it may not be is prose interleaved with its own code.
MAX_RATIO="${IR_COMMENT_MAX_RATIO:-0.45}"

python3 - "${PLATFORM}" "${MAX_RATIO}" "${STRICT}" <<'PY'
import re, sys, pathlib, collections

root = pathlib.Path(sys.argv[1])
max_ratio = float(sys.argv[2])
strict = sys.argv[3] == "1"

MARK = {".sh": "#", ".py": "#", ".yml": "#", ".yaml": "#", ".hcl": "#", ".hujson": "//"}
# Migrations carry a generated header with a date; it is the tool's, not a development marker.
SKIP = ("node_modules", "/archive/", "/test/results/", "/.git/", "/corpus/", "/change_logs/",
        "/migrations/")

# Deliberately high-precision. A pattern that also matches ordinary technical prose ("the
# account used to reach it", "rarity is measured against every host") produces findings nobody
# can act on, and a gate whose findings are usually wrong gets ignored.
PATTERNS = [
    (r"\b20\d\d-\d\d-\d\d\b", "dated development marker"),
    (r"\b(it|this|that|which|they|there) used to\b|\bused to be\b", "past-tense narrative"),
    (r"\b(was|were|had been) previously\b|\bpreviously (forced|caused|made|produced|reported|broke|left)\b",
     "past-tense narrative"),
    (r"\bthe (first|original|old|earlier|previous) (version|implementation|approach|attempt|design)\b",
     "past-tense narrative"),
    (r"\b(turned out|we found|nobody noticed|went unnoticed|for weeks|not theoretical|"
     r"is what previously|once read as|is exactly what happened)\b", "incident narrative"),
    (r"\b(reported a platform|read as a platform|sent the last deployment|"
     r"which is what (broke|caused|killed)|has been observed)\b", "incident narrative"),
    # Only a measurement being REPORTED. Case-sensitive, and the phrase must be a report:
    # "rarity is measured against every host" is ordinary technical prose and must not match.
    (r"\bMeasured\b|\bmeasured that\b|\bmeasured:|\bgave \d+\b|"
     r"\b\d+ successes?\b|\b\d+ failures?\b|\b\d+ ok\s*/\s*\d+\b|\bmeasured at \d",
     "measurement", 0),
]

# Case-insensitive unless a pattern carries its own flags: capitalisation separates a reported
# measurement from ordinary technical prose about measuring.
PATTERNS = [(rx, kind, flags[0] if flags else re.I) for rx, kind, *flags in PATTERNS]

findings = collections.defaultdict(list)
dense = []

for p in sorted(root.rglob("*")):
    if not p.is_file():
        continue
    s = str(p)
    if any(k in s for k in SKIP):
        continue
    mark = MARK.get(p.suffix)
    if mark is None and p.name not in (".env", ".env.example"):
        continue
    mark = mark or "#"
    try:
        lines = p.read_text(errors="ignore").splitlines()
    except Exception:
        continue
    rel = s[len(str(root)) + 1:]

    # The header block is excluded from density. A file documenting what it is and how it is
    # invoked is the point; density is about prose interleaved with the code, which is what
    # buries the operative lines and what goes stale.
    body = 0
    for i, line in enumerate(lines):
        t = line.strip()
        if i == 0 and t.startswith("#!"):
            continue
        if not t or t.startswith(mark):
            continue
        body = i
        break

    com = code = 0
    for n, line in enumerate(lines, 1):
        t = line.strip()
        if not t:
            continue
        if t.startswith(mark):
            com += 1
            # A CITATION of a change log is the sanctioned way to point at history
            # (CHANGE-MANAGEMENT.md §2 rule 6). Its filename carries a date; that is the
            # reference, not a development marker.
            if "change_logs/" in t:
                continue
            for rx, kind, flags in PATTERNS:
                if re.search(rx, t, flags):
                    findings[rel].append((n, kind, t[:96]))
                    break
        else:
            code += 1

    com_body = sum(1 for l in lines[body:] if l.strip().startswith(mark))
    code_body = sum(1 for l in lines[body:] if l.strip() and not l.strip().startswith(mark))
    com, code = com_body, code_body
    total = com + code
    # A compose file, an .env or an .hcl is mostly declarations, and each one needs a line
    # saying what it does. Code is held tighter.
    ceiling = max_ratio if p.suffix in (".sh", ".py") else max_ratio + 0.15
    if total > 20 and com / total > ceiling:
        dense.append((rel, com, code, com / total))

BAD = "\033[1;31m"; OK = "\033[1;32m"; HD = "\033[1;36m"; DIM = "\033[0;37m"; OFF = "\033[0m"

print(f"\n{HD}== Narrative in comments{OFF}")
n_narr = sum(len(v) for v in findings.values())
if not findings:
    print(f"  {OK}no dated, measured or past-tense comments{OFF}")
for rel in sorted(findings, key=lambda r: -len(findings[r])):
    print(f"  {BAD}{len(findings[rel]):>3}{OFF}  {rel}")
    for n, kind, text in findings[rel][:3]:
        print(f"       {DIM}{rel}:{n} ({kind}) {text}{OFF}")

print(f"\n{HD}== Comment density (ceiling {max_ratio:.0%} code, {max_ratio + 0.15:.0%} config){OFF}")
if not dense:
    print(f"  {OK}no file is majority prose{OFF}")
for rel, com, code, r in sorted(dense, key=lambda d: -d[3]):
    print(f"  {BAD}{r:>5.0%}{OFF}  {rel} ({com} comment / {code} code)")

total = n_narr + len(dense)
print(f"\n{HD}== Comment style{OFF}")
if total == 0:
    print(f"  {OK}no findings{OFF}")
    sys.exit(0)
print(f"  {BAD}{n_narr} narrative comment(s) in {len(findings)} file(s), {len(dense)} file(s) over the density ceiling{OFF}")
print(f"  {DIM}history and measurements belong in change_logs/ — a comment may cite one, not retell it{OFF}")
sys.exit(1 if strict else 0)
PY
