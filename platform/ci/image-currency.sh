#!/usr/bin/env bash
# ==============================================================================
# IMAGE CURRENCY — every pinned upstream image is checked against the registry.
#
# A pinned tag freezes a vulnerability set. The image does not change, so anything unpatched at
# pin time stays unpatched, silently, for as long as the pin survives — and a pin that is never
# revisited is indistinguishable from one that was deliberately chosen.
#
# Reading the compose files does not surface this. The tag looks deliberate and the stack comes
# up green either way, so the only thing that catches drift is asking the registry.
#
#   ci/image-currency.sh          # report
#   ci/image-currency.sh --strict # non-zero exit when anything has moved on (CI gate)
#   ci/image-currency.sh --record # report, then write ci/image-currency.record
#   ci/image-currency.sh --age    # fail if the record is older than the review interval
#
# SRG-APP-000456-WSR-000187 requires security-relevant updates within 30 days. Detecting drift
# was never the gap — this script already did that.
#
# Track precision is respected: a pin of `postgres:18` tracks the 18.x line and is current as
# long as no 19 exists, while `coredns:1.13.1` names an exact build and is stale the moment
# 1.13.2 ships. A floating tag (`:latest`) is reported as a finding of its own — it is not
# current, it is unpinned, which trades a known vulnerability set for an unknown one.
# ==============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"
STRICT=0; RECORD=0
case "${1:-}" in
    --strict) STRICT=1 ;;
    --record) RECORD=1 ;;
esac
FINDINGS=0

# The interval the control names. Thirty days is the SRG's own ceiling, not a preference.
REVIEW_DAYS="${IR_IMAGE_REVIEW_DAYS:-30}"
RECORD_FILE="${HERE}/image-currency.record"

# Asked BEFORE any registry call, so an unreachable registry cannot mask an overdue review —
# the two failures are different and must not report the same way.
if [[ "${1:-}" == "--age" ]]; then
    if [[ ! -f "${RECORD_FILE}" ]]; then
        printf '  \033[1;31mNO RECORD\033[0m image currency has never been reviewed — run ci/image-currency.sh --record\n'
        exit 1
    fi
    last="$(awk -F'= *' '/^reviewed/ {print $2}' "${RECORD_FILE}" | tr -d '"')"
    last_s="$(date -d "${last}" +%s 2>/dev/null)" || { printf '  \033[1;31mBAD RECORD\033[0m cannot read review date %s\n' "${last}"; exit 1; }
    age=$(( ( $(date +%s) - last_s ) / 86400 ))
    if (( age > REVIEW_DAYS )); then
        printf '  \033[1;31mOVERDUE\033[0m  last reviewed %s (%dd ago, ceiling %dd)\n' "${last}" "${age}" "${REVIEW_DAYS}"
        exit 1
    fi
    printf '  \033[1;32mCURRENT\033[0m  reviewed %s (%dd ago, ceiling %dd)\n' "${last}" "${age}" "${REVIEW_DAYS}"
    exit 0
fi

say()  { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
ok()   { printf '  \033[1;32mCURRENT\033[0m  %s\n' "$*"; }
old()  { printf '  \033[1;33mSTALE\033[0m    %s\n' "$*"; FINDINGS=$((FINDINGS+1)); }
bad()  { printf '  \033[1;31mUNPINNED\033[0m %s\n' "$*"; FINDINGS=$((FINDINGS+1)); }
skip() { printf '  \033[0;37mSKIP\033[0m     %s\n' "$*"; }

# Locally built images carry no upstream tag to compare against; their bases are pinned in the
# Dockerfiles this same sweep reads.
mapfile -t PINS < <(
    grep -rhoE "image: *(docker\.io/|quay\.io/)?[a-z0-9._/-]+:[a-zA-Z0-9._-]+" \
        "${PLATFORM}"/deploy/*/docker-compose.yml "${PLATFORM}"/*/Dockerfile* 2>/dev/null \
    | sed 's/image: *//' | grep -v 'localhost/' | sort -u
)

# Ask the registry for the tag list, normalize to semver, and report the newest tag that shares
# the pin's precision — comparing a three-part pin against a two-part track would call every
# major-track pin stale and train everyone to ignore the output.
query() {
python3 - "$1" <<'PY'
import json, re, sys, urllib.request

ref = sys.argv[1]
host, path = ("quay.io", ref[len("quay.io/"):]) if ref.startswith("quay.io/") else \
             ("docker.io", ref[len("docker.io/"):] if ref.startswith("docker.io/") else ref)
repo, _, tag = path.rpartition(":")
if "/" not in repo:
    repo = f"library/{repo}"

def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "ir-platform-image-currency"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)

names = []
try:
    if host == "quay.io":
        d = fetch(f"https://quay.io/api/v1/repository/{repo}/tag/?limit=100&onlyActiveTags=true")
        names = [t["name"] for t in d.get("tags", [])]
    else:
        for page in (1, 2):
            d = fetch(f"https://hub.docker.com/v2/repositories/{repo}/tags/"
                      f"?page_size=100&page={page}&ordering=last_updated")
            names += [t["name"] for t in d.get("results", [])]
            if not d.get("next"):
                break
except Exception as e:
    print(f"ERROR|{e}")
    raise SystemExit(0)

# Date-stamped releases (MinIO) carry no semver at all, and skipping them would let the one
# image with no version discipline rot unnoticed — the same silent staleness this check exists
# to catch. They sort lexically, which for a fixed-width timestamp is chronological.
if tag.startswith("RELEASE."):
    same = sorted(n for n in set(names)
                  if n.startswith("RELEASE.") and n.endswith("-cpuv1") == tag.endswith("-cpuv1"))
    if same:
        print(f"{'OK' if tag >= same[-1] else 'STALE'}|{same[-1]}|")
    else:
        print(f"NOCANDS|{tag}")
    raise SystemExit(0)

# The pin's shape defines what "newer" means. Suffixes travel with the track: an `-alpine` pin
# must not be compared against the glibc line.
m = re.fullmatch(r"v?(\d+(?:\.\d+)*)(-[a-z0-9.]+)?", tag)
if not m:
    print(f"UNPARSED|{tag}")
    raise SystemExit(0)
parts, suffix = m.group(1).split("."), (m.group(2) or "")
prefix = "v" if tag.startswith("v") else ""
depth = len(parts)

cands = []
for n in set(names):
    pat = (re.escape(prefix) + rf"(\d+(?:\.\d+){{{depth-1}}})" + re.escape(suffix))
    mm = re.fullmatch(pat, n)
    if mm:
        cands.append((tuple(int(x) for x in mm.group(1).split(".")), n))
if not cands:
    print(f"NOCANDS|{tag}")
    raise SystemExit(0)

newest = max(cands)
cur = tuple(int(x) for x in parts)
# A newer track existing at all is worth saying even when the pin is current within its own
# line: staying on 18.x is a choice, but it should be a visible one.
tracks = sorted({c[0][0] for c in cands})
print(f"{'OK' if cur >= newest[0] else 'STALE'}|{newest[1]}|"
      f"{'newer-major' if tracks and tracks[-1] > cur[0] else ''}")
PY
}

say "Pinned upstream images (${#PINS[@]})"
for ref in "${PINS[@]}"; do
    tag="${ref##*:}"
    # A floating tag is its own finding: the running image can change under the deployment with
    # no change to the repository, so what was tested and what is deployed are not the same
    # artifact and neither is auditable after an incident.
    if [[ "${tag}" == "latest" || "${tag}" == "stable" ]]; then
        bad "${ref} — floating tag; pin a release so the deployed artifact is reproducible"
        continue
    fi
    res="$(query "${ref}")"
    case "${res%%|*}" in
        OK)
            rest="${res#OK|}"
            if [[ "${rest##*|}" == "newer-major" ]]; then
                old "${ref} — current within its track, but a newer major exists"
            else
                ok "${ref}"
            fi ;;
        STALE)
            rest="${res#STALE|}"
            old "${ref} — registry has ${rest%%|*}" ;;
        ERROR)    skip "${ref} — registry unreachable (${res#ERROR|})" ;;
        UNPARSED) skip "${ref} — tag is not semver, compare by hand" ;;
        NOCANDS)  skip "${ref} — no comparable tags at this precision" ;;
        *)        skip "${ref} — ${res}" ;;
    esac
done

say "Image currency"

# The record states what was found, not merely that a review happened. A review that found
# five stale images and a review that found none are different events, and a record that
# cannot tell them apart is a signature on an empty page.
if (( RECORD )); then
    {   printf '# Image currency review — SRG-APP-000456-WSR-000187.\n'
        printf '# Written by ci/image-currency.sh --record. Checked by --age.\n'
        printf 'reviewed = "%s"\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        printf 'findings = %d\n' "${FINDINGS}"
        printf 'interval_days = %d\n' "${REVIEW_DAYS}"
    } > "${RECORD_FILE}"
    printf '  \033[0;37mrecorded: %s (%d finding(s))\033[0m\n' "${RECORD_FILE#"${PLATFORM}/"}" "${FINDINGS}"
fi

if (( FINDINGS )); then
    printf '  \033[1;33m%d image(s) need attention\033[0m\n\n' "${FINDINGS}"
    (( STRICT )) && exit 1
    exit 0
fi
printf '  \033[1;32mall pinned images are current\033[0m\n\n'
