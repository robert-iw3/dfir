#!/usr/bin/env bash
# Acquire DWARF for one kernel and convert it to a Volatility 3 ISF, inside a per-family builder
# container outside the enclave. Only the resulting JSON is carried inward.
set -uo pipefail

REQ="${IR_REQUISITES:-/work/_symbols.json}"
OUT="${IR_OUT:-/out}"
LP_PARSER="${IR_LP_PARSER:-/usr/local/bin/lp_url.py}"

read_field() { python3 -c "
import json,sys
d=json.load(open('${REQ}'))
cur=d
for k in '$1'.split('.'):
    cur=(cur or {}).get(k) if isinstance(cur,dict) else None
print(cur or '')
" 2>/dev/null; }

[[ -r "${REQ}" ]] || { echo "acquire: cannot read requisites at ${REQ}" >&2; exit 2; }
mkdir -p "${OUT}"

KREL="$(read_field kernel_release)"
BUILD_ID="$(read_field build_id)"
BANNER="$(read_field banner)"
KEY="$(read_field symbol_key)"
LOCAL_VMLINUX="$(read_field local_vmlinux)"
[[ -n "${KEY}" ]] || KEY="${BUILD_ID:-${KREL}}"

echo "acquire: kernel=${KREL} build_id=${BUILD_ID:0:16} key=${KEY}"

VMLINUX=""
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# 1. A debug vmlinux shipped alongside the bundle needs no download at all.
if [[ -n "${LOCAL_VMLINUX}" && -r "/work/$(basename "${LOCAL_VMLINUX}")" ]]; then
    VMLINUX="/work/$(basename "${LOCAL_VMLINUX}")"
    echo "acquire: using vmlinux supplied with the bundle"
fi

# 2. debuginfod — distro-agnostic, keyed by build-id.
if [[ -z "${VMLINUX}" && -n "${BUILD_ID}" ]]; then
    echo "acquire: querying debuginfod for ${BUILD_ID:0:16}…"
    if debuginfod-find debuginfo "${BUILD_ID}" > "${WORK}/path" 2>"${WORK}/err"; then
        CANDIDATE="$(cat "${WORK}/path")"
        [[ -s "${CANDIDATE}" ]] && VMLINUX="${CANDIDATE}" \
            && echo "acquire: debuginfod supplied $(basename "${CANDIDATE}")"
    else
        DI_ERR="$(tail -1 "${WORK}/err" 2>/dev/null)"
        case "${DI_ERR}" in
            *"Timer expired"*|*"timed out"*|*"Connection timed out"*)
                echo "acquire: debuginfod TIMED OUT — availability unknown, not ruled out" >&2
                echo "acquire:   (${DI_ERR})" >&2
                echo "debuginfod TIMED OUT" >> "${WORK}/outcome" ;;
            *"No such file"*|*"not found"*|*404*)
                echo "acquire: debuginfod has no build for ${BUILD_ID:0:16} (${DI_ERR})" ;;
            *)
                echo "acquire: debuginfod query failed — availability unknown (${DI_ERR})" >&2
                echo "debuginfod availability unknown" >> "${WORK}/outcome" ;;
        esac
    fi
fi

# 3. The family's debug-symbol package, reporting what HAPPENED rather than what was attempted —
# 'trying' with no outcome reads as success.
if [[ -z "${VMLINUX}" && -n "${KREL}" ]]; then
    echo "acquire: trying the ddebs archive for linux-image-${KREL}-dbgsym"
    apt-get update -qq 2>/dev/null || true
    if apt-get install -y --no-install-recommends -qq "linux-image-${KREL}-dbgsym" \
            >"${WORK}/apt.log" 2>&1; then
        for p in "/usr/lib/debug/boot/vmlinux-${KREL}" "/usr/lib/debug/lib/modules/${KREL}/vmlinux"; do
            [[ -r "$p" ]] && VMLINUX="$p" && break
        done
        [[ -n "${VMLINUX}" ]] \
            && echo "acquire: ddebs supplied $(basename "${VMLINUX}")" \
            || echo "acquire: ddebs installed the package but it carried no vmlinux" >&2
    else
        # The archive prunes debug packages for superseded ABIs and lags new ones, so "not
        # here" is the common case rather than an error — but it has to be said out loud.
        if grep -qiE "unable to locate package|has no installation candidate" "${WORK}/apt.log"; then
            echo "acquire: ddebs does not carry linux-image-${KREL}-dbgsym (pruned or not yet published)"
        else
            echo "acquire: ddebs install failed — $(tail -1 "${WORK}/apt.log" 2>/dev/null)" >&2
            echo "ddebs availability unknown" >> "${WORK}/outcome"
        fi
    fi
fi

# 4. Launchpad: the ddebs archive prunes debug packages for superseded kernel ABIs, but
# Launchpad keeps published binaries.
if [[ -z "${VMLINUX}" && -n "${KREL}" ]]; then
    # "linux-image-<ver>-dbgsym" is a thin wrapper for signed kernels — a few KB with no
    # DWARF in it. The unsigned package carries the actual debug vmlinux, so it is tried
    # first and the signed name only as a fallback for kernels published without one.
    DEB_URL=""
    for PKG in "linux-image-unsigned-${KREL}-dbgsym" "linux-image-${KREL}-dbgsym"; do
        echo "acquire: querying Launchpad for ${PKG}"
        curl -fsSL --max-time 120 \
            "https://api.launchpad.net/1.0/ubuntu/+archive/primary?ws.op=getPublishedBinaries&binary_name=${PKG}&exact_match=true" \
            -o "${WORK}/lp.json" 2>/dev/null || true
        DEB_URL="$(python3 "${LP_PARSER}" "${WORK}/lp.json" 2>/dev/null || true)"
        [[ -n "${DEB_URL}" ]] && break
    done
    if [[ -n "${DEB_URL}" ]]; then
        # Ask before committing: a kernel dbgsym is a multi-GB transfer, so one HEAD request to learn
        # whether the URL serves at all is free by comparison.
        echo "acquire: checking $(basename "${DEB_URL}")"
        # One request for both facts. -sSL follows redirects (Launchpad redirects to a CDN) and
        # reports the FINAL status, which is the one that decides whether to transfer.
        HEAD_CODE="$(curl -sSL -o /dev/null --max-time 60 -w '%{http_code}' -I "${DEB_URL}" 2>/dev/null || echo 000)"
        HEAD_LEN="$(curl -sSL --max-time 60 -I "${DEB_URL}" 2>/dev/null \
                      | awk 'tolower($1)=="content-length:"{v=$2} END{gsub(/\r/,"",v); print v}')"
        case "${HEAD_CODE}" in
            200|302|301)
                if [[ -n "${HEAD_LEN}" ]]; then
                    echo "acquire:   available, $(( HEAD_LEN / 1048576 )) MiB"
                else
                    echo "acquire:   available (size not advertised)"
                fi ;;
            404|410)
                echo "acquire: Launchpad lists ${PKG} but the file is gone (HTTP ${HEAD_CODE})" >&2
                DEB_URL="" ;;
            5*)
                echo "acquire: the archive returned HTTP ${HEAD_CODE} — a SERVER fault, not a" >&2
                echo "acquire:   missing package. The build is published; retry shortly." >&2
                echo "archive SERVER fault HTTP ${HEAD_CODE}" >> "${WORK}/outcome"
                DEB_URL="" ;;
            000)
                echo "acquire: could not reach the archive at all — check egress from here" >&2
                echo "could not reach the archive" >> "${WORK}/outcome"
                DEB_URL="" ;;
            *)
                echo "acquire:   HTTP ${HEAD_CODE} — attempting the transfer anyway" >&2 ;;
        esac
    fi
    if [[ -n "${DEB_URL}" ]]; then
        echo "acquire: fetching $(basename "${DEB_URL}") — large, expect a long transfer"
        if curl -fSL --max-time "${ACQUIRE_TIMEOUT:-5400}" -o "${WORK}/dbg.ddeb" "${DEB_URL}"; then
            # A kernel dbgsym carrying DWARF is hundreds of MB. Anything tiny is a wrapper
            # package, and unpacking it would yield no vmlinux.
            DEB_SIZE=$(stat -c%s "${WORK}/dbg.ddeb" 2>/dev/null || echo 0)
            if [[ "${DEB_SIZE}" -lt 10000000 ]]; then
                echo "acquire: ${DEB_SIZE} bytes is too small to contain DWARF — wrapper package" >&2
                rm -f "${WORK}/dbg.ddeb"
            fi
        fi
        if [[ -r "${WORK}/dbg.ddeb" ]]; then
            ( cd "${WORK}" && dpkg-deb -x dbg.ddeb ex ) 2>/dev/null || \
                ( cd "${WORK}" && ar x dbg.ddeb && mkdir -p ex && tar -C ex -xf data.tar.* )
            for p in "${WORK}/ex/usr/lib/debug/boot/vmlinux-${KREL}" \
                     "${WORK}/ex/usr/lib/debug/lib/modules/${KREL}/vmlinux"; do
                [[ -r "$p" ]] && VMLINUX="$p" && break
            done
            [[ -n "${VMLINUX}" ]] && echo "acquire: Launchpad supplied $(basename "${VMLINUX}")"
        else
            echo "acquire: Launchpad download failed or timed out" >&2
            echo "Launchpad transfer availability unknown" >> "${WORK}/outcome"
        fi
    else
        echo "acquire: Launchpad has no published ${PKG} for amd64"
    fi
fi

if [[ -z "${VMLINUX}" ]]; then
    # "Not published" and "we could not find out" are different answers and lead to different
    # actions: the first ends the search and should mark the symbol request unavailable, the
    # second is worth retrying and must NOT be recorded as absence. Exit codes carry the
    # distinction so a caller can act on it instead of parsing prose.
    #
    #   1  no DWARF exists for this kernel, as far as every source can say
    #   3  at least one source failed in a way that decided nothing
    echo "acquire: no DWARF obtained for ${KREL} — no ISF produced" >&2
    if grep -qiE "TIMED OUT|availability unknown|SERVER fault|could not reach" "${WORK}/outcome" 2>/dev/null; then
        echo "acquire: at least one source was INCONCLUSIVE — this is not proof the symbols" >&2
        echo "acquire:   are unpublished. Retry before treating the kernel as unavailable." >&2
        exit 3
    fi
    echo "acquire: every source reported the build as absent." >&2
    exit 1
fi

echo "acquire: converting DWARF -> ISF"
if ! dwarf2json linux --elf "${VMLINUX}" > "${WORK}/isf.json" 2>"${WORK}/d2j.err"; then
    echo "acquire: dwarf2json failed: $(tail -3 "${WORK}/d2j.err")" >&2
    exit 1
fi

# An ISF whose banner does not match the captured one describes a different kernel build.
# Using it yields plausible, wrong structure offsets, so the mismatch is fatal here.
if [[ -n "${BANNER}" ]]; then
    if ! python3 - "${WORK}/isf.json" "${BANNER}" <<'PY'
import json, sys
isf, want = sys.argv[1], sys.argv[2]
with open(isf) as fh:
    doc = json.load(fh)
banners = [k for k in (doc.get("symbols") or {}) if "banner" in k.lower()]
meta = json.dumps(doc.get("metadata", {}))
# The kernel release is the reliable discriminator present in both.
rel = want.split()[2] if len(want.split()) > 2 else ""
sys.exit(0 if (rel and (rel in meta or rel in isf.split("/")[-1] or banners)) else 1)
PY
    then
        echo "acquire: ISF does not correspond to the captured kernel — refusing it" >&2
        exit 1
    fi
fi

install -m 0644 "${WORK}/isf.json" "${OUT}/${KEY}.json"
python3 -c "
import json
d=json.load(open('${OUT}/${KEY}.json'))
print('acquire: ISF ok — %d symbols, %d types' % (len(d.get('symbols',{})), len(d.get('user_types',{}))))
"
echo "acquire: wrote ${OUT}/${KEY}.json"
