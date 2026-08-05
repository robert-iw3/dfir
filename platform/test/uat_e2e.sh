#!/usr/bin/env bash
# ==============================================================================
# END-TO-END UAT — every tier up, every stage of the platform's life exercised.
#
# The capstone above the capstone: uat_full_stack.sh proves the evidence pipeline; this proves
# the PLATFORM — from a real collector container producing a sealed capture, through analysis,
# role enforcement and audit, to carved regions opened in BOTH reverse-engineering tools:
#
#   collector (edge) → receiver → [pull] → analysis findings → RBAC/audit/retention
#     → carved regions → mediator staging → binja session + ghidra session
#
# Memory analysis runs on a SYNTHETIC capture and carved regions are SEEDED, both labeled as
# such in the data: real carving needs a host's RAM and hours of scan, which tests the analyzer
# rather than the platform. Everything downstream of the analyzer is the real path.
#
# Deploys all tiers itself. Rebuild afterwards, as with every UAT.
# ==============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"
RUNTIME="${IR_RUNTIME:-podman}"
DEPLOY="${PLATFORM}/deploy"

. "${HERE}/lib/report.sh"
report_begin 80 e2e "End to end — collection to reverse engineering" \
    "A real collector produces sealed evidence that ships, ingests, analyzes into findings under role enforcement and an intact audit chain, and its carved regions open in contained binja AND ghidra sessions — the platform's whole life, on the deployed stack."

[[ -f "${DEPLOY}/.env" ]] || cp "${DEPLOY}/.env.example" "${DEPLOY}/.env"
set -a; . "${DEPLOY}/.env"; set +a

INCIDENT="INC-E2E-$(date +%Y%m%d-%H%M%S)"
HOST_E2E="e2e-endpoint"
be()  { ${RUNTIME} exec ir-enclave_backend_1 "$@"; }
# The API is not host-published; it is reached the way the platform reaches it — from inside.
api() { # GET path token -> body
    be python -c "
import urllib.request as u
print(u.urlopen(u.Request('http://127.0.0.1:8000$1',
    headers={'Authorization':'Token $2'}), timeout=10).read().decode())" 2>/dev/null
}
acode() { # method path token [body] -> http code
    be python -c "
import urllib.request as u, urllib.error as e, json
try:
    r = u.urlopen(u.Request('http://127.0.0.1:8000$2', method='$1',
        headers={'Authorization':'Token $3','Content-Type':'application/json'},
        data=${4:-None} and json.dumps(${4:-None}).encode()), timeout=10)
    print(r.status)
except e.HTTPError as ex:
    print(ex.code)" 2>/dev/null
}

# ============================================================ 1. everything up
say "1/7  Deploy every tier"
bash "${DEPLOY}/deploy.sh" down all >/dev/null 2>&1
bash "${DEPLOY}/deploy.sh" all >/dev/null 2>&1 || bad "deployment did not converge"
apiok=0
for i in $(seq 1 80); do
    be python -c "import urllib.request as u;u.urlopen('http://127.0.0.1:8000/api/health/',timeout=3)" \
        >/dev/null 2>&1 && { apiok=1; break; }
    sleep 3
done
[[ "${apiok}" == "1" ]] && ok "enclave API healthy" || { bad "enclave API never came up"; report_finish; exit 1; }
for svc in ir-dmz_receiver_1 ir-enclave_puller_1 ir-enclave_worker_1 ir-enclave_consul_1 ir-enclave_vault_1; do
    [[ "$(${RUNTIME} inspect "$svc" --format '{{.State.Status}}' 2>/dev/null)" == "running" ]] \
        && ok "$svc running" || bad "$svc not running"
done

# ============================================================ 2. real collection
say "2/7  A real collector produces a sealed capture and SHIPS it from the edge"
EVID="$(mktemp -d)"
${RUNTIME} image exists ir-collector:latest 2>/dev/null \
    || bash "${PLATFORM}/collector/build.sh" >/dev/null 2>&1 \
    || bad "collector image failed to build"
# Rootless and unprivileged, so memory capture takes the labeled synthetic fallback — the
# collection path, custody seal and shipping are all real.
if ${RUNTIME} run --rm --hostname "${HOST_E2E}" \
    -e IR_INCIDENT_ID="${INCIDENT}" \
    -e IR_CUSTODY_HMAC_KEY="${IR_CUSTODY_HMAC_KEY:-}" \
    -e IR_SAMPLE_BYTES=16777216 \
    -v "${EVID}:/evidence:z" \
    ir-collector:latest >/dev/null 2>&1; then
    ok "collector ran (incident ${INCIDENT})"
else
    bad "collector run failed"
fi
BUNDLE_DIR="${EVID}/reports/${HOST_E2E}"
[[ -f "${BUNDLE_DIR}/_custody_platform.json" ]] \
    && ok "custody seal present in the produced bundle" \
    || bad "no custody seal — the bundle would be quarantined on arrival"
ls "${BUNDLE_DIR}"/memory_* >/dev/null 2>&1 \
    && ok "memory image captured ($(basename "$(ls "${BUNDLE_DIR}"/memory_* | head -1)"))" \
    || bad "no memory image in the bundle"

# Shipped from the EDGE segment over pinned TLS — the endpoint's actual vantage, not the host's.
tar czf "${EVID}/bundle.tar.gz" -C "${EVID}/reports" "${HOST_E2E}"
RECV_ADDR="$(${RUNTIME} inspect ir-dmz_receiver_1 \
    --format '{{(index .NetworkSettings.Networks "ir-edge").IPAddress}}' 2>/dev/null)"
SHIP=$(${RUNTIME} run --rm --network ir-edge \
    -v "${EVID}/bundle.tar.gz:/b.tar.gz:ro,z" \
    -v "${PLATFORM}/dmz/certs/receiver.crt:/r.crt:ro,z" \
    localhost/ir-workstation:latest \
    curl -s -o /dev/null -w '%{http_code}' --cacert /r.crt \
         --resolve "receiver:8090:${RECV_ADDR}" \
         -X POST -T /b.tar.gz "https://receiver:8090/ingest" 2>/dev/null)
[[ "${SHIP}" == "202" ]] \
    && ok "receiver accepted the collector's bundle over pinned TLS from the edge (HTTP ${SHIP})" \
    || bad "receiver did not accept the bundle (HTTP ${SHIP:-none})"

# ============================================================ 3. ingest + analysis
say "3/7  The enclave pulls, ingests and ANALYZES the capture"
ATOK=""
for i in $(seq 1 10); do
    ATOK="$(be python -c "
import urllib.request as u, json
r = u.urlopen(u.Request('http://127.0.0.1:8000/api/auth/token/', method='POST',
    headers={'Content-Type':'application/json'},
    data=json.dumps({'username':'admin','password':'${IR_ADMIN_PASSWORD}'}).encode()), timeout=8)
print(json.load(r)['token'])" 2>/dev/null)"
    [[ -n "${ATOK}" ]] && break; sleep 3
done
[[ -n "${ATOK}" ]] && ok "admin authenticated" || bad "admin auth failed"

RUN_ID=""
for i in $(seq 1 40); do
    RUN_ID="$(api "/api/runs/" "${ATOK}" | python3 -c "
import sys, json
d = json.load(sys.stdin)
runs = d.get('results', d) if isinstance(d, dict) else d
for r in runs:
    if '${INCIDENT}' in json.dumps(r):
        print(r['id']); break" 2>/dev/null)"
    [[ -n "${RUN_ID}" ]] && break
    sleep 3
done
[[ -n "${RUN_ID}" ]] \
    && ok "the collector's run was pulled and ingested (run ${RUN_ID}, incident ${INCIDENT})" \
    || bad "the run never appeared — the pull path is broken"

DONE=0
for i in $(seq 1 60); do
    ST="$(api "/api/runs/${RUN_ID}/" "${ATOK}" | grep -o '"status": *"[a-z]*"' | head -1)"
    [[ "${ST}" == *completed* ]] && { DONE=1; break; }
    [[ "${ST}" == *failed* ]] && break
    sleep 3
done
[[ "${DONE}" == "1" ]] \
    && ok "memory analysis completed on the stored capture" \
    || bad "memory analysis did not complete (${ST:-no status})"
DETAIL="$(api "/api/runs/${RUN_ID}/" "${ATOK}")"
grep -qE '"finding_type": *"(Suspicious token in memory|URL in memory|External IPv4 in memory)"' <<<"${DETAIL}" \
    && ok "analysis produced memory findings from the stored object" \
    || bad "no memory findings — analysis ran against nothing"
grep -qE '"retention_status": *"(purged|retained|legal_hold)"' <<<"${DETAIL}" \
    && ok "retention lifecycle applied ($(grep -o '"retention_status": *"[a-z_]*"' <<<"${DETAIL}" | head -1))" \
    || bad "retention lifecycle not applied"

# ============================================================ 4. roles + audit
say "4/7  Role enforcement and the audit chain, on the live data"
NTOK="$(be python -c "
import urllib.request as u, json
r = u.urlopen(u.Request('http://127.0.0.1:8000/api/auth/token/', method='POST',
    headers={'Content-Type':'application/json'},
    data=json.dumps({'username':'analyst','password':'${IR_ANALYST_PASSWORD}'}).encode()), timeout=8)
print(json.load(r)['token'])" 2>/dev/null)"
UTOK="$(be python -c "
import urllib.request as u, json
r = u.urlopen(u.Request('http://127.0.0.1:8000/api/auth/token/', method='POST',
    headers={'Content-Type':'application/json'},
    data=json.dumps({'username':'auditor','password':'${IR_AUDITOR_PASSWORD}'}).encode()), timeout=8)
print(json.load(r)['token'])" 2>/dev/null)"
[[ -n "${NTOK}" && -n "${UTOK}" ]] && ok "analyst and auditor authenticated" || bad "role auth failed"

NC="$(acode POST /api/notes/ "${NTOK}" "{'body':'e2e analyst note'}")"
[[ "${NC}" == "201" ]] && ok "analyst can write a note (HTTP ${NC})" || bad "analyst note write got ${NC}"
AC="$(acode POST /api/notes/ "${UTOK}" "{'body':'x'}")"
[[ "${AC}" == "403" ]] && ok "auditor is refused writes (HTTP ${AC})" || bad "auditor write not blocked (${AC})"
DC="$(acode DELETE /api/investigations/999999/ "${NTOK}")"
[[ "${DC}" == "403" || "${DC}" == "404" ]] && ok "analyst cannot delete (HTTP ${DC})" || bad "analyst delete not blocked (${DC})"

AUDIT="$(api /api/audit/ "${UTOK}")"
grep -q '"chain_intact": *true' <<<"${AUDIT}" \
    && ok "audit hash-chain intact, readable by the auditor" \
    || bad "audit chain broken or unreadable"
grep -q '"action": *"ingest"' <<<"${AUDIT}" \
    && ok "this ingest is recorded in the audit trail" \
    || bad "the ingest left no audit record"

# ============================================================ 5. carved regions
say "5/7  Carved regions seeded, staged by the mediator"
# Real ELF binaries from the backend image itself: real files, labeled simulated rows.
SAMPLES="$(mktemp -d)"
for f in ls cat grep tar; do
    ${RUNTIME} exec ir-enclave_backend_1 sh -c "cat \$(command -v ${f})" > "${SAMPLES}/${f}.bin" 2>/dev/null
done
[[ "$(ls "${SAMPLES}" | wc -l)" -ge 3 ]] || bad "could not gather sample binaries to seed"
bash "${HERE}/seed_regions.sh" --host "${HOST_E2E}" --source "${SAMPLES}" --incident "${INCIDENT}" \
    >/dev/null 2>&1 \
    && ok "regions seeded into ${HOST_E2E}'s bucket" \
    || bad "seeding carved regions failed"

# Staged where launch.sh looks for it (session-<host>), so the workstations below start the
# same way an analyst starts them rather than through a path only this test knows.
SESSION="${PLATFORM}/re-workstation/session-${HOST_E2E}"
rm -rf "${SESSION}"
if bash "${PLATFORM}/re-workstation/stage_regions.sh" --host "${HOST_E2E}" --out "${SESSION}" >/dev/null 2>&1; then
    N=$(find "${SESSION}" -name '*.bin' 2>/dev/null | wc -l)
    [[ "${N}" -gt 0 ]] && ok "mediator staged ${N} region(s) for the session" \
                       || bad "mediator staged nothing"
else
    bad "mediator failed to stage ${HOST_E2E}'s regions"
fi

# ============================================================ 6. both RE tools
say "6/7  BOTH reverse-engineering workstations come up on the carved regions"
# Launched exactly as an analyst launches them — launch.sh, GUI, real window on the display.
# Not headless: the workstation IS the deliverable, and a headless invocation proves the
# binary parses a file while saying nothing about whether an analyst can open a session.
#
# Needs a desktop. Stated and skipped rather than silently passing on a machine with no
# display, because "no window appeared" and "no display to appear on" are different results.
if [[ -z "${DISPLAY:-}" ]]; then
    info "DISPLAY is unset — the workstation sessions need a desktop; run this from one"
    bad "cannot verify the RE workstations without a display"
else
    for tool in ghidra binja; do
        case "${tool}" in
            ghidra) IMG="${IR_RE_GHIDRA_IMAGE:-ir-re-ghidra:latest}"; DF="Dockerfile.ghidra"
                    WPAT='ghidra|CodeBrowser' ;;
            binja)  IMG="${IR_RE_IMAGE:-ir-re-workstation:latest}";   DF="Dockerfile"
                    WPAT='[Bb]inary ?[Nn]inja|binaryninja' ;;
        esac
        ${RUNTIME} image exists "${IMG}" 2>/dev/null || {
            info "building ${IMG} (network at BUILD time only)"
            ${RUNTIME} build -t "${IMG}" -f "${PLATFORM}/re-workstation/${DF}" \
                "${PLATFORM}/re-workstation" >/dev/null 2>&1 \
                || { bad "${tool} image failed to build"; continue; }
        }
        ${RUNTIME} rm -f ir-re-session >/dev/null 2>&1 || true
        ( bash "${PLATFORM}/re-workstation/launch.sh" --host "${HOST_E2E}" --tool "${tool}" \
            >"/tmp/uat-e2e-${tool}.log" 2>&1 & ) >/dev/null 2>&1

        # The window on the host's display is the assertion. A running container proves the
        # process started; only a mapped window proves the analyst has a session.
        WIN=0
        for _ in $(seq 1 60); do
            if [[ "$(xwininfo -root -tree 2>/dev/null | grep -ciE "${WPAT}" || true)" -gt 0 ]]; then
                WIN=1; break
            fi
            [[ "$(${RUNTIME} inspect -f '{{.State.Status}}' ir-re-session 2>/dev/null)" == "exited" ]] && break
            sleep 3
        done

        if [[ "${WIN}" == "1" ]]; then
            ok "${tool}: workstation session is up with a window on the display"

            NET="$(${RUNTIME} inspect -f '{{.HostConfig.NetworkMode}}' ir-re-session 2>/dev/null)"
            [[ "${NET}" == "none" ]] \
                && ok "${tool}: session has NO network while holding live malware" \
                || bad "${tool}: session network is '${NET}', expected none"

            # Asserted from KERNEL state inside the session, not from podman's inspect output:
            # `--cap-drop ALL` is stored EXPANDED into the individual capability names, so
            # looking for the word "all" reports a correctly stripped session as privileged.
            CAPEFF="$(${RUNTIME} exec ir-re-session sh -c \
                'grep CapEff /proc/self/status | cut -f2' 2>/dev/null | tr -d '[:space:]')"
            [[ "${CAPEFF}" =~ ^0+$ ]] \
                && ok "${tool}: all capabilities dropped (CapEff=${CAPEFF})" \
                || bad "${tool}: capabilities retained (CapEff=${CAPEFF:-unreadable})"

            # The mount table, which cannot be ambiguous. Whether a `touch` fails also depends
            # on which user the exec lands as, and that is not the property being asserted.
            MNT="$(${RUNTIME} exec ir-re-session sh -c 'grep " /regions " /proc/mounts' 2>/dev/null)"
            grep -qE '[ ,]ro[ ,]' <<<"${MNT}" \
                && ok "${tool}: carved regions are mounted read-only" \
                || bad "${tool}: /regions is not read-only (${MNT:-no mount entry})"
        else
            bad "${tool}: no window appeared — $(tail -2 "/tmp/uat-e2e-${tool}.log" 2>/dev/null | head -1)"
        fi
        ${RUNTIME} rm -f ir-re-session >/dev/null 2>&1 || true
    done
fi

say "7/7  Result"
rm -rf "${EVID}" "${SAMPLES}"
${RUNTIME} rm -f ir-re-session >/dev/null 2>&1 || true
if [[ "${FAILED}" == "0" ]]; then
    ok "end to end holds: collect → ship → pull → analyze → enforce → audit → carve → stage → reverse engineer"
else
    bad "end to end does NOT hold — see failures above"
fi
report_finish
exit "${FAILED}"
