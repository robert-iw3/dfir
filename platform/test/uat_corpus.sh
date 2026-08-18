#!/usr/bin/env bash
# ==============================================================================
# CORPUS v2 — 25 endpoints through the REAL pipeline, benign baseline included: every endpoint is
# a real collector run with custody seal and synthetic memory sample. Passing proves the engine
# reconstructs the encoded campaigns and stays quiet on the benign fleet.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"

. "${HERE}/lib/report.sh"
report_begin 60 corpus "Corpus v2 — 25 endpoints, end to end" \
    "25 real collector runs — 16 compromised across two investigations, 9 clean, fleet-wide benign noise on all — ship, ingest, analyze and correlate through the production path; clean hosts classify clean and join no campaign."
RUNTIME="${IR_RUNTIME:-podman}"

set -a; . "${PLATFORM}/deploy/.env" 2>/dev/null || true; set +a

BE=ir-enclave_backend_1
be() { ${RUNTIME} exec -i "${BE}" "$@"; }

# ---------------------------------------------------------------- preconditions
# Every service here is load-bearing: without the receiver the 25 ships go nowhere, without
# the worker nothing is analyzed. A missing one ABORTS rather than being recorded, because the
# alternative is a 20-minute run whose every failure restates the same fact.
say "Preconditions"
MISSING=()
for svc in ir-dmz_receiver_1 ir-enclave_puller_1 ir-enclave_backend_1 ir-enclave_worker_1; do
    if [[ "$(${RUNTIME} inspect "$svc" --format '{{.State.Status}}' 2>/dev/null)" == "running" ]]; then
        ok "$svc running"
    else
        bad "$svc not running"; MISSING+=("$svc")
    fi
done
if [[ "${#MISSING[@]}" -gt 0 ]]; then
    bad "aborting: ${MISSING[*]} absent — deploy the tier(s) first (deploy.sh dmz / deploy.sh enclave)"
    report_finish
    exit 1
fi
# Rebuilt when its source is NEWER, not merely when absent — built-only-when-absent is how a stale
# worker runs old models against a migrated database.
collector_stale() {
    ${RUNTIME} image exists ir-collector:latest 2>/dev/null || return 0
    local built
    built="$(${RUNTIME} image inspect ir-collector:latest --format '{{.Created}}' 2>/dev/null)"
    built="$(date -d "${built}" +%s 2>/dev/null)" || return 0
    [[ -n "$(find "${PLATFORM}/collector" -type f -not -path '*/__pycache__/*' \
             -newermt "@${built}" -print -quit 2>/dev/null)" ]]
}
if collector_stale; then
    bash "${PLATFORM}/collector/build.sh" >/dev/null 2>&1 \
        && ok "collector image rebuilt from current source" \
        || { bad "collector image failed to build"; report_finish; exit 1; }
else
    ok "collector image current with collector/"
fi

# The collector must run the FULL forensics collection, not the inline snapshot — asserted on the
# source, because the difference is invisible in the output shape.
grep -q -- '--deep' "${PLATFORM}/collector/collect.sh" \
    && ok "the collector runs the full forensics collection (--deep)" \
    || bad "collect.sh no longer passes --deep — SUID, authorized_keys, shell-init persistence and running-binary hashes will not be collected"

SCEN="$(mktemp -d)"
python3 "${HERE}/corpus/scenarios.py" "${SCEN}" >/dev/null \
    && ok "25 endpoint scenarios generated" \
    || { bad "scenario generation failed"; report_finish; exit 1; }

# Reset prior corpus data so a re-run is deterministic, scoped to the corpus investigations; real
# evidence is untouched.
be python3 - <<'PYEOF' >/dev/null 2>&1
import os, django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ir_platform.settings"); django.setup()
from cases.models import Investigation, CollectionRun, Host
from correlation.models import CorrelationRun
invs = list(Investigation.objects.filter(incident_id__in=("INC-CORPUS-A", "INC-CORPUS-B")))
host_ids = set(CollectionRun.objects.filter(investigation__in=invs).values_list("host_id", flat=True))
for inv in invs:
    CorrelationRun.objects.filter(investigation_id=inv.id).delete()
CollectionRun.objects.filter(investigation__in=invs).delete()
Investigation.objects.filter(id__in=[i.id for i in invs]).delete()
# Hosts that existed only for the corpus, now with no runs left.
Host.objects.filter(id__in=host_ids, runs__isnull=True).delete()
PYEOF
ok "prior corpus data reset (real evidence untouched)"

RECV_ADDR="$(${RUNTIME} inspect ir-dmz_receiver_1 \
    --format '{{(index .NetworkSettings.Networks "ir-edge").IPAddress}}' 2>/dev/null)"
# The address is used, never recorded: these reports are kept, and a live address of a
# running deployment is not something to write into one.
[[ -n "${RECV_ADDR}" ]] && ok "receiver holds an address on the edge network" \
                        || bad "receiver has no edge address"

# ---------------------------------------------------------------- collect + ship ×25
say "Collection — 25 real collector runs, shipped from the edge"
SHIPPED=0
for f in "${SCEN}"/*.json; do
    host="$(basename "${f}" .json)"
    [[ "${host}" == "manifest" ]] && continue
    incident="$(python3 -c "import json;print(json.load(open('${f}'))['incident_id'])")"
    mid="$(python3 -c "import json;print(json.load(open('${f}'))['machine_id'])")"
    EVID="$(mktemp -d)"
    # IR_MACHINE_ID is the collector's own identity override, resolved before any hunt — a
    # distinct value per endpoint, so the enclave keeps 25 hosts rather than merging them.
    if ! ${RUNTIME} run --rm --hostname "${host}" \
        -e IR_HOSTNAME="${host}" \
        -e IR_MACHINE_ID="${mid}" \
        -e IR_INCIDENT_ID="${incident}" \
        -e IR_CUSTODY_HMAC_KEY="${IR_CUSTODY_HMAC_KEY:-}" \
        -e IR_SCENARIO_FILE=/scenario.json \
        -e IR_SAMPLE_BYTES=8388608 \
        -v "${f}:/scenario.json:ro,z" \
        -v "${EVID}:/evidence:z" \
        ir-collector:latest >/dev/null 2>&1; then
        bad "${host}: collector run failed"; rm -rf "${EVID}"; continue
    fi
    [[ -f "${EVID}/reports/${host}/_custody_platform.json" ]] \
        || { bad "${host}: no custody seal"; rm -rf "${EVID}"; continue; }
    tar czf "${EVID}/bundle.tar.gz" -C "${EVID}/reports" "${host}"
    code=$(${RUNTIME} run --rm --network ir-edge \
        -v "${EVID}/bundle.tar.gz:/b.tar.gz:ro,z" \
        -v "${PLATFORM}/dmz/certs/receiver.crt:/r.crt:ro,z" \
        localhost/ir-workstation:latest \
        curl -s -o /dev/null -w '%{http_code}' --cacert /r.crt \
             --resolve "receiver:8090:${RECV_ADDR}" \
             -X POST -T /b.tar.gz "https://receiver:8090/ingest" 2>/dev/null)
    rm -rf "${EVID}"
    if [[ "${code}" == "202" ]]; then
        SHIPPED=$((SHIPPED + 1))
    else
        bad "${host}: receiver answered ${code:-nothing}"
    fi
done
[[ "${SHIPPED}" == "25" ]] \
    && ok "all 25 bundles collected, sealed and accepted by the receiver" \
    || bad "only ${SHIPPED}/25 bundles were accepted"

# ---------------------------------------------------------------- ingest
say "Ingest — the puller delivers all 25 runs"
INGESTED=0
for _ in $(seq 1 60); do
    INGESTED="$(be python3 -c "
import os, django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ir_platform.settings'); django.setup()
from cases.models import CollectionRun
print(CollectionRun.objects.filter(investigation__incident_id__in=('INC-CORPUS-A', 'INC-CORPUS-B')).count())" 2>/dev/null)"
    [[ "${INGESTED:-0}" -ge 25 ]] && break
    sleep 10
done
[[ "${INGESTED:-0}" -ge 25 ]] \
    && ok "25 corpus runs ingested through receiver -> puller -> ingest" \
    || bad "only ${INGESTED:-0}/25 corpus runs arrived"

HOSTS="$(be python3 -c "
import os, django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ir_platform.settings'); django.setup()
from cases.models import Host, CollectionRun
runs = CollectionRun.objects.filter(investigation__incident_id__in=('INC-CORPUS-A', 'INC-CORPUS-B')).select_related('host')
hosts = {r.host.hostname: r.host.machine_id for r in runs}
print(len(hosts), len(set(hosts.values())))" 2>/dev/null)"
read -r NHOSTS NMIDS <<<"${HOSTS}"
[[ "${NHOSTS:-0}" == "25" && "${NMIDS:-0}" == "25" ]] \
    && ok "25 distinct hosts with 25 distinct machine ids — no endpoint merged into another" \
    || bad "host identity collapsed: ${NHOSTS:-0} hosts, ${NMIDS:-0} machine ids"

# ---------------------------------------------------------------- analysis settles
say "Analysis — every capture is analyzed and adjudicated before compromise is read"
# Compromise is set by the investigation engine AFTER a capture's analysis flips to
# 'completed' (adjudicate runs later in the same worker task), so waiting on analysis status
# alone reads compromise mid-flight. The pipeline is quiesced when every capture is terminal
# AND the compromised count has stopped moving — the real settle signal, no sleep-and-hope.
STABLE=0; PREV=-1
for _ in $(seq 1 150); do
    read -r TERMINAL NCOMP <<<"$(be python3 -c "
import os, django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ir_platform.settings'); django.setup()
from cases.models import MemoryCapture, CollectionRun
caps = MemoryCapture.objects.filter(run__investigation__incident_id__in=('INC-CORPUS-A', 'INC-CORPUS-B'))
term = sum(1 for c in caps if c.analyses.filter(status__in=('completed','failed')).exists())
comp = CollectionRun.objects.filter(investigation__incident_id__in=('INC-CORPUS-A', 'INC-CORPUS-B'), compromised=True).count()
print(term, comp)" 2>/dev/null)"
    if [[ "${TERMINAL:-0}" -ge 25 && "${NCOMP:-0}" == "${PREV}" ]]; then
        STABLE=$((STABLE + 1)); [[ "${STABLE}" -ge 2 ]] && break
    else
        STABLE=0
    fi
    PREV="${NCOMP:-0}"; sleep 10
done
[[ "${TERMINAL:-0}" -ge 25 ]] \
    && ok "all 25 captures terminal and compromise settled (${NCOMP} compromised)" \
    || info "only ${TERMINAL:-0}/25 captures terminal within the wait — classification may read hosts mid-flight"

# 'Terminal' counts failed analyses too, so the settle gate stays quiet when every analysis
# failed. Assert the OUTCOME, not that the pipeline stopped moving.
while read -r line; do
    case "${line}" in
        AOK*)  ok "${line#AOK }" ;;
        ABAD*) bad "${line#ABAD }" ;;
    esac
done < <(be python3 - <<'PYEOF' 2>&1
import os, django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ir_platform.settings"); django.setup()
from cases.models import MemoryAnalysisRun
qs = MemoryAnalysisRun.objects.filter(
    capture__run__investigation__incident_id__in=("INC-CORPUS-A", "INC-CORPUS-B"))
failed = [r for r in qs if r.status == "failed"]
if failed:
    print(f"ABAD {len(failed)}/{qs.count()} corpus analyses FAILED: {failed[0].error or '?'}"[:400])
else:
    print(f"AOK every corpus analysis completed ({qs.count()})")

# Adjudication is what turns leads into verdicts. It never raises, so a broken engine leaves
# completed analyses carrying no conclusions at all.
ran = [r for r in qs if ((r.summary or {}).get("adjudication") or {}).get("ran")]
if len(ran) == qs.count() and qs.exists():
    print(f"AOK every analysis was adjudicated by the investigation engine ({len(ran)})")
else:
    why = next((((r.summary or {}).get("adjudication") or {}).get("reason")
                for r in qs if not ((r.summary or {}).get("adjudication") or {}).get("ran")), None)
    print(f"ABAD only {len(ran)}/{qs.count()} analyses adjudicated — {why or 'no reason recorded'}"[:400])
PYEOF
)

# ---------------------------------------------------------------- classification
say "Classification — compromise is derived from verdicts, and clean means clean"
# The comparison runs INSIDE the backend and emits result tokens, rather than shuttling JSON
# out through a heredoc and re-parsing it in the shell — the same in-container pattern the
# correlation checks below use, and which does not lose the payload to a capture quirk.
EXPECT_CLEAN="$(python3 -c "import json;print(','.join(json.load(open('${SCEN}/manifest.json'))['clean']))")"
while read -r line; do
    case "${line}" in
        CLEAN_OK*) ok "the 9 clean endpoints classify CLEAN despite carrying the full benign baseline" ;;
        CLEAN_BAD*) bad "clean-host classification diverged — ${line#CLEAN_BAD }" ;;
        COMP_OK*) ok "the 16 seeded intrusions classify compromised" ;;
        COMP_BAD*) bad "expected 16 compromised endpoints — ${line#COMP_BAD }" ;;
    esac
done < <(be python3 - "${EXPECT_CLEAN}" <<'PYEOF' 2>/dev/null
import os, sys, django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ir_platform.settings"); django.setup()
from cases.models import CollectionRun
comp, clean = set(), set()
for r in CollectionRun.objects.filter(investigation__incident_id__in=("INC-CORPUS-A", "INC-CORPUS-B")).select_related("host"):
    (comp if r.compromised else clean).add(r.host.hostname)
clean -= comp
expect = sorted(x for x in sys.argv[1].split(",") if x)
got = sorted(clean)
print("CLEAN_OK" if got == expect else f"CLEAN_BAD expected {expect}, got {got}")
print("COMP_OK" if len(comp) == 16 else f"COMP_BAD got {len(comp)}: {sorted(comp)}")
PYEOF
)

# ---------------------------------------------------------------- memory analysis
say "Memory — the analyzer derives the scenario's artifacts from the image itself"
MEMOK=""
for _ in $(seq 1 90); do
    MEMOK="$(be python3 -c "
import os, django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ir_platform.settings'); django.setup()
from cases.models import Finding
q = Finding.objects.filter(run__investigation__incident_id='INC-CORPUS-A',
                           run__host__hostname='WS-007', source='memory')
print('HIT' if any('198.51.100.23' in (f.target or '') + str(f.raw) for f in q) else '')" 2>/dev/null)"
    [[ "${MEMOK}" == "HIT" ]] && break
    sleep 10
done
[[ "${MEMOK}" == "HIT" ]] \
    && ok "WS-007's memory image analysis surfaced its C2 address — derived from the image, not declared" \
    || bad "WS-007's memory analysis never surfaced the planted C2"

# ---------------------------------------------------------------- correlation
say "Correlation — computed from the ingested evidence"
CORR="$(be python manage.py correlate 2>&1 | tail -5)"
grep -q "campaign" <<<"${CORR}" || true
SUMMARY="$(be python3 - <<'PYEOF' 2>/dev/null
import json, os, django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ir_platform.settings"); django.setup()
from cases.models import Investigation
from correlation.models import Campaign, CampaignHost
out = []
for inv in Investigation.objects.filter(incident_id__in=("INC-CORPUS-A", "INC-CORPUS-B")):
    for c in Campaign.objects.filter(investigation_id=inv.id, run__is_current=True):
        hosts = sorted(CampaignHost.objects.filter(campaign=c).values_list("hostname", flat=True))
        out.append({"inv": inv.name, "pz": c.patient_zero, "hosts": hosts})
print(json.dumps(out))
PYEOF
)"
while read -r line; do
    case "${line}" in
        PASSCHK*) ok "${line#PASSCHK }" ;;
        FAILCHK*) bad "${line#FAILCHK }" ;;
        V1LIMIT*) info "${line#V1LIMIT }" ;;
        SEPARATE*) ok "${line#SEPARATE }" ;;
    esac
done < <(python3 - "$SUMMARY" <<'PYEOF'
import json, sys
camps = json.loads(sys.argv[1] or "[]")
clean = {"WS-001","WS-002","WS-004","WS-005","WS-006","WS-008","WS-009","WS-010","WS-102"}
in_campaign = set(h for c in camps for h in c["hosts"])
print(("PASSCHK " if not (clean & in_campaign) else "FAILCHK ") + "no clean endpoint appears in ANY campaign")
print(("PASSCHK " if any(c["pz"]=="WS-007" and "DC-01" in c["hosts"] for c in camps) else "FAILCHK ") + "Ember Fox correlates with WS-007 as patient zero")
print(("PASSCHK " if any(c["pz"]=="WS-101" and "DC-101" in c["hosts"] for c in camps) else "FAILCHK ") + "Quiet Fox correlates with WS-101 as patient zero")
ember = next((c for c in camps if "WS-007" in c["hosts"]), None)
if ember and ("WS-012" in ember["hosts"] or "VPN-GW-01" in ember["hosts"]):
    print("FAILCHK the cryptominer merged into Ember Fox through the fleet-wide account (G2)")
else:
    print("PASSCHK the cryptominer stays separate DESPITE sharing a fleet-wide account (G2 closed)")
PYEOF
)

# ---------------------------------------------------------------- weighted linkage (L1/L2)
say "Weighted linkage — evidence is scored, and weak links are declined with reasons"
while read -r line; do
    case "${line}" in
        PASSCHK*) ok "${line#PASSCHK }" ;;
        FAILCHK*) bad "${line#FAILCHK }" ;;
        INFOCHK*) info "${line#INFOCHK }" ;;
    esac
done < <(be python3 - <<'PYEOF' 2>/dev/null
import os, django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ir_platform.settings"); django.setup()
from cases.models import Investigation
from correlation.models import Campaign, CorrelationRun, HostLink

def chk(cond, label):
    print(("PASSCHK " if cond else "FAILCHK ") + label)

runs = {}
for inv in Investigation.objects.filter(incident_id__in=("INC-CORPUS-A", "INC-CORPUS-B")):
    r = CorrelationRun.objects.filter(investigation_id=inv.id, is_current=True).first()
    if r:
        runs[inv.incident_id] = r
MINER = {"WS-012", "VPN-GW-01"}
EMBER = {"WS-007", "JUMP-01", "DC-01", "SRV-FILE-01", "SRV-DB-01",
         "SRV-BACKUP-01", "DC-02", "SRV-APP-01", "WS-003", "WS-011"}
QUIET = {"WS-101", "JUMP-101", "SRV-FILE-101", "DC-101"}
THRESHOLD = 0.35

a, b = runs.get("INC-CORPUS-A"), runs.get("INC-CORPUS-B")
chk(bool(a) and a.algorithm_version == "2.0",
    f"correlation ran at the weighted algorithm version ({a.algorithm_version if a else 'none'})")

if a:
    links = {(l.host_a, l.host_b): l for l in HostLink.objects.filter(run=a)}

    # The MECHANISM behind G2, not just its outcome. Ember and the miner genuinely share the
    # fleet-wide helpdesk account, so the candidate pair must EXIST — if it were absent the
    # separation would prove nothing about weighting, only that the pair was never compared.
    cross = [(k, l) for k, l in links.items()
             if (k[0] in EMBER and k[1] in MINER) or (k[0] in MINER and k[1] in EMBER)]
    chk(bool(cross),
        f"the Ember/miner pair was CONSIDERED — the shared fleet-wide account makes it a candidate ({len(cross)} pairs)")
    if cross:
        chk(all(not l.linked for _, l in cross),
            "every Ember/miner candidate was DECLINED — G2 closed by weighting, not by absence")
        # The trap is asserted at its NODE, not at whichever contribution came out on top:
        # a shared MITRE technique can out-weigh the account, and technique nodes carry
        # floored rarity by construction — no clean carrier exists to break the
        # confirmed-everywhere floor, so TYPE weight is what declines them.
        from correlation.models import BehaviorNode
        from correlation.linkage import rarity as node_rarity
        from cases.models import Host
        acct = BehaviorNode.objects.filter(run=a, kind="account",
                                           value="CORP\\svc_helpdesk").first()
        chk(bool(acct), "the ubiquitous helpdesk account is in the behavior graph")
        if acct:
            # What the account CONTRIBUTES, not its raw rarity. Rarity is measured against
            # the whole deployment, so it drifts upward every time another corpus adds hosts
            # — this assertion sat 0.007 from the threshold and flipped when corpus X landed,
            # reporting a population change as an engine regression. The property that
            # actually matters survives that: a fleet-wide account cannot carry a pair on its
            # own, whatever the fleet grows to.
            from correlation.linkage import TYPE_WEIGHT
            r = node_rarity(acct.host_count, Host.objects.count())
            alone = TYPE_WEIGHT["account"] * r          # best case: confirmed, contemporaneous
            chk(alone < THRESHOLD,
                f"the fleet-wide account cannot link a pair BY ITSELF "
                f"(contributes {alone:.3f} at best, under {THRESHOLD}; "
                f"rarity {r:.3f} across {acct.host_count} carriers of "
                f"{Host.objects.count()} deployment hosts)")
        heaviest = max((l.weight for _, l in cross), default=1.0)
        chk(heaviest < THRESHOLD,
            f"declined weights sit below the threshold (heaviest {heaviest:.4f} < {THRESHOLD})")

    # The converse, which is what stops a threshold that simply refuses everything from
    # passing: the same mechanism must ACCEPT the real intrusion.
    inside = [l for k, l in links.items() if k[0] in EMBER and k[1] in EMBER]
    linked_inside = [l for l in inside if l.linked]
    chk(len(linked_inside) >= 9 and all(l.weight >= THRESHOLD for l in linked_inside),
        f"Ember's own pairs LINK on their real evidence ({len(linked_inside)} at or above threshold)")

    # A score nobody can decompose is not evidence.
    required = {"type_weight", "rarity", "verdict_weight", "temporal", "weight", "kind"}
    chk(bool(links) and all(required <= set(l.factors.get("top", {})) for l in links.values()),
        "every link decomposes into all four named factors plus their product")

    # Cohesion must REFLECT the links rather than merely exist: the campaign minimum has to
    # equal the weakest linked pair inside it.
    for c in Campaign.objects.filter(run=a):
        hosts = set(c.hosts.values_list("hostname", flat=True))
        internal = [l.weight for k, l in links.items()
                    if k[0] in hosts and k[1] in hosts and l.linked]
        if internal:
            chk(abs(c.cohesion_min - round(min(internal), 4)) < 1e-6,
                f"campaign pz={c.patient_zero}: cohesion_min equals its weakest internal link ({c.cohesion_min})")

    # Held together by indicators with no observed movement, the miner must read WEAKER than an
    # intrusion reconstructed from movement — a true statement about that evidence.
    camps = list(Campaign.objects.filter(run=a))
    ember_c = next((c for c in camps if "WS-007" in set(c.hosts.values_list("hostname", flat=True))), None)
    miner_c = next((c for c in camps if set(c.hosts.values_list("hostname", flat=True)) & MINER), None)
    chk(bool(ember_c and miner_c) and miner_c.cohesion_mean < ember_c.cohesion_mean,
        f"the miner campaign scores visibly weaker than Ember "
        f"(mean {miner_c.cohesion_mean if miner_c else 'none'} vs "
        f"{ember_c.cohesion_mean if ember_c else 'none'}; "
        f"min {miner_c.cohesion_min if miner_c else 'none'} vs "
        f"{ember_c.cohesion_min if ember_c else 'none'})")

    # And the claim underneath the number: what each campaign actually rests on.
    def kinds_of(c):
        hosts = set(c.hosts.values_list("hostname", flat=True))
        return {((l.factors or {}).get("top") or {}).get("kind")
                for k, l in links.items() if k[0] in hosts and k[1] in hosts and l.linked}

    chk(bool(miner_c) and kinds_of(miner_c) == {"indicator"},
        f"the miner rests on shared indicators alone ({sorted(kinds_of(miner_c)) if miner_c else []})")
    chk(bool(ember_c) and "movement" in kinds_of(ember_c),
        f"Ember rests on observed movement as well ({sorted(kinds_of(ember_c)) if ember_c else []})")

if b:
    # G1's mechanism: Quiet Fox rotated every indicator, so no linked pair may rest on a
    # shared indicator — a cluster here can only have been carried by tradecraft or movement.
    qlinks = list(HostLink.objects.filter(run=b, linked=True))
    kinds = {l.factors.get("top", {}).get("kind") for l in qlinks}
    chk(bool(qlinks) and "indicator" not in kinds,
        f"Quiet Fox links are carried by tradecraft and movement, never a shared indicator ({sorted(k for k in kinds if k)})")

    # DC-101 has NO movement recorded — the collector never caught the hop — so its only tie
    # is the persistence service name it shares with SRV-FILE-101. Movement outranks
    # artifacts wherever both exist, so without this host the artifact path is built but
    # never exercised, and "clusters on tradecraft" would be an assumption.
    dc = [l for l in qlinks if "DC-101" in (l.host_a, l.host_b)]
    chk(bool(dc), "DC-101 is linked into the campaign despite no movement to it")
    if dc:
        top_kinds = {l.factors.get("top", {}).get("kind") for l in dc}
        chk(top_kinds == {"artifact"},
            f"DC-101's link is carried by a shared ARTIFACT — the tradecraft path, proven ({top_kinds})")
        names = {l.factors.get("top", {}).get("value", "") for l in dc}
        chk(any("WinDefendHelper" in n for n in names),
            f"the linking artifact is the actor's persistence service name ({sorted(names)})")

    qc = Campaign.objects.filter(run=b).first()
    qhosts = set(qc.hosts.values_list("hostname", flat=True)) if qc else set()
    chk(qhosts >= QUIET,
        f"Quiet Fox clusters all four hosts despite per-host C2 and hashes ({sorted(qhosts)})")
PYEOF
)

# The banding truth table runs first in the app's own tests (pure logic over link weights); this
# section then asserts the bands the deployed engine actually assigned.
say "L3 — banding truth table"
BAND_TESTS=$(be python3 -c "
import os, sys, unittest, django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ir_platform.settings'); django.setup()
res = unittest.main(module='correlation.tests', exit=False, argv=['x'], verbosity=0).result
print(f'{res.testsRun} run, {len(res.failures)} failed, {len(res.errors)} errored')
sys.exit(0 if res.wasSuccessful() else 1)
" 2>/dev/null | tail -1)
if [[ -n "${BAND_TESTS}" && "${BAND_TESTS}" == *"0 failed, 0 errored"* ]]; then
    ok "correlation banding truth table: ${BAND_TESTS}"
else
    bad "correlation banding truth table FAILED (${BAND_TESTS:-no output}) — reproduce with:"
    bad "  ${RUNTIME} exec -it ${BE} python3 -m unittest correlation.tests -v"
fi

say "L3 — membership confidence decomposes into the evidence that produced it"
while read -r line; do
    case "${line}" in
        PASSCHK*) ok "${line#PASSCHK }" ;;
        FAILCHK*) bad "${line#FAILCHK }" ;;
        INFOCHK*) info "${line#INFOCHK }" ;;
    esac
done < <(be python3 - <<'PYEOF' 2>/dev/null
import os, django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ir_platform.settings"); django.setup()
from cases.models import Investigation
from correlation.models import CampaignHost, CorrelationRun, HostLink

def chk(cond, label):
    print(("PASSCHK " if cond else "FAILCHK ") + label)

runs = {}
for inv in Investigation.objects.filter(incident_id__in=("INC-CORPUS-A", "INC-CORPUS-B")):
    r = CorrelationRun.objects.filter(investigation_id=inv.id, is_current=True).first()
    if r:
        runs[inv.incident_id] = r
a, b = runs.get("INC-CORPUS-A"), runs.get("INC-CORPUS-B")
BANDS = {"confirmed", "probable", "possible", "indeterminate"}
ORDER = {"confirmed": 3, "probable": 2, "possible": 1, "indeterminate": 0}

hosts_a = list(CampaignHost.objects.filter(campaign__run=a)) if a else []
hosts_b = list(CampaignHost.objects.filter(campaign__run=b)) if b else []
allh = hosts_a + hosts_b

chk(bool(allh) and all(h.confidence_band in BANDS for h in allh),
    f"every campaign host carries a band from the declared vocabulary ({len(allh)} hosts)")

# The exit criterion: a label nobody can take apart is not evidence.
NAMED = {"band", "best_link", "evidence_kinds", "corroboration", "temporal",
         "contradiction", "why"}
chk(bool(allh) and all(NAMED <= set(h.confidence_factors or {}) for h in allh),
    "every band decomposes into its named factors, not just a label")

linked_hosts = [h for h in allh if (h.confidence_factors or {}).get("best_link")]
chk(bool(linked_hosts) and all(
        (h.confidence_factors["best_link"] or {}).get("with") and
        (h.confidence_factors["best_link"] or {}).get("weight") is not None
        for h in linked_hosts),
    f"each band names the host and the weight it rests on ({len(linked_hosts)} linked hosts)")

# A band must be REACHED, not merely declared: a scale nothing attains is decorative.
chk("confirmed" in {h.confidence_band for h in hosts_a},
    f"the Ember intrusion reaches the top band ({sorted({h.confidence_band for h in hosts_a})})")

# The contradiction. Movement out of JUMP-101 is recorded BEFORE anything compromised it,
# so SRV-FILE-101 — the host that edge reaches — must not read as settled membership.
srv = next((h for h in hosts_b if h.hostname == "SRV-FILE-101"), None)
peers = [h for h in hosts_b if h.hostname != "SRV-FILE-101"]
if srv and peers:
    top_peer = max(peers, key=lambda h: ORDER[h.confidence_band])
    chk(ORDER[srv.confidence_band] < ORDER[top_peer.confidence_band],
        f"the contradiction host bands BELOW its peers "
        f"({srv.confidence_band} vs {top_peer.confidence_band} on {top_peer.hostname})")
    chk("contradict" in (srv.confidence_factors or {}).get("why", "").lower(),
        "and the stated reason names the contradiction rather than only scoring it lower")
else:
    chk(False, "SRV-FILE-101 and its peers are present in the Quiet Fox campaign")

# Bands are READ FROM the links, so they must agree with them: no host may outrank one
# whose strongest accepted link is stronger.
if a:
    links = [l for l in HostLink.objects.filter(run=a, linked=True)]
    def best_of(name):
        w = [l.weight for l in links if name in (l.host_a, l.host_b)]
        return max(w) if w else None
    ranked = [(best_of(h.hostname), ORDER[h.confidence_band], h.hostname)
              for h in hosts_a if best_of(h.hostname) is not None]
    inversions = [(n1, n2) for w1, o1, n1 in ranked for w2, o2, n2 in ranked
                  if w1 + 1e-9 < w2 and o1 > o2]
    chk(not inversions,
        f"no host outranks one with a stronger link ({len(ranked)} compared, "
        f"{len(inversions)} inversions)")

# An unlinked host must not be banded as though it had been measured.
unlinked = [h for h in allh if not (h.confidence_factors or {}).get("best_link")]
chk(all(h.confidence_band == "indeterminate" for h in unlinked),
    f"a host with no cross-host link reads INDETERMINATE, not weak ({len(unlinked)} such)")
PYEOF
)

# ---------------------------------------------------------------- indicator completeness
say "Indicator completeness — nothing recovered is stranded before correlation"
while read -r line; do
    case "${line}" in
        PASSCHK*) ok "${line#PASSCHK }" ;;
        FAILCHK*) bad "${line#FAILCHK }" ;;
    esac
done < <(be python3 - <<'PYEOF' 2>/dev/null
import os, django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ir_platform.settings"); django.setup()
from cases.models import Investigation
from correlation.models import BehaviorNode, CorrelationRun, HostLink

def chk(cond, label):
    print(("PASSCHK " if cond else "FAILCHK ") + label)

runs = {}
for inv in Investigation.objects.filter(incident_id__in=("INC-CORPUS-A", "INC-CORPUS-B")):
    r = CorrelationRun.objects.filter(investigation_id=inv.id, is_current=True).first()
    if r:
        runs[inv.incident_id] = r
a, b = runs.get("INC-CORPUS-A"), runs.get("INC-CORPUS-B")

# Each of these is emitted by a different producer — memory enrichment, MWCP config
# extraction, the reverse engineer — and each was invisible to correlation when the graph
# read a fixed three-key list. An indicator the engine cannot see cannot link anything.
for label, kind, subkind, frag in (
        ("the implant's user-agent", "indicator", "user_agent", "EmberSync"),
        ("the implant's mutex", "indicator", "mutex", "1BA6BD98D9"),
        ("the extracted C2 campaign id", "artifact", "c2_campaign_id", "EF-2026"),
        ("the YARA rule that matched", "artifact", "yara_rule", "EmberFox"),
        ("the attributed malware family", "artifact", "malware_family", "EmberFox")):
    node = BehaviorNode.objects.filter(run=a, kind=kind, subkind=subkind,
                                       value__icontains=frag).first() if a else None
    chk(bool(node), f"{label} reaches the graph as a {subkind} node"
                    + (f" on {node.host_count} hosts" if node else ""))

# The reverse engineer's recovered infrastructure and key material: held only on the
# RegionAnalysis row they never reached an indicator index at all.
for label, subkind, frag in (
        ("RE-recovered C2 infrastructure", "network_indicator", "cdn-telemetry"),
        ("RE-recovered wallet", "crypto_material", "bc1qe4mb3rf0x")):
    node = BehaviorNode.objects.filter(run=b, kind="indicator", subkind=subkind,
                                       value__icontains=frag).first() if b else None
    chk(bool(node), f"{label} reaches the graph ({subkind})")

# The point of all of it: an indicator shared across endpoints must CARRY a link. Quiet Fox
# rotates every address, so the builder-fixed user-agent and mutex are the shared material,
# and they must appear as corroboration on real links rather than sitting unused.
if b:
    ua = BehaviorNode.objects.filter(run=b, kind="indicator", subkind="user_agent").first()
    chk(bool(ua) and ua.host_count >= 3,
        f"the user-agent is shared across Quiet Fox endpoints ({ua.host_count if ua else 0} hosts on one node)")
    carried = set()
    for l in HostLink.objects.filter(run=b):
        carried.update(l.factors.get("evidence_kinds", []))
    chk({"user_agent", "mutex"} <= carried,
        f"the shared user-agent and mutex are CARRIED as link evidence ({sorted(carried)})")

# ROLLUP — what a finding recovered must reach the HOST's IOC index, not only the graph: 'which
# other hosts carry this mutex' is the question that survives archival.
from django.db.models import Count
from cases.models import IOC as IOCRow, CollectionRun
for host, want in (("WS-007", {"user_agent", "mutex", "pipe", "ja3", "registry_key"}),
                   ("WS-101", {"user_agent", "mutex", "malware_family", "yara_rule"})):
    types = set(IOCRow.objects.filter(run__host__hostname=host)
                .values_list("ioc_type", flat=True))
    chk(want <= types,
        f"{host}: the implant's identifying material is in its IOC index (missing: {sorted(want - types)})")
# The C2 config's ADDRESS is pivotable and belongs in the index; its sleep interval is not an
# indicator and must not be, or the index fills with timing values nobody searches.
chk(IOCRow.objects.filter(ioc_type="domain", value="updates.cdn-telemetry.net").exists(),
    "the extracted C2 address is in the IOC index (deduplicated against the hunt's own row)")
chk(IOCRow.objects.filter(context__origin="config_extracted").exists(),
    "config-recovered fields reach the index with their provenance recorded")
chk(not IOCRow.objects.filter(context__field="sleep").exists(),
    "the config's sleep interval is NOT indexed — it identifies nothing")
# Deduplication keeps the index readable: one row per (type, value) per RUN, however many
# findings carried it. Scoped to a run, not a hostname — hostnames repeat across
# investigations (this corpus and the older seed both have a WS-007, distinct machine-ids
# and therefore distinct hosts), so a hostname filter counts two cases' evidence as one
# host's duplicates.
if a:
    corpus_run = (CollectionRun.objects
                  .filter(investigation_id=a.investigation_id, host__hostname="WS-007")
                  .order_by("-id").first())
    dupes = (IOCRow.objects.filter(run=corpus_run)
             .values("ioc_type", "value").annotate(n=Count("id")).filter(n__gt=1).count()
             if corpus_run else -1)
    chk(dupes == 0, f"no indicator is indexed twice within a run ({dupes} duplicated)")
# Cross-host pivot: the builder-fixed mutex must return every host running that implant.
mutex_hosts = set(IOCRow.objects.filter(ioc_type="mutex")
                  .values_list("run__host__hostname", flat=True))
chk(len(mutex_hosts) >= 8,
    f"the shared mutex pivots across the campaign's hosts ({len(mutex_hosts)} hosts)")

# The rolled-up rows must not SPLIT a determination. Family arrives both as a finding field
# and as an IOC row now; if the graph filed the row as an indicator it would sit beside the
# artifact node carrying the same value, each with half the evidence.
split = BehaviorNode.objects.filter(run__in=[r for r in (a, b) if r],
                                    kind="indicator",
                                    subkind__in=["malware_family", "yara_rule", "campaign_id"])
chk(not split.exists(),
    f"attribution stays ONE node per determination, not split across kinds ({split.count()} strays)")

# COVERAGE — every indicator kind the extractor DECLARES is exercised by this corpus.
# Derived from the code, never a hand list: a key added to the vocabulary without a corpus
# exerciser fails here, which is what keeps "all fields populate" true over time rather
# than true on the day it was checked.
from correlation.behavior import SCALAR_INDICATORS, LIST_INDICATORS
live = [r for r in (a, b) if r]
required = set(SCALAR_INDICATORS.values()) | set(LIST_INDICATORS.values())
present = set(BehaviorNode.objects.filter(run__in=live, kind="indicator")
              .values_list("subkind", flat=True))
missing = sorted(required - present)
chk(not missing,
    f"every declared indicator kind populates ({len(required) - len(missing)}/{len(required)}"
    + (f"; missing: {missing}" if missing else "") + ")")
# The MWCP config fields the scenarios recover, each a first-class c2_* artifact.
for ck in ("campaign_id", "sleep", "address", "port"):
    chk(BehaviorNode.objects.filter(run__in=live, kind="artifact",
                                    subkind=f"c2_{ck}").exists(),
        f"MWCP config field '{ck}' populates as artifact/c2_{ck}")
PYEOF
)

# ---------------------------------------------------------------- behavior graph (L0)
say "Behavior graph — tradecraft is a first-class node, traceable to its findings"
while read -r line; do
    case "${line}" in
        PASSCHK*) ok "${line#PASSCHK }" ;;
        FAILCHK*) bad "${line#FAILCHK }" ;;
    esac
done < <(be python3 - <<'PYEOF' 2>/dev/null
import os, django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ir_platform.settings"); django.setup()
from cases.models import Investigation
from correlation.models import BehaviorEvent, BehaviorNode, CorrelationRun

runs = {}
for inv in Investigation.objects.filter(incident_id__in=("INC-CORPUS-A", "INC-CORPUS-B")):
    r = CorrelationRun.objects.filter(investigation_id=inv.id, is_current=True).first()
    if r:
        runs[inv.incident_id] = r

def chk(cond, label):
    print(("PASSCHK " if cond else "FAILCHK ") + label)

a, b = runs.get("INC-CORPUS-A"), runs.get("INC-CORPUS-B")
chk(bool(a and b), "both corpus investigations carry a current graph-bearing run")
if a and b:
    na, nb = a.behavior_nodes.count(), b.behavior_nodes.count()
    chk(na > 0 and nb > 0, f"graphs populated (A: {na} nodes, B: {nb} nodes)")

    # The actor's persistence task name spans hosts WITHIN Ember Fox — a behavioral link
    # that exists with no shared indicator involved.
    task = a.behavior_nodes.filter(kind="artifact", subkind="persistence_task",
                                   value__contains="UpdateOrchestrator").first()
    chk(bool(task and task.host_count >= 2),
        f"persistence task name spans {task.host_count if task else 0} Ember hosts as ONE artifact node")

    # The same artifact value exists in Quiet Fox's graph: the cross-run comparability
    # fingerprinting consumes — same actor, rotated indicators, identical tradecraft.
    btask = b.behavior_nodes.filter(kind="artifact", subkind="persistence_task",
                                    value__contains="UpdateOrchestrator").exists()
    chk(btask, "the SAME persistence artifact appears in Quiet Fox's graph (rotated indicators, identical tradecraft)")

    # The fleet agent hash is on (nearly) every Ember-world host, and the graph must show
    # it as environment-wide — that population figure is what rarity weighting divides by.
    agent = a.behavior_nodes.filter(kind="indicator", subkind="hash").order_by("-host_count").first()
    chk(bool(agent and agent.host_count >= 15),
        f"fleet-wide benign hash visible as environment ({agent.host_count if agent else 0} hosts on one node)")

    # Traceability: every finding-derived event names its source finding.
    untraced = BehaviorEvent.objects.filter(run__in=[a, b], source_finding_id__isnull=True) \
                                    .exclude(detail__has_key="from").count()
    chk(untraced == 0, "every finding-derived event is traceable to its custody-sealed finding")
PYEOF
)

# ---------------------------------------------------------------- L4/L5 tradecraft
say "L4/L5 — fingerprints built from behavior, attribution kept advisory"
while read -r line; do
    case "${line}" in
        PASSCHK*) ok "${line#PASSCHK }" ;;
        FAILCHK*) bad "${line#FAILCHK }" ;;
        INFOCHK*) info "${line#INFOCHK }" ;;
    esac
done < <(be python3 - <<'PYEOF' 2>/dev/null
import os, django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ir_platform.settings"); django.setup()
from cases.models import Investigation
from correlation.models import (ActorProfile, AttributionCandidate, CampaignFingerprint,
                                CampaignSimilarity, CorrelationRun)

def chk(cond, label):
    print(("PASSCHK " if cond else "FAILCHK ") + label)

runs = {}
for inv in Investigation.objects.filter(incident_id__in=("INC-CORPUS-A", "INC-CORPUS-B")):
    r = CorrelationRun.objects.filter(investigation_id=inv.id, is_current=True).first()
    if r:
        runs[inv.incident_id] = r
a, b = runs.get("INC-CORPUS-A"), runs.get("INC-CORPUS-B")

fps = list(CampaignFingerprint.objects.filter(run__in=[r for r in (a, b) if r]))
chk(bool(fps), f"every campaign got a fingerprint ({len(fps)})")

# Built from BEHAVIOR. Quiet Fox rotated every indicator per host, so if a fingerprint
# were resting on indicators it would have nothing to say about that campaign at all.
qfp = [f for f in fps if b and f.run_id == b.id]
chk(bool(qfp) and any(f.techniques for f in qfp),
    "Quiet Fox has a fingerprint despite per-host rotated indicators")

# The naming convention is the SHAPE, not the name: an actor who renames between
# engagements keeps the habit, and matching the literal name would miss exactly that.
convs = [c for f in fps for c in (f.artifact_conventions or [])]
chk(any("<" in c for c in convs),
    f"artifact conventions are name SHAPES, not literal names ({convs[:3]})")

# A vector nobody can decompose cannot explain an attribution.
chk(all({"techniques", "technique_ngrams", "artifact_conventions",
         "c2_pattern", "account_chain", "basis"} <= set(
            {"techniques": f.techniques, "technique_ngrams": f.technique_ngrams,
             "artifact_conventions": f.artifact_conventions, "c2_pattern": f.c2_pattern,
             "account_chain": f.account_chain, "basis": f.basis})
        for f in fps),
    "each fingerprint carries all five named components plus its basis")

# A thin fingerprint must SAY it is thin rather than read as an actor with no tradecraft.
chk(all("sufficient" in (f.basis or {}) for f in fps),
    "every fingerprint states whether it carries enough tradecraft to compare")

# Attribution is advisory and nothing writes an actor onto the case.
cands = list(AttributionCandidate.objects.filter(run__in=[r for r in (a, b) if r]))
chk(all(c.source == "heuristic" for c in cands),
    f"every attribution candidate is marked heuristic ({len(cands)})")
chk(all(c.rationale.get("components") is not None for c in cands),
    "every candidate carries a per-component rationale, not just a score")
if ActorProfile.objects.exists():
    chk(True, f"the staged actor library is loaded ({ActorProfile.objects.count()} profiles)")
else:
    print("INFOCHK no actor profiles staged — run seed_actor_profiles; L5 has nothing to rank against")

# Cross-investigation similarity: Ember and Quiet Fox are different actors and must not
# read as the same one. The corpus is the control for this measure.
sims = list(CampaignSimilarity.objects.filter(run__in=[r for r in (a, b) if r]))
chk(all(s.score < 0.9 for s in sims),
    f"no two different corpus campaigns are scored near-identical ({max([s.score for s in sims], default=0)})")
chk(all(s.rationale.get("components") for s in sims),
    "every similarity names the components it rests on")
PYEOF
)

# Render path: everything above reads the DATABASE; this drives the UI's own endpoints so evidence
# proven landed is also proven REACHABLE.
say "Render path — the values the collector planted reach the API the UI calls"
while read -r line; do
    case "${line}" in
        PASSCHK*) ok "${line#PASSCHK }" ;;
        FAILCHK*) bad "${line#FAILCHK }" ;;
        INFOCHK*) info "${line#INFOCHK }" ;;
    esac
done < <(be python3 - <<'PYEOF' 2>/dev/null
import json, os, urllib.request, django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ir_platform.settings"); django.setup()
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
from cases.models import Investigation
from correlation.models import Campaign, CorrelationRun

def chk(cond, label):
    print(("PASSCHK " if cond else "FAILCHK ") + label)

admin = User.objects.filter(is_superuser=True).first()
TOKEN = Token.objects.get_or_create(user=admin)[0].key

def api(path):
    req = urllib.request.Request(
        "http://127.0.0.1:8000/api" + path,
        headers={"Authorization": "Token " + TOKEN})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())

# The exact strings planted at the endpoint in test/corpus/scenarios.py.
PERSIST_SVC, PERSIST_TASK = "WinDefendHelper", "\\Microsoft\\Windows\\UpdateOrchestrator\\Sync"
CAMPAIGN_ID, STAGING = "EF-2026-Q3", "_archive.7z"

inv = Investigation.objects.filter(incident_id="INC-CORPUS-A").first()
run = CorrelationRun.objects.filter(investigation_id=inv.id, is_current=True).first() if inv else None
camp = Campaign.objects.filter(run=run).order_by("-host_count").first() if run else None
if not camp:
    chk(False, "the Ember campaign is reachable for a render-path check")
else:
    tc = api(f"/correlation/campaigns/{camp.id}/tradecraft/")
    fp = tc.get("fingerprint") or {}
    blob = json.dumps(fp)

    # A served field, not merely a stored one.
    seq = fp.get("technique_sequence") or []
    chk(bool(seq), f"the API serves the technique SEQUENCE, not only the id-sorted set ({len(seq)})")
    chk(seq and seq != sorted(seq),
        f"and it is a real order rather than the set relabeled ({' > '.join(seq[:4])}...)")
    chk(seq and seq[0].startswith("T1566"),
        f"which starts at the initial access the scenario planted ({seq[0] if seq else '-'})")

    # The collected values behind the abstractions. This is the whole claim: the shapes on
    # the page are computed from evidence this deployment collected, not rendered from
    # placeholders.
    ex = fp.get("convention_examples") or {}
    served = {v.get("example") for v in ex.values() if isinstance(v, dict)}
    for planted, what in ((CAMPAIGN_ID, "the MWCP-extracted campaign id"),
                          (STAGING, "the staging archive name")):
        chk(planted in served,
            f"{what} the collector planted is served as the example behind its shape "
            f"({planted})")

    # NOT every planted value becomes a convention: `WinDefendHelper` abstracts to a pattern matching
    # every CamelCase Windows name, and a convention that matches everything identifies nothing.
    chk(PERSIST_SVC not in served,
        f"a generic name shape is refused as a convention while the value still links "
        f"hosts ({PERSIST_SVC})")

    chk(any("<number>" in c for c in fp.get("artifact_conventions") or []),
        "and the shape beside it is an abstraction, so rotation is what it survives")
    chk(all(isinstance(v, dict) and v.get("hosts") for v in ex.values()),
        f"every example states how many hosts carried it ({len(ex)} conventions)")

    # File extensions are format, not name: abstracting them destroys the shape.
    chk(not any("<number>z" in c for c in fp.get("artifact_conventions") or []),
        "an archive extension survives abstraction intact (.7z is not read as digits)")

    # The graph the page draws, over HTTP, carrying the same planted tradecraft.
    g = api(f"/correlation/campaigns/{camp.id}/graph/")
    chk(bool(g.get("nodes")) and bool(g.get("edges")),
        f"the attack graph endpoint is populated "
        f"({len(g.get('nodes') or [])} nodes, {len(g.get('edges') or [])} edges)")

    # Behavioral edges are the tradecraft path — hosts tied by a shared artifact rather than observed
    # movement. Asserted on QUIET FOX, where every linked pair rests on behavior alone.
    inv_b = Investigation.objects.filter(incident_id="INC-CORPUS-B").first()
    run_b = CorrelationRun.objects.filter(investigation_id=inv_b.id, is_current=True).first() if inv_b else None
    camp_b = Campaign.objects.filter(run=run_b).order_by("-host_count").first() if run_b else None
    if not camp_b:
        chk(False, "the Quiet Fox campaign is reachable for a render-path check")
    else:
        gb = api(f"/correlation/campaigns/{camp_b.id}/graph/")
        beh = gb.get("behavioral_edges") or []
        carried = {(e.get("top_factor") or {}).get("value") for e in beh}
        chk(bool(beh),
            f"the tradecraft-only campaign renders behavioral edges ({len(beh)})")
        chk(any(v in (PERSIST_TASK, PERSIST_SVC, CAMPAIGN_ID) for v in carried if v),
            f"and one is carried by tradecraft the collector planted "
            f"({sorted(v for v in carried if v)[:2]})")

    # Movement edges name the account the collector recorded on the session.
    accounts = {e.get("account") for e in (g.get("edges") or []) if e.get("account")}
    chk(any(a.startswith("CORP\\") for a in accounts),
        f"movement edges name the collected account, not a placeholder ({sorted(accounts)[:2]})")

    # Every host on the page can state why it is there.
    banded = [n for n in (g.get("nodes") or []) if n.get("confidence_band")]
    chk(bool(banded) and all((n.get("confidence_factors") or {}).get("why") for n in banded),
        f"every banded host on the graph carries its stated reason ({len(banded)})")
PYEOF
)

rm -rf "${SCEN}"

# ---------------------------------------------------------------- summary
say "Result"
if [[ "${FAILED}" == "0" ]]; then
    ok "the corpus rode the production path end to end, and benign stayed benign"
else
    bad "corpus run does NOT hold — see failures above"
fi
report_finish
exit "${FAILED}"
