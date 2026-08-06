#!/usr/bin/env bash
# ==============================================================================
# CORPUS L — 22 Linux endpoints, "Rust Fox", through the REAL pipeline.
#
# The second attack shape. Corpus v2 is a Windows intrusion, and every threshold in the
# correlation engine was calibrated while it was the only dataset. This one changes the
# platform underneath those thresholds:
#
#   - the Linux hunts' own finding vocabulary (Systemd Persistence, Cron Persistence,
#     Shell Init Backdoor, Library Preload Hijack, Webshell, SSH Authorized Key)
#   - Linux adjudication's verdict ceiling — its highest-fidelity types return LIKELY True
#     Positive, so nothing here reaches the top of the ladder
#   - Unix accounts, with root on all 22 hosts
#   - no shared C2: each host egresses somewhere different, so the campaign has to hold
#     together on tradecraft and movement alone
#
# Two hosts are reached with NO movement record. They are members or they are not, and
# nothing but the artifact path can put them there.
#
# Seeds INC-CORPUS-L; re-running supersedes its correlation run. Scenario data is declared
# synthetic in the bundle itself (_scenario.json).
# ==============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"

. "${HERE}/lib/report.sh"
report_begin 61 corpus_linux "Corpus L — 22 Linux endpoints, end to end" \
    "A Linux-native intrusion correlates through the production path on the Linux hunts' own vocabulary and verdict ceiling: persistence names reach the graph, two hosts reached without any movement record join on tradecraft alone, an unrelated compromise on the same fleet stays separate, and the estate's own units and accounts bind nothing."

CORPUS_PREFIX=INC-CORPUS-L
CORPUS_COUNT=22
CORPUS_MANIFEST=/tmp/corpus-linux-manifest.json
. "${HERE}/lib/corpus_pipeline.sh"

set -a; . "${PLATFORM}/deploy/.env" 2>/dev/null || true; set +a

corpus_preconditions

SCEN="$(mktemp -d)"
python3 "${HERE}/corpus/linux.py" "${SCEN}" >/dev/null \
    && ok "${CORPUS_COUNT} Linux endpoint scenarios generated" \
    || { bad "scenario generation failed"; report_finish; exit 1; }

# The assertion blocks run inside the backend and read the manifest to compare the deployment
# against what was planted. Comparing against values retyped into this script instead would
# let the dataset and the test drift apart silently, each still green.
${RUNTIME} cp "${SCEN}/manifest.json" "${BE}:${CORPUS_MANIFEST}" 2>/dev/null \
    && ok "manifest published to the backend for comparison" \
    || { bad "could not publish the manifest to ${BE}"; report_finish; exit 1; }

corpus_reset
corpus_receiver_addr

say "Collection — ${CORPUS_COUNT} real collector runs, shipped from the edge"
corpus_collect_and_ship "${SCEN}"

say "Ingest — the puller delivers all ${CORPUS_COUNT} runs"
corpus_await_ingest

say "Analysis — every capture is analyzed and adjudicated before compromise is read"
corpus_await_analysis
corpus_assert_analysis_ran

say "Correlation"
corpus_correlate

# ---------------------------------------------------------------- classification
say "Classification — the Linux verdict ceiling still separates compromised from clean"
corpus_checks <<'PYEOF'
from cases.models import CollectionRun, Finding

m = manifest()
runs = {r.host.hostname: r for r in CollectionRun.objects.filter(
    investigation__incident_id=PREFIX).select_related("host")}

got_comp = sorted(h for h, r in runs.items() if r.compromised)
got_clean = sorted(h for h, r in runs.items() if not r.compromised)
chk(got_comp == m["compromised"],
    f"{len(m['compromised'])} endpoints classify compromised, exactly the planted set"
    + ("" if got_comp == m["compromised"] else f" — got {got_comp}"))
chk(got_clean == m["clean"],
    f"{len(m['clean'])} endpoints classify clean despite carrying the full fleet baseline"
    + ("" if got_clean == m["clean"] else f" — got {got_clean}"))

# The ceiling itself: if any Linux finding arrived as True Positive the dataset is not
# modelling what the Linux hunts produce, and every weight below is measuring something else.
verdicts = set(Finding.objects.filter(
    run__investigation__incident_id=PREFIX).values_list("verdict", flat=True))
chk("True Positive" not in verdicts,
    f"no finding reaches True Positive — Linux adjudication's ceiling is intact ({sorted(verdicts)})")

# A likely-false-positive finding is not a compromise. The fleet's packaged SUID binary is
# unmodified on all 22 hosts and sits on the clean ones too.
lfp = Finding.objects.filter(run__investigation__incident_id=PREFIX,
                             verdict="Likely False Positive").count()
chk(lfp == COUNT,
    f"the fleet's packaged SUID binary is adjudicated a likely false positive on every host ({lfp})")
PYEOF

# ---------------------------------------------------------------- the behavior graph
say "L0 — Linux tradecraft reaches the graph as artifacts, named by what the actor chose"
corpus_checks <<'PYEOF'
from cases.models import Investigation
from correlation.models import BehaviorNode, CorrelationRun

m = manifest()
inv = Investigation.objects.filter(incident_id=PREFIX).first()
run = CorrelationRun.objects.filter(investigation_id=inv.id, is_current=True).first() if inv else None


def node(subkind, value):
    return BehaviorNode.objects.filter(run=run, kind="artifact", subkind=subkind,
                                       value=value).first() if run else None


# Each of these is a finding type the Linux hunts emit and the graph did not map. An unmapped
# type contributes no artifact at all, so the name it carries — the one thing an actor keeps
# between engagements — never reaches linkage or the fingerprint.
for subkind, value, label in (
        ("persistence_service", m["persistence_unit"], "the persistence unit"),
        ("persistence_cron", "certbot-renew-helper", "the cron entry"),
        ("persistence_shell_init", "00-locale-fix.sh", "the shell-init backdoor"),
        ("persistence_preload", "libnss_cache.so.2", "the preloaded library"),
        ("webshell", ".sess_handler.php", "the webshell"),
        ("kernel_module", "nf_conntrack_helper.ko", "the kernel module")):
    n = node(subkind, value)
    chk(bool(n), f"{label} is an artifact node valued '{value}'"
                 + (f" on {n.host_count} host(s)" if n else " — MISSING"))

# The unit is named by the unit, not by the directory systemd requires it to live in.
paths = BehaviorNode.objects.filter(run=run, kind="artifact", subkind="persistence_service",
                                    value__startswith="/etc/") if run else []
chk(not paths,
    "no persistence artifact carries its mandatory directory — the path is the platform's, the name is the actor's")

# A payload's directory IS the choice, so that one keeps its path.
payload = BehaviorNode.objects.filter(run=run, kind="artifact", subkind="payload_path",
                                      value__contains="/dev/shm/").first() if run else None
chk(bool(payload), "the payload keeps the directory it was placed in"
                   + (f" ({payload.value})" if payload else ""))

# The estate's own units must be visible AS fleet-wide, or the rarity floor has nothing to
# measure the actor's against.
for unit in (m["fleet_unit"], m["fleet_unit_same_shape"]):
    n = node("persistence_service", unit)
    chk(bool(n) and n.host_count == COUNT,
        f"the estate's own {unit} is on all {n.host_count if n else 0} hosts, not a rare artifact")
PYEOF

# ---------------------------------------------------------------- campaign membership
say "L1/L2 — the campaign holds together, including the hosts no movement record reaches"
corpus_checks <<'PYEOF'
from cases.models import Investigation
from correlation.models import Campaign, CampaignHost, CorrelationRun, HostLink

m = manifest()
inv = Investigation.objects.filter(incident_id=PREFIX).first()
run = CorrelationRun.objects.filter(investigation_id=inv.id, is_current=True).first() if inv else None
camps = list(Campaign.objects.filter(run=run).order_by("-host_count")) if run else []

if not camps:
    chk(False, "Rust Fox forms a campaign at all")
else:
    main = camps[0]
    members = sorted(CampaignHost.objects.filter(campaign=main).values_list("hostname", flat=True))
    expected = m["campaign_hosts"]
    chk(members == expected,
        f"all {len(expected)} Rust Fox hosts are one campaign"
        + ("" if members == expected else f" — got {members}"))

    # The point of the shape: two hosts have no movement record on either side, so the
    # artifact path is the only thing that can reach them.
    for host in m["tradecraft_only_hosts"]:
        ch = CampaignHost.objects.filter(campaign=main, hostname=host).first()
        chk(bool(ch), f"{host} is a member with no movement record anywhere")
        best = (ch.confidence_factors or {}).get("best_link") if ch else None
        if best:
            chk(best.get("kind") != "movement",
                f"and it is held by {best.get('subkind') or best.get('kind')} evidence, "
                f"not movement (weight {best.get('weight')})")

    # The disjoint compromise. It is real, adjudicated and on the same fleet, and it shares
    # nothing with Rust Fox but the estate's own baseline — plus one routine admin session.
    for host in m["disjoint_hosts"]:
        chk(not CampaignHost.objects.filter(campaign=main, hostname=host).exists(),
            f"{host} — an unrelated compromise on the same fleet — does not join Rust Fox")

    # The trap that puts it there if movement ignores its verdict: one Indeterminate SSH
    # session from a campaign member to a workstation carrying that other compromise.
    src, dst = m["admin_hop"]
    key = (src, dst) if src < dst else (dst, src)
    hop = HostLink.objects.filter(run=run, host_a=key[0], host_b=key[1]).first()
    if hop:
        top = (hop.factors or {}).get("top") or {}
        chk(not hop.linked,
            f"the routine {src} -> {dst} admin session is DECLINED "
            f"(weight {hop.weight}, verdict factor {top.get('verdict_weight')})")
    else:
        chk(True, f"the {src} -> {dst} admin session never became a candidate pair")

    # Nothing clean may be in any campaign, however much fleet baseline it carries.
    everywhere = set(CampaignHost.objects.filter(campaign__run=run).values_list("hostname", flat=True))
    strays = sorted(everywhere & set(m["clean"]))
    chk(not strays, f"no clean endpoint appears in any campaign ({len(m['clean'])} clean)"
                    + (f" — strays: {strays}" if strays else ""))

    # The ubiquitous account is on all 22 hosts and is also the account the intrusion uses.
    # Rarity has to carry that on its own.
    joined = [l for l in HostLink.objects.filter(run=run, linked=True)
              if ((l.factors or {}).get("top") or {}).get("value") == m["ubiquitous_account"]]
    chk(not joined,
        f"no pair is joined by '{m['ubiquitous_account']}', present on every host in the estate")

    chk(main.patient_zero == "web-edge-02",
        f"patient zero is the exposed web host ({main.patient_zero})")
PYEOF

# ---------------------------------------------------------------- fingerprint
say "L4 — the fingerprint is the actor's habits, not the distribution's"
corpus_checks <<'PYEOF'
import urllib.request
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
from cases.models import Investigation
from correlation.models import Campaign, CorrelationRun

m = manifest()
admin = User.objects.filter(is_superuser=True).first()
TOKEN = Token.objects.get_or_create(user=admin)[0].key


def api(path):
    req = urllib.request.Request("http://127.0.0.1:8000/api" + path,
                                 headers={"Authorization": "Token " + TOKEN})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


inv = Investigation.objects.filter(incident_id=PREFIX).first()
run = CorrelationRun.objects.filter(investigation_id=inv.id, is_current=True).first() if inv else None
camp = Campaign.objects.filter(run=run).order_by("-host_count").first() if run else None

if not camp:
    chk(False, "the Rust Fox campaign is reachable for a fingerprint check")
else:
    # Over HTTP, because a value that is stored but not served renders as a blank panel.
    fp = (api(f"/correlation/campaigns/{camp.id}/tradecraft/") or {}).get("fingerprint") or {}
    conventions = fp.get("artifact_conventions") or []
    examples = fp.get("convention_examples") or {}
    blob = json.dumps(fp)

    chk(bool(conventions),
        f"the campaign has naming conventions at all ({len(conventions)}): {conventions[:4]}")

    # One of these ships with the distribution and reduces to exactly the shape the actor's
    # unit does. Only the rarity floor separates them.
    for unit in (m["fleet_unit"], m["fleet_unit_same_shape"]):
        chk(unit not in blob, f"the estate's {unit} is not reported as this actor's tradecraft")

    unit_shape = "persistence_service:<name>-<name>.service"
    chk(unit_shape in conventions, f"the actor's unit naming habit is reported ({unit_shape})")
    ex = (examples.get(unit_shape) or {}).get("example")
    chk(ex == m["persistence_unit"],
        f"and it names the collected value it was abstracted from ({ex})")

    # A Linux campaign's kill chain, ordered by observation. T1190 is the entry.
    seq = fp.get("technique_sequence") or []
    chk(bool(seq) and seq[0] == "T1190",
        f"the technique sequence opens on the exploited service ({seq[:5]})")

    # Movement was SSH throughout, and the estate is administered over SSH too — so the
    # protocol alone must not be what identifies the actor.
    c2 = fp.get("c2_pattern") or {}
    chk(c2.get("movement_protocols") == ["SSH"],
        f"movement is recorded as SSH ({c2.get('movement_protocols')})")

    # Unix accounts carry no domain part. The component must be empty rather than absent: a
    # missing key and an empty one read the same in a panel and mean different things.
    chain = fp.get("account_chain") or {}
    chk("domain_style" in chain and not chain["domain_style"],
        "the account shape records no domain style, because Unix accounts have none")
PYEOF

# ---------------------------------------------------------------- cross-corpus
say "L5 / population — an unrelated fleet in the same deployment changes nothing"
corpus_checks <<'PYEOF'
from cases.models import CollectionRun, Host, Investigation
from correlation.models import Campaign, CampaignHost, CorrelationRun

m = manifest()

# Rarity divides by the DEPLOYMENT's host population, so the Windows corpus's presence is not
# neutral to this one. Recorded rather than assumed.
note(f"deployment host population at correlation time: {Host.objects.count()}")

# Attribution across corpora: Rust Fox shares no habit with Ember or Quiet Fox, so the
# similarity measure must decline. Skipped rather than guessed when corpus v2 is absent — a
# comparison with nothing to compare against is not a passing comparison.
win = list(Investigation.objects.filter(incident_id__in=("INC-CORPUS-A", "INC-CORPUS-B")))
if not win:
    note("corpus v2 is not deployed — the cross-actor and population checks are not applicable")
else:
    lin_inv = Investigation.objects.filter(incident_id=PREFIX).first()
    lin_run = CorrelationRun.objects.filter(investigation_id=lin_inv.id, is_current=True).first()
    lin_camp = Campaign.objects.filter(run=lin_run).order_by("-host_count").first()
    related = list(lin_camp.similar_to.all()) if lin_camp else []
    names = [f"{s.other_label}={s.score:.2f}" for s in related]
    chk(not related,
        "Rust Fox is not attributed to the Windows actor — no habit is shared"
        + (f" — but got {names}" if related else ""))

    # The Windows corpus's own classification must be exactly what it was before this fleet
    # existed. If 22 unrelated hosts move it, rarity is not the environment statement it
    # claims to be.
    for incident, expect in (("INC-CORPUS-A", 12), ("INC-CORPUS-B", 4)):
        i = Investigation.objects.filter(incident_id=incident).first()
        if not i:
            continue
        n = CollectionRun.objects.filter(investigation=i, compromised=True).count()
        chk(n == expect,
            f"{incident} still classifies {n} compromised with a larger fleet around it")

    # And no campaign may reach across the two estates.
    for incident in ("INC-CORPUS-A", "INC-CORPUS-B"):
        i = Investigation.objects.filter(incident_id=incident).first()
        if not i:
            continue
        r = CorrelationRun.objects.filter(investigation_id=i.id, is_current=True).first()
        crossed = sorted(set(CampaignHost.objects.filter(campaign__run=r)
                             .values_list("hostname", flat=True)) & set(m["endpoints"]))
        chk(not crossed, f"no {incident} campaign reaches a Linux endpoint"
                         + (f" — {crossed}" if crossed else ""))
PYEOF

rm -rf "${SCEN}"
report_finish
exit "${FAILED}"
