#!/usr/bin/env bash
# UAT — analyst-facing capabilities, asserted against the seeded intrusion with REAL DATA, never
# reachability. The seed prints its ground truth, so checks assert what the scenario encodes
# rather than whatever the code produces.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"
RUNTIME="${IR_RUNTIME:-podman}"
BE="${IR_BACKEND_CONTAINER:-ir-enclave_backend_1}"

. "${HERE}/lib/report.sh"

[[ $(${RUNTIME} ps --format '{{.Names}}' | grep -cx "${BE}") -gt 0 ]] || {
    printf '\033[1;31mbackend container %s is not running\033[0m\n' "${BE}"; exit 1; }

report_begin 65 ui "Analyst capabilities, asserted against a real intrusion" \
    "Every analyst-facing view answers from seeded evidence with known ground truth — paging, correlation, visualization, case work, custody and export — rather than rendering without having been asked anything."

# The whole suite runs inside the backend: it holds the API, both databases and an admin
# identity, so no management port has to be opened to test.
run_in_backend() {
    ${RUNTIME} cp "$1" "${BE}:/tmp/_uat_ui.py" >/dev/null 2>&1 || return 1
    ${RUNTIME} exec -w /app -e PYTHONPATH=/app "${BE}" python /tmp/_uat_ui.py 2>&1
}

# Pre-flight: every CSS custom property the UI reads must be defined — an undefined `var(--x)` is
# not a build error, and on an SVG `fill` it renders BLACK. Static, so it runs before the stack is
# touched.
say "0/8  Every CSS variable the UI reads is defined"
FE="${PLATFORM}/frontend/src"
UNDEF=$(comm -23 \
    <(grep -rohE 'var\(--[a-z0-9-]+' "${FE}" --include='*.jsx' --include='*.js' --include='*.css' \
        | sed 's/var(--//' | sort -u) \
    <(grep -rhoE '^\s*--[a-z0-9-]+' "${FE}" --include='*.css' | tr -d ' \t' | sed 's/--//' | sort -u))
if [[ -z "${UNDEF}" ]]; then
    ok "no undefined custom properties ($(grep -rohE 'var\(--[a-z0-9-]+' "${FE}" \
        --include='*.jsx' --include='*.js' --include='*.css' | sort -u | wc -l) distinct in use)"
else
    bad "undefined CSS variables — these render black, not styled: $(echo ${UNDEF} | tr '\n' ' ')"
fi

say "0b/8  The reverse-engineering page can start a session, not only close one"
# The disassembler runs on air-gapped hardware, so the platform's part is to name the regions
# and mint the commands. Asserted against the SERVED bundle: a control that exists only in
# the source reaches no analyst.
FE_BUNDLE="$(${RUNTIME} exec "${FRONTEND:-ir-enclave_frontend_1}" sh -c \
    'cat /usr/share/nginx/html/assets/*.js 2>/dev/null' | wc -c)"
if [[ "${FE_BUNDLE:-0}" -gt 1000 ]]; then
    ok "the built bundle is being served ($(( FE_BUNDLE / 1024 )) KB)"
else
    bad "no built bundle is being served — every assertion below would pass vacuously"
fi
for NEEDLE in "open in RE" "Record determination" "Reverse-engineering sessions" "download session kit"; do
    N="$(${RUNTIME} exec "${FRONTEND:-ir-enclave_frontend_1}" sh -c \
        "grep -c '${NEEDLE}' /usr/share/nginx/html/assets/*.js 2>/dev/null | paste -sd+ | bc" 2>/dev/null)"
    [[ "$(printf '%s' "${N:-0}" | tr -cd '0-9')" -gt 0 ]] \
        && ok "the served UI offers \"${NEEDLE}\"" \
        || bad "\"${NEEDLE}\" is not in the served UI — the source has it, the bundle does not"
done
# The two ends of the work are named for which end they are: a button that says "analyze"
# when it means "write up what you found" costs a wrong click in the middle of the night.
if grep -rq '>\s*analyze\s*<' "${FE}/pages/Reversing.jsx"; then
    bad "the region row still offers a bare \"analyze\" — ambiguous between starting and finishing"
else
    ok "the region actions distinguish opening a session from recording a determination"
fi

say "1/8  Seed the 20-host intrusion and correlate it"
SEED=$(${RUNTIME} exec -w /app "${BE}" python manage.py seed_campaign --reset 2>&1 | tail -40)
if printf '%s' "$SEED" | grep -q '"patient_zero": "WS-007"'; then
    ok "scenario seeded (ground truth: WS-007 is the entry point)"
else
    bad "seed did not report the expected ground truth"
    # The seeder's own words, or the failure cannot be diagnosed after the run.
    info "seed output (tail): $(printf '%s' "$SEED" | tail -3 | tr '\n' ' ' | cut -c1-300)"
fi
${RUNTIME} exec -w /app "${BE}" python manage.py correlate >/dev/null 2>&1 \
    && ok "correlation computed from collected evidence" \
    || bad "correlation failed"

cat > /tmp/_uat_ui.py <<'PYEOF'
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

import django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ir_platform.settings")
django.setup()

from django.contrib.auth.models import User
from django.db.models import Count
from rest_framework.authtoken.models import Token

from cases.models import (AuditLog, CollectionRun, Finding, FindingReclassification,
                          Investigation, MemoryCapture)
from correlation.models import Campaign, CampaignEdge, CampaignHost

admin = User.objects.filter(is_superuser=True).first()
TOKEN = Token.objects.get_or_create(user=admin)[0].key
BASE = "http://127.0.0.1:8000/api"

results = []
def check(cond, msg):
    results.append((bool(cond), msg))

def section(title):
    # The payload NAMES its own sections. The host parser once mapped headers onto fixed
    # index ranges — every inserted check shifted the labels, and the final range's cap
    # silently dropped (and never counted) every row past it, so a failing check past the
    # cap could hide under a green verdict.
    results.append(("SEC", title))

def api(path, data=None, raw=False, expect_status=None):
    """Call the API. With expect_status, return the STATUS CODE instead of the body.

    A refusal is an outcome to be asserted, not an exception to be escaped: without this an
    expected 403 raises out of the test and reads as a broken harness.
    """
    req = urllib.request.Request(
        BASE + path,
        headers={"Authorization": "Token " + TOKEN, "Content-Type": "application/json"},
        data=json.dumps(data).encode() if data is not None else None,
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            body, code = r.read(), r.getcode()
    except urllib.error.HTTPError as exc:
        if expect_status is None:
            raise
        return exc.code
    if expect_status is not None:
        return code
    return body if raw else json.loads(body)

# The API must answer before any contract check runs — asserted, not assumed: one refused
# connection at first contact otherwise reports 'checks did not run' over a backend healthy
# seconds before and after. Bounded, and the wait itself is a recorded assertion.
import time
_deadline = time.monotonic() + 30
while True:
    try:
        api("/health/", expect_status=True)
        check(True, "the API answers before the contract checks begin")
        break
    except Exception as exc:
        if time.monotonic() > _deadline:
            check(False, f"the API never answered within 30s — {exc}")
            print(json.dumps([{"ok": o, "msg": m} for o, m in results]))
            sys.exit(0)
        time.sleep(2)

# V-API, called because nothing else called them: an endpoint that 500s on every request is
# invisible to a suite that only asserts about pages. Status FIRST, then shape — a 500 and an
# empty body are different failures.
inv_id = (CollectionRun.objects
          .filter(host__hostname="WS-007").values_list("investigation_id", flat=True)
          .first())

if inv_id is None:
    check(False, "no investigation to aggregate over — the seed did not land (a harness failure, not an API one)")
else:
    for label, path in (
        ("investigation stats", f"/investigations/{inv_id}/stats/"),
        ("investigation coverage", f"/investigations/{inv_id}/coverage/"),
        ("stalled investigations", "/investigations/stalled/"),
        ("findings facets", "/facets/"),
        ("platform stats", "/stats/"),
    ):
        code = api(path, expect_status=True)
        check(code == 200, f"{label} answers 200 (got {code}) — every chart reading it renders")

    # Shape, not just a status: an endpoint that answers 200 with nothing useful is the other
    # way this fails silently.
    stats = api(f"/investigations/{inv_id}/stats/")
    check(isinstance(stats.get("by_verdict"), dict) and sum(stats["by_verdict"].values()) > 0,
          f"investigation stats counts findings by verdict ({sum(stats.get('by_verdict', {}).values())} counted)")
    check(stats.get("total_findings", 0) > 0,
          f"investigation stats reports a total ({stats.get('total_findings')} findings)")
    # The drill-down contract: every bucket must be reproducible in the findings table, so a
    # chart can never claim a set the table cannot show.
    check(isinstance(stats.get("killchain"), list) and isinstance(stats.get("hosts"), list),
          "stats carries the killchain and host buckets the charts drill into")

    # Per-run aggregates, over a run that actually exists.
    run_id = None
    for _r in CollectionRun.objects.filter(investigation_id=inv_id)[:1]:
        run_id = _r.id
    if run_id is None:
        check(False, "no collection run under the investigation — per-run aggregates unmeasured")
    else:
        for label, path in (("run timeline", f"/runs/{run_id}/timeline/"),
                            ("run custody", f"/runs/{run_id}/custody/")):
            code = api(path, expect_status=True)
            check(code == 200, f"{label} answers 200 (got {code})")

# Per planning/VISUALIZATION.md §5: aggregates must match rows, verdicts must not merge, and every
# drill-down is FOLLOWED — the destination must accept the chart's params and return exactly the
# claimed rows.
if inv_id is not None:
    stats = api(f"/investigations/{inv_id}/stats/")

    # The kill-chain buckets must SUM to the total: a lane chart missing findings is a chart
    # quietly flattering the case.
    kc_sum = sum(b["count"] for b in stats.get("killchain", []))
    check(kc_sum == stats.get("total_findings"),
          f"kill-chain buckets sum to the total ({kc_sum} == {stats.get('total_findings')})")
    kc_conf = sum(b["confirmed"] for b in stats.get("killchain", []))
    check(kc_conf == stats.get("confirmed_findings"),
          f"confirmed stays a dimension in every bucket ({kc_conf} == {stats.get('confirmed_findings')})")

    # The technique rollup the bars render must ALSO sum to the totals, and a bar's drill
    # must return EXACTLY its rows — the rollup's params are the table's own filters. The
    # probe deliberately includes the case where a technique is "unmapped": findings with no
    # ATT&CK mapping are a real state the table now expresses, not a dead mark.
    trows = stats.get("techniques", [])
    check(sum(t["count"] for t in trows) >= stats.get("total_findings", 0) and trows,
          f"technique rows COVER every finding — a multi-technique finding counts under each ({sum(t['count'] for t in trows)} >= {stats.get('total_findings')})")
    check(sum(t["confirmed"] for t in trows) >= stats.get("confirmed_findings", 0),
          f"confirmed stays a dimension in every row ({sum(t['confirmed'] for t in trows)} >= {stats.get('confirmed_findings')})")
    # The chord's ribbons ARE the host x tactic pairs, and its percentages are the
    # platform's: each pair's share must be its count over that host's findings, or the
    # picture is dividing numbers the API never agreed to.
    pairs = stats.get("host_tactics", [])
    host_tot = {h["host"]: h["findings"] for h in stats.get("hosts", [])}
    check(pairs and all(
        abs(p["pct_of_host"] - (100.0 * p["count"] / max(host_tot.get(p["host"], 1), 1))) < 0.15
        for p in pairs),
        f"every ribbon's percentage is its own share of that host's findings ({len(pairs)} pairs)")
    check(all(p["confirmed"] <= p["count"] for p in pairs),
          "no ribbon claims more confirmed than findings")
    # The chord folds its smallest arcs so it stays readable at fleet scale, and the fold
    # must never lose evidence: the pairs the API serves are the whole set whatever the
    # picture chooses to draw, and the side table renders them all.
    drawn_hosts = len({p["host"] for p in pairs})
    check(drawn_hosts == len(stats.get("hosts", [])),
          f"every affected host appears in the chord's data ({drawn_hosts} == {len(stats.get('hosts', []))}) — folding is a drawing choice, never a dropped row")
    check(sum(p["count"] for p in pairs) >= stats.get("total_findings", 0),
          f"the ribbons cover every finding ({sum(p['count'] for p in pairs)} >= {stats.get('total_findings')})")

    # A ribbon drills by host AND tactic together; the table must reproduce that pairing.
    if pairs:
        pr = pairs[0]
        got = api(f"/findings/?investigation={inv_id}&tactic={pr['tactic']}&host={pr['host_id']}&page_size=1").get("count", 0)
        check(got == pr["count"],
              f"a ribbon drills to exactly its pairing ({got} == {pr['count']} for {pr['host']} x {pr['tactic']})")

    # The progression must serve EVERY canonical stage, evidenced or not: a gap is the
    # finding, and omitting empty stages is what hides it.
    kstages = stats.get("killchain_stages", [])
    check(len([k for k in kstages if k["tactic"] != "unmapped"]) == 12,
          f"the kill chain serves all 12 canonical stages, gaps included ({len(kstages)} rows)")
    gaps = [k["name"] for k in kstages if k["count"] == 0]
    check(True, f"stages with no evidence are stated rather than dropped ({len(gaps)}: {', '.join(gaps[:4])}{'…' if len(gaps) > 4 else ''})")
    for k in [k for k in kstages if k["count"] > 0][:1]:
        got = api(f"/findings/?investigation={inv_id}&tactic={k['tactic']}&page_size=1").get("count", 0)
        check(got == k["count"],
              f"a stage drills to exactly its findings ({got} == {k['count']} for {k['name']})")

    probes = trows[:1] + [t for t in trows if t["technique"] == "unmapped"][:1]
    for t in probes:
        drilled = api(f"/findings/?investigation={inv_id}&technique={t['technique']}&page_size=1")
        check(drilled.get("count", 0) == t["count"],
              f"a bar's drill returns exactly its rows ({drilled.get('count')} == {t['count']} for {t['technique']})")
    if not probes:
        check(False, "no technique bar to follow — the seed produced nothing to drill")

    # The ring's drill: the hosts table's own search param must find the host by name.
    hosts_b = stats.get("hosts", [])
    if hosts_b:
        h = hosts_b[0]
        found = api(f"/hosts/?search={h['host']}")
        names = [r.get("hostname") for r in found.get("results", [])]
        check(h["host"] in names,
              f"a ring mark's drill finds its host through the table's search ({h['host']})")
        check(all(x["confirmed"] <= x["findings"] for x in hosts_b),
              "no host claims more confirmed findings than findings")
    else:
        check(False, "no host bucket to follow")

    # Coverage: the two sets must partition — a host both collected and uncollected is a
    # coverage bar lying in both directions at once.
    cov = api(f"/investigations/{inv_id}/coverage/")
    overlap = set(cov.get("collected", [])) & set(cov.get("implicated_not_collected", []))
    check(not overlap,
          f"collected and implicated-never-collected are disjoint ({len(overlap)} overlap)")
    check(cov.get("implicated_not_collected") == sorted(set(cov.get("implicated", [])) - set(cov.get("collected", []))),
          "the uncollected list IS implicated minus collected — not an independent claim")

    # V5: the rarity weights are the ENGINE'S. Monotonic within a kind — more hosts can
    # never mean more linkage weight; an inversion here is the mass-impact defect.
    shared = api("/correlation/indicators/")
    rows = shared.get("indicators", [])
    check(shared.get("population", 0) >= 1 and all("link_weight" in r for r in rows),
          f"every shared indicator carries the engine-computed link weight (population {shared.get('population')})")
    by_kind = {}
    for r in rows:
        by_kind.setdefault(r["kind"], []).append((r["host_count"], r["link_weight"]))
    bad_kinds = []
    for kind, pairs in by_kind.items():
        pairs.sort()
        if any(pairs[i][1] < pairs[i + 1][1] for i in range(len(pairs) - 1)):
            bad_kinds.append(kind)
    check(not bad_kinds,
          f"rarity is monotonic: within a kind, more hosts never weighs more (checked {len(by_kind)} kinds{', INVERTED: ' + ','.join(bad_kinds) if bad_kinds else ''})")

    # A scatter dot's drill: the IOC search must find the indicator it names. Probed with a
    # kind the IOC index actually stores — an `account` is shared context, not an IOC, and
    # asserting its absence would fail the drill for being honest.
    indexed = [r for r in rows if r["kind"] in ("ip", "domain", "hash", "mutex", "useragent")]
    if indexed:
        probe_row = indexed[0]
        hit = api(f"/ioc-search/?q={urllib.parse.quote(str(probe_row['value']))}")
        check(any(str(m.get("value", "")) == str(probe_row["value"]) for m in hit.get("results", [])),
              f"a scatter dot's drill finds its indicator in IOC search ({probe_row['kind']})")
    else:
        check(len(rows) > 0,
              f"no IOC-indexed indicator kind among the shared set ({sorted(set(r['kind'] for r in rows))[:5]}) — the drill is unexercised, and that is stated")

    # V5: cohesion history — the strip's data, present and bounded.
    hist = api(f"/correlation/investigations/{inv_id}/history/")
    runs_h = hist.get("runs", [])
    check(len(runs_h) >= 1, f"correlation history holds the runs the strip renders ({len(runs_h)})")
    coh_ok = all(0.0 <= c["cohesion_mean"] <= 1.0 and c["cohesion_min"] <= c["cohesion_mean"] + 1e-9
                 for r in runs_h for c in r["campaigns"])
    check(coh_ok, "every campaign's cohesion is bounded [0,1] with min <= mean")
    check(sum(1 for r in runs_h if r.get("is_current")) <= 1,
          "at most one correlation run claims to be current")

    # V5: the link bars render STORED corroboration rows. Strongest first, and the stored
    # top factor is exactly the first row — the bars and the summary cannot disagree.
    corr_run = api(f"/correlation/investigations/{inv_id}/")
    camp = (corr_run.get("campaigns") or [{}])[0].get("id")
    if camp:
        g = api(f"/correlation/campaigns/{camp}/graph/")
        be = [e for e in g.get("behavioral_edges", []) if e.get("corroboration")]
        if be:
            e0 = be[0]
            weights = [c.get("weight", 0) for c in e0["corroboration"]]
            check(weights == sorted(weights, reverse=True),
                  f"a link's corroboration rows arrive strongest-first ({len(weights)} rows)")
            check(e0.get("top_factor", {}).get("weight", 0) >= (weights[0] if weights else 0),
                  "nothing in corroboration outranks the stored top — the record's own ordering holds (top is stored apart and the bars re-join it first)")
        else:
            check(True, "no behavioral edge carries corroboration in this campaign — bars fall back to kinds, stated as such")

# The batch V1/V3/V4/V6/V7 render from, same contract: figures match rows, stages reproduce via
# the table's own filters, and the day filter reads the same clock the aggregates bucket by.
if inv_id is not None:
    fun = api(f"/findings/funnel/?investigation={inv_id}")
    stages = {s["stage"]: s for s in fun.get("stages", [])}
    check(set(stages) == {"collected", "adjudicated", "confirmed"},
          f"the funnel serves its three narrowing stages ({sorted(stages)})")
    seq = [stages[k]["count"] for k in ("collected", "adjudicated", "confirmed")]
    check(seq == sorted(seq, reverse=True),
          f"the funnel narrows: collected {seq[0]} >= adjudicated {seq[1]} >= confirmed {seq[2]} — a widening funnel is a counting error")
    ms = fun.get("memory_share", {})
    got_ms = api(f"/findings/?investigation={inv_id}&source=memory&page_size=1").get("count", 0)
    check(got_ms == ms.get("count"),
          f"the memory share beside the funnel is reproducible ({got_ms} == {ms.get('count')})")
    # FOLLOW each stage's declared params: the table must reproduce the stage's count.
    for name, st in stages.items():
        qs_parts = "".join(f"&{k}={urllib.parse.quote(str(v))}" for k, v in st.get("params", {}).items())
        got = api(f"/findings/?investigation={inv_id}{qs_parts}&page_size=1").get("count", 0)
        check(got == st["count"],
              f"funnel stage '{name}' is reproducible by its own params ({got} == {st['count']})")

    # Backlog — the dashboard's "getting better or worse" series. Its numbers have to
    # partition the set and its cumulative walk has to close, or the curve drifts without
    # ever reading as wrong.
    bl = api("/findings/backlog/?days=30")
    check(bl.get("open_now", 0) + bl.get("decided_total", 0) == bl.get("total", -1),
          f"backlog partitions every finding: {bl.get('open_now')} open + "
          f"{bl.get('decided_total')} decided == {bl.get('total')} collected")
    bdays = bl.get("days", [])
    walked = bl.get("opening_backlog", 0) + sum(d["arrived"] - d["decided"] for d in bdays)
    check(not bdays or walked == bdays[-1]["open"],
          f"the cumulative walk closes: opening {bl.get('opening_backlog')} plus arrivals less "
          f"decisions == {bdays[-1]['open'] if bdays else 0} on the last day")
    check(all(d["open"] >= 0 for d in bdays),
          "and open backlog never goes negative — decisions are never counted against a day "
          "before the findings they settle arrived")
    # A direction may only be DRAWN when decisions land on more than one day. Below that the
    # client states the standing, so the flag the client branches on has to be honest.
    check(bl.get("decision_days", 0) == len([d for d in bdays if d["decided"]]),
          f"decision_days counts the days that carry a decision ({bl.get('decision_days')}) — "
          f"the flag the dashboard uses to refuse a slope through too few points")

    mx = api(f"/findings/matrix/?investigation={inv_id}")
    check(mx.get("computed_over") == stages["collected"]["count"],
          f"the matrix covers the same rows as the funnel ({mx.get('computed_over')} == {stages['collected']['count']})")

    # The triage rings' rollup. Each type's totals must partition the same set the cells
    # count, and the open figure must be reproducible by the ring's own drill params — a
    # ring nobody can open is a number taken on trust.
    ttypes = mx.get("types", [])
    check(sum(t["total"] for t in ttypes) == mx.get("computed_over"),
          f"per-type totals partition the matrix ({sum(t['total'] for t in ttypes)} == {mx.get('computed_over')})")
    if ttypes:
        t0 = ttypes[0]
        qs_parts = "".join(f"&{k}={urllib.parse.quote(str(v))}" for k, v in t0["params"].items())
        got = api(f"/findings/?investigation={inv_id}{qs_parts}&page_size=1").get("count", 0)
        check(got == t0["open"],
              f"the busiest ring ('{t0['finding_type']}': {t0['open']} open) reproduces by its "
              f"own drill params ({got} == {t0['open']})")
    cells = mx.get("cells", [])
    if cells:
        c = max(cells, key=lambda c: c["count"])
        got = api(f"/findings/?investigation={inv_id}&finding_type={urllib.parse.quote(c['finding_type'])}&verdict={urllib.parse.quote(c['verdict'])}&page_size=1").get("count", 0)
        check(got == c["count"],
              f"a matrix cell drills to exactly its rows ({got} == {c['count']} for {c['finding_type']} x {c['verdict']})")

    # Heatmap multi-select: `cells` is an OR of EXACT pairs, and the test pair is chosen so its cross
    # product is populated — equality with the plain sum is what proves pair semantics over per-
    # dimension sets.
    def cells_count(pairs):
        raw = "|".join(f"{p['finding_type']}::{p['verdict']}" for p in pairs)
        return api(f"/findings/?investigation={inv_id}&cells={urllib.parse.quote(raw, safe='')}"
                   f"&page_size=1").get("count", 0)
    if len(cells) >= 2:
        have = {(c["finding_type"], c["verdict"]) for c in cells}
        pair = None
        for a in cells:
            for b in cells:
                if (a["finding_type"] != b["finding_type"] and a["verdict"] != b["verdict"]
                        and ((a["finding_type"], b["verdict"]) in have
                             or (b["finding_type"], a["verdict"]) in have)):
                    pair = (a, b)
                    break
            if pair:
                break
        trap = bool(pair)
        if not pair:
            pair = (cells[0], next(c for c in cells[1:]
                                   if (c["finding_type"], c["verdict"])
                                   != (cells[0]["finding_type"], cells[0]["verdict"])))
        a, b = pair
        one = cells_count([a])
        check(one == a["count"],
              f"one selected heatmap cell filters the table to exactly its rows ({one} == {a['count']})")
        both = cells_count([a, b])
        check(both == a["count"] + b["count"],
              f"two selected cells are their SUM, not their cross product ({both} == "
              f"{a['count']} + {b['count']}"
              + (", off-diagonal exists and is excluded)" if trap else ")"))
        full = api(f"/findings/?investigation={inv_id}&page_size=1").get("count", 0)
        check(full == stages["collected"]["count"],
              f"clearing the selection returns the full table ({full} == collected)")
    agree = mx.get("agreement", [])
    check(all(a["corroborated"] <= a["hosts"] for a in agree),
          f"no type claims more corroborated hosts than hosts ({len(agree)} types)")
    # V4's agreement bars drill by finding_type alone; the table must accept it.
    if agree:
        a0 = agree[0]
        got = api(f"/findings/?finding_type={urllib.parse.quote(a0['finding_type'])}&page_size=1").get("count", 0)
        check(got > 0,
              f"an agreement bar's drill returns rows ({got} for {a0['finding_type']})")
    # Verdict columns must stay SEPARATE: a matrix that folded Indeterminate into confirmed
    # would flatter the case, which is the failure rule 4 of VISUALIZATION.md forbids.
    verdicts_seen = {c["verdict"] for c in cells}
    check("Indeterminate" not in verdicts_seen or
          sum(c["count"] for c in cells if c["verdict"] == "Indeterminate")
          == stages["collected"]["count"] - stages["adjudicated"]["count"],
          f"the matrix's Indeterminate column equals what the funnel has not adjudicated "
          f"({sum(c['count'] for c in cells if c['verdict'] == 'Indeterminate')} vs "
          f"{stages['collected']['count'] - stages['adjudicated']['count']})")

    act = api("/investigations/activity/?days=60")
    fleet = act.get("fleet", [])
    check(act.get("computed_over") == sum(d["count"] for d in fleet),
          f"the activity totals equal their own days ({act.get('computed_over')})")
    check(all(d["confirmed"] <= d["count"] for d in fleet),
          "no day claims more confirmed than findings")
    # A day cell's drill: the findings table's day filter must return that day's rows for
    # this investigation, read from the SAME clock the aggregate used.
    mine = next((r for r in act.get("investigations", []) if r["investigation_id"] == inv_id), None)
    if mine and mine["days"]:
        day, dv = sorted(mine["days"].items())[0]
        got = api(f"/findings/?investigation={inv_id}&day={day}&page_size=1").get("count", 0)
        check(got == dv["count"],
              f"a day cell drills to exactly its rows ({got} == {dv['count']} for {day})")
    else:
        check(False, "the seeded investigation has no activity days inside the window — nothing to drill")

# --- 1d. V3/V6 — the run timeline and the indicator spread --------------------------
if run_id is not None:
    tl = api(f"/runs/{run_id}/timeline/")
    evs = tl.get("events", [])
    check(tl.get("event_count") == len(evs),
          f"the timeline's count equals its own events ({tl.get('event_count')} == {len(evs)})")
    ordered = [e["at"] or "" for e in evs]
    check(ordered == sorted(ordered),
          "timeline events arrive in time order — the ribbon renders them as served")
    # Every event names a SOURCE, or the ribbon cannot say whether memory corroborated
    # collection; that comparison is the chart's whole reason to exist.
    check(all(e.get("source") for e in evs) if evs else True,
          f"every timeline event names its source ({len({e.get('source') for e in evs})} distinct)")
    # The run's timeline must not silently disagree with the run's own finding count.
    run_rows = api(f"/findings/?run={run_id}&page_size=1").get("count", 0)
    check(len(evs) <= run_rows,
          f"the timeline draws no event the findings table lacks ({len(evs)} <= {run_rows})")

# V6: the spread is the "seen before?" anchor, so it must agree with the IOC index it
# summarizes rather than being a second, independent count.
if indexed:
    probe_ioc = indexed[0]
    sp = api(f"/iocs/{urllib.parse.quote(probe_ioc['kind'])}/{urllib.parse.quote(str(probe_ioc['value']))}/spread/")
    invs = sp.get("investigations", [])
    check(sp.get("investigation_count") == len(invs),
          f"the spread's investigation count equals its own rows ({sp.get('investigation_count')} == {len(invs)})")
    check(sp.get("host_count", 0) >= max([r.get("host_count", 0) for r in invs] or [0]),
          f"no single investigation claims more hosts than the indicator's total ({sp.get('host_count')})")
    if invs:
        # Sightings OUTLIVE their investigation (T2): a spread row may name an archived
        # case, whose drill is legitimately empty. The drill is asserted on a live one.
        live = [r for r in invs
                if Investigation.objects.filter(id=r["investigation_id"]).exists()]
        if live:
            got = api(f"/findings/?investigation={live[0]['investigation_id']}&page_size=1").get("count", 0)
            check(got > 0,
                  f"a spread bar's drill returns its investigation's rows ({got})")
        else:
            check(True, "every case carrying this indicator is archived — spread rows "
                        "outlive their investigation by design (T2)")

# --- 2. Correlation identifies the intrusion the scenario encodes -------------------
section("3/8  Correlation identifies the seeded intrusion")
# Found by PATIENT ZERO within the seeder-named investigation. Patient zero alone is not unique
# (the corpora replicate the scenario) and campaign ids track correlate's processing order, not
# seed recency; the investigation NAME is seeder-assigned, so it is safe to pin where the
# evidence-derived campaign label is not.
seed_inv = Investigation.objects.filter(name="Ember Fox").order_by("-id").first()
ember = Campaign.objects.filter(patient_zero="WS-007", run__is_current=True,
                                investigation_id=seed_inv.id if seed_inv else 0).first()
miner_inv = Investigation.objects.filter(name="Cryptominer Outbreak").order_by("-id").first()
miner = (Campaign.objects.filter(
    run__is_current=True, host_count=2, hosts__hostname="WS-012",
    investigation_id=miner_inv.id if miner_inv else 0)
    .exclude(id=ember.id if ember else 0).distinct().first())

check(ember and ember.patient_zero == "WS-007",
      f"entry point identified as WS-007 (got {ember.patient_zero if ember else 'no campaign'})")
check(ember and ember.initial_vector == "T1566.001",
      f"initial vector T1566.001 (got {ember.initial_vector if ember else '-'})")
check(ember and ember.host_count == 10,
      f"blast radius is 10 hosts (got {ember.host_count if ember else 0})")
check(CampaignEdge.objects.filter(campaign=ember).count() == 9,
      "9 lateral-movement edges reconstructed")

# The negative control: a separate compromise must not be folded into the intrusion.
miner_hosts = set(CampaignHost.objects.filter(campaign=miner).values_list("hostname", flat=True))
ember_hosts = set(CampaignHost.objects.filter(campaign=ember).values_list("hostname", flat=True))
check(miner and miner.host_count == 2 and not (miner_hosts & ember_hosts),
      "unrelated compromise stays a separate campaign (no false linking)")
check(not (ember_hosts & {"WS-001", "WS-002", "WS-006", "WS-009"}),
      "clean hosts are excluded from the blast radius")

# Movement is reconstructed in the right direction, with the account that was used.
first_hop = CampaignEdge.objects.filter(campaign=ember, src_hostname="WS-007").first()
check(first_hop and first_hop.dst_hostname == "JUMP-01"
      and first_hop.account.endswith("j.okafor"),
      "first hop WS-007 -> JUMP-01 carries the harvested account")

# --- 3. Graph and timeline serve the same picture ------------------------------------
section("4/8  Attack graph, timeline and shared indicators")
graph = api(f"/correlation/campaigns/{ember.id}/graph/")
roles = {n["role"] for n in graph["nodes"]}
check(len(graph["nodes"]) == 10 and len(graph["edges"]) == 9,
      "graph endpoint serves 10 nodes / 9 edges")
check("patient_zero" in roles and "pivot" in roles,
      "graph distinguishes the entry point from pivots")

timeline = api(f"/correlation/campaigns/{ember.id}/timeline/")
times = [e["at"] for e in timeline["events"]]
check(len(times) > 10 and times == sorted(times), "timeline is populated and ordered")
check(any(e["kind"] == "lateral_movement" for e in timeline["events"]),
      "timeline includes movement between hosts")

# This campaign's own row: the endpoint aggregates fleet-wide across investigations on
# purpose — that recurrence is the "seen before?" signal — so the row is selected by the
# campaign it belongs to rather than by value, which other cases legitimately share.
indicators = api("/correlation/indicators/")["indicators"]
c2 = next((i for i in indicators
           if i["value"] == "198.51.100.23" and ember.id in i["campaign_ids"]), None)
check(c2 and set(ember_hosts) <= set(c2["hostnames"]),
      "shared C2 indicator spans all 10 intrusion hosts")

# --- 4. Paging, sorting and filtering happen at the database -------------------------
section("5/8  Paging, sorting and filtering at the database")
p1 = api("/findings/?page_size=5")
p2 = api("/findings/?page_size=5&page=2")
check(p1["count"] > 50 and p1["total_pages"] > 1, "findings are paged")
check({r["id"] for r in p1["results"]}.isdisjoint({r["id"] for r in p2["results"]}),
      "page 2 returns a different slice")
asc = [r["finding_type"] for r in api("/findings/?page_size=20&ordering=finding_type")["results"]]
check(asc == sorted(asc), "ordering is applied by the database")
tp = api("/findings/?verdict=" + urllib.parse.quote("True Positive") + "&page_size=1")
check(0 < tp["count"] < p1["count"], "verdict filter narrows the set")
# Scoped to this seed's investigation: the technique filter is global by design (searching
# across cases is the point), and the 25-endpoint corpus carries the same T1021.001 hop.
tech = api(f"/findings/?technique=T1021.001&investigation={ember.investigation_id}&page_size=10")
check(tech["count"] == 1 and tech["results"][0]["hostname"] == "JUMP-01",
      "ATT&CK filter returns exactly the RDP movement (JUMP-01)")
hosts = api("/hosts/?page_size=3&ordering=-hostname")["results"]
check([h["hostname"] for h in hosts] == sorted([h["hostname"] for h in hosts], reverse=True),
      "host ordering is applied by the database")

# --- 5. Re-analysis diff surfaces what a newer ruleset adds --------------------------
section("6/8  Re-analysis diff and recovered evidence")
# Selected by the property under test — a capture carrying TWO analyses. Hostnames are not unique
# across investigations, so hostname-alone lands on another case's capture with nothing to diff.
cap = (MemoryCapture.objects
       .filter(run__host__hostname="WS-007")
       .annotate(n_analyses=Count("analyses"))
       .filter(n_analyses__gte=2).order_by("-id").first())
# A missing capture is a failing ASSERTION, never an AttributeError: crashing here discards
# every check after it and reports the whole suite as "did not run".
if cap is None:
    n_caps = MemoryCapture.objects.filter(run__host__hostname="WS-007").count()
    check(False, f"no WS-007 capture anywhere carries two analyses to diff "
                 f"({n_caps} WS-007 capture(s) exist) — the re-analysis the diff compares never ran")
    diff = {"added": [], "removed": [], "baseline": {}, "latest": {}}
else:
    diff = api(f"/captures/{cap.id}/diff/")
added = {f["finding_type"] for f in diff["added"]}
check(diff["comparable"] and diff["base"]["ruleset_version"] == "2026.05"
      and diff["head"]["ruleset_version"] == "current",
      "diff compares oldest -> newest ruleset")
check("Known tool signature" in added and len(diff["added"]) == 3,
      f"diff finds the 3 detections the newer ruleset adds (got {sorted(added)})")
check(not diff["removed"], "nothing is lost between rulesets")

# The analysis summary is an OPEN map with structured values (`adjudication` carries verdict +
# reason); rendering with String() turns those into '[object Object]'. Asserted: every structured
# value the API serves has a renderable shape.
summaries = [a.summary for c in MemoryCapture.objects.all() for a in c.analyses.all()
             if isinstance(a.summary, dict)]
check(bool(summaries), f"analyses carry a summary for the run page to render ({len(summaries)})")
structured = sorted({k for s in summaries for k, v in s.items()
                     if isinstance(v, (dict, list))})
check(bool(structured),
      f"the summary carries structured values the chip row must render, not stringify ({structured})")
# Rendering rule asserted against the data: a structured value must expose either a scalar
# answer or named keys, or there is nothing for a chip to say about it.
empty = [k for s in summaries for k, v in s.items()
         if isinstance(v, (dict, list)) and not v]
check(not empty, f"every structured summary value has something to show ({empty})")

# The graph reads Finding.raw; the table showed only type/target/verdict/ATT&CK, so recovered
# evidence (user-agent, mutex, JA3, C2 config) was served and shown nowhere. Asserted end to end:
# what the parsers extracted reaches the UI.
beacon = (Finding.objects
          .filter(run__host__hostname="WS-007", finding_type="C2 Beacon",
                  raw__user_agent__isnull=False)
          .order_by("-id").first())
check(beacon is not None, "the enriched beacon finding exists to render")
if beacon:
    served = api(f"/findings/?run={beacon.run_id}&page_size=200")["results"]
    row = next((r for r in served if r["id"] == beacon.id), None)
    check(row is not None and isinstance(row.get("raw"), dict),
          "the findings API serves `raw` — the detail panel has something to render")
    raw = (row or {}).get("raw") or {}
    want = ["user_agent", "mutex", "pipe", "ja3", "registry_key", "certificate"]
    missing = [k for k in want if not raw.get(k)]
    check(not missing,
          f"every recovered indicator on the beacon is served to the UI (missing: {missing})")
    cfg = raw.get("config_extracted") or {}
    check(isinstance(cfg, dict) and {"campaign_id", "sleep", "address", "port"} <= set(cfg),
          f"the extracted C2 config reaches the UI with all its fields ({sorted(cfg)})")

    # The expander must DISCRIMINATE: every raw carries the collector's own record, so a permissive
    # rule puts the control on every row and it stops meaning anything.
    INDICATORS = {"malware_family", "yara_rule", "user_agent", "useragent", "mutex", "pipe",
                  "ja3", "certificate", "registry_key", "domain", "ip", "url", "onion",
                  "sha256", "md5", "wallet", "account", "src_host", "dst_host", "protocol",
                  "technique", "yara_matches", "urls", "domains", "ips", "hashes",
                  "related_hashes", "mutexes", "pipes", "user_agents", "wallets", "xmr",
                  "aws_keys", "telegram_tokens", "discord_webhooks", "crypto_material",
                  "network_indicators", "indicators"}
    def has_evidence(r):
        r = r or {}
        for k in INDICATORS:
            v = r.get(k)
            if v not in (None, "", [], {}):
                return True
        c = r.get("config_extracted")
        return isinstance(c, dict) and bool(c)

    rows = api(f"/findings/?run={beacon.run_id}&page_size=200")["results"]
    withev = [r for r in rows if has_evidence(r.get("raw"))]
    check(has_evidence(raw), "the enriched beacon offers its evidence panel")
    # Memory-derived structural findings carry an offset and an entropy figure and nothing
    # else — no indicator to show. (An "Installed Agent" row DOES get a panel, and should:
    # its vendor domain and agent hash are the fleet-wide benign material rarity weighting
    # divides by. Listing it as noise was a wrong assumption, corrected here.)
    noise = [r["finding_type"] for r in rows
             if has_evidence(r.get("raw"))
             and r["finding_type"].startswith("High-entropy region")]
    check(not noise, f"structural memory rows carry no indicators and offer no panel ({sorted(set(noise))})")
    check(0 < len(withev) < len(rows),
          f"the panel is offered on some rows and not others ({len(withev)} of {len(rows)})")

# --- 6. Adjudication and export are recorded in the tamper-proof ledger --------------
section("7/8  Adjudication, export and the audit ledger")
ids = list(Finding.objects.filter(verdict="Indeterminate").values_list("id", flat=True)[:3])
before = {f.id: f.verdict for f in Finding.objects.filter(id__in=ids)}
owned = {f.id: f.adjudicated_by for f in Finding.objects.filter(id__in=ids)}
res = api("/findings/bulk-verdict/",
          {"ids": ids, "verdict": "False Positive", "reason": "uat"})
check(res["changed"] == len(ids), "bulk verdict applied to every selected finding")
check(all(f.verdict == "False Positive" for f in Finding.objects.filter(id__in=ids)),
      "verdicts persisted")
check(all(f.adjudicated_by == "analyst" for f in Finding.objects.filter(id__in=ids)),
      "a bulk verdict is the analyst's, so a later engine pass cannot silently replace it")
check(FindingReclassification.objects.filter(finding_id__in=ids, note="uat").count() == len(ids),
      "a bulk action leaves per-finding history, not only an aggregate audit entry")

entry = AuditLog.objects.filter(action="finding.bulk_verdict").order_by("-id").first()
recorded = {c["id"]: c["from"] for c in (entry.detail or {}).get("changes", [])}
check(recorded == before,
      "ledger records each finding's prior verdict, not just an aggregate")

# Restore, so the suite is repeatable. Ownership has to be restored explicitly: the revert
# goes through the same analyst path, which would otherwise leave these three findings
# marked as adjudicated by a human who never looked at them.
api("/findings/bulk-verdict/", {"ids": ids, "verdict": "Indeterminate", "reason": "uat revert"})
for _fid, _by in owned.items():
    Finding.objects.filter(id=_fid).update(adjudicated_by=_by)
FindingReclassification.objects.filter(finding_id__in=ids,
                                       note__in=("uat", "uat revert")).delete()

csv_body = api("/findings/export/?fmt=csv", raw=True).decode()
check(csv_body.startswith("host,investigation,finding_type") and csv_body.count("\n") > 50,
      "CSV export carries the findings with host attribution")
bundle = json.loads(api("/findings/export/?fmt=ioc", raw=True).decode())
values = {i["value"] for i in bundle["indicators"]}
check("198.51.100.23" in values and "203.0.113.77" in values,
      "IOC bundle contains indicators from both compromises")
check(AuditLog.objects.filter(action="export.completed").count() >= 2,
      "every export is written to the audit trail")

# The chain records that an export happened; the ledger answers what has left, as a query
# rather than as a filter over a hash-chained log with a free-form detail blob.
led = api("/exports/")
kinds = {e["kind"] for e in led["entries"]}
check({"findings", "ioc"} <= kinds,
      f"the ledger separates a findings dump from a shareable IOC bundle ({sorted(kinds)})")
row = next(e for e in led["entries"] if e["kind"] == "ioc")
check(row["outcome"] == "completed" and row["row_count"] > 0 and row["actor"] == "admin",
      f"a ledger row names actor, outcome and volume ({row['actor']}, {row['outcome']}, "
      f"{row['row_count']} rows)")
check(led["total_rows_taken"] >= row["row_count"],
      "totals are computed over the filtered set, not the page returned")

# Read access does not imply the right to take it. Proven by WITHDRAWING the right and
# watching the same call refuse — a permission asserted only in the granted direction is
# satisfied by a check that always returns true.
denied_before = api("/exports/")["denied"]
was_groups = list(admin.groups.all())
admin.groups.clear()                # admin holds export by role, so the role has to go too
admin.is_superuser = False
admin.save(update_fields=["is_superuser"])
code = api("/findings/export/?fmt=csv", raw=True, expect_status=403)
check(code == 403, f"an identity that can READ findings is refused the EXPORT (HTTP {code})")
admin.is_superuser = True
admin.save(update_fields=["is_superuser"])
admin.groups.set(was_groups)
after = api("/exports/")
check(after["denied"] == denied_before + 1,
      "the refusal is in the ledger beside the successes — 'what was tried' and 'what left' "
      "are one question during an investigation into a responder")
den = next(e for e in after["entries"] if e["outcome"] == "denied")
check(den["kind"] == "findings" and den["denied_reason"],
      f"a denied row carries the kind and why it was refused ({den['kind']}: "
      f"{den['denied_reason'][:60]})")

audit = api("/audit/?page_size=5")
# The chain and the signature are separate claims. Conflating them made the platform accuse
# itself: after the signing key was replaced, every historical row failed signature checking
# and the ledger reported BROKEN with nothing tampered with.
from cases.audit import _key_id, verify_audit_detail
from cases.models import AuditLog

chain_ok, broken_at, sigs = verify_audit_detail()
check(sigs["invalid"] == [],
      f"no row claims the CURRENT signing key and fails it ({len(sigs['invalid'])} invalid) — "
      f"the only signature state that accuses anyone")
check(sigs["superseded"] + sigs["current"] + sigs["unsigned"] > 0,
      f"signatures are classified rather than collapsed: {sigs['current']} verified under the "
      f"current key, {sigs['superseded']} unverifiable (key superseded), {sigs['unsigned']} unsigned")

# Every break must be EXPLAINED. An acknowledged discontinuity carries a signed checkpoint
# naming the gap and the reason; an unexplained one is tampering or loss and fails here.
acknowledged = sigs.get("discontinuities", [])
if chain_ok:
    bridged = (f", bridging {len(acknowledged)} signed discontinuity(ies): "
               + "; ".join(f"#{d['at']} {d['reason']}" for d in acknowledged)) if acknowledged else ""
    check(True, f"the audit hash chain verifies end to end{bridged}")
else:
    check(False, f"UNEXPLAINED break at entry #{broken_at} — no signed checkpoint accounts "
                 f"for it, so the ledger cannot be verified")

# Negative control: a forgery must still be caught — and the probe is ROLLED BACK, never
# committed. Committed, it is the chain tip for its lifetime, a real append can chain onto it, and
# deleting it then manufactures a permanent unexplained break.
from django.db import transaction

from cases.audit import _chain_hash


class _ProbeDone(Exception):
    """Unwinds the probe's transaction. The rollback is the point, not a failure."""


tail = AuditLog.objects.order_by("-id").first()
forged_id = detected = seen_at = None
try:
    with transaction.atomic():
        forged = AuditLog.objects.create(
            actor="uat-forgery", role="", action="uat.forgery.probe", method="", path="",
            object_type="", object_id="", detail={}, prev_hash=tail.entry_hash,
            entry_hash="0" * 64, signature="deadbeef" * 8, sig_key_id=_key_id())
        forged_id = forged.id
        payload = {"actor": forged.actor, "role": forged.role, "action": forged.action,
                   "method": forged.method, "path": forged.path,
                   "object_type": forged.object_type, "object_id": forged.object_id,
                   "detail": forged.detail}
        detected = _chain_hash(tail.entry_hash, payload) != forged.entry_hash
        _, seen_at, _ = verify_audit_detail()
        raise _ProbeDone
except _ProbeDone:
    pass

check(detected, f"a forged row (#{forged_id}) fails its own hash — a superseded key never "
                f"produces this, so rotation and forgery give different verdicts")
check(seen_at == forged_id,
      f"and the verifier stops AT the forgery (#{forged_id}), not at some earlier row — the "
      f"break is located, not merely noticed")

ok_r, broken_r, _ = verify_audit_detail()
check(not AuditLog.objects.filter(id=forged_id).exists() and (ok_r, broken_r) == (chain_ok, broken_at),
      "and the ledger is byte-for-byte at its prior verdict — the probe was never visible to "
      "another appender, so nothing could chain onto it")

# --- V7. Platform-health charts serve figures that match the rows --------------------
section("V7 — queue depth, storage allocation, first-person mesh evidence")

from cases.models import CarvedRegion, MemoryAnalysisRun

qd = api("/admin/queue-depth/")
by_state = dict(MemoryAnalysisRun.objects.values_list("status").annotate(n=Count("id"))
                .values_list("status", "n"))
check(qd.get("queued", -1) == by_state.get("queued", 0)
      and qd.get("running", -1) == by_state.get("running", 0),
      f"queue depth matches the run table (queued {qd.get('queued')}, "
      f"running {qd.get('running')})")
check(qd.get("captures_awaiting_analysis", -1)
      == MemoryCapture.objects.filter(analyses__isnull=True).count(),
      "captures-awaiting counts exactly the captures with no analysis")
samples = qd.get("samples")
check(isinstance(samples, list)
      and all({"sampled_at", "queued", "running", "awaiting",
               "oldest_waiting_seconds"} <= set(s) for s in samples),
      f"the sample series carries every field the chart draws ({len(samples or [])} samples)")
if samples:
    stamps = [s["sampled_at"] for s in samples]
    check(stamps == sorted(stamps), "samples arrive oldest-first, as the time axis assumes")

sa = api("/admin/storage-allocation/")
ev = sa.get("evidence_bucket") or {}
db_bytes = sum(c.size_bytes or 0 for c in MemoryCapture.objects.all())
check(ev.get("bytes") == db_bytes and ev.get("count") == MemoryCapture.objects.count(),
      f"evidence-bucket figures match the capture rows ({ev.get('count')} captures, "
      f"{ev.get('bytes')} bytes)")
check(sum(s.get("bytes", 0) for s in ev.get("states", [])) == ev.get("bytes", -1),
      "retention-state segments sum to the bucket total — the bar cannot disagree with "
      "its own headline")
carved = sa.get("carved_buckets") or []
check(sum(c.get("count", 0) for c in carved) == CarvedRegion.objects.count(),
      f"carved-bucket counts cover every stored region ({CarvedRegion.objects.count()})")

mh = api("/admin/mesh-health/")
obs = mh.get("observed") or {}
be_pg = (obs.get("ir-backend") or {}).get("ir-postgres") or {}
check(be_pg.get("cx_total", 0) > 0,
      "the backend testifies about its own sidecar — its Postgres upstream shows counted "
      "connections")
check(all(set(c) >= {"connect_fail", "cx_total", "cx_active"}
          for row in obs.values() for c in row.values()),
      "every observed cell carries the three counters the matrix renders")

print(json.dumps([{"ok": o, "msg": m} for o, m in results]))
PYEOF

say "2/8  Server aggregates and every chart's data contract"
OUT=$(run_in_backend /tmp/_uat_ui.py)
# The LAST line that is actually the results array. Django's shell prints an import banner
# and any view may log, so "the last line" is not reliably the payload — reading it that way
# reported "checks did not run" over a run in which every check had passed.
JSON=$(printf '%s' "$OUT" | grep -E '^\[\{"ok"' | tail -1)

if [[ -z "${JSON}" ]]; then
    bad "checks did not run — backend output follows"
    printf '%s\n' "$OUT" | tail -20
else
    # Headers come from sentinel rows the payload itself emits, and EVERY row is rendered and counted.
    # A parser that can skip rows can pass a failing suite.
    python3 - "$JSON" <<'PY'
import json, sys
rows = json.loads(sys.argv[1])
failed = 0
for r in rows:
    if r["ok"] == "SEC":
        print(f"\n\033[1;36m== {r['msg']}\033[0m")
    elif r["ok"]:
        print(f"  \033[1;32mPASS\033[0m {r['msg']}")
    else:
        print(f"  \033[1;31mFAIL\033[0m {r['msg']}")
        failed = 1
sys.exit(failed)
PY
    [[ $? -ne 0 ]] && FAILED=1
fi

echo
if [[ "${FAILED}" -eq 0 ]]; then
    printf '\033[1;32m  UI UAT PASSED\033[0m — analyst capabilities verified against real data.\n'
else
    printf '\033[1;31m  UI UAT FAILED\033[0m (see above)\n'
fi
report_finish
exit "${FAILED}"
