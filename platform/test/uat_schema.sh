#!/usr/bin/env bash
# ==============================================================================
# SCHEMA INTEGRITY — the store refuses what the application merely avoided.
#
# Every assertion here tries to BREAK an invariant and requires the database to stop it.
# Asserting that a constraint appears in pg_constraint proves the DDL ran, not that the
# defect is closed: the defect was a read-then-write race, so the test has to race.
#
# Non-destructive and re-runnable: a run leaves the evidence store exactly as it found it.
# Sections proving the database REFUSES something roll back, since nothing they write should
# land. T1 and T2 must commit — a rollup that outlives the evidence it summarizes cannot be
# demonstrated inside a transaction thrown away regardless — so they delete their fixtures
# instead, this run's and any an earlier run left.
# ==============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"

. "${HERE}/lib/report.sh"
report_begin 45 schema "Schema integrity — invariants enforced by the database" \
    "Identity and idempotency are refused at the store, not merely avoided by the application: a concurrent duplicate host is rejected, a re-posted collection cannot duplicate, and the queries the UI runs use the indexes built for them. Adjudication is held to the same standard — a re-analysis supersedes rather than deletes, and an automated pass cannot discard an analyst's verdict without recording that it disagreed."
RUNTIME="${IR_RUNTIME:-podman}"
BE=ir-enclave_backend_1
be() { ${RUNTIME} exec -i "${BE}" "$@"; }

say "Preconditions"
[[ "$(${RUNTIME} inspect "${BE}" --format '{{.State.Status}}' 2>/dev/null)" == "running" ]] \
    && ok "${BE} running" || { bad "${BE} not running — deploy the enclave first"; report_finish; exit 1; }

# Anything the probe script prints that is not an assertion is kept, not dropped. A traceback
# matches none of these prefixes, so swallowing unknown lines let an exception truncate a whole
# section while the suite still reported PASS — the assertions that never ran looked identical
# to assertions that did not exist. DONECHK is the last line the script prints; its absence is
# what turns a crash into a failure rather than a shorter report.
TRACE=""; COMPLETED=0
while read -r line; do
    case "${line}" in
        PASSCHK*) ok "${line#PASSCHK }" ;;
        FAILCHK*) bad "${line#FAILCHK }" ;;
        SECTION*) say "${line#SECTION }" ;;
        DONECHK)  COMPLETED=1 ;;
        *)        TRACE="${TRACE}${line}"$'\n' ;;
    esac
done < <(be python3 - <<'PYEOF' 2>&1
import os, django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ir_platform.settings"); django.setup()
from django.db import IntegrityError, transaction
from django.utils import timezone
from django.db.utils import ProgrammingError
from cases.models import CollectionRun, Finding, Host, Investigation

def chk(cond, label):
    print(("PASSCHK " if cond else "FAILCHK ") + label)

MID = "uat-schema-machine-id-0001"

print("SECTION Host identity — one machine cannot become two")
try:
    with transaction.atomic():
        Host.objects.create(hostname="uat-schema-a", machine_id=MID)
        # The second create is the losing side of the race the constraint exists to stop.
        refused = False
        try:
            with transaction.atomic():
                Host.objects.create(hostname="uat-schema-b", machine_id=MID)
        except IntegrityError:
            refused = True
        chk(refused, "a second host claiming the same machine-id is REFUSED by the database")

        # Blank machine-id means "not recorded" and must stay repeatable — a non-partial
        # index would collapse every such host into one.
        blanks_ok = True
        try:
            with transaction.atomic():
                Host.objects.create(hostname="uat-schema-blank-1", machine_id="")
                Host.objects.create(hostname="uat-schema-blank-2", machine_id="")
        except IntegrityError:
            blanks_ok = False
        chk(blanks_ok, "hosts with NO machine-id remain distinct — the constraint is partial")
        raise RuntimeError("rollback")
except RuntimeError:
    pass
chk(not Host.objects.filter(machine_id=MID).exists(), "the probe left no rows behind")

print("SECTION Collection idempotency — one collection cannot be counted twice")
inv = Investigation.objects.order_by("id").first()
host = Host.objects.order_by("id").first()
if inv and host:
    try:
        with transaction.atomic():
            r1 = CollectionRun.objects.create(investigation=inv, host=host, stamp="uat-schema-stamp")
            refused = False
            try:
                with transaction.atomic():
                    CollectionRun.objects.create(investigation=inv, host=host, stamp="uat-schema-stamp")
            except IntegrityError:
                refused = True
            chk(refused, "re-posting the same (investigation, host, stamp) is REFUSED by the database")

            # A different stamp is a different collection and must still be allowed, or
            # re-collection of a host would be blocked — the opposite of what is wanted.
            allowed = True
            try:
                with transaction.atomic():
                    CollectionRun.objects.create(investigation=inv, host=host, stamp="uat-schema-stamp-2")
            except IntegrityError:
                allowed = False
            chk(allowed, "a SECOND collection of the same host under a new stamp is still accepted")
            raise RuntimeError("rollback")
    except RuntimeError:
        pass
    chk(not CollectionRun.objects.filter(stamp__startswith="uat-schema-stamp").exists(),
        "the probe left no runs behind")
else:
    chk(False, "no investigation/host available to test run idempotency")

print("SECTION Host identity is historised, not overwritten")
# Driven through resolve_host — the real ingest path — because the defect was that this
# function overwrote the name while its comment claimed an audit trail held it.
from cases.ingest import resolve_host
from cases.models import HostIdentityChange

RENAME_MID = "uat-schema-rename-0001"
try:
    with transaction.atomic():
        h1 = resolve_host({"hostname": "uat-old-name", "machine_id": RENAME_MID,
                           "hostname_source": "host-mount"},
                          {"stamp": "uat-stamp-1"})
        h2 = resolve_host({"hostname": "uat-new-name", "machine_id": RENAME_MID,
                           "hostname_source": "host-mount"},
                          {"stamp": "uat-stamp-2"})
        chk(h1.id == h2.id, "a renamed machine still resolves to ONE host (machine-id is the key)")
        chk(h2.hostname == "uat-new-name", "the host follows the current name")

        changes = list(HostIdentityChange.objects.filter(host=h2, field="hostname"))
        chk(len(changes) == 1, f"the rename produced exactly one history row ({len(changes)})")
        if changes:
            c = changes[0]
            chk(c.from_value == "uat-old-name" and c.to_value == "uat-new-name",
                f"the history names what it WAS and what it became ({c.from_value} -> {c.to_value})")
            chk(c.source_stamp == "uat-stamp-2",
                f"the history names the collection that observed it ({c.source_stamp})")

        # A collection that reports the SAME name must not manufacture history.
        resolve_host({"hostname": "uat-new-name", "machine_id": RENAME_MID,
                      "hostname_source": "host-mount"}, {"stamp": "uat-stamp-3"})
        chk(HostIdentityChange.objects.filter(host=h2, field="hostname").count() == 1,
            "an unchanged name writes NO history row")

        # An untrusted name — the collecting container's own id — must not be taken as a
        # rename, or every containerised collection would rewrite the machine's identity.
        resolve_host({"hostname": "3f9a1c2b4d5e", "machine_id": RENAME_MID,
                      "hostname_source": "container-fallback"}, {"stamp": "uat-stamp-4"})
        h_after = Host.objects.get(id=h2.id)
        chk(h_after.hostname == "uat-new-name",
            "a container-fallback name is REFUSED as a rename — identity is not rewritten by it")
        raise RuntimeError("rollback")
except RuntimeError:
    pass
chk(not Host.objects.filter(machine_id=RENAME_MID).exists(), "the rename probe left no rows behind")

print("SECTION Indexes serve the queries they were built for")
from django.db import connections
cur = connections["default"].cursor()
# The technique filter is jsonb containment; a B-tree cannot serve it. Proving the planner
# CHOOSES the GIN index is the difference between having an index and using one.
cur.execute("SET LOCAL enable_seqscan = off")
cur.execute("EXPLAIN SELECT id FROM cases_finding WHERE mitre @> '[\"T1021.001\"]'::jsonb")
plan = " ".join(r[0] for r in cur.fetchall())
chk("finding_mitre_gin" in plan, f"the ATT&CK containment query uses the GIN index")
cur.execute("EXPLAIN SELECT id FROM cases_finding WHERE source = 'memory'")
plan2 = " ".join(r[0] for r in cur.fetchall())
chk("finding_source_idx" in plan2 or "Index" in plan2, "the source filter uses an index")

# raw is deliberately unindexed; assert that decision holds rather than drifting.
cur.execute("""SELECT count(*) FROM pg_indexes
               WHERE tablename='cases_finding' AND indexdef ILIKE '%raw%'""")
chk(cur.fetchone()[0] == 0,
    "Finding.raw carries no index — it is read in Python, never queried by key in SQL")

print("SECTION S5 — a re-analysis supersedes the prior adjudication, never deletes it")
from django.db.models import Count as _C
from cases.models import CollectionRun, MemoryAnalysisRun, MemoryCapture, ProcessVerdict
# Against a run that HAS been adjudicated: asserting supersede on an empty table would pass
# while the behavior was absent.
pv_run = CollectionRun.objects.filter(process_verdicts__isnull=False).distinct().first()
chk(pv_run is not None, "a run carrying engine adjudication exists to assert against")
if pv_run:
    live_n = ProcessVerdict.objects.filter(run=pv_run, is_current=True).count()
    chk(live_n > 0, f"the run's current adjudication is present ({live_n} PIDs)")
    # One PID must never appear twice in the LIVE set — that is what superseding buys over
    # accumulating, and it is the failure an analyst would see as a duplicated process.
    dup = ProcessVerdict.objects.filter(run=pv_run, is_current=True) \
        .values("pid").annotate(n=_C("id")).filter(n__gt=1).count()
    chk(dup == 0, f"no PID carries two live verdicts ({dup} duplicated)")
    # The supersede path exercised rather than described: mark the live set superseded the
    # way investigation.persist does, confirm the rows SURVIVE and leave the live set, then
    # roll back so the deployment is untouched.
    try:
        with transaction.atomic():
            total_before = ProcessVerdict.objects.filter(run=pv_run).count()
            ProcessVerdict.objects.filter(run=pv_run, is_current=True).update(
                is_current=False, superseded_at=timezone.now())
            total_after = ProcessVerdict.objects.filter(run=pv_run).count()
            still_live = ProcessVerdict.objects.filter(run=pv_run, is_current=True).count()
            chk(total_after == total_before,
                f"superseding DESTROYS NOTHING — {total_before} rows before, {total_after} after")
            chk(still_live == 0,
                f"the superseded pass leaves the live set ({live_n} -> {still_live})")
            chk(ProcessVerdict.objects.filter(run=pv_run, is_current=False,
                                              superseded_at__isnull=False).count() >= live_n,
                "every superseded row records WHEN it was superseded")
            raise RuntimeError("rollback")
    except RuntimeError:
        pass
    chk(ProcessVerdict.objects.filter(run=pv_run, is_current=True).count() == live_n,
        "the supersede probe left the deployment's adjudication as it found it")

print("SECTION S6 — purging an image keeps the conclusions drawn from it")
cap = MemoryCapture.objects.filter(analyses__isnull=False).distinct().first()
chk(cap is not None, "an analyzed capture exists to assert against")
if cap:
    # The guarantee: an image can be purged for retention and the ANALYSIS survives, or the
    # platform erases its own conclusions the moment storage policy runs.
    n_analyses = MemoryAnalysisRun.objects.filter(capture=cap).count()
    n_findings = Finding.objects.filter(run=cap.run, source="memory").count()
    n_verdicts = ProcessVerdict.objects.filter(analysis__capture=cap).count()
    was = cap.retention_status
    try:
        with transaction.atomic():
            MemoryCapture.objects.filter(id=cap.id).update(retention_status="purged")
            chk(MemoryAnalysisRun.objects.filter(capture=cap).count() == n_analyses,
                f"purging the image leaves every analysis run intact ({n_analyses})")
            chk(Finding.objects.filter(run=cap.run, source="memory").count() == n_findings,
                f"purging the image leaves its findings intact ({n_findings})")
            chk(ProcessVerdict.objects.filter(analysis__capture=cap).count() == n_verdicts,
                f"purging the image leaves the per-PID adjudication intact ({n_verdicts})")
            raise RuntimeError("rollback")
    except RuntimeError:
        pass
    chk(MemoryCapture.objects.get(id=cap.id).retention_status == was,
        "the purge probe left the capture's retention state as it found it")

print("SECTION S3/S4 — an automated pass may not quietly discard a human determination")
# Driven through `_apply_to_findings` itself, with real ProcessVerdict rows: the defect was
# that this function overwrote whatever it found, so asserting on the field alone would pass
# while the behavior stayed absent.
from cases.investigation import NON_DETECTION_TYPES, _apply_to_findings, _finding_pid
from cases.models import FindingReclassification

adj_run = (CollectionRun.objects
           .filter(process_verdicts__isnull=False, findings__isnull=False)
           .distinct().first())
analysis = (MemoryAnalysisRun.objects.filter(capture__run=adj_run).order_by("-id").first()
            if adj_run else None)
chk(adj_run is not None and analysis is not None,
    "an adjudicated run with a memory analysis pass exists to assert against")

target, pvs = None, []
if adj_run and analysis:
    pvs = list(ProcessVerdict.objects.filter(run=adj_run, is_current=True))
    by_pid = {v.pid: v for v in pvs if v.pid is not None}
    for _f in Finding.objects.filter(run=adj_run):
        if any(_f.finding_type.startswith(p) for p in NON_DETECTION_TYPES):
            continue
        _pid = _finding_pid(_f)
        _pid = 0 if _pid is None else _pid
        if _pid in by_pid:
            target = (_f, by_pid[_pid])
            break
    chk(target is not None, "a finding the engine holds a verdict for exists to assert against")

if target:
    f, v = target
    was = (f.verdict, f.adjudicated_by, f.adjudication_conflict or {})
    # A verdict the engine actively disagrees with, so "unchanged" cannot be mistaken for
    # agreement.
    held = "True Positive" if v.verdict != "True Positive" else "False Positive"

    try:
        with transaction.atomic():
            Finding.objects.filter(id=f.id).update(
                verdict=held, confidence="High",
                adjudicated_by="analyst", adjudication_conflict={})
            before_n = FindingReclassification.objects.filter(finding_id=f.id).count()
            _apply_to_findings(adj_run, analysis, pvs)
            after = Finding.objects.get(id=f.id)
            chk(after.verdict == held,
                f"an engine pass does NOT overwrite the analyst's verdict "
                f"(kept {held}; the engine said {v.verdict})")
            conflict = after.adjudication_conflict or {}
            chk(conflict.get("engine_verdict") == v.verdict,
                f"the disagreement is RECORDED for review instead of applied "
                f"(engine: {conflict.get('engine_verdict')})")
            chk(conflict.get("analysis_run") == analysis.id,
                f"the conflict names the pass that disagreed (run {conflict.get('analysis_run')})")
            chk(FindingReclassification.objects.filter(finding_id=f.id).count() == before_n,
                "a refused overwrite writes no history — nothing changed to record")
            raise RuntimeError("rollback")
    except RuntimeError:
        pass

    # Precedence is not a blanket freeze: a verdict the engine owns is still its own to
    # revise, or re-adjudication would stop working the moment this landed.
    try:
        with transaction.atomic():
            stale = "True Positive" if v.verdict != "True Positive" else "False Positive"
            Finding.objects.filter(id=f.id).update(
                verdict=stale, confidence="Low",
                adjudicated_by="engine", adjudication_conflict={})
            _apply_to_findings(adj_run, analysis, pvs)
            after = Finding.objects.get(id=f.id)
            chk(after.verdict == v.verdict,
                f"a verdict the ENGINE owns is still revised by a later pass "
                f"({stale} -> {after.verdict})")
            row = (FindingReclassification.objects
                   .filter(finding_id=f.id, actor="investigation-engine")
                   .order_by("-id").first())
            chk(row is not None and row.from_verdict == stale and row.to_verdict == v.verdict,
                f"the change of mind is history naming BOTH values "
                f"({row.from_verdict} -> {row.to_verdict})" if row
                else "the engine's change of verdict produced NO history row")
            chk(row is not None and str(analysis.id) in row.note,
                "the history row names the analysis pass that decided it")
            chk(after.adjudication_run_id == analysis.id,
                "the finding records which pass produced its verdict")
            raise RuntimeError("rollback")
    except RuntimeError:
        pass

    # Agreement must clear a standing conflict, or the analyst is sent back to a question
    # the engine has stopped asking.
    try:
        with transaction.atomic():
            Finding.objects.filter(id=f.id).update(
                verdict=v.verdict, confidence=v.confidence, adjudicated_by="analyst",
                adjudication_conflict={"engine_verdict": "stale", "analysis_run": 0})
            _apply_to_findings(adj_run, analysis, pvs)
            after = Finding.objects.get(id=f.id)
            chk(after.adjudication_conflict == {},
                "where the engine AGREES, the standing conflict is cleared")
            chk(after.verdict == v.verdict and after.adjudicated_by == "analyst",
                "agreement does not quietly transfer ownership away from the analyst")
            raise RuntimeError("rollback")
    except RuntimeError:
        pass

    now = Finding.objects.get(id=f.id)
    chk((now.verdict, now.adjudicated_by, now.adjudication_conflict or {}) == was,
        f"the precedence probes left the finding exactly as they found it ({was[0]})")

# The migration's backfill is what protects verdicts that already existed. Untested, S4
# would hold only for findings adjudicated after it deployed — the ones least at risk.
cur.execute("""SELECT count(*) FROM cases_finding
                WHERE adjudicated_by = '' AND jsonb_exists(raw, 'adjudication')""")
_n = cur.fetchone()[0]
chk(_n == 0, f"no engine-adjudicated finding was left unowned by the backfill ({_n} stranded)")

cur.execute("""SELECT count(*) FROM cases_finding f
                WHERE f.adjudicated_by <> 'analyst' AND EXISTS (
                      SELECT 1 FROM cases_findingreclassification r
                       WHERE r.finding_id = f.id AND r.actor <> 'investigation-engine')""")
_n = cur.fetchone()[0]
chk(_n == 0, f"every finding an analyst reclassified is marked as theirs ({_n} unprotected)")

# --- T1: the lifecycle is enforced by the model, not by whoever calls it ------------------
from cases.models import Investigation, InvalidTransition
from django.db import transaction as _txn


# T1 and T2 write real rows and clean up by DELETING them, not by rolling back.
#
# Both run in autocommit, like the ingest path they exercise, because T2's whole claim is
# that a rollup survives the deletion of the evidence it summarizes — and survival cannot be
# demonstrated inside a transaction that is thrown away regardless.
#
# The sections above roll back instead, and are right to: they prove the database REFUSES
# something, so nothing they write should ever land.
#
# What was here before was `transaction.savepoint()`, which returns None outside an atomic
# block. `savepoint_rollback(None)` did nothing, the fixtures were committed, and the probe
# passed exactly once before failing on its own leftovers at the unique machine-id
# constraint on every later run.
def _clear_fixtures():
    """Remove T1/T2 fixtures — this run's, and any a previous run committed."""
    from cases.models import Host as _H, IndicatorSighting as _S
    _S.objects.filter(value="Global\\uat-t2-mutex").delete()
    Investigation.objects.filter(incident_id__in=("UAT-T1", "UAT-T2")).delete()
    _H.objects.filter(machine_id="uat-t2-machine").delete()


_clear_fixtures()
_inv = Investigation.objects.create(name="uat-lifecycle", incident_id="UAT-T1")
chk(_inv.status == "open", "a new investigation starts open")

_refused = False
try:
    _inv.transition_to("archived")          # skipping the whole engagement
except InvalidTransition:
    _refused = True
chk(_refused, "the model REFUSES open -> archived; archival cannot skip conclusion")

_inv.transition_to("concluded")
chk(_inv.concluded_at is not None, "concluding stamps concluded_at for the stalled-case query")

_inv.transition_to("open")
chk(_inv.concluded_at is None,
    "reopening CLEARS concluded_at — a reopened case is not a concluded one")

_inv.transition_to("concluded")
_inv.transition_to("archived")
_terminal = False
try:
    _inv.transition_to("open")
except InvalidTransition:
    _terminal = True
chk(_terminal, "archived is terminal — its evidence has been moved out")
_clear_fixtures()

# --- T2: the rollup outlives the rows it summarizes ---------------------------------------
from cases.ingest import as_datetime, roll_up_sightings
from cases.models import CollectionRun, Host, IndicatorSighting, IOC

# A bundle carries collected_at as an ISO STRING, and Django leaves an assigned attribute
# exactly as given until it is reloaded — so the run object the ingest path uses held a str.
# Comparing it against a first_seen from the database raised, and only on RE-collection: the
# first ingest of an indicator created the row and never compared, the second returned HTTP
# 500, and the puller held the bundle in the DMZ rather than discard evidence it could not
# store. Asserted on the parser AND on the second rollup below, because the shape is the
# cause and the re-collection is where it bites.
import datetime as _dt
chk(isinstance(as_datetime("2026-07-15T09:30:00+00:00"), _dt.datetime),
    "a bundle's ISO timestamp parses to a datetime")
chk(as_datetime(_dt.datetime(2026, 7, 15, tzinfo=_dt.timezone.utc)).tzinfo is not None,
    "a datetime passes through still aware")
_naive = as_datetime("2026-07-15T09:30:00")
chk(_naive is not None and _naive.tzinfo is not None,
    "a naive timestamp is made aware rather than refused — the instant is still real")
chk(as_datetime(None) is None and as_datetime("") is None and as_datetime("not a date") is None,
    "an absent or unparseable timestamp yields None, so the caller falls back to now()")

_inv = Investigation.objects.create(name="uat-sightings", incident_id="UAT-T2")
_host = Host.objects.create(hostname="uat-t2-host", machine_id="uat-t2-machine")
_run = CollectionRun.objects.create(investigation=_inv, host=_host, stamp="uat-t2-1")
_iocs = [IOC(run=_run, ioc_type="mutex", value="Global\\uat-t2-mutex")]
IOC.objects.bulk_create(_iocs)
roll_up_sightings(_run, _iocs)

_s = IndicatorSighting.objects.filter(ioc_type="mutex", value="Global\\uat-t2-mutex")
chk(_s.count() == 1, "ingest writes an indicator sighting beside the IOC rows")
_row = _s.first()
chk(_row.investigation_id == _inv.id and _row.hostname == "uat-t2-host",
    "the sighting carries its investigation and hostname denormalized")

_run2 = CollectionRun.objects.create(investigation=_inv, host=_host, stamp="uat-t2-2")
_iocs2 = [IOC(run=_run2, ioc_type="mutex", value="Global\\uat-t2-mutex")]
IOC.objects.bulk_create(_iocs2)
roll_up_sightings(_run2, _iocs2)
chk(_s.count() == 1 and _s.first().sighting_count == 2,
    "a re-collection increments the sighting rather than duplicating it")

# The point of the whole model: deleting the evidence must NOT delete the summary.
_run.delete(); _run2.delete()
chk(IOC.objects.filter(value="Global\\uat-t2-mutex").count() == 0,
    "deleting the runs took their IOC rows with them")
chk(_s.count() == 1,
    "and the indicator sighting SURVIVED — the cross-case pivot still answers")
_clear_fixtures()
chk(not Investigation.objects.filter(incident_id__in=("UAT-T1", "UAT-T2")).exists()
    and not Host.objects.filter(machine_id="uat-t2-machine").exists(),
    "T1/T2 left nothing behind — the probe is re-runnable")

print("DONECHK")
PYEOF
)

say "Probe completed"
if [[ "${COMPLETED}" == "1" ]]; then
    ok "every assertion in the probe ran — no section was cut short"
else
    bad "the probe DID NOT finish — assertions after the failure never ran"
    printf '%s\n' "${TRACE}" >&2
fi

# ============================================================ audit chain under concurrency
say "The audit chain stays linear when writers collide"

# The chain is the platform's tamper-evidence, and ordinary concurrent work could break it:
# `select_for_update()` on the last row cannot lock a row that does not exist yet, so two
# appenders read the same predecessor and both chain from it. A load test's concurrent
# provisioning did exactly that and forked the ledger at row 2024.
#
# Asserted by RACING it. The defect is invisible to a sequential test, which is why it
# survived every previous run of this suite.
RACE="$(${RUNTIME} exec -i "${BE}" python3 - <<'PY' 2>&1 | tail -6
import os, django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ir_platform.settings"); django.setup()
from concurrent.futures import ThreadPoolExecutor
from django.db import connections
from cases.audit import audit, verify_audit_detail
from cases.models import AuditLog

N = 24
def one(i):
    try:
        audit("uat-race", "uat.chain.race", role="admin", method="POST",
              path="/uat/race", object_id=str(i), detail={"i": i})
    finally:
        connections.close_all()

before_ok, before_broken, _ = verify_audit_detail()
with ThreadPoolExecutor(max_workers=N) as ex:
    list(ex.map(one, range(N)))
written = AuditLog.objects.filter(action="uat.chain.race").count()
ok, broken, _ = verify_audit_detail()
prevs = list(AuditLog.objects.filter(action="uat.chain.race")
             .values_list("prev_hash", flat=True))
print(f"WRITTEN {written}/{N}")
print(f"DISTINCT_PREV {len(set(prevs))}/{len(prevs)}")
print(f"CHAIN_AFTER {'ok' if ok else 'broken@' + str(broken)}")
print(f"CHAIN_BEFORE {'ok' if before_ok else 'broken@' + str(before_broken)}")
AuditLog.objects.filter(action="uat.chain.race").delete()
PY
)"
W="$(sed -n 's#^WRITTEN \([0-9]*\)/.*#\1#p' <<<"${RACE}")"
read -r D_UNIQ D_TOT <<<"$(sed -n 's#^DISTINCT_PREV \([0-9]*\)/\([0-9]*\)#\1 \2#p' <<<"${RACE}")"
[[ "${W:-0}" -eq 24 ]] \
    && ok "24 concurrent appenders all wrote (${W}/24) — none lost to lock contention" \
    || bad "only ${W:-0}/24 concurrent audit writes landed"
[[ "${D_UNIQ:-0}" -eq "${D_TOT:-1}" && "${D_TOT:-0}" -gt 0 ]] \
    && ok "every racing row chained from a DIFFERENT predecessor (${D_UNIQ}/${D_TOT} distinct) — the appenders serialized" \
    || bad "${D_UNIQ:-0} distinct predecessors across ${D_TOT:-0} racing rows — writers collided and the chain forked"
# Compared BEFORE against AFTER, not against perfection. This ledger carries a historical
# break from the very race being fixed (rows 2023/2024, written before the lock existed), and
# an absolute assertion would fail forever on damage already done while saying nothing about
# whether the appenders still collide. The question is whether the race makes it WORSE.
C_BEFORE="$(sed -n 's/^CHAIN_BEFORE //p' <<<"${RACE}")"
C_AFTER="$(sed -n 's/^CHAIN_AFTER //p' <<<"${RACE}")"
[[ -n "${C_AFTER}" && "${C_AFTER}" == "${C_BEFORE}" ]] \
    && ok "24 simultaneous appends left the chain exactly as they found it (${C_AFTER}) — concurrency adds no break" \
    || bad "concurrent appends CHANGED the chain verdict: ${C_BEFORE:-?} -> ${C_AFTER:-?}"

# ============================================================ checkpoints cannot hide tampering
say "An acknowledged discontinuity is not a way to clear a real one"

# A checkpoint lets a KNOWN historical break be declared rather than re-chained. That is only
# safe if it cannot also clear a break nobody declared, and cannot survive the row it covers
# being edited afterwards. Both run inside a transaction that is rolled back, so the ledger is
# unchanged either way — asserted at the end.
CP="$(${RUNTIME} exec -i -w /app ir-enclave_backend_1 python - <<'PYCP' 2>&1
import os, django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ir_platform.settings")
django.setup()
from django.db import transaction
from cases import audit as A
from cases.models import AuditCheckpoint, AuditLog

base_ok, base_bad, base_sigs = A.verify_audit_detail()
print(f"BASE {base_ok} {len(base_sigs.get('discontinuities', []))}")

# 1. Edit a row the checkpoints do NOT cover. The chain must break.
with transaction.atomic():
    row = AuditLog.objects.order_by("-id").first()
    row.detail = dict(row.detail or {}, uat_tamper=True)
    row.save(update_fields=["detail"])
    ok, bad, _ = A.verify_audit_detail()
    print(f"TAMPER {ok} {bad}")
    transaction.set_rollback(True)

# 2. A checkpoint whose hashes do not match the gap must NOT clear it.
with transaction.atomic():
    row = AuditLog.objects.order_by("-id").first()
    row.detail = dict(row.detail or {}, uat_tamper=True)
    row.save(update_fields=["detail"])
    AuditCheckpoint.objects.create(
        at_entry_id=row.id, observed_prev_hash="0" * 64, declared_prev_hash="0" * 64,
        reason="uat forged acknowledgement", recorded_by="uat",
        signature="", sig_key_id=A._key_id())
    ok, bad, _ = A.verify_audit_detail()
    print(f"FORGED {ok} {bad}")
    transaction.set_rollback(True)

after_ok, _, after_sigs = A.verify_audit_detail()
print(f"AFTER {after_ok} {len(after_sigs.get('discontinuities', []))}")
PYCP
)"
read -r B_OK B_N <<<"$(sed -n 's/^BASE //p' <<<"${CP}")"
read -r T_OK T_AT <<<"$(sed -n 's/^TAMPER //p' <<<"${CP}")"
read -r F_OK F_AT <<<"$(sed -n 's/^FORGED //p' <<<"${CP}")"
read -r A_OK A_N <<<"$(sed -n 's/^AFTER //p' <<<"${CP}")"

if [[ -z "${B_OK}" || -z "${T_OK}" || -z "${F_OK}" || -z "${A_OK}" ]]; then
    # A missing verdict is not a failed one. Reporting each absent line as "the platform is
    # broken" hides that the probe stopped, and the reason is in its output.
    bad "the checkpoint probe stopped part-way (base=${B_OK:-none} tamper=${T_OK:-none} forged=${F_OK:-none} after=${A_OK:-none}) — a test defect, not a platform verdict"
    while IFS= read -r l; do [[ -n "${l}" ]] && info "${l}"; done < <(tail -6 <<<"${CP}")
else
    [[ "${B_OK}" == "True" ]] \
        && ok "the chain verifies with ${B_N} acknowledged discontinuit(ies) and no unexplained break" \
        || bad "the chain has an UNEXPLAINED break — a checkpoint covers only what was declared"
    [[ "${T_OK}" == "False" ]] \
        && ok "editing a row still breaks the chain (detected at entry ${T_AT}) — checkpoints do not blanket-forgive" \
        || bad "a tampered row verified clean — the chain no longer detects tampering"
    [[ "${F_OK}" == "False" ]] \
        && ok "a checkpoint naming the wrong hashes did NOT clear the break (still ${F_AT}) — an acknowledgement must match its gap" \
        || bad "a forged checkpoint cleared a real break — anyone able to write the table could hide tampering"
    [[ "${A_OK}" == "True" && "${A_N}" == "${B_N}" ]] \
        && ok "the ledger is unchanged by this test (${A_N} discontinuities, same as before)" \
        || bad "this test altered the ledger: ${B_N} -> ${A_N} discontinuities"
fi

say "Result"
if [[ "${FAILED}" == "0" ]]; then
    ok "the schema enforces its own invariants — the application no longer has to be careful"
else
    bad "schema integrity does NOT hold — see failures above"
fi
report_finish
exit "${FAILED}"
