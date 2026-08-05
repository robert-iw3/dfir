"""
Ingest normalization: turn a collection bundle (posted by the store-and-forward
broker) into normalized rows.

The broker has already verified the custody seal and uploaded the memory image to
object storage; this module records the structured artifacts and the object pointer,
then the caller enqueues server-side memory analysis.

Idempotent: re-posting the same (host, stamp) within an investigation returns the
existing run rather than duplicating it.
"""
import json
import logging

from django.db import IntegrityError, transaction
from django.utils import timezone

from . import audit
from .models import (
    CollectionRun,
    Finding,
    Host,
    HostIdentityChange,
    IndicatorSighting,
    IOC,
    Investigation,
    MemoryCapture,
    Principal,
)

logger = logging.getLogger(__name__)


def _ci(d, *names, default=None):
    """Case-insensitive fetch across candidate field names (finding_schema is CI)."""
    low = {k.lower(): v for k, v in d.items()}
    for n in names:
        if n.lower() in low and low[n.lower()] not in (None, ""):
            return low[n.lower()]
    return default


def _as_list(mitre):
    if mitre is None:
        return []
    if isinstance(mitre, list):
        return [str(m) for m in mitre]
    return [str(mitre)]


def _normalize_finding(run, f, source="collector"):
    return Finding(
        run=run,
        finding_type=str(_ci(f, "Type", default="Unknown"))[:255],
        target=str(_ci(f, "Target", default=""))[:512],
        verdict=str(_ci(f, "Verdict", default="")),
        confidence=str(_ci(f, "Confidence", default="")),
        mitre=_as_list(_ci(f, "MITRE", "Mitre", "Technique")),
        tier=str(_ci(f, "Tier", "mechanism_id", default="")),
        subject_path=str(_ci(f, "SubjectPath", default=""))[:1024],
        source=source,
        raw=f,
    )


def _normalize_iocs(run, iocs):
    """IOCs.json is a dict of typed lists (or already a flat list). Flatten to rows."""
    rows = []
    if isinstance(iocs, dict):
        for ioc_type, values in iocs.items():
            if not isinstance(values, list):
                values = [values]
            for v in values:
                if isinstance(v, dict):
                    val = v.get("value") or v.get("indicator") or json.dumps(v)
                    ctx = v
                else:
                    val, ctx = v, {}
                rows.append(IOC(run=run, ioc_type=str(ioc_type)[:64],
                                value=str(val)[:1024], context=ctx))
    elif isinstance(iocs, list):
        for v in iocs:
            if isinstance(v, dict):
                rows.append(IOC(run=run,
                                ioc_type=str(v.get("type", "unknown"))[:64],
                                value=str(v.get("value", ""))[:1024], context=v))
    return rows


def _iocs_from_findings(run, findings, existing=()):
    """Roll every indicator a finding RECOVERED up into this run's IOC index.

    IOCs.json carries the hunt's own output — the addresses and hashes it matched on. The
    material that identifies the IMPLANT rather than its infrastructure (the builder-fixed
    user-agent, mutex, named pipe, JA3, the extracted C2 config, a reverse engineer's
    attribution) is written into the finding and, until now, reached only the correlation
    graph. So a host's IOC list under-reported what was found on it, and IOC search could
    not answer "which other hosts carry this mutex" — the question that survives the
    infrastructure rotation an actor performs between investigations.

    Deduplicated on (type, value), against the hunt's rows and within this batch: the same
    builder indicator rides every beacon finding, and an index that repeats it once per
    finding is a count no analyst can read.
    """
    from .indicators import extract

    seen = {(r.ioc_type, r.value) for r in existing}
    rows = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        for ioc_type, value, ctx in extract(f):
            key = (ioc_type[:64], value[:1024])
            if key in seen:
                continue
            seen.add(key)
            rows.append(IOC(run=run, ioc_type=key[0], value=key[1],
                            context={**ctx, "finding_type": str(f.get("Type", ""))[:128]}))
    return rows


def roll_up_sightings(run, iocs):
    """Write the per-(indicator, host, investigation) rollup beside the IOC rows.

    Written at ingest rather than derived on demand, because the point of the rollup is to
    answer after the rows it summarizes are gone. A re-collection of the same host widens the
    window and increments the count instead of forking a second row — the same indicator on
    the same host in the same engagement is one sighting record, seen more than once.
    """
    if not iocs:
        return 0
    host = run.host
    inv = run.investigation
    investigation_id = getattr(inv, "id", None)
    if investigation_id is None:
        # Nothing to pivot within. Recorded as a warning rather than silently skipped: a
        # sighting that was never written is indistinguishable later from one that never
        # happened.
        logger.warning("run %s has no investigation; %d indicator sighting(s) not rolled up",
                       run.id, len(iocs))
        return 0

    seen = run.collected_at or timezone.now()
    written = 0
    for ioc in iocs:
        obj, created = IndicatorSighting.objects.get_or_create(
            ioc_type=ioc.ioc_type, value=ioc.value,
            host_id=host.id, investigation_id=investigation_id,
            defaults={
                "incident_id": getattr(inv, "incident_id", "") or "",
                "hostname": host.hostname,
                "first_seen": seen, "last_seen": seen,
                "context": {"finding_type": (ioc.context or {}).get("finding_type", "")},
            },
        )
        if not created:
            obj.sighting_count += 1
            if obj.first_seen is None or (seen and seen < obj.first_seen):
                obj.first_seen = seen
            if obj.last_seen is None or (seen and seen > obj.last_seen):
                obj.last_seen = seen
            # The hostname is denormalized, so a rename has to reach the rollup too or the
            # cross-case pivot answers under a name the fleet no longer uses.
            obj.hostname = host.hostname
            obj.save(update_fields=["sighting_count", "first_seen", "last_seen",
                                    "hostname", "updated_at"])
        written += 1
    return written


def resolve_host(host_in, run_in=None):
    """Find or create the Host this evidence belongs to.

    Collection artifacts land in minutes; a memory image of the same machine is analyzed by a
    worker and lands hours later, and with several workers running they arrive interleaved and
    out of order. Every one of those arrivals has to converge on the same host record, or a
    memory finding and the collection finding that corroborates it end up filed under
    different hosts and never meet.

    machine-id is the join key, because it is the only thing that stays constant across the
    gap: hostnames are renamed, and a collection run without the host filesystem mounted
    reports a container id that differs on every run. A bundle carrying no machine-id --
    collected before the collector recorded it, or where it was unreadable -- falls back to
    the hostname, which is what the earlier behavior did for every bundle.

    When a machine-id first arrives for a host already known by name, it is recorded on that
    host rather than creating a second one; a later rename then still resolves to it.
    """
    machine_id = (host_in.get("machine_id") or "").strip()
    hostname = host_in.get("hostname", "unknown")
    platform = host_in.get("platform", "linux")

    # Only a name resolved from the host filesystem, or supplied deliberately, describes the
    # machine. The fallback is the collecting container's id, which differs on every run --
    # accepting it as a rename would replace a good name with a disposable one.
    name_is_trustworthy = host_in.get("hostname_source", "") in ("host-mount", "override", "")

    # When the collection that observed the change was taken — not when this row is written.
    # Taken from the run, since a bundle can arrive long after the rename it reports; the
    # host payload carries identity, the run payload carries timing.
    observed = (run_in or {}).get("collected_at") or None
    stamp = (run_in or {}).get("stamp", "")

    def record_change(host, field, from_value, to_value):
        """Historise an identity change before the Host row loses the old value."""
        HostIdentityChange.objects.create(
            host=host, field=field, from_value=from_value or "", to_value=to_value or "",
            observed_at=observed, source_stamp=stamp,
        )

    host = None
    if machine_id:
        host = Host.objects.filter(machine_id=machine_id).first()
        if host and host.hostname != hostname and name_is_trustworthy:
            # Same machine, renamed since it was last collected. Follow the current name and
            # keep the previous one: overwriting it silently left every earlier run rendering
            # under a name that host did not have when its evidence was collected.
            record_change(host, "hostname", host.hostname, hostname)
            host.hostname = hostname
            host.save(update_fields=["hostname"])
    if host is None:
        host = Host.objects.filter(hostname=hostname, platform=platform).first()
        if host and machine_id and not host.machine_id:
            # The machine reported an id for the first time. Recorded because it changes how
            # every future collection resolves to this host.
            record_change(host, "machine_id", "", machine_id)
            host.machine_id = machine_id
            host.save(update_fields=["machine_id"])
    if host is None:
        # The lookups above read before writing, so two arrivals for the same machine can
        # both reach here and both try to create it. The unique constraint on machine_id
        # makes the loser fail rather than succeed — catching it and re-reading is what
        # turns a split-evidence race into a no-op for the second arrival.
        try:
            with transaction.atomic():
                host = Host.objects.create(
                    hostname=hostname, platform=platform, machine_id=machine_id,
                    clock_context=host_in.get("clock_context", {}),
                )
        except IntegrityError:
            host = Host.objects.filter(machine_id=machine_id).first() if machine_id else None
            if host is None:
                raise
    if host_in.get("clock_context") and not host.clock_context:
        host.clock_context = host_in["clock_context"]
        host.save(update_fields=["clock_context"])

    # The endpoint's declared requirement, recorded against the machine that made it. Kept on
    # the host rather than the run because it describes the hardware — the next collection
    # from this machine will need the same again, which is what makes it worth acting on
    # before that collection starts.
    declaration = host_in.get("capacity_declaration") or {}
    if declaration:
        context = dict(host.clock_context or {})
        context["capacity_declaration"] = declaration
        host.clock_context = context
        host.save(update_fields=["clock_context"])
    return host


@transaction.atomic
def ingest_bundle(payload, actor="ir-broker"):
    """
    payload keys: investigation, host, run, custody, findings, iocs, principals, captures.
    Returns (CollectionRun, created: bool).
    """
    inv_in = payload.get("investigation", {})
    investigation, _ = Investigation.objects.get_or_create(
        incident_id=inv_in.get("incident_id", "") or "",
        name=inv_in.get("name") or inv_in.get("incident_id") or "Untitled investigation",
        defaults={
            "operator": inv_in.get("operator", ""),
            "severity": inv_in.get("severity", ""),
        },
    )

    host = resolve_host(payload.get("host", {}), payload.get("run", {}))

    run_in = payload.get("run", {})
    stamp = run_in.get("stamp", "")

    existing = CollectionRun.objects.filter(
        investigation=investigation, host=host, stamp=stamp
    ).first()
    if existing:
        return existing, False

    custody = payload.get("custody", {})
    run = CollectionRun.objects.create(
        investigation=investigation,
        host=host,
        stamp=stamp,
        toolkit_version=run_in.get("toolkit_version", ""),
        overall_status=run_in.get("overall_status", ""),
        tp_count=int(run_in.get("tp_count", 0) or 0),
        status_json=run_in.get("status_json", {}),
        custody_verified=bool(custody.get("verified", False)),
        custody_summary=custody.get("summary", {}),
        collected_at=run_in.get("collected_at") or timezone.now(),
        run_kind=run_in.get("run_kind", "initial"),
    )

    Finding.objects.bulk_create(
        [_normalize_finding(run, f) for f in payload.get("findings", []) if isinstance(f, dict)]
    )
    # The hunt's own IOCs first, then everything the findings recovered that is not already
    # among them — so the host's index holds the implant's identifying material, not only
    # the infrastructure it happened to touch.
    hunt_iocs = _normalize_iocs(run, payload.get("iocs", {}))
    all_iocs = hunt_iocs + _iocs_from_findings(run, payload.get("findings", []), hunt_iocs)
    IOC.objects.bulk_create(all_iocs)
    roll_up_sightings(run, all_iocs)
    Principal.objects.bulk_create([
        Principal(run=run, name=str(p.get("name") or p) if isinstance(p, dict) else str(p),
                  context=p if isinstance(p, dict) else {})
        for p in payload.get("principals", [])
    ])

    captures = []
    for c in payload.get("captures", []):
        captures.append(MemoryCapture.objects.create(
            run=run,
            store_backend=c.get("store_backend", "minio"),
            bucket=c.get("bucket", ""),
            object_key=c.get("object_key", ""),
            etag=c.get("etag", ""),
            size_bytes=int(c.get("size_bytes", 0) or 0),
            sha256=c.get("sha256", ""),
            image_format=c.get("image_format", "raw"),
            capture_tool=c.get("capture_tool", ""),
            symbol_context=c.get("symbol_context", {}),
            is_synthetic=bool(c.get("is_synthetic", False)),
        ))

    # Custody ledger continues into the DB, hash-chained.
    audit.custody(run, "ingest", custody.get("actor", actor),
                  {"custody_verified": run.custody_verified,
                   "summary": run.custody_summary, "captures": len(captures)})

    run._captures = captures  # hand back to caller so it can enqueue analysis
    return run, True
