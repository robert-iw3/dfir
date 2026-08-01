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

from django.db import transaction
from django.utils import timezone

from . import audit
from .models import (
    CollectionRun,
    Finding,
    Host,
    IOC,
    Investigation,
    MemoryCapture,
    Principal,
)


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


def resolve_host(host_in):
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

    host = None
    if machine_id:
        host = Host.objects.filter(machine_id=machine_id).first()
        if host and host.hostname != hostname and name_is_trustworthy:
            # Same machine, renamed since it was last collected. Follow the current name;
            # the audit trail holds the previous one.
            host.hostname = hostname
            host.save(update_fields=["hostname"])
    if host is None:
        host = Host.objects.filter(hostname=hostname, platform=platform).first()
        if host and machine_id and not host.machine_id:
            host.machine_id = machine_id
            host.save(update_fields=["machine_id"])
    if host is None:
        host = Host.objects.create(
            hostname=hostname, platform=platform, machine_id=machine_id,
            clock_context=host_in.get("clock_context", {}),
        )
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

    host = resolve_host(payload.get("host", {}))

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
    IOC.objects.bulk_create(_normalize_iocs(run, payload.get("iocs", {})))
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
