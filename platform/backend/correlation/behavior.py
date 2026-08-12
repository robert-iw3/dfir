"""
L0 — the behavior graph. Typed nodes and events derived from collected findings.

Built for EVERY host in the investigation, clean ones included: rarity weighting divides by
the population, so an artifact on all 25 hosts must be visible as being on all 25 — a graph
of only compromised hosts would make fleet-wide software look like rare shared tradecraft.

Extraction is deterministic table-driven mapping, no inference: what a finding type
contributes is stated below, every event carries the finding id it derives from, and the
verdict travels with the event so later layers can weight without re-joining `cases`.

Nothing reads this yet at v1.1 — clustering is unchanged. The graph is written and proven
first, so weighted linkage lands on a substrate that already exists on real data.
"""
from collections import defaultdict

from cases.models import Finding, IOC, Principal

from .models import BehaviorEvent, BehaviorNode

# finding_type -> (event verb, artifact subkind or None). Types absent here contribute
# indicator/technique/account nodes only, under the default "observed" verb.
EVENT_MAP = {
    "Implant Dropped": ("dropped", None),
    "C2 Beacon": ("beaconed", None),
    "Scheduled Task Persistence": ("persisted", "persistence_task"),
    "Service Persistence": ("persisted", "persistence_service"),
    "Scheduled Task": ("observed", "persistence_task"),
    "Autorun Entry": ("observed", "persistence_autorun"),
    "Data Staged": ("staged", "staging_name"),
    "Lateral Movement": ("moved", None),
    "Remote Execution": ("moved", None),
    "Authentication": ("authenticated", None),
    "Macro Execution": ("executed", None),
    "Cryptominer Process": ("executed", None),

    # The Linux hunts' vocabulary: every name is an operator choice kept between engagements, which
    # is what makes it a behavioral signal rather than a label.
    "Systemd Persistence": ("persisted", "persistence_service"),
    "Systemd Unit": ("observed", "persistence_service"),
    "Suspicious systemd service": ("persisted", "persistence_service"),
    "Cron Persistence": ("persisted", "persistence_cron"),
    "Cron Entry": ("observed", "persistence_cron"),
    "Shell Init Backdoor": ("persisted", "persistence_shell_init"),
    "Library Preload Hijack": ("persisted", "persistence_preload"),
    "Suspicious Kernel Module": ("persisted", "kernel_module"),
    "Hidden Kernel Module": ("persisted", "kernel_module"),
    "Unsigned Kernel Module": ("observed", "kernel_module"),
    "Webshell": ("dropped", "webshell"),
    "Execution From Writable Path": ("executed", "payload_path"),
    "Memory-Only Executable (memfd)": ("executed", "payload_path"),
    "Crypto Miner": ("executed", None),
    "Reverse Shell": ("executed", None),

    # Impact and the destruction around it. The ransom note's name and the policy object the
    # payload rode out on are chosen by the affiliate and reused across engagements; the rest
    # carry no name of their own and contribute their verb and technique only.
    "Ransomware": ("encrypted", "ransom_note"),
    "Group Policy Modification": ("persisted", "gpo_name"),
    "DLL Sideload": ("dropped", "sideloaded_dll"),
    "Phishing Attachment": ("delivered", None),
    "Shadow Copy Deletion": ("destroyed", None),
    "Backup Deletion": ("destroyed", None),
    "Service Stop": ("stopped", None),
    "Defender Disabled": ("evaded", None),
    "Event Log Cleared": ("evaded", None),
    "Audit Logging Disabled": ("evaded", None),

    # Long-dwell persistence and the tooling around it.
    "WMI Event Subscription": ("persisted", "persistence_wmi"),
    "Certificate Theft": ("stole", None),
    "External Connection": ("beaconed", None),
    "Exfiltration Over C2": ("exfiltrated", None),
    "Exfiltration Over Web Service": ("exfiltrated", None),
    # A remote-access tool's NAME is what distinguishes sanctioned from unsanctioned, and two
    # endpoints running the same unsanctioned one are worth comparing — which is exactly why
    # it must be an artifact rather than a hash alone.
    "Remote Access Tool": ("executed", "rmm_tool"),
}


# The indicator vocabulary lives in `cases.indicators` — the app that RECEIVES evidence
# owns it, because ingest rolls the same keys up into IOC rows. Two definitions would let
# the index and the graph disagree about what an indicator is.
from cases.indicators import LIST_INDICATORS, SCALAR_INDICATORS  # noqa: E402
from cases.indicators import as_values as _as_values  # noqa: E402

# An IOC row's type maps to the node it becomes. Ingest rolls finding-recovered material into
# IOC rows, so the same fact arrives on both paths and must resolve to ONE node.
IOC_ARTIFACTS = {"malware_family", "yara_rule", "campaign_id"}


# Subkinds whose VALUE is the file name, not the containing path — where these live is fixed, so
# the name is the actor's choice and the directory is not.
BASENAME_SUBKINDS = {
    "staging_name", "persistence_service", "persistence_cron",
    "persistence_shell_init", "persistence_preload", "webshell",
}


def artifact_value(subkind, target):
    """What the artifact node holds for this subkind: a name, or the whole path."""
    if not target:
        return ""
    if subkind not in BASENAME_SUBKINDS:
        return target
    # A preload hijack records both ends — `/etc/ld.so.preload -> /usr/lib/.../libX.so.2`.
    # The library is the actor's; the file naming it is the platform's.
    return target.replace("\\", "/").rsplit("/", 1)[-1].strip()


def build_graph(crun, run_ids):
    """Populate BehaviorNode/BehaviorEvent for one correlation run. Returns (nodes, events)."""
    nodes = {}          # (kind, subkind, value) -> {"hosts": set}
    events = []         # (key, hostname, event, observed_at, verdict, confidence, fid, detail)

    def touch(kind, subkind, value, host):
        value = str(value)[:1024]
        if not value:
            return None
        key = (kind, subkind, value)
        nodes.setdefault(key, {"hosts": set()})["hosts"].add(host)
        return key

    def record(key, host, event, f, detail=None):
        if key is None:
            return
        events.append((key, host, event, (f.raw or {}).get("observed_at"),
                       f.verdict, f.confidence, f.id, detail or {}))

    for f in Finding.objects.filter(run_id__in=run_ids).select_related("run__host"):
        host = f.run.host.hostname
        touch("host", "", host, host)
        verb, artifact_subkind = EVENT_MAP.get(f.finding_type, ("observed", None))
        raw = f.raw if isinstance(f.raw, dict) else {}

        if artifact_subkind:
            record(touch("artifact", artifact_subkind,
                         artifact_value(artifact_subkind, f.target), host), host, verb, f)

        # Indicators embedded in the finding itself: IOC rows cover the hunt's output, these cover what
        # a finding attributes to THIS event.
        for key, subkind in SCALAR_INDICATORS.items():
            if raw.get(key):
                record(touch("indicator", subkind, raw[key], host), host, verb, f)
        for key, subkind in LIST_INDICATORS.items():
            for item in _as_values(raw.get(key)):
                record(touch("indicator", subkind, item, host), host, verb, f)

        # Recovered C2 configuration — campaign id, sleep, jitter, keys. Each field is its
        # own node: two implants sharing a campaign id are the same operation even when
        # every address differs, which is precisely the rotating-actor case.
        config = raw.get("config_extracted")
        if isinstance(config, dict):
            for ckey, cval in config.items():
                if isinstance(cval, (str, int, float)) and str(cval).strip():
                    record(touch("artifact", f"c2_{ckey}"[:32], cval, host), host, verb, f)

        # The reverse engineer's attribution, and structural matches that outlive a rebuild.
        if raw.get("malware_family"):
            record(touch("artifact", "malware_family", raw["malware_family"], host),
                   host, verb, f)
        for rule in _as_values(raw.get("yara_matches")):
            record(touch("artifact", "yara_rule", rule, host), host, verb, f)

        if raw.get("account"):
            record(touch("account", "", raw["account"], host), host,
                   "authenticated" if verb == "observed" else verb, f)

        for t in (f.mitre or []):
            record(touch("technique", "", str(t).split()[0], host), host, verb, f)

        if verb == "moved" and raw.get("src_host") and raw.get("dst_host"):
            # The movement event lives on BOTH endpoint host nodes, detail naming the pair —
            # an edge is evidence about two hosts, and either side's analyst must find it.
            detail = {k: raw.get(k, "") for k in
                      ("src_host", "dst_host", "technique", "protocol", "account")}
            for endpoint in (raw["src_host"], raw["dst_host"]):
                record(touch("host", "", endpoint, endpoint), host, "moved", f, detail)

    for ioc in IOC.objects.filter(run_id__in=run_ids).select_related("run__host"):
        host = ioc.run.host.hostname
        subkind = "hash" if ioc.ioc_type in ("hash", "sha256") else ioc.ioc_type
        # Family, rule and campaign id are ARTIFACTS wherever they arrive from. Filing the
        # rolled-up row as an indicator would split one determination across two nodes,
        # halving the evidence on each and weakening the link it should have strengthened.
        kind = "artifact" if ioc.ioc_type in IOC_ARTIFACTS else "indicator"
        key = touch(kind, subkind, ioc.value, host)
        if key:
            # An IOC row carries no verdict field, but it is not unadjudicated: the toolkit emits IOCs.json
            # only from findings that already passed the verdict floor.
            verdict = "True Positive" if ioc.run.compromised else ""
            events.append((key, host, "observed", None, verdict, "", None, {"from": "ioc"}))

    for p in Principal.objects.filter(run_id__in=run_ids).select_related("run__host"):
        host = p.run.host.hostname
        key = touch("account", "", p.name, host)
        if key:
            # Same reasoning as IOC rows: an implicated principal recorded on a compromised
            # run is part of that determination, not an unweighted observation.
            verdict = "True Positive" if p.run.compromised else ""
            events.append((key, host, "observed", None, verdict, "", None, {"from": "principal"}))

    node_rows = {
        key: BehaviorNode(run=crun, kind=key[0], subkind=key[1], value=key[2],
                          host_count=len(data["hosts"]), hostnames=sorted(data["hosts"]))
        for key, data in nodes.items()
    }
    BehaviorNode.objects.bulk_create(node_rows.values(), batch_size=500)

    def as_dt(value):
        from django.utils import timezone
        if not value:
            return None
        try:
            parsed = timezone.datetime.fromisoformat(value)
            return parsed if timezone.is_aware(parsed) else timezone.make_aware(parsed)
        except (ValueError, TypeError):
            return None

    BehaviorEvent.objects.bulk_create(
        [BehaviorEvent(run=crun, node=node_rows[key], hostname=host, event=event,
                       observed_at=as_dt(observed), verdict=verdict, confidence=confidence,
                       source_finding_id=fid, detail=detail)
         for key, host, event, observed, verdict, confidence, fid, detail in events],
        batch_size=500,
    )
    return len(node_rows), len(events)
