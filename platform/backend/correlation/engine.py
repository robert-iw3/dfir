"""
Derives the multi-host intrusion picture from collected evidence.

Reads `cases` (per-host, custody-sealed) and writes `correlation` (derived, multi-host).
The direction is one-way by design: nothing here mutates collected evidence.

Clustering is evidence-driven, never proximity-driven. Two hosts join the same campaign
only when they share a concrete artifact — an indicator, an implicated account, or an
observed movement between them. Hosts that merely appear in the same investigation, or
were collected at a similar time, are not linked; an engagement that uncovers two
unrelated compromises yields two campaigns.
"""
from collections import defaultdict

from django.db import transaction
from django.utils import timezone

from cases.models import CollectionRun, Finding, IOC, Principal

from .models import Campaign, CampaignEdge, CampaignHost, CorrelationRun, SharedIndicator

ALGORITHM_VERSION = "1.0"

# Techniques that place a host at the start of an intrusion rather than downstream of it.
INITIAL_ACCESS = ("T1566", "T1190", "T1133", "T1078", "T1200", "T1091", "T1195")


class _Union:
    """Union-find over hostnames; clusters hosts that share evidence."""

    def __init__(self):
        self.parent = {}

    def add(self, x):
        self.parent.setdefault(x, x)

    def find(self, x):
        self.add(x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra

    def clusters(self):
        out = defaultdict(set)
        for node in self.parent:
            out[self.find(node)].add(node)
        return list(out.values())


def _movement_edges(runs_by_host):
    """Movement recorded by the collector, with both endpoints named."""
    edges = []
    for f in Finding.objects.filter(
        run__in=[r.id for r in runs_by_host.values()], finding_type="Lateral Movement"
    ):
        raw = f.raw or {}
        src, dst = raw.get("src_host"), raw.get("dst_host")
        if not src or not dst:
            continue
        edges.append({
            "src": src, "dst": dst, "technique": raw.get("technique", ""),
            "protocol": raw.get("protocol", ""), "account": raw.get("account", ""),
            "observed_at": raw.get("observed_at"), "finding_id": f.id,
        })
    return edges


def correlate_investigation(investigation_id, investigation_name=""):
    """Recompute correlation for one investigation. Returns the new CorrelationRun."""
    runs = list(
        CollectionRun.objects.filter(investigation_id=investigation_id).select_related("host")
    )
    runs_by_host = {r.host.hostname: r for r in runs}
    run_ids = [r.id for r in runs]

    # Only compromised hosts participate. A clean host shares no intrusion evidence, and
    # including it would inflate the blast radius with hosts that were merely examined.
    compromised = {h: r for h, r in runs_by_host.items() if r.compromised}

    # --- Evidence index: indicator/account -> hosts carrying it ----------------------
    carriers = defaultdict(set)
    first_seen = {}
    for ioc in IOC.objects.filter(run_id__in=run_ids).select_related("run__host"):
        host = ioc.run.host.hostname
        if host not in compromised:
            continue
        key = (ioc.ioc_type, ioc.value)
        carriers[key].add(host)
        ts = ioc.run.collected_at
        if ts and (key not in first_seen or ts < first_seen[key]):
            first_seen[key] = ts
    for pr in Principal.objects.filter(run_id__in=run_ids).select_related("run__host"):
        host = pr.run.host.hostname
        if host not in compromised:
            continue
        carriers[("account", pr.name)].add(host)

    # --- Cluster ---------------------------------------------------------------------
    uf = _Union()
    for host in compromised:
        uf.add(host)
    for hosts in carriers.values():
        hosts = sorted(hosts)
        for other in hosts[1:]:
            uf.union(hosts[0], other)

    edges = _movement_edges(runs_by_host)
    for e in edges:
        if e["src"] in compromised and e["dst"] in compromised:
            uf.union(e["src"], e["dst"])

    # --- Per-host technique + timing profile -----------------------------------------
    techniques = defaultdict(set)
    host_first = {}
    for f in Finding.objects.filter(run_id__in=run_ids).select_related("run__host"):
        host = f.run.host.hostname
        if host not in compromised:
            continue
        for t in (f.mitre or []):
            techniques[host].add(t)
        observed = (f.raw or {}).get("observed_at")
        if observed and (host not in host_first or observed < host_first[host]):
            host_first[host] = observed

    def as_dt(value):
        if not value:
            return None
        parsed = timezone.datetime.fromisoformat(value)
        return parsed if timezone.is_aware(parsed) else timezone.make_aware(parsed)

    with transaction.atomic(using="correlation"):
        CorrelationRun.objects.filter(
            investigation_id=investigation_id, is_current=True
        ).update(is_current=False)

        crun = CorrelationRun.objects.create(
            investigation_id=investigation_id,
            investigation_name=investigation_name,
            algorithm_version=ALGORITHM_VERSION,
            input_summary={
                "runs": len(runs), "compromised_hosts": len(compromised),
                "findings": Finding.objects.filter(run_id__in=run_ids).count(),
                "indicators": len(carriers),
            },
            is_current=True,
        )

        # Indicators shared by more than one host carry the cross-host signal; a
        # single-host indicator says nothing about linkage and is already in `cases`.
        shared = {k: v for k, v in carriers.items() if len(v) > 1}

        for cluster in uf.clusters():
            cluster = {h for h in cluster if h in compromised}
            if not cluster:
                continue

            cluster_edges = [e for e in edges
                             if e["src"] in cluster and e["dst"] in cluster]
            sources = {e["src"] for e in cluster_edges}
            destinations = {e["dst"] for e in cluster_edges}

            # Patient zero: a host with an initial-access technique that nothing else
            # moved to. Falls back to the earliest host, and stays blank when the
            # evidence supports neither.
            entered = [
                h for h in cluster
                if h not in destinations
                and any(t.startswith(INITIAL_ACCESS) for t in techniques.get(h, ()))
            ]
            if entered:
                pz = min(entered, key=lambda h: host_first.get(h, "9999"))
            else:
                unreached = [h for h in cluster if h not in destinations]
                pz = min(unreached or cluster, key=lambda h: host_first.get(h, "9999"))

            vector = next(
                (t for t in sorted(techniques.get(pz, ())) if t.startswith(INITIAL_ACCESS)),
                "",
            )

            times = [as_dt(host_first[h]) for h in cluster if host_first.get(h)]
            cluster_shared = {k: v for k, v in shared.items() if v & cluster}

            campaign = Campaign.objects.create(
                run=crun, investigation_id=investigation_id,
                label=investigation_name or f"Investigation {investigation_id}",
                patient_zero=pz if len(cluster) > 1 or vector else "",
                initial_vector=vector,
                first_activity=min(times) if times else None,
                last_activity=max(times) if times else None,
                host_count=len(cluster),
                confidence="High" if cluster_edges and vector else "Medium",
                linking_evidence=[
                    {"kind": k[0], "value": k[1], "hosts": sorted(v & cluster)}
                    for k, v in sorted(cluster_shared.items(), key=lambda kv: -len(kv[1]))[:10]
                ],
            )

            for host in sorted(cluster):
                if host == pz:
                    role = "patient_zero"
                elif host in sources:
                    role = "pivot"
                else:
                    role = "affected"
                entry = next((e for e in cluster_edges if e["dst"] == host), None)
                CampaignHost.objects.create(
                    campaign=campaign,
                    host_id=compromised[host].host_id,
                    hostname=host, role=role,
                    first_activity=as_dt(host_first.get(host)),
                    entry_technique=(entry or {}).get("technique", ""),
                    entry_account=(entry or {}).get("account", ""),
                    tp_count=compromised[host].tp_count,
                    techniques=sorted(techniques.get(host, ())),
                )

            for e in cluster_edges:
                CampaignEdge.objects.create(
                    campaign=campaign, src_hostname=e["src"], dst_hostname=e["dst"],
                    technique=e["technique"], protocol=e["protocol"], account=e["account"],
                    observed_at=as_dt(e["observed_at"]), source_finding_id=e["finding_id"],
                )

            for (kind, value), hosts in cluster_shared.items():
                in_cluster = sorted(hosts & cluster)
                SharedIndicator.objects.create(
                    campaign=campaign, run=crun, kind=kind, value=value,
                    host_count=len(in_cluster), hostnames=in_cluster,
                    first_seen=first_seen.get((kind, value)),
                )

    return crun


def correlate_all():
    """Recompute every investigation. Returns the runs created."""
    from cases.models import Investigation

    return [
        correlate_investigation(inv.id, inv.name)
        for inv in Investigation.objects.all()
    ]
