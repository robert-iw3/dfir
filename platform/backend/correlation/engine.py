"""
Derives the multi-host intrusion picture from collected evidence.

Reads `cases` (per-host, custody-sealed) and writes `correlation` (derived, multi-host).
The direction is one-way by design: nothing here mutates collected evidence.

Clustering is evidence-driven, never proximity-driven, and **weighted**: two hosts join the
same campaign when their strongest shared evidence clears a threshold, not merely because
they share something. Sharing alone merges whatever it touches, so one account present
across the fleet fused unrelated compromises into a single campaign.

Each candidate pair is scored from the behavior graph (`behavior.py`) on link type, how rare
the shared thing is in this deployment, the verdict of the evidence behind it, and whether
the timing coheres (`linkage.py`). Every link keeps its per-factor breakdown — including the
ones the engine declined — so a merge can be defended and a refusal explained.

Hosts that merely appear in the same investigation, or were collected at a similar time, are
not linked; an engagement that uncovers two unrelated compromises yields two campaigns.
"""
import os
from collections import defaultdict

from django.db import transaction
from django.utils import timezone

from cases.models import CollectionRun, Finding, Host, IOC, Principal

from .behavior import build_graph
from .confidence import band_for
from .fingerprint import build_fingerprint, compare, profile_as_fingerprint
from .linkage import (
    CONFIRMING_VERDICTS, build_links, cluster as weighted_cluster, cohesion,
)
from .models import (ActorProfile, AttributionCandidate, BehaviorEvent, BehaviorNode,
                     Campaign, CampaignEdge, CampaignFingerprint, CampaignHost,
                     CampaignSimilarity, CorrelationRun, SharedIndicator)

# Below these a match is coincidence with a number on it. Ranking such a thing beside a real
# one is how a heuristic turns into a false accusation, so they are floors on what is STORED,
# not just on what is displayed.
ATTRIBUTION_FLOOR = 0.25
SIMILARITY_FLOOR = 0.30

# 2.0 — weighted linkage replaces union-find: hosts join when their strongest shared evidence
# clears a threshold, so a service account on forty machines no longer merges the fleet.
ALGORITHM_VERSION = "2.0"

# Techniques that place a host at the start of an intrusion rather than downstream of it.
INITIAL_ACCESS = ("T1566", "T1190", "T1133", "T1078", "T1200", "T1091", "T1195")


def sets_compromise_baseline(finding_type, verdict):
    """Whether a finding can establish WHEN a host first showed compromise.

    Two kinds cannot. A movement record, because a movement out of a host is recorded on that
    host — an edge would set the very baseline it is later compared against, making the
    contradiction test unanswerable. And an Indeterminate one, because ordinary fleet life
    (an inventory scan, an agent install, a patch push) sits on every host at every hour and
    asserts nothing about compromise.
    """
    return finding_type != "Lateral Movement" and verdict in CONFIRMING_VERDICTS


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
            # Carried so linkage weighs the record on the same ladder as everything else.
            "verdict": f.verdict,
        })
    return edges


def _deployment_population(investigation_id):
    """How many machines the ESTATE has, which is not how many have been collected from.

    Rarity asks what fraction of the fleet carries something, and `Host.objects.count()`
    answers a different question: how many hosts this platform has ingested. Early in an
    engagement those are wildly apart — with two hosts collected, the C2 domain they share
    sits on 100% of what the platform can see and scores as environment, so the two hosts an
    analyst most needs joined do not link. It is the exact failure scoping to the
    investigation was rejected for, reached by another route.

    So the estate size is DECLARED (`IR_DEPLOYMENT_HOSTS`) and the observed count is only the
    fallback. Failing that, an investigation already correlated keeps the population its last
    run used, because a case must not reach a different verdict because unrelated collections
    landed in the meantime — the report was written from the first answer.
    """
    declared = os.environ.get("IR_DEPLOYMENT_HOSTS", "").strip()
    if declared.isdigit() and int(declared) > 0:
        return int(declared)

    previous = (CorrelationRun.objects
                .filter(investigation_id=investigation_id)
                .order_by("-created_at").first())
    if previous:
        held = (previous.input_summary or {}).get("population")
        if isinstance(held, int) and held > 0:
            return held

    return max(1, Host.objects.count())


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

    edges = _movement_edges(runs_by_host)

    # --- Per-host technique + timing profile -----------------------------------------
    techniques = defaultdict(set)
    host_first = {}
    # When each host first showed COMPROMISE, over the findings able to establish that —
    # see `sets_compromise_baseline`. Only the contradiction test reads it.
    host_first_standalone = {}
    # The intrusion's own clock: the earliest CONFIRMING finding of any kind, movement
    # included. `host_first` above is the earliest finding at all, which on every endpoint is
    # ordinary fleet life hours before anything happened — the corpus's inventory scan puts
    # all 25 hosts at 01:00, so "first activity" read as the scanner's schedule, every host
    # looked simultaneous, and temporal coherence had nothing left to discriminate with.
    host_first_confirmed = {}
    # When each TECHNIQUE was first observed on each HOST, from the confirming finding that carried
    # it — the campaign's tradecraft order is read from this, not from host first-seen times.
    technique_first_host = defaultdict(dict)
    for f in Finding.objects.filter(run_id__in=run_ids).select_related("run__host"):
        host = f.run.host.hostname
        if host not in compromised:
            continue
        for t in (f.mitre or []):
            techniques[host].add(t)
        observed = (f.raw or {}).get("observed_at")
        if not observed:
            continue
        if host not in host_first or observed < host_first[host]:
            host_first[host] = observed
        if sets_compromise_baseline(f.finding_type, f.verdict) and (
                host not in host_first_standalone
                or observed < host_first_standalone[host]):
            host_first_standalone[host] = observed
        # Technique timing takes CONFIRMING findings of every kind, movement included; the movement
        # exclusion elsewhere is narrow — a movement cannot testify about its own destination.
        if f.verdict in CONFIRMING_VERDICTS:
            if (host not in host_first_confirmed
                    or observed < host_first_confirmed[host]):
                host_first_confirmed[host] = observed
            seen = technique_first_host[host]
            for t in (f.mitre or []):
                base = (t or "").split(".")[0].strip().upper()
                if base and (base not in seen or observed < seen[base]):
                    seen[base] = observed

    def as_dt(value):
        if not value:
            return None
        try:
            parsed = timezone.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return None
        return parsed if timezone.is_aware(parsed) else timezone.make_aware(parsed)

    with transaction.atomic(using="correlation"):
        CorrelationRun.objects.filter(
            investigation_id=investigation_id, is_current=True
        ).update(is_current=False)

        population = _deployment_population(investigation_id)

        crun = CorrelationRun.objects.create(
            investigation_id=investigation_id,
            investigation_name=investigation_name,
            algorithm_version=ALGORITHM_VERSION,
            input_summary={
                "runs": len(runs), "compromised_hosts": len(compromised),
                "findings": Finding.objects.filter(run_id__in=run_ids).count(),
                "indicators": len(carriers),
                # The denominator every rarity in this run was measured against. Recorded so
                # the run can be reproduced, and so a reader can see what "rare" meant here.
                "population": population,
            },
            is_current=True,
        )

        # L0: the behavior graph, over the WHOLE population — clean hosts included, because
        # rarity is measured against everyone, and fleet-wide software must be visible as
        # fleet-wide.
        graph_nodes, graph_events = build_graph(crun, run_ids)

        # L1: score every candidate pair, then take connected components over links clearing the
        # threshold. Timestamps resolve to datetimes first so ordering is comparable across sources.
        intrusion_first = {
            h: host_first_standalone.get(h) or host_first_confirmed.get(h, v)
            for h, v in host_first.items()
        }
        first_dt = {h: as_dt(v) for h, v in intrusion_first.items()}
        standalone_dt = {h: as_dt(v) for h, v in host_first_standalone.items()}
        for e in edges:
            e["observed_dt"] = as_dt(e.get("observed_at"))
        links = build_links(crun, compromised, first_dt, edges,
                            population=population,
                            first_standalone=standalone_dt)

        crun.input_summary.update({
            "behavior_nodes": graph_nodes, "behavior_events": graph_events,
            "candidate_links": len(links),
            "linked": sum(1 for l in links.values() if l.linked),
        })
        crun.save(update_fields=["input_summary"])

        # Indicators shared by more than one host carry the cross-host signal; a
        # single-host indicator says nothing about linkage and is already in `cases`.
        shared = {k: v for k, v in carriers.items() if len(v) > 1}

        # Which hosts carry each piece of evidence, keyed exactly as `corroboration` records
        # it. Clustering uses this to tell an actor's own material from the estate's: a hash
        # nothing outside a component carries is a signature, one the wider fleet also holds
        # is furniture. Every host counts here, clean included — a clean endpoint holding the
        # same tool is the strongest argument that it is environmental.
        node_carriers = {
            (n.kind, n.subkind, (n.value or "")[:200]): set(n.hostnames or [])
            for n in BehaviorNode.objects.filter(run=crun)
        }

        for cluster in weighted_cluster(compromised, links, carriers=node_carriers):
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
                pz = min(entered, key=lambda h: intrusion_first.get(h, "9999"))
            else:
                unreached = [h for h in cluster if h not in destinations]
                pz = min(unreached or cluster, key=lambda h: intrusion_first.get(h, "9999"))

            vector = next(
                (t for t in sorted(techniques.get(pz, ())) if t.startswith(INITIAL_ACCESS)),
                "",
            )

            times = [as_dt(intrusion_first[h]) for h in cluster if intrusion_first.get(h)]
            cluster_shared = {k: v for k, v in shared.items() if v & cluster}
            c_min, c_mean = cohesion(cluster, links)

            # Named from the campaign's OWN evidence, not the case it sits in — otherwise two intrusions in
            # one engagement carry the same name and neither is identifiable.
            family = sorted({v for (kind, v), hosts in carriers.items()
                             if kind == "malware_family" and hosts & cluster})
            if family and pz:
                label = f"{family[0]} · {pz}"
            elif family:
                label = family[0]
            elif pz:
                label = f"{pz} intrusion"
            else:
                label = investigation_name or f"Investigation {investigation_id}"

            campaign = Campaign.objects.create(
                run=crun, investigation_id=investigation_id,
                label=label,
                patient_zero=pz if len(cluster) > 1 or vector else "",
                initial_vector=vector,
                first_activity=min(times) if times else None,
                last_activity=max(times) if times else None,
                host_count=len(cluster),
                cohesion_min=c_min, cohesion_mean=c_mean,
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
                band, band_factors = band_for(host, links)
                CampaignHost.objects.create(
                    campaign=campaign,
                    host_id=compromised[host].host_id,
                    hostname=host, role=role,
                    first_activity=as_dt(intrusion_first.get(host)),
                    entry_technique=(entry or {}).get("technique", ""),
                    entry_account=(entry or {}).get("account", ""),
                    tp_count=compromised[host].tp_count,
                    techniques=sorted(techniques.get(host, ())),
                    confidence_band=band, confidence_factors=band_factors,
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

    # L4/L5 run after every campaign in this investigation exists, because a fingerprint is
    # per campaign and cross-campaign similarity compares finished ones.
    build_fingerprints(crun, investigation_id, technique_first_host={
        host: {t: as_dt(v) for t, v in seen.items()}
        for host, seen in technique_first_host.items()})
    attribute(crun, investigation_id)

    return crun


def build_fingerprints(crun, investigation_id, technique_first_host=None):
    """L4 — one fingerprint per campaign in this run, from its own slice of the L0 graph."""
    made = []
    technique_first_host = technique_first_host or {}
    for campaign in Campaign.objects.filter(run=crun):
        hosts = list(campaign.hosts.all())
        hostnames = {h.hostname for h in hosts}
        # Technique times narrowed to THIS campaign's hosts, so a second intrusion in the
        # same investigation cannot set this one's tradecraft order.
        technique_first = {}
        for name in hostnames:
            for t, when in (technique_first_host.get(name) or {}).items():
                if when and (t not in technique_first or when < technique_first[t]):
                    technique_first[t] = when
        edges = list(campaign.edges.all())
        # Only the nodes this campaign's hosts actually touched. Fingerprinting the whole
        # run would describe the investigation, and two campaigns in one investigation are
        # two intrusions precisely because the engine declined to link them.
        events = [e for e in BehaviorEvent.objects.filter(run=crun) if e.hostname in hostnames]
        nodes = {e.node_id for e in events}
        node_rows = [n for n in BehaviorNode.objects.filter(run=crun) if n.id in nodes]
        # Nodes this campaign adjudicated as compromise, for the fingerprint's verdict floor.
        confirmed_nodes = {e.node_id for e in events if e.verdict in CONFIRMING_VERDICTS}

        vector = build_fingerprint(hosts, edges, node_rows,
                                   technique_first=technique_first,
                                   confirmed_nodes=confirmed_nodes)
        made.append(CampaignFingerprint.objects.create(
            run=crun, campaign=campaign, investigation_id=investigation_id, **vector))
    return made


def attribute(crun, investigation_id):
    """L5 — advisory actor candidates, and campaigns elsewhere that share this tradecraft.

    Both comparisons read stored fingerprints and neither writes an actor onto a case. A
    platform that assigns attribution has converted a similarity score into a claim nobody
    made; this ranks and explains, and a person decides.
    """
    profiles = [(p, profile_as_fingerprint(p)) for p in ActorProfile.objects.all()]
    # Every other investigation's CURRENT fingerprints. Superseded runs are excluded: a
    # similarity to a conclusion that has already been recomputed is not a finding.
    current_runs = CorrelationRun.objects.filter(is_current=True).exclude(
        investigation_id=investigation_id).values_list("id", flat=True)
    others = list(CampaignFingerprint.objects.filter(run_id__in=list(current_runs))
                  .select_related("campaign"))

    candidates, similarities = [], []
    for fp in CampaignFingerprint.objects.filter(run=crun).select_related("campaign"):
        mine = _vector(fp)
        for profile, pf in profiles:
            score, rationale = compare(mine, pf)
            if score >= ATTRIBUTION_FLOOR:
                candidates.append(AttributionCandidate(
                    run=crun, campaign=fp.campaign, actor_key=profile.key,
                    actor_name=profile.name, score=score, source="heuristic",
                    rationale={**rationale, "library_provenance": profile.provenance}))
        for other in others:
            score, rationale = compare(mine, _vector(other))
            if score >= SIMILARITY_FLOOR:
                similarities.append(CampaignSimilarity(
                    run=crun, campaign=fp.campaign,
                    other_campaign_id=other.campaign_id,
                    other_investigation_id=other.investigation_id,
                    other_label=other.campaign.label, score=score, rationale=rationale))

    AttributionCandidate.objects.bulk_create(candidates, batch_size=200)
    CampaignSimilarity.objects.bulk_create(similarities, batch_size=200)
    return candidates, similarities


def _vector(fp):
    return {
        "techniques": fp.techniques, "technique_ngrams": fp.technique_ngrams,
        "artifact_conventions": fp.artifact_conventions, "c2_pattern": fp.c2_pattern,
        "account_chain": fp.account_chain, "basis": fp.basis,
    }


def correlate_all():
    """Recompute every investigation. Returns the runs created."""
    from cases.models import Investigation

    return [
        correlate_investigation(inv.id, inv.name)
        for inv in Investigation.objects.all()
    ]
