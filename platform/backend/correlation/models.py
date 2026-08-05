"""
Correlated intrusion data — the multi-host picture, held separately from collection data.

**This is a derived store, never a system of record.** `cases` holds what the toolkit
collected from each endpoint, under chain of custody, per host. Everything here is an
*interpretation* of that evidence spanning several hosts: which hosts belong to one
intrusion, where it started, how it moved, and what it reached.

Keeping the two apart is an evidentiary boundary, not just a schema one:

  * Collected evidence is never mutated by analysis. A correlation bug cannot damage the
    custody-sealed record it was computed from.
  * Correlation is reproducible. Every row is attributable to a `CorrelationRun` — an
    algorithm version over a defined input set — so a conclusion drawn months ago can be
    explained, re-derived, or superseded without touching evidence.
  * The two have opposite access patterns. Collection is write-heavy at ingest then
    read-mostly; correlation is rewritten wholesale on recompute and read constantly by
    the UI. They tune, replicate and scale differently.

Because the stores are separate databases, there are **no foreign keys into `cases`**.
Hosts and runs are referenced by id *and* by denormalized hostname, so a correlation
result stays readable on its own and can be rebuilt from scratch at any time.
"""
from django.db import models


class CorrelationRun(models.Model):
    """One execution of the correlation engine over one investigation.

    Results are scoped to a run so a recompute supersedes rather than mutates: the prior
    view of the intrusion remains explainable.
    """

    investigation_id = models.IntegerField(db_index=True)   # cases.Investigation.id
    investigation_name = models.CharField(max_length=255, blank=True)
    algorithm_version = models.CharField(max_length=32, default="1.0")
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    # What the run consumed, so a stale result is recognizable as stale.
    input_summary = models.JSONField(default=dict, blank=True)  # run/finding/ioc counts
    is_current = models.BooleanField(default=True, db_index=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"correlation {self.pk} of investigation {self.investigation_id}"


class Campaign(models.Model):
    """A cluster of hosts linked by shared evidence — one intrusion.

    An investigation can contain more than one: unrelated compromises found during the
    same engagement stay separate clusters rather than being merged by proximity.
    """

    run = models.ForeignKey(CorrelationRun, related_name="campaigns", on_delete=models.CASCADE)
    investigation_id = models.IntegerField(db_index=True)
    label = models.CharField(max_length=255)
    # Earliest compromised host carrying an initial-access technique. Blank when the
    # evidence does not identify one — the UI must not imply certainty the data lacks.
    patient_zero = models.CharField(max_length=255, blank=True)
    initial_vector = models.CharField(max_length=255, blank=True)   # ATT&CK technique id
    first_activity = models.DateTimeField(null=True, blank=True)
    last_activity = models.DateTimeField(null=True, blank=True)
    host_count = models.IntegerField(default=0)
    confidence = models.CharField(max_length=16, default="Medium")
    linking_evidence = models.JSONField(default=list, blank=True)   # why these hosts cluster
    # How tightly the campaign holds together. The MINIMUM is stated beside the mean
    # because it is the link an opposing analyst attacks first.
    cohesion_min = models.FloatField(default=0.0)
    cohesion_mean = models.FloatField(default=0.0)

    class Meta:
        ordering = ["-host_count"]

    def __str__(self):
        return f"{self.label} ({self.host_count} hosts)"


class CampaignHost(models.Model):
    """A host's place in a campaign: when it was reached, how, and by which account."""

    ROLE = [
        ("patient_zero", "patient_zero"),   # where the intrusion entered
        ("pivot", "pivot"),                 # both reached and used to reach others
        ("affected", "affected"),           # reached, no onward movement observed
    ]
    campaign = models.ForeignKey(Campaign, related_name="hosts", on_delete=models.CASCADE)
    host_id = models.IntegerField(db_index=True)          # cases.Host.id
    hostname = models.CharField(max_length=255, db_index=True)
    role = models.CharField(max_length=16, choices=ROLE, default="affected")
    first_activity = models.DateTimeField(null=True, blank=True)
    entry_technique = models.CharField(max_length=64, blank=True)
    entry_account = models.CharField(max_length=255, blank=True)
    tp_count = models.IntegerField(default=0)
    techniques = models.JSONField(default=list, blank=True)   # ATT&CK ids seen on this host
    # L3: how confident the engine is that THIS host belongs to THIS campaign. A band, not a
    # float — a UI handed 0.62 and 0.67 invents a threshold between them that nobody can
    # defend in a report. `confidence_factors` is what the band decomposes into; a label
    # nobody can take apart is not evidence, and an analyst asking why one host bands lower
    # than its peers has to be able to read the answer rather than re-derive it.
    #
    # `indeterminate` is not the bottom of the scale. It is the value for a host with no link
    # to any other host in its campaign, where there is no cross-host evidence to be confident
    # or doubtful about — recording that as `possible` would report an absence of evidence as
    # evidence of weakness. The vocabulary tracks the verdict ladder for the same reason.
    BAND_CONFIRMED = "confirmed"
    BAND_PROBABLE = "probable"
    BAND_POSSIBLE = "possible"
    BAND_INDETERMINATE = "indeterminate"
    BANDS = [(b, b) for b in (BAND_CONFIRMED, BAND_PROBABLE, BAND_POSSIBLE,
                              BAND_INDETERMINATE)]

    confidence_band = models.CharField(
        max_length=16, choices=BANDS, default=BAND_INDETERMINATE, db_index=True)
    confidence_factors = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["first_activity", "hostname"]

    def __str__(self):
        return f"{self.hostname} [{self.role}]"


class CampaignEdge(models.Model):
    """Observed movement between two hosts, with the evidence that established it."""

    campaign = models.ForeignKey(Campaign, related_name="edges", on_delete=models.CASCADE)
    src_hostname = models.CharField(max_length=255, db_index=True)
    dst_hostname = models.CharField(max_length=255, db_index=True)
    technique = models.CharField(max_length=64, blank=True)
    protocol = models.CharField(max_length=32, blank=True)
    account = models.CharField(max_length=255, blank=True)
    observed_at = models.DateTimeField(null=True, blank=True)
    # Which collection finding established this edge, so the graph is traceable back to
    # the custody-sealed record it was derived from.
    source_finding_id = models.IntegerField(null=True, blank=True)

    class Meta:
        ordering = ["observed_at"]

    def __str__(self):
        return f"{self.src_hostname} -> {self.dst_hostname} ({self.technique})"


class SharedIndicator(models.Model):
    """An indicator or account observed on more than one host — the correlation key.

    Single-host indicators are not stored: they carry no cross-host signal and are
    already in `cases`.
    """

    campaign = models.ForeignKey(
        Campaign, related_name="indicators", on_delete=models.CASCADE, null=True, blank=True
    )
    run = models.ForeignKey(CorrelationRun, related_name="indicators", on_delete=models.CASCADE)
    kind = models.CharField(max_length=32, db_index=True)      # ip/domain/hash/tool/account
    value = models.CharField(max_length=1024, db_index=True)
    host_count = models.IntegerField(default=0)
    hostnames = models.JSONField(default=list, blank=True)
    first_seen = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-host_count", "kind", "value"]
        indexes = [models.Index(fields=["kind", "value"])]

    def __str__(self):
        return f"{self.kind}:{self.value} on {self.host_count} hosts"

class BehaviorNode(models.Model):
    """One observable the intrusion touched: a host, account, indicator, technique, or a
    NAMED ARTIFACT of tradecraft (persistence task/service name, staging convention).

    The substrate for weighted linkage and fingerprinting: two hosts that share a rare
    artifact node are behaviorally linked even when every indicator between them was
    rotated. Scoped to a run like everything else here — recompute supersedes.

    `host_count` is denormalized at build time because it is the population figure rarity
    weighting divides by, and computing it per query would walk the event table for every
    candidate link.
    """

    KIND = [
        ("host", "host"),
        ("account", "account"),
        ("indicator", "indicator"),   # subkind: ip / domain / hash / tool
        ("technique", "technique"),   # subkind: ATT&CK id prefix bucket
        ("artifact", "artifact"),     # subkind: persistence_task / persistence_service / staging_name
    ]
    run = models.ForeignKey(CorrelationRun, related_name="behavior_nodes", on_delete=models.CASCADE)
    kind = models.CharField(max_length=16, choices=KIND, db_index=True)
    subkind = models.CharField(max_length=32, blank=True, db_index=True)
    value = models.CharField(max_length=1024, db_index=True)
    host_count = models.IntegerField(default=0)
    hostnames = models.JSONField(default=list, blank=True)

    class Meta:
        ordering = ["kind", "subkind", "value"]
        indexes = [models.Index(fields=["run", "kind", "subkind"])]
        constraints = [models.UniqueConstraint(
            fields=["run", "kind", "subkind", "value"], name="uniq_behavior_node")]

    def __str__(self):
        return f"{self.kind}/{self.subkind}:{self.value} ({self.host_count} hosts)"


class BehaviorEvent(models.Model):
    """One observation tying a host to a node, traceable to the finding that recorded it.

    The verdict travels with the event so weighting can read it without a cross-database
    join back into `cases` — a True Positive beacon and an Indeterminate package install
    are different evidence, and the graph must know which it is holding.
    """

    EVENT = [
        ("dropped", "dropped"),          # implant/file landed
        ("beaconed", "beaconed"),        # C2 communication
        ("persisted", "persisted"),      # persistence established under a name
        ("staged", "staged"),            # data staged for exfil
        ("moved", "moved"),              # lateral movement (detail carries src/dst)
        ("authenticated", "authenticated"),
        ("executed", "executed"),
        ("observed", "observed"),        # default: present, uncategorized
    ]
    run = models.ForeignKey(CorrelationRun, related_name="behavior_events", on_delete=models.CASCADE)
    node = models.ForeignKey(BehaviorNode, related_name="events", on_delete=models.CASCADE)
    hostname = models.CharField(max_length=255, db_index=True)
    event = models.CharField(max_length=16, choices=EVENT, db_index=True)
    observed_at = models.DateTimeField(null=True, blank=True)
    verdict = models.CharField(max_length=32, blank=True)
    confidence = models.CharField(max_length=16, blank=True)
    # Which collection finding recorded this, so every edge of the graph is traceable to
    # the custody-sealed record it derives from.
    source_finding_id = models.IntegerField(null=True, blank=True)
    detail = models.JSONField(default=dict, blank=True)   # movement src/dst/account/protocol

    class Meta:
        ordering = ["observed_at", "id"]
        indexes = [models.Index(fields=["run", "hostname"])]

    def __str__(self):
        return f"{self.hostname} {self.event} {self.node_id}"


class HostLink(models.Model):
    """A scored candidate link between two hosts, with the reasoning kept.

    Written for every candidate pair, INCLUDING those below the threshold: a link the engine
    declined is as informative as one it accepted, and an analyst asking "why aren't these
    two the same campaign?" deserves the answer rather than silence. `linked` records the
    decision, `factors` records how it was reached.
    """

    run = models.ForeignKey(CorrelationRun, related_name="host_links", on_delete=models.CASCADE)
    host_a = models.CharField(max_length=255, db_index=True)
    host_b = models.CharField(max_length=255, db_index=True)
    weight = models.FloatField(default=0.0)
    linked = models.BooleanField(default=False, db_index=True)
    # Per-factor breakdown: the strongest contribution, its corroboration, and the counts.
    # This is the explainability record — a score nobody can decompose is not evidence.
    factors = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-weight"]
        indexes = [models.Index(fields=["run", "linked"])]
        constraints = [models.UniqueConstraint(
            fields=["run", "host_a", "host_b"], name="uniq_host_link")]

    def __str__(self):
        return f"{self.host_a} ~ {self.host_b} = {self.weight:.3f}{'' if self.linked else ' (declined)'}"


class CampaignFingerprint(models.Model):
    """L4 — a campaign's tradecraft as a structured, named vector.

    Computed from the L0 behavior graph, never from indicators. Infrastructure is what an
    actor rotates between engagements; what survives is *how they work* — which techniques in
    which order, what they name their persistence, which protocols they move over, how they
    acquire accounts. That is the only thing L5 can honestly compare across investigations.

    Components are stored separately rather than hashed into one opaque value: the similarity
    measure has to be able to say WHICH components two campaigns share, and a digest cannot
    be taken apart to answer that.
    """

    run = models.ForeignKey(CorrelationRun, related_name="fingerprints",
                            on_delete=models.CASCADE)
    campaign = models.OneToOneField(Campaign, related_name="fingerprint",
                                    on_delete=models.CASCADE)
    investigation_id = models.IntegerField(db_index=True)

    # The technique SET, the ordered sequence, and the n-grams over that order. Two actors can
    # use the same techniques in a different order and the difference is tradecraft, so order
    # is stored beside the set rather than instead of it.
    #
    # All three, because they answer different questions: the set is what the similarity
    # measure compares, the n-grams are what make ORDER comparable, and the sequence is what a
    # person reads. Sorting the set by id produces something that looks like an order and is
    # not one.
    techniques = models.JSONField(default=list, blank=True)
    technique_sequence = models.JSONField(default=list, blank=True)
    technique_ngrams = models.JSONField(default=list, blank=True)
    # Naming conventions, not the names: "svc_<word><digits>" carries across engagements
    # where "WinDefendHelper" does not.
    artifact_conventions = models.JSONField(default=list, blank=True)
    # {convention: {"example": <collected value>, "hosts": n}} — the value each shape was
    # abstracted from. Provenance only; matching is always on the shape. Without it a shape
    # is unfalsifiable to a reader, who cannot tell a computed abstraction from a placeholder.
    convention_examples = models.JSONField(default=dict, blank=True)
    c2_pattern = models.JSONField(default=dict, blank=True)      # protocols, ports, cadence
    account_chain = models.JSONField(default=dict, blank=True)   # acquisition shape
    # What the vector was computed over, so a thin fingerprint is recognizable as thin
    # rather than as an actor with little tradecraft.
    basis = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-id"]
        indexes = [models.Index(fields=["investigation_id"])]

    def __str__(self):
        return f"fingerprint of campaign {self.campaign_id} ({len(self.techniques)} techniques)"


class ActorProfile(models.Model):
    """A staged actor-profile library entry — offline, like symbol tables.

    Seeded from an offline ATT&CK groups export extended with artifact conventions. Never
    fetched at analysis time: an enclave has no egress, and an attribution that silently
    depends on a network call is an attribution that stops being reproducible.
    """

    key = models.CharField(max_length=64, unique=True)          # e.g. G0016
    name = models.CharField(max_length=255, db_index=True)
    aliases = models.JSONField(default=list, blank=True)
    techniques = models.JSONField(default=list, blank=True)
    artifact_conventions = models.JSONField(default=list, blank=True)
    c2_pattern = models.JSONField(default=dict, blank=True)
    # Where the entry came from and when, because an attribution candidate is only as
    # current as the library behind it.
    provenance = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return f"{self.name} ({self.key})"


class AttributionCandidate(models.Model):
    """L5 — a ranked, ADVISORY match between a campaign and a staged actor profile.

    `source` is always heuristic and attribution is never auto-assigned: the platform ranks
    candidates and names why, and a person decides. A tool that writes an actor name into a
    case record has converted a similarity score into a claim nobody made.
    """

    run = models.ForeignKey(CorrelationRun, related_name="attributions",
                            on_delete=models.CASCADE)
    campaign = models.ForeignKey(Campaign, related_name="attributions",
                                 on_delete=models.CASCADE)
    actor_key = models.CharField(max_length=64, db_index=True)
    actor_name = models.CharField(max_length=255)
    score = models.FloatField(default=0.0)
    source = models.CharField(max_length=16, default="heuristic")
    # Per-component overlap with the names of what matched — the rationale an analyst reads
    # instead of the number.
    rationale = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-score"]
        indexes = [models.Index(fields=["campaign", "-score"])]

    def __str__(self):
        return f"{self.actor_name} ~ campaign {self.campaign_id} = {self.score:.3f} (advisory)"


class CampaignSimilarity(models.Model):
    """L5 — "the same adversary as the March engagement", with the shared components named.

    Compared over stored fingerprints rather than by re-running correlation across
    investigations, so a per-investigation recompute stays per-investigation.
    """

    run = models.ForeignKey(CorrelationRun, related_name="similarities",
                            on_delete=models.CASCADE)
    campaign = models.ForeignKey(Campaign, related_name="similar_to",
                                 on_delete=models.CASCADE)
    # The other side is identified by value, not by FK: it belongs to another investigation
    # whose correlation rows are superseded on their own schedule, and a dangling reference
    # to a recomputed run would read as a similarity that no longer exists.
    other_campaign_id = models.IntegerField(db_index=True)
    other_investigation_id = models.IntegerField(db_index=True)
    other_label = models.CharField(max_length=255, blank=True)
    score = models.FloatField(default=0.0)
    rationale = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-score"]
        indexes = [models.Index(fields=["campaign", "-score"])]

    def __str__(self):
        return f"campaign {self.campaign_id} ~ {self.other_campaign_id} = {self.score:.3f}"
