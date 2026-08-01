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
