"""
PostgreSQL data model — the system of record for every past investigation.

Shape follows planning/ROADMAP-FORENSIC-PLATFORM.md §4. Structured artifacts live
here; the raw memory image lives in object storage (MinIO/S3) and is referenced by
``MemoryCapture``. The canonical verdict ladder is owned by the toolkit's
finding_schema.py, not redefined here — VERDICTS mirrors it for DB-level indexing.
"""
from django.contrib.postgres.indexes import GinIndex
from django.db import models
from django.utils import timezone

# Mirror of finding_schema.VERDICTS (kept in lockstep; do not diverge the ordering).
VERDICTS = (
    "False Positive",
    "Likely False Positive",
    "Indeterminate",
    "Likely True Positive",
    "True Positive",
)
VERDICT_CHOICES = [(v, v) for v in VERDICTS]


class TimeStamped(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class InvalidTransition(Exception):
    """A lifecycle move the model refuses. Carries both states so the caller can report it."""

    def __init__(self, current, target):
        self.current, self.target = current, target
        super().__init__(f"{current} -> {target} is not a legal transition")


class Investigation(TimeStamped):
    """One incident engagement; groups hosts and their collection runs.

    `status` was free text, which made every downstream question a guess: whether a case is
    finished, whether it may be archived, how long it has been stalled. Archival in
    particular cannot rest on a string somebody typed — the states below are the contract
    T4/T5 will archive against.
    """

    OPEN = "open"
    CONTAINED = "contained"
    CONCLUDED = "concluded"
    ARCHIVED = "archived"
    STATUS = [(s, s) for s in (OPEN, CONTAINED, CONCLUDED, ARCHIVED)]

    # Forward through the engagement, with two ways back. Reopening a concluded case is
    # ordinary — evidence arrives late — so `concluded -> open` is legal and clears
    # `concluded_at`. `archived` is terminal: its evidence has been moved out, and a
    # transition out of it would assert data that is no longer there.
    TRANSITIONS = {
        OPEN: {CONTAINED, CONCLUDED},
        CONTAINED: {CONCLUDED, OPEN},
        CONCLUDED: {ARCHIVED, OPEN},
        ARCHIVED: set(),
    }

    name = models.CharField(max_length=255)
    incident_id = models.CharField(max_length=128, blank=True, db_index=True)
    operator = models.CharField(max_length=128, blank=True)
    severity = models.CharField(max_length=32, blank=True)
    status = models.CharField(max_length=32, choices=STATUS, default=OPEN, db_index=True)
    # When the case was concluded, not when the row was last written. The stalled-case query
    # needs an age that a later note or re-analysis does not reset.
    concluded_at = models.DateTimeField(null=True, blank=True, db_index=True)
    notes = models.TextField(blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.name} ({self.incident_id or self.pk})"

    def can_transition_to(self, target):
        return target in self.TRANSITIONS.get(self.status, set())

    def transition_to(self, target, save=True):
        """Move to `target` or raise InvalidTransition. Maintains `concluded_at`.

        Refused in the model rather than in a view, so an import, a management command and
        the API cannot each hold a different idea of which moves are legal.
        """
        if target == self.status:
            return self                      # idempotent; a no-op move is not an error
        if not self.can_transition_to(target):
            raise InvalidTransition(self.status, target)
        self.status = target
        if target == self.CONCLUDED:
            self.concluded_at = timezone.now()
        elif target == self.OPEN:
            self.concluded_at = None         # reopened: it is not a concluded case any more
        if save:
            self.save(update_fields=["status", "concluded_at", "updated_at"])
        return self


class Host(TimeStamped):
    """A collected endpoint. Recurs across investigations — the 'seen before?' anchor."""

    hostname = models.CharField(max_length=255, db_index=True)
    # What actually identifies the machine. A hostname is a mutable label: it gets renamed,
    # reused across environments, and reported as a container id when collection runs without
    # the host filesystem mounted. Resolving by name alone forks a second record on any
    # mismatch, and evidence for one machine then sits under two — a memory image analyzed
    # hours after its collection landed no longer corroborates against it.
    #
    # /etc/machine-id: generated once at install, stable across reboots and renames. Blank for
    # hosts collected before the collector recorded it, or where it was unreadable, in which
    # case resolution falls back to the hostname.
    machine_id = models.CharField(max_length=64, blank=True, db_index=True)
    platform = models.CharField(max_length=32, default="linux")  # linux/windows/cloud
    clock_context = models.JSONField(default=dict, blank=True)   # _clock.json verbatim

    class Meta:
        ordering = ["hostname"]
        constraints = [
            # machine-id is what makes a collection and the memory image analyzed hours
            # later converge on one host. Enforced only in Python, that convergence was a
            # read-then-write race: two arrivals for the same machine could each find no
            # host and each create one, splitting the machine's evidence across two records
            # with no way to tell afterwards. The database refuses it instead.
            #
            # Partial, because blank means "not recorded" — collections predating the
            # machine-id capture, or where it was unreadable, legitimately have none and
            # fall back to hostname resolution. A unique index over them would collapse
            # every such host into one.
            models.UniqueConstraint(
                fields=["machine_id"],
                condition=models.Q(machine_id__gt=""),
                name="uniq_host_machine_id",
            ),
        ]

    def __str__(self):
        return self.hostname


class HostIdentityChange(TimeStamped):
    """A change to how a machine identifies itself, kept because the Host row cannot hold it.

    `Host` carries the CURRENT hostname, machine-id and platform — a machine renamed between
    collections overwrites the old value, and every earlier run then renders under a name that
    host did not have when its evidence was collected. An analyst reading a six-week-old run
    would see today's name and have no way to learn it ever had another.

    So identity is historised: the row here says what the value was, what it became, when it
    was observed and which collection observed it. Answering "what was this machine called at
    the time of that run" is a lookup rather than a guess.

    Written by ingest, never by a user. Renames are observed, not requested.
    """

    FIELD = [
        ("hostname", "hostname"),
        ("machine_id", "machine_id"),   # adopted when a host first reports one
        ("platform", "platform"),
    ]
    host = models.ForeignKey(Host, related_name="identity_changes", on_delete=models.CASCADE)
    field = models.CharField(max_length=32, choices=FIELD, db_index=True)
    from_value = models.CharField(max_length=255, blank=True)
    to_value = models.CharField(max_length=255)
    # When the COLLECTION that observed the change was taken, which is not when the row was
    # written: a bundle can arrive long after the machine was renamed.
    observed_at = models.DateTimeField(null=True, blank=True)
    source_stamp = models.CharField(max_length=255, blank=True)   # the collection that saw it
    actor = models.CharField(max_length=128, default="ingest")

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["host", "field"])]

    def __str__(self):
        return f"{self.host_id} {self.field}: {self.from_value or '(none)'} -> {self.to_value}"


class CollectionRun(TimeStamped):
    """One execution of the collection container on a host."""

    KIND = [
        ("initial", "initial"),               # first collection in an investigation
        ("validation", "validation"),         # rescan to confirm a restored/good baseline
        ("eradication_check", "eradication_check"),  # rescan to confirm eradication held
    ]
    investigation = models.ForeignKey(
        Investigation, related_name="runs", on_delete=models.CASCADE
    )
    host = models.ForeignKey(Host, related_name="runs", on_delete=models.CASCADE)
    stamp = models.CharField(max_length=64, blank=True)
    toolkit_version = models.CharField(max_length=64, blank=True)
    overall_status = models.CharField(max_length=32, blank=True)  # COMPLETED/PARTIAL/FAILED
    tp_count = models.IntegerField(default=0)
    status_json = models.JSONField(default=dict, blank=True)      # _status.json verbatim
    custody_verified = models.BooleanField(default=False)
    custody_summary = models.JSONField(default=dict, blank=True)
    collected_at = models.DateTimeField(null=True, blank=True)
    # Rescan / validation (web-app-initiated).
    run_kind = models.CharField(max_length=24, choices=KIND, default="initial", db_index=True)
    baseline_run = models.ForeignKey(
        "self", null=True, blank=True, related_name="validations", on_delete=models.SET_NULL
    )
    compromised = models.BooleanField(default=False, db_index=True)
    validation_result = models.JSONField(default=dict, blank=True)  # diff vs baseline, pass/fail

    class Meta:
        ordering = ["-created_at"]
        constraints = [
            # Ingest documents itself as idempotent on this triple: re-posting a bundle
            # returns the existing run rather than duplicating it. That was a convention the
            # application observed, not a rule the store enforced — so a retried delivery
            # arriving twice concurrently could produce two runs for one collection, and the
            # same evidence would then be counted, correlated and reported twice.
            models.UniqueConstraint(
                fields=["investigation", "host", "stamp"],
                name="uniq_run_investigation_host_stamp",
            ),
        ]

    def __str__(self):
        return f"{self.host} @ {self.stamp or self.created_at:%Y-%m-%d}"

    def evaluate_compromise(self):
        """A run is compromised if any TP-class collector finding or a High/Critical
        memory finding exists. Drives object-storage retention (retain vs purge).

        Findings from a synthetic capture are excluded. The synthetic sample exists so the
        pipeline can be exercised where `avml` cannot reach host memory, and it carries
        planted strings by construction — a C2 URL, a reverse-shell token, a routable
        address. Counting those makes every such run declare its host compromised and retain
        placeholder bytes as evidence: wrong, and the kind of wrong that erodes trust in the
        real verdicts sitting beside it.
        """
        tp = self.findings.filter(
            verdict__in=("True Positive", "Likely True Positive")
        ).exists()
        mem = (MemoryFinding.objects
               .filter(analysis__capture__run=self, severity__in=("High", "Critical"))
               .exclude(analysis__capture__is_synthetic=True)
               .exists())
        self.compromised = bool(tp or mem or self.tp_count > 0)
        return self.compromised


class Finding(TimeStamped):
    """A normalized finding_schema record. Verbatim JSON kept for fidelity."""

    run = models.ForeignKey(CollectionRun, related_name="findings", on_delete=models.CASCADE)
    finding_type = models.CharField(max_length=255, db_index=True)      # schema 'Type'
    target = models.CharField(max_length=512)                           # schema 'Target'
    verdict = models.CharField(max_length=32, choices=VERDICT_CHOICES, blank=True, db_index=True)
    confidence = models.CharField(max_length=32, blank=True)
    mitre = models.JSONField(default=list, blank=True)                  # ATT&CK technique ids
    tier = models.CharField(max_length=32, blank=True)
    subject_path = models.CharField(max_length=1024, blank=True)
    source = models.CharField(max_length=32, default="collector")      # collector | memory | LLM
    raw = models.JSONField(default=dict)                               # verbatim finding

    # Who owns the current verdict: "" (nobody has judged it), "engine", or "analyst".
    # An automated pass may set and revise a verdict it owns; it may not replace one an
    # analyst set. A report rests on the human determination, and an engine re-run that
    # quietly overturns it invalidates the report rather than merely annoying its author.
    adjudicated_by = models.CharField(max_length=16, blank=True, default="")
    # The analysis pass that PRODUCED the current verdict — not the last pass that looked at
    # it. A later run that reached the same conclusion did not produce anything.
    adjudication_run = models.ForeignKey(
        "MemoryAnalysisRun", related_name="adjudicated_findings",
        on_delete=models.SET_NULL, null=True, blank=True,
    )
    # What the engine would have said where an analyst already ruled otherwise. Empty when
    # they agree. This is how disagreement reaches review instead of being applied.
    #
    # Deliberately unindexed: the conflict set is small, and the triage queue is already
    # scoped to a run, so an index here would cost writes on the largest table in the store
    # to serve a query that filters a few hundred rows.
    adjudication_conflict = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["finding_type", "verdict"]),
            # `mitre` is queried by containment (`mitre__contains=[technique]`), which a
            # B-tree cannot serve; GIN is the index that applies to jsonb `@>`.
            GinIndex(fields=["mitre"], name="finding_mitre_gin"),
            # Exact-match filter used by the API and by correlation to separate collector,
            # memory and reverse-engineering evidence.
            models.Index(fields=["source"], name="finding_source_idx"),
        ]
        # `raw` is deliberately NOT indexed. It is read in Python by the correlation engine
        # and never queried by key in SQL, so a GIN over it would cost write throughput on
        # the largest table in the store to serve no query. Index it if and when a query
        # needs it.

    def __str__(self):
        return f"{self.finding_type} -> {self.target} [{self.verdict}]"


class FindingReclassification(TimeStamped):
    """A change of verdict on a finding, with the reasoning that justified it.

    Automated analysis produces leads at a severity the tool guessed. Downgrading a noisy
    YARA hit or promoting an overlooked one is normal analytic work — but it changes what
    the incident asserts, so it is recorded rather than silently overwritten. The note is
    required: a verdict that changed for no stated reason cannot be evaluated later.
    """

    finding = models.ForeignKey(
        "Finding", related_name="reclassifications", on_delete=models.CASCADE
    )
    # Carried explicitly rather than walked through finding→run→investigation. Everything
    # an analyst or reverse engineer asserts belongs to the incident record, and a record
    # you can only assemble by traversing three joins is one nobody assembles.
    investigation = models.ForeignKey(
        "Investigation", related_name="reclassifications", on_delete=models.CASCADE,
        null=True, blank=True,
    )
    actor = models.CharField(max_length=128)
    role = models.CharField(max_length=32, blank=True)
    from_verdict = models.CharField(max_length=32, blank=True)
    to_verdict = models.CharField(max_length=32)
    from_confidence = models.CharField(max_length=32, blank=True)
    to_confidence = models.CharField(max_length=32, blank=True)
    note = models.TextField()

    def save(self, *args, **kwargs):
        if self.investigation_id is None and self.finding_id:
            self.investigation_id = self.finding.run.investigation_id
        super().save(*args, **kwargs)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.finding_id}: {self.from_verdict or '—'} -> {self.to_verdict}"


class IOC(TimeStamped):
    """Indicator of compromise. Indexed for cross-investigation lookup."""

    run = models.ForeignKey(CollectionRun, related_name="iocs", on_delete=models.CASCADE)
    ioc_type = models.CharField(max_length=64, db_index=True)   # ip / domain / hash / tool / technique
    value = models.CharField(max_length=1024, db_index=True)
    context = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["ioc_type", "value"]
        indexes = [models.Index(fields=["ioc_type", "value"])]

    def __str__(self):
        return f"{self.ioc_type}:{self.value}"


class IndicatorSighting(TimeStamped):
    """One (indicator, host, investigation) rollup — what survives archival of the evidence.

    `IOC` rows hang off a `CollectionRun`, so archiving an investigation takes them with it
    and the cross-case question dies: *which other engagements has this mutex appeared in?*
    That question is the whole point of L5 attribution, and it has to be answerable after the
    raw evidence has been moved out — an actor's builder-fixed indicators are precisely what
    outlives the infrastructure they rotate between engagements.

    Deliberately denormalized. No foreign key to `CollectionRun`, and hostname and incident
    are copied rather than joined, because a cascade from the rows this summarizes would
    delete the summary along with them — which is the exact failure it exists to prevent.
    `host_id` and `investigation_id` are kept as plain integers for pivoting while those
    records live, and mean nothing once they do not.
    """

    ioc_type = models.CharField(max_length=64, db_index=True)
    value = models.CharField(max_length=1024, db_index=True)
    investigation_id = models.IntegerField(db_index=True)
    incident_id = models.CharField(max_length=128, blank=True, db_index=True)
    host_id = models.IntegerField(db_index=True)
    hostname = models.CharField(max_length=255, db_index=True)
    first_seen = models.DateTimeField(null=True, blank=True)
    last_seen = models.DateTimeField(null=True, blank=True)
    sighting_count = models.IntegerField(default=1)
    # Kept so an archived sighting still says what kind of finding produced it.
    context = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["ioc_type", "value", "hostname"]
        indexes = [
            # The cross-case pivot: everywhere this indicator has ever been seen.
            models.Index(fields=["ioc_type", "value"]),
            # And the per-case read, for the investigation's own indicator index.
            models.Index(fields=["investigation_id", "ioc_type"]),
        ]
        constraints = [models.UniqueConstraint(
            fields=["ioc_type", "value", "host_id", "investigation_id"],
            name="uniq_indicator_sighting")]

    def __str__(self):
        return f"{self.ioc_type}:{self.value} on {self.hostname} x{self.sighting_count}"


class Principal(TimeStamped):
    """Implicated account (Principals.json) — credential-revocation history."""

    run = models.ForeignKey(CollectionRun, related_name="principals", on_delete=models.CASCADE)
    name = models.CharField(max_length=255, db_index=True)
    context = models.JSONField(default=dict, blank=True)

    def __str__(self):
        return self.name


class MemoryCapture(TimeStamped):
    """Pointer to a raw memory image in object storage + provenance for re-analysis."""

    run = models.ForeignKey(CollectionRun, related_name="captures", on_delete=models.CASCADE)
    # Object-store reference (D1): the bytes never enter PostgreSQL.
    store_backend = models.CharField(max_length=16, default="minio")  # minio | s3
    bucket = models.CharField(max_length=255)
    object_key = models.CharField(max_length=1024)
    etag = models.CharField(max_length=128, blank=True)
    size_bytes = models.BigIntegerField(default=0)
    sha256 = models.CharField(max_length=64, blank=True, db_index=True)
    image_format = models.CharField(max_length=16, default="raw")  # raw/lime/aff4/dmp
    capture_tool = models.CharField(max_length=64, blank=True)     # avml / synthetic-fallback / ...
    # Symbol/ISF context must travel with the capture so a years-later re-run resolves symbols.
    symbol_context = models.JSONField(default=dict, blank=True)
    is_synthetic = models.BooleanField(default=False)  # honest flag: not a real RAM image
    # Retention lifecycle: a clean host's capture is purged after analysis; a compromised
    # host's capture is kept as evidence under legal hold (never auto-purged).
    RETENTION = [
        ("pending", "pending"),        # analysis not yet complete
        ("retained", "retained"),      # kept (compromised host) — evidence
        ("legal_hold", "legal_hold"),  # explicit hold, admin-set, never auto-purged
        ("purged", "purged"),          # object deleted from storage; metadata/results kept
    ]
    retention_status = models.CharField(max_length=16, choices=RETENTION, default="pending", db_index=True)
    retention_reason = models.CharField(max_length=255, blank=True)
    purged_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.object_key} ({self.size_bytes} bytes)"


class MemoryAnalysisRun(TimeStamped):
    """One server-side analysis of a capture. Multiple runs per capture = re-analysis history."""

    STATUS = [
        ("queued", "queued"),
        ("running", "running"),
        ("completed", "completed"),
        ("failed", "failed"),
    ]
    capture = models.ForeignKey(MemoryCapture, related_name="analyses", on_delete=models.CASCADE)
    engine = models.CharField(max_length=64, default="native-scan")  # vol3 / memprocfs / native-scan
    engine_version = models.CharField(max_length=64, blank=True)
    ruleset_version = models.CharField(max_length=64, blank=True)
    status = models.CharField(max_length=16, choices=STATUS, default="queued", db_index=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    summary = models.JSONField(default=dict, blank=True)
    # The investigation engine's narrative output for this analysis: attack chains, named
    # TTP pattern matches, and where the engine disagreed with the on-host adjudication.
    # Per-PID verdicts are rows in ProcessVerdict, not JSON, because they are the queue.
    investigation = models.JSONField(default=dict, blank=True)
    error = models.TextField(blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"analysis {self.pk} [{self.status}] on capture {self.capture_id}"


class ProcessVerdict(TimeStamped):
    """One process, as adjudicated by the toolkit's investigation engine.

    The engine judges processes, not findings: a rule name is not a verdict, but several
    independent signals converging on one PID is. These rows hold that output verbatim, so
    the platform never re-derives a conclusion the toolkit already reached. They are also
    the right size for a UI — hundreds of processes rather than thousands of raw hits — so
    the adjudication view can show convergence first and detail on drill-down.
    """

    run = models.ForeignKey(CollectionRun, related_name="process_verdicts",
                            on_delete=models.CASCADE)
    analysis = models.ForeignKey(MemoryAnalysisRun, related_name="process_verdicts",
                                 on_delete=models.CASCADE)
    pid = models.IntegerField(db_index=True)
    process = models.CharField(max_length=255, blank=True)
    # The engine's own label, kept alongside the platform's ladder term so a verdict can
    # always be traced back to what the engine actually said.
    engine_label = models.CharField(max_length=32)
    verdict = models.CharField(max_length=32, choices=VERDICT_CHOICES, db_index=True)
    confidence = models.CharField(max_length=32, blank=True)
    positive_weight = models.FloatField(default=0.0)
    rationale = models.TextField(blank=True)
    sources = models.JSONField(default=list, blank=True)        # which detections agreed
    mitre = models.JSONField(default=list, blank=True)
    positive_dims = models.JSONField(default=list, blank=True)  # the dimensions that fired
    prior_adjudication = models.CharField(max_length=64, blank=True)  # the host's verdict
    # A re-analysis SUPERSEDES rather than replaces. Deleting the prior pass destroyed the
    # only record that the engine once judged a PID differently — and "what did we conclude
    # before, and what changed it" is a question a report has to answer. Same shape as
    # CorrelationRun, so the two derived stores behave alike.
    is_current = models.BooleanField(default=True, db_index=True)
    superseded_at = models.DateTimeField(null=True, blank=True)
    superseded_by = models.ForeignKey(
        "MemoryAnalysisRun", null=True, blank=True, on_delete=models.SET_NULL,
        related_name="superseded_process_verdicts")

    class Meta:
        ordering = ["-positive_weight", "pid"]
        indexes = [
            models.Index(fields=["run", "verdict"]),
            # Every read path wants the live set; without this the filter scans history that
            # grows with each re-analysis.
            models.Index(fields=["run", "is_current"]),
        ]

    def __str__(self):
        return f"pid {self.pid} ({self.process}) — {self.engine_label}"


class MemoryFinding(TimeStamped):
    """A finding produced by server-side memory analysis.

    Promoted into a Finding on the owning run so it appears alongside collector findings
    and can be adjudicated: an automated hit is a lead, not a conclusion, and the analyst
    needs one place to triage everything the platform knows about a host.
    """

    analysis = models.ForeignKey(
        MemoryAnalysisRun, related_name="findings", on_delete=models.CASCADE
    )
    finding_type = models.CharField(max_length=255, db_index=True)
    severity = models.CharField(max_length=32, blank=True, db_index=True)
    detail = models.TextField(blank=True)
    offset = models.BigIntegerField(null=True, blank=True)
    evidence = models.JSONField(default=dict, blank=True)
    # The adjudicable Finding this was promoted to, so the two stay linked and a
    # reclassification is traceable back to the memory evidence that produced it.
    promoted_finding = models.ForeignKey(
        "Finding", null=True, blank=True, related_name="memory_findings",
        on_delete=models.SET_NULL,
    )

    class Meta:
        ordering = ["-severity", "offset"]

    def __str__(self):
        return f"{self.finding_type} [{self.severity}]"


class CustodyEvent(TimeStamped):
    """Append-only custody ledger, continuing _custody_log.jsonl into the DB."""

    run = models.ForeignKey(
        CollectionRun, related_name="custody_events", on_delete=models.CASCADE,
        null=True, blank=True,
    )
    action = models.CharField(max_length=64)   # ingest / verify / analyze / purge / access
    actor = models.CharField(max_length=128, blank=True)
    detail = models.JSONField(default=dict, blank=True)
    prev_hash = models.CharField(max_length=64, blank=True)
    entry_hash = models.CharField(max_length=64, blank=True)

    class Meta:
        ordering = ["created_at"]


class Note(TimeStamped):
    """An entry in the investigation record.

    A free-text body alone does not survive contact with a real incident. Three months on,
    a reviewer needs to know *when the thing happened* rather than when someone typed it up,
    *which host* it concerns, *what kind* of entry it is — an observation is not a decision
    and neither is a containment action — and *what evidence* it rests on. Those are the
    fields; the body is what they annotate.

    Entries are append-only. An investigation record whose history can be quietly edited is
    not a record, so a mistaken entry is retracted with a reason and stays visible.
    """

    KIND = [
        ("observation", "Observation"),      # something seen in the evidence
        ("analysis", "Analysis"),            # an interpretation drawn from it
        ("decision", "Decision"),            # a call made, and why
        ("action", "Action taken"),          # something done to a host or account
        ("containment", "Containment"),
        ("eradication", "Eradication"),
        ("handoff", "Handoff"),              # transfer of the case or a workstream
        ("request", "Request"),              # information or access asked for
    ]
    CONFIDENCE = [("high", "High"), ("medium", "Medium"), ("low", "Low")]

    investigation = models.ForeignKey(
        Investigation, related_name="case_notes", on_delete=models.CASCADE, null=True, blank=True
    )
    run = models.ForeignKey(
        CollectionRun, related_name="case_notes", on_delete=models.CASCADE, null=True, blank=True
    )
    # A note usually concerns one host even when it is filed against the investigation.
    host = models.ForeignKey(
        Host, related_name="case_notes", on_delete=models.SET_NULL, null=True, blank=True
    )
    author = models.CharField(max_length=128)
    author_role = models.CharField(max_length=32, blank=True)
    kind = models.CharField(max_length=16, choices=KIND, default="observation", db_index=True)
    summary = models.CharField(max_length=255, blank=True)   # the one line in a timeline
    body = models.TextField()
    # When the thing described happened, as distinct from when it was written down. An
    # incident timeline built from record-creation times is a record of the analyst's
    # working hours, not of the intrusion.
    occurred_at = models.DateTimeField(null=True, blank=True, db_index=True)
    confidence = models.CharField(max_length=16, choices=CONFIDENCE, blank=True)
    mitre = models.JSONField(default=list, blank=True)
    tags = models.JSONField(default=list, blank=True)
    # What the entry rests on. Without this a conclusion in the record cannot be traced
    # back to the evidence that produced it.
    findings = models.ManyToManyField(Finding, related_name="case_notes", blank=True)

    retracted = models.BooleanField(default=False)
    retracted_by = models.CharField(max_length=128, blank=True)
    retracted_at = models.DateTimeField(null=True, blank=True)
    retraction_reason = models.TextField(blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["investigation", "kind"])]

    def save(self, *args, **kwargs):
        # An entry filed against a run still belongs to that run's investigation. Deriving
        # it here means no note can exist outside the incident record.
        if self.investigation_id is None and self.run_id:
            self.investigation_id = self.run.investigation_id
        if self.host_id is None and self.run_id:
            self.host_id = self.run.host_id
        super().save(*args, **kwargs)

    @property
    def effective_at(self):
        """When this entry belongs on a timeline."""
        return self.occurred_at or self.created_at

    def __str__(self):
        return f"{self.kind}: {self.summary or self.body[:60]}"


class RescanRequest(TimeStamped):
    """A web-app-initiated request to re-collect a host and validate its state
    (eradication held / restored to a good baseline). Fulfilled by a collector run
    whose result is diffed against the baseline."""

    KIND = [("baseline", "baseline"), ("eradication", "eradication")]
    STATUS = [("pending", "pending"), ("fulfilled", "fulfilled"), ("failed", "failed")]
    host = models.ForeignKey(Host, related_name="rescans", on_delete=models.CASCADE)
    investigation = models.ForeignKey(
        Investigation, related_name="rescans", on_delete=models.CASCADE, null=True, blank=True
    )
    baseline_run = models.ForeignKey(
        CollectionRun, related_name="rescan_requests", on_delete=models.SET_NULL,
        null=True, blank=True,
    )
    kind = models.CharField(max_length=16, choices=KIND, default="baseline")
    status = models.CharField(max_length=16, choices=STATUS, default="pending", db_index=True)
    requested_by = models.CharField(max_length=128)
    resulting_run = models.ForeignKey(
        CollectionRun, related_name="fulfills_rescan", on_delete=models.SET_NULL,
        null=True, blank=True,
    )
    result = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-created_at"]


class ComponentHealth(TimeStamped):
    """The latest resource and environment report a component sent about itself.

    Liveness probes answer "is it up", which is the question an admin asks after something
    already broke. These are the figures that predict the break: a holding volume with less
    room than the next capture needs, a worker near its cgroup ceiling, a link dropping
    frames mid-transfer. A capture is sized by the endpoint's RAM, so the margin an admin has
    to act in is the time between two reports, not between two incidents.

    Self-reported rather than probed, because a container's real limits are only visible from
    inside it, and because the DMZ receiver has no route inward — its report reaches the
    platform the same way its bundles do, carried by the puller on its outbound poll.

    One row per component, overwritten in place: this is a current-state panel, not a metrics
    store. `reported_at` is what makes a stale reporter visible as stale rather than as
    healthy-but-quiet.
    """

    component = models.CharField(max_length=64, unique=True, db_index=True)
    tier = models.CharField(max_length=32, blank=True)      # data | application | dmz | identity
    reported_at = models.DateTimeField(db_index=True)
    # Whole sysstats.collect() payload: disk, memory, cpu, network, process, logs.
    metrics = models.JSONField(default=dict, blank=True)
    # Set by the reporter when it knows something a resource figure cannot express.
    note = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ["tier", "component"]

    def __str__(self):
        return f"{self.component} @ {self.reported_at:%Y-%m-%d %H:%M}"


class AuditLog(TimeStamped):
    """Append-only, hash-chained audit trail. Every mutation and privileged read is
    recorded; each entry hashes the previous entry's hash (and is optionally HMAC-signed)
    so any deletion or edit of history is detectable. Auditors read this; nobody edits it."""

    actor = models.CharField(max_length=128, db_index=True)
    role = models.CharField(max_length=32, blank=True)
    action = models.CharField(max_length=64, db_index=True)   # e.g. ingest, note.create, capture.purge, run.delete
    method = models.CharField(max_length=8, blank=True)
    path = models.CharField(max_length=512, blank=True)
    object_type = models.CharField(max_length=64, blank=True)
    object_id = models.CharField(max_length=64, blank=True)
    detail = models.JSONField(default=dict, blank=True)
    prev_hash = models.CharField(max_length=64, blank=True)
    entry_hash = models.CharField(max_length=64, db_index=True)
    signature = models.CharField(max_length=128, blank=True)  # HMAC-SHA256 when IR_AUDIT_HMAC_KEY set

    class Meta:
        ordering = ["id"]  # insertion order == chain order


class SymbolRequest(TimeStamped):
    """A kernel whose Volatility symbol table (ISF) the enclave does not have.

    Volatility cannot parse a Linux image without an ISF matching the exact kernel build,
    and building one needs debug symbols downloaded from the internet. Neither the
    collector (on a possibly compromised endpoint) nor the enclave may reach the internet,
    so acquisition is an out-of-band act by an administrator.

    A request records what is needed, so the admin has the exact requisites without
    touching the evidence, and so a capture analyzed at reduced depth is visibly waiting
    on symbols rather than silently under-analyzed.

    Symbols are perishable: distributions prune debug packages for superseded kernel
    ABIs, so a request that goes unfulfilled can become unfulfillable. `first_needed_at`
    exists to make that ageing visible.
    """

    STATUS = [
        ("needed", "needed"),            # no ISF; captures are analyzed at reduced depth
        ("fulfilled", "fulfilled"),      # ISF present in the enclave symbol store
        ("unavailable", "unavailable"),  # no debug symbols published for this build
    ]

    symbol_key = models.CharField(max_length=128, unique=True, db_index=True)
    kernel_release = models.CharField(max_length=128, blank=True)
    arch = models.CharField(max_length=32, blank=True)
    banner = models.TextField(blank=True)
    build_id = models.CharField(max_length=128, blank=True, db_index=True)
    os_release = models.JSONField(default=dict, blank=True)
    status = models.CharField(max_length=16, choices=STATUS, default="needed", db_index=True)
    first_needed_at = models.DateTimeField(null=True, blank=True)
    fulfilled_at = models.DateTimeField(null=True, blank=True)
    isf_sha256 = models.CharField(max_length=64, blank=True)
    note = models.CharField(max_length=255, blank=True)
    # How many captures are waiting on it — the priority signal for an admin.
    waiting_captures = models.IntegerField(default=0)

    class Meta:
        ordering = ["status", "-waiting_captures", "-created_at"]

    def __str__(self):
        return f"{self.kernel_release or self.symbol_key} [{self.status}]"


class CarvedRegion(TimeStamped):
    """A memory region carved out of a capture because YARA matched it.

    Regions are the raw material of reverse engineering: extracted bytes that are, by
    assumption, live malware. They live in the host's own object-storage bucket and are
    tracked here so the work of identifying them can be assigned, recorded and audited
    rather than happening in someone's notes.
    """

    TRIAGE = [
        ("unanalyzed", "unanalyzed"),
        ("in_progress", "in_progress"),
        ("analyzed", "analyzed"),
        ("benign", "benign"),          # examined and determined not to be malicious
        ("purged", "purged"),          # bytes deleted; the determination is kept
    ]

    analysis = models.ForeignKey(
        MemoryAnalysisRun, related_name="regions", on_delete=models.CASCADE
    )
    # Per-host bucket: a reverse-engineering session is granted one host's regions and
    # cannot see another investigation's malware.
    bucket = models.CharField(max_length=255)
    object_key = models.CharField(max_length=1024)
    size_bytes = models.BigIntegerField(default=0)
    sha256 = models.CharField(max_length=64, blank=True, db_index=True)
    # What caused it to be carved — the rule or plugin that matched.
    carved_by = models.CharField(max_length=255, blank=True)
    # The signature hits that flagged this region: rule names, which strings matched, the
    # memory permissions, and the severity the analyzer assigned.
    #
    # Without this a reverse engineer is handed two megabytes of heap and asked for a
    # verdict with no statement of what to look for. The permissions matter as much as the
    # rule name: a rule hitting anonymous rw- memory is matching data, while the same rule
    # on anonymous rwx is matching code that nothing on disk accounts for.
    trigger = models.JSONField(default=dict, blank=True)
    # Where it came from inside the image, when the analyzer could attribute it.
    source_pid = models.IntegerField(null=True, blank=True)
    source_process = models.CharField(max_length=255, blank=True)
    triage_status = models.CharField(max_length=16, choices=TRIAGE, default="unanalyzed",
                                     db_index=True)
    # Set when the bytes are deleted. The row and its analyses are kept: what a region was
    # determined to be remains part of the investigation even once the sample is gone.
    purged_at = models.DateTimeField(null=True, blank=True)
    purged_by = models.CharField(max_length=128, blank=True)
    purge_reason = models.CharField(max_length=500, blank=True)
    purge_statement = models.TextField(blank=True)
    pre_purge_sha256 = models.CharField(max_length=64, blank=True)

    class Meta:
        ordering = ["triage_status", "-size_bytes"]
        indexes = [models.Index(fields=["triage_status"])]

    def __str__(self):
        return f"{self.object_key} [{self.triage_status}]"


class RegionAnalysis(TimeStamped):
    """A reverse engineer's determination about one carved region.

    Recorded separately from the collector's findings because it is a different kind of
    claim, made by a different role, from different evidence. When it identifies something
    malicious it raises a Finding on the owning run, so the incident picture stays whole
    and the analyst sees the conclusion without needing to read the region.
    """

    VERDICT = [
        ("malicious", "malicious"),
        ("suspicious", "suspicious"),
        ("benign", "benign"),
        ("inconclusive", "inconclusive"),
    ]

    CONFIDENCE = [
        ("definitive", "definitive"),   # identified beyond doubt; evidence is mandatory
        ("high", "high"),
        ("medium", "medium"),
        ("low", "low"),
    ]

    region = models.ForeignKey(CarvedRegion, related_name="analyses", on_delete=models.CASCADE)
    analyst = models.CharField(max_length=128)          # who made the determination
    verdict = models.CharField(max_length=16, choices=VERDICT, db_index=True)
    confidence = models.CharField(max_length=16, choices=CONFIDENCE, default="medium")
    malware_family = models.CharField(max_length=128, blank=True)
    variant = models.CharField(max_length=128, blank=True)
    capability = models.CharField(max_length=255, blank=True)   # what it does

    # --- Evidence -------------------------------------------------------------------
    # A verdict on its own is an opinion. These carry what the determination rests on, so
    # a reader months later can evaluate the reasoning rather than take it on trust — and
    # so it stands up as evidence rather than as a note.
    statement = models.TextField(blank=True)            # the written determination
    capabilities = models.JSONField(default=list, blank=True)    # injection, persistence, …
    strings_of_interest = models.JSONField(default=list, blank=True)  # [{value, why}]
    yara_matches = models.JSONField(default=list, blank=True)
    file_characteristics = models.JSONField(default=dict, blank=True)
    # entropy, packer, compiler artifacts, section names, imports
    network_indicators = models.JSONField(default=list, blank=True)   # [{type, value, role}]
    crypto_material = models.JSONField(default=list, blank=True)      # keys, wallets, certs
    config_extracted = models.JSONField(default=dict, blank=True)     # campaign id, sleep, jitter
    related_hashes = models.JSONField(default=list, blank=True)       # comparable samples

    # Indicators recovered by hand that the automated pass did not surface.
    indicators = models.JSONField(default=list, blank=True)     # [{type, value}]
    mitre = models.JSONField(default=list, blank=True)
    notes = models.TextField(blank=True)
    # The finding this raised on the incident, so the two stay linked in both directions.
    finding = models.ForeignKey(
        "Finding", null=True, blank=True, related_name="region_analyses",
        on_delete=models.SET_NULL,
    )
    # Reverse-engineering happens away from the case screen, on a workstation with no path
    # back to the platform, so the link to the incident has to be carried on the record
    # itself. Everything an RE determines belongs to the investigation that produced the
    # region, and this is what makes it show up there.
    investigation = models.ForeignKey(
        "Investigation", related_name="region_analyses", on_delete=models.CASCADE,
        null=True, blank=True,
    )

    def save(self, *args, **kwargs):
        if self.investigation_id is None and self.region_id:
            self.investigation_id = self.region.analysis.capture.run.investigation_id
        super().save(*args, **kwargs)

    class Meta:
        ordering = ["-created_at"]
        verbose_name_plural = "region analyses"

    def __str__(self):
        return f"{self.region_id}: {self.verdict} ({self.malware_family or 'unattributed'})"


class RemediationAction(TimeStamped):
    """An admin's request for a named repair, and what happened when it ran.

    THE WEB TIER NEVER EXECUTES THIS. The backend records a request; a privileged agent on the
    enclave host polls for queued rows, runs the matching entry from its OWN allow-list, and
    posts the result back. That split is the whole design: giving a request-serving container
    the container runtime's socket would hand anything that compromised the web tier full
    control of every other service — the precise escape the tier separation exists to prevent.

    The agent trusts the ACTION NAME and nothing else. No command, no arguments and no paths
    cross this boundary, so a forged or tampered row can only ask for one of a fixed set of
    repairs that were reviewed when the agent was written.

    Every row is an audit record whether it succeeded or not: who asked, for what, when, and
    what the agent reported back.
    """

    STATUS_CHOICES = [
        ("queued", "queued"),        # recorded, no agent has claimed it
        ("running", "running"),      # an agent claimed it
        ("succeeded", "succeeded"),
        ("failed", "failed"),
        ("rejected", "rejected"),    # the agent does not know this action
    ]

    action = models.CharField(max_length=64)
    actor = models.CharField(max_length=128, db_index=True)
    reason = models.TextField(blank=True, default="")
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default="queued")
    # Bounded, because it is operator output rendered in a browser and an unbounded field is a
    # way to fill the database from a failing repair loop.
    output = models.TextField(blank=True, default="")
    exit_code = models.IntegerField(null=True, blank=True)
    claimed_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    agent_host = models.CharField(max_length=128, blank=True, default="")

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.action} [{self.status}]"
