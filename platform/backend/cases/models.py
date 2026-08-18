"""
PostgreSQL data model — the system of record for every past investigation.

Shape follows planning/ROADMAP-FORENSIC-PLATFORM.md §4. Structured artifacts live
here; the raw memory image lives in object storage (MinIO/S3) and is referenced by
``MemoryCapture``. The canonical verdict ladder is owned by the toolkit's
finding_schema.py, not redefined here — VERDICTS mirrors it for DB-level indexing.
"""
from django.conf import settings
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
    archival runs against.
    """

    OPEN = "open"
    CONTAINED = "contained"
    CONCLUDED = "concluded"
    ARCHIVED = "archived"
    STATUS = [(s, s) for s in (OPEN, CONTAINED, CONCLUDED, ARCHIVED)]

    # Forward through the engagement, with two ways back: reopening a concluded case is ordinary
    # (evidence arrives late), and `concluded -> open` clears the conclusion fields.
    TRANSITIONS = {
        OPEN: {CONTAINED, CONCLUDED},
        CONTAINED: {CONCLUDED, OPEN},
        CONCLUDED: {ARCHIVED, OPEN},
        ARCHIVED: set(),
    }

    # A restricted case is visible only to its assigned members and to admins. Coarse and
    # explainable: per-artifact ACLs would let two analysts reach different conclusions from
    # different visible subsets of the same case, which is what an opposing expert attacks.
    OPEN_COMPARTMENT = "open"
    RESTRICTED = "restricted"
    COMPARTMENTS = [(c, c) for c in (OPEN_COMPARTMENT, RESTRICTED)]

    name = models.CharField(max_length=255)
    incident_id = models.CharField(max_length=128, blank=True, db_index=True)
    compartment = models.CharField(max_length=16, choices=COMPARTMENTS,
                                   default=OPEN_COMPARTMENT, db_index=True)
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
    # What actually identifies the machine: a hostname is a mutable label, so identity is (hostname,
    # machine_id) and a rename becomes history rather than a new host.
    machine_id = models.CharField(max_length=64, blank=True, db_index=True)
    platform = models.CharField(max_length=32, default="linux")  # linux/windows/cloud
    clock_context = models.JSONField(default=dict, blank=True)   # _clock.json verbatim

    class Meta:
        ordering = ["hostname"]
        constraints = [
            # machine-id is what makes a collection and the memory image analyzed later converge on one host;
            # enforced in the DATABASE, because Python-only enforcement leaves every other write path free to
            # diverge.
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

    # Who owns the current verdict: '' (unjudged), 'engine', or 'analyst'. An automated pass may
    # revise a verdict it owns; it may not replace an analyst's.
    adjudicated_by = models.CharField(max_length=16, blank=True, default="")
    # The analysis pass that PRODUCED the current verdict — not the last pass that looked at
    # it. A later run that reached the same conclusion did not produce anything.
    adjudication_run = models.ForeignKey(
        "MemoryAnalysisRun", related_name="adjudicated_findings",
        on_delete=models.SET_NULL, null=True, blank=True,
    )
    # What the engine would have said where an analyst ruled otherwise — empty when they agree.
    # Disagreement reaches review instead of being applied.
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
        # `raw` is deliberately NOT indexed: it is read in Python by the correlation engine and never
        # queried by key in SQL, so a GIN would cost write throughput for nothing.

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
            # Named to match what the migration created — unnamed, Django derives a different name and
            # proposes a rename on every makemigrations.
            models.Index(fields=["ioc_type", "value"], name="cases_indic_ioc_typ_pivot_idx"),
            # And the per-case read, for the investigation's own indicator index.
            models.Index(fields=["investigation_id", "ioc_type"],
                         name="cases_indic_inv_type_idx"),
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
    # A re-analysis SUPERSEDES rather than replaces: deleting the prior pass destroys the only record
    # that the engine once judged a PID differently.
    is_current = models.BooleanField(default=True, db_index=True)
    superseded_at = models.DateTimeField(null=True, blank=True)
    superseded_by = models.ForeignKey(
        "MemoryAnalysisRun", null=True, blank=True, on_delete=models.SET_NULL,
        related_name="superseded_process_verdicts")

    class Meta:
        ordering = ["-positive_weight", "pid"]
        indexes = [
            # Named for the same reason as IndicatorSighting's: the migration named it, so
            # the model has to, or the autodetector proposes a rename forever.
            models.Index(fields=["run", "verdict"], name="cases_proce_run_id_04a726_idx"),
            # Every read path wants the live set; without this the filter scans history that
            # grows with each re-analysis.
            models.Index(fields=["run", "is_current"], name="cases_proce_run_id_5c9a54_idx"),
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
    # The custody key in force when this seal was written. Same reasoning as AuditLog: a seal
    # seals under a key, and which key must travel with it or the seal cannot be evaluated.
    sig_key_id = models.CharField(max_length=16, blank=True)

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
        # Both feed the case reports and belong in the append-only record for the same
        # reason every other entry does: they are assertions somebody made and owns.
        ("summary", "Case summary"),         # the one-paragraph account of what happened
        ("recommendation", "Recommendation"),
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


class QueueSample(models.Model):
    """One reading of the analysis backlog, taken on the backend's health-report beat.

    ComponentHealth is a current-state panel, one row overwritten in place; a queue-depth
    LINE needs history, which is a different contract, so it gets its own table rather than
    a shape change there. Rows are pruned on the same beat that writes them — the line
    answers "is the platform keeping up this week", not "what happened in March".
    """

    sampled_at = models.DateTimeField(auto_now_add=True, db_index=True)
    queued = models.IntegerField(default=0)
    running = models.IntegerField(default=0)
    # Captures no analysis has claimed yet — backlog that predates the queue.
    awaiting = models.IntegerField(default=0)
    oldest_waiting_seconds = models.IntegerField(default=0)

    class Meta:
        ordering = ["sampled_at"]


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
    # WHICH key signed this row — a digest of it, never the key. Without this, a signature
    # written under a previous key is indistinguishable from a forged one, and the platform
    # reports its own trail as tampered every time a key is replaced.
    sig_key_id = models.CharField(max_length=16, blank=True, db_index=True)

    class Meta:
        ordering = ["id"]  # insertion order == chain order


class SsoSession(TimeStamped):
    """One analyst's sign-on, from login to sign-out.

    SSO authentication is stateless: every request carries the identity in headers and is
    authenticated on its own. That leaves no login and no logout to observe, so a sign-on has
    to be reconstructed from the identity the gate forwards. This row is that reconstruction —
    the span a set of requests belongs to, and the record a brokered session is attributed
    through.
    """

    # Keycloak's session id when the access token carries one; a derived key otherwise.
    # `key_source` says which, so a correlation is never read as stronger than its evidence.
    session_key = models.CharField(max_length=128, unique=True)
    key_source = models.CharField(max_length=16, default="derived")   # oidc | derived

    # SET_NULL, not CASCADE: deleting an account must not delete the record of what it did.
    user = models.ForeignKey("auth.User", null=True, blank=True, on_delete=models.SET_NULL,
                             related_name="sso_sessions")
    username = models.CharField(max_length=150, db_index=True)
    role = models.CharField(max_length=32, blank=True)

    started_at = models.DateTimeField(default=timezone.now, db_index=True)
    last_seen_at = models.DateTimeField(default=timezone.now, db_index=True)
    ended_at = models.DateTimeField(null=True, blank=True, db_index=True)
    end_reason = models.CharField(max_length=32, blank=True)  # signout | expired | superseded

    client_address = models.CharField(max_length=64, blank=True)
    user_agent = models.CharField(max_length=256, blank=True)
    # Which workstation the sign-on came from, when the tunnel makes that knowable.
    workstation = models.CharField(max_length=64, blank=True, db_index=True)

    request_count = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["-started_at"]
        indexes = [models.Index(fields=["username", "started_at"])]

    @property
    def active(self):
        return self.ended_at is None


class AuditCheckpoint(TimeStamped):
    """An acknowledged discontinuity in the audit chain, recorded rather than repaired.

    A hash chain that breaks stays broken: re-chaining the rows so verification passes is
    precisely the act a tamper-evident ledger exists to detect, and a ledger that quietly
    heals itself proves nothing afterwards.

    So a known break is DECLARED instead. The checkpoint names the row where the chain
    restarts, the hashes on both sides of the gap, and why. Verification then reports two
    different things — an acknowledged discontinuity and an unexplained one — and only the
    second is evidence of tampering. It still fails.

    Recording one is an audited, admin-only act, and the checkpoint carries its own signature
    so a forged acknowledgement cannot be used to cover a real break.
    """

    at_entry_id = models.BigIntegerField(db_index=True, unique=True)
    # What the walk computed on arriving at that row, and what the row itself claims. Keeping
    # both makes the gap reviewable: an acknowledgement whose hashes do not match the break it
    # claims to cover proves nothing.
    observed_prev_hash = models.CharField(max_length=64, blank=True)
    declared_prev_hash = models.CharField(max_length=64, blank=True)
    reason = models.TextField()
    recorded_by = models.CharField(max_length=128)
    signature = models.CharField(max_length=128, blank=True)
    sig_key_id = models.CharField(max_length=16, blank=True)

    class Meta:
        ordering = ["at_entry_id"]


class ExportLedger(TimeStamped):
    """What left the platform, when, and who took it — answerable from one query.

    Every export already wrote an audit row, and an audit row is the right place for "this
    happened". It is the wrong place for "what has left": answering that meant reading a
    hash-chained log designed to be walked in order, filtering by an action name, and
    unpacking a free-form JSON detail whose shape each call site chose for itself. The
    question an incident lead actually asks after a case turns adversarial — what has already
    gone out of this platform — was reconstructible rather than answerable.

    So the ledger is a table with columns, and the audit trail keeps recording the act. The
    two do not compete: the chain proves nothing was removed, the ledger says what to look at.

    A DENIED export is recorded here too. An attempt that was refused belongs in the same
    place as one that succeeded — an export ledger showing only successes answers "what left"
    and cannot answer "what was tried", and those are the same question during an
    investigation into the responder.
    """

    OUTCOMES = (("completed", "completed"), ("denied", "denied"))

    actor = models.CharField(max_length=128, db_index=True)
    role = models.CharField(max_length=32, blank=True)
    # What was exported, not which endpoint served it: `findings`, `audit`, `ioc`,
    # `symbol_requisites`. The endpoint is an implementation detail that will move.
    kind = models.CharField(max_length=32, db_index=True)
    fmt = models.CharField(max_length=16, blank=True)
    # The filter set as applied, so the export can be reproduced or bounded later. An export
    # whose scope cannot be restated is a row count with no meaning.
    filters = models.JSONField(default=dict, blank=True)
    row_count = models.IntegerField(default=0)
    # Where it went. Today every export is a browser download over the brokered session, so
    # this is the destination as the platform can honestly describe it — not a guess at what
    # the analyst did with the file afterwards.
    destination = models.CharField(max_length=255, blank=True)
    outcome = models.CharField(max_length=16, choices=OUTCOMES, default="completed",
                               db_index=True)
    # Populated on a denial: which permission refused, so a pattern of refusals is legible
    # without re-deriving it from the role and the path.
    denied_reason = models.CharField(max_length=255, blank=True)
    path = models.CharField(max_length=512, blank=True)

    class Meta:
        ordering = ["-id"]
        indexes = [
            models.Index(fields=["actor", "-id"]),
            models.Index(fields=["kind", "-id"]),
            models.Index(fields=["outcome", "-id"]),
        ]

    def __str__(self):
        return f"{self.actor} {self.outcome} {self.kind} ({self.row_count} rows)"


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
    # The signature hits that flagged this region: rule names, matched strings, memory permissions,
    # and the analyzer's severity.
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
    # Which session produced this. Set when the region was in an open workset at the time,
    # so the platform can answer what came out of a given session rather than only what is
    # known about a region. SET_NULL: a workset can be tidied away; the determination is
    # part of the investigation and outlives it.
    workset = models.ForeignKey(
        "ReWorkset", related_name="determinations", on_delete=models.SET_NULL,
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


class ReWorkset(TimeStamped):
    """A bounded selection of carved regions staged for one reverse-engineering session.

    A host's carved bucket is the wrong unit to hand a human: parallel analysis carves regions
    faster than anyone examines them, and a serious engagement produces hundreds. A disassembler
    opened on all of them is a crash, and the twenty worth a person's time are indistinguishable
    inside the pile. A workset names WHICH regions a session is for.

    Scope stays one investigation and one host, because that is the wall the per-host carved
    bucket already draws — a session sees one investigation's malware and nothing else.
    """

    ASSEMBLED = "assembled"      # selected, nothing pulled yet
    STAGED = "staged"            # the mediator has pulled these regions for a session
    CLOSED = "closed"            # the session is over; determinations are on the regions
    STATES = [(s, s) for s in (ASSEMBLED, STAGED, CLOSED)]

    # The cap is the feature: "stage everything" stays possible only by assembling more than
    # one workset, deliberately. Raising it is a decision about what a disassembler can hold.
    MAX_REGIONS = 50

    slug = models.SlugField(max_length=64, unique=True)
    investigation = models.ForeignKey(
        "Investigation", related_name="re_worksets", on_delete=models.CASCADE)
    host = models.ForeignKey("Host", related_name="re_worksets", on_delete=models.CASCADE)
    created_by = models.CharField(max_length=128)
    state = models.CharField(max_length=16, choices=STATES, default=ASSEMBLED, db_index=True)
    note = models.TextField(blank=True)
    staged_at = models.DateTimeField(null=True, blank=True)
    closed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["investigation", "state"])]

    def __str__(self):
        return f"{self.slug} ({self.host_id}, {self.state})"


class ReWorksetRegion(TimeStamped):
    """One region's membership of one workset.

    A join rather than a copy: the same region can be examined in two sessions without its
    bytes being duplicated, and the platform can answer which sessions have looked at it.
    """

    workset = models.ForeignKey(ReWorkset, related_name="members", on_delete=models.CASCADE)
    region = models.ForeignKey(CarvedRegion, related_name="worksets", on_delete=models.CASCADE)
    # Where the ranking put it when the workset was assembled, kept so a session's order is
    # reproducible after the signals behind it have moved on.
    rank = models.IntegerField(default=0)
    added_by = models.CharField(max_length=128, blank=True)

    class Meta:
        ordering = ["rank", "id"]
        constraints = [
            models.UniqueConstraint(fields=["workset", "region"],
                                    name="uniq_region_per_workset"),
        ]

    def __str__(self):
        return f"{self.workset_id}:{self.region_id}"


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


class InvestigationArchive(TimeStamped):
    """One case bundle in cold storage, and the record that it went there.

    The hot Investigation row is PROTECTED: an archived case stays listed with its dates and
    counts, because a case that vanished from the list would be indistinguishable from a
    deleted one. `row_counts` is the manifest's copy, so the UI can state what the bundle
    holds without fetching it.
    """

    STATE = [("archived", "archived"), ("restored", "restored")]

    investigation = models.ForeignKey(
        Investigation, related_name="archives", on_delete=models.PROTECT)
    object_key = models.CharField(max_length=512)
    bundle_sha256 = models.CharField(max_length=64)
    schema_version = models.CharField(max_length=128, blank=True)
    row_counts = models.JSONField(default=dict, blank=True)
    size_bytes = models.BigIntegerField(default=0)
    # Archived past the hard ceiling while still open — the anomaly flag the stalled-case
    # list and the handover dashboard read.
    archived_while_open = models.BooleanField(default=False)
    state = models.CharField(max_length=16, choices=STATE, default="archived", db_index=True)
    restored_until = models.DateTimeField(null=True, blank=True, db_index=True)
    created_by = models.CharField(max_length=128, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"archive of {self.investigation_id} [{self.state}]"


class RestoreRequest(TimeStamped):
    """A restore is a job with an outcome, never a silent query."""

    STATE = [("pending", "pending"), ("completed", "completed"),
             ("failed", "failed"), ("noop", "noop")]

    archive = models.ForeignKey(
        InvestigationArchive, related_name="restores", on_delete=models.CASCADE)
    requested_by = models.CharField(max_length=128, blank=True)
    state = models.CharField(max_length=16, choices=STATE, default="pending", db_index=True)
    detail = models.TextField(blank=True, default="")
    completed_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]


class CaseAssignment(TimeStamped):
    """Who is working a case. Membership is the scoping unit, not the artifact.

    Assignment governs visibility of a restricted case and is recorded for every case, so
    "who could see this" is answerable after the fact rather than inferred from a role.
    """

    investigation = models.ForeignKey(
        Investigation, related_name="assignments", on_delete=models.CASCADE)
    username = models.CharField(max_length=150, db_index=True)
    assigned_by = models.CharField(max_length=150, blank=True)
    removed_at = models.DateTimeField(null=True, blank=True, db_index=True)

    class Meta:
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["investigation", "username"],
                condition=models.Q(removed_at__isnull=True),
                name="uniq_active_case_assignment"),
        ]

    def __str__(self):
        return f"{self.username} on {self.investigation_id}"


class CaseTag(TimeStamped):
    """A curated tag. Free text produces #malware, #Malware and #malwares — three tags for
    one idea — so the vocabulary is admin-managed and findings reference it by id."""

    label = models.CharField(max_length=64, unique=True)
    category = models.CharField(max_length=32, blank=True)
    description = models.CharField(max_length=255, blank=True)
    retired = models.BooleanField(default=False, db_index=True)

    class Meta:
        ordering = ["category", "label"]

    def __str__(self):
        return self.label


class CaseTagAssignment(TimeStamped):
    """One curated tag applied to one investigation, by whom."""

    investigation = models.ForeignKey(
        Investigation, related_name="tag_links", on_delete=models.CASCADE)
    tag = models.ForeignKey(CaseTag, related_name="assignments", on_delete=models.CASCADE)
    applied_by = models.CharField(max_length=150, blank=True)

    class Meta:
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(fields=["investigation", "tag"],
                                    name="uniq_case_tag"),
        ]


class CaseTask(TimeStamped):
    """A unit of work on a case, in the states real incident response moves through.

    Every transition is audited: a board that silently reorders itself is a worse record
    than no board, because it looks like history.
    """

    # The digital forensics process, which is the lifecycle this work actually follows.
    # Movement is free in both directions: evidence arriving late sends a case back to
    # analysis, and a board that only advances would misrepresent that as progress.
    IDENTIFICATION = "identification"
    PRESERVATION = "preservation"
    ANALYSIS = "analysis"
    DOCUMENTATION = "documentation"
    PRESENTATION = "presentation"
    STATES = [(IDENTIFICATION, "Identification"), (PRESERVATION, "Preservation"),
              (ANALYSIS, "Analysis"), (DOCUMENTATION, "Documentation"),
              (PRESENTATION, "Presentation")]
    STATE_INTENT = {
        IDENTIFICATION: "Collect the right evidence",
        PRESERVATION: "Maintain integrity of the evidence",
        ANALYSIS: "Determine the results' accuracy",
        DOCUMENTATION: "Document findings to use in court",
        PRESENTATION: "Summarize and present findings",
    }

    investigation = models.ForeignKey(
        Investigation, related_name="tasks", on_delete=models.CASCADE)
    title = models.CharField(max_length=255)
    state = models.CharField(max_length=20, choices=STATES, default=IDENTIFICATION,
                             db_index=True)
    # Blocked is an ATTRIBUTE, not a column: a blocked task is still in its stage, and
    # giving it a column of its own loses where the work actually stopped.
    blocked = models.BooleanField(default=False, db_index=True)
    blocked_reason = models.CharField(max_length=255, blank=True)
    due_at = models.DateTimeField(null=True, blank=True)
    assignee = models.CharField(max_length=150, blank=True, db_index=True)
    # What the task is about, when it is about one thing: a host, a run, a finding.
    artifact_type = models.CharField(max_length=32, blank=True)
    artifact_id = models.IntegerField(null=True, blank=True)
    detail = models.TextField(blank=True)
    created_by = models.CharField(max_length=150, blank=True)
    closed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["state", "-created_at"]

    def __str__(self):
        return f"{self.title} [{self.state}]"


class CaseTaskNote(TimeStamped):
    """An analyst's working note on a task — the reasoning behind the work, kept with it."""

    task = models.ForeignKey(CaseTask, related_name="notes", on_delete=models.CASCADE)
    author = models.CharField(max_length=150, blank=True)
    body = models.TextField()

    class Meta:
        ordering = ["created_at"]


class CaseTaskAttachment(TimeStamped):
    """A document or an evidence reference carried on a task.

    A DOCUMENT is bytes an analyst uploaded (a scan, a memo, a third-party report); its
    sha256 is recorded on receipt so the file can be shown to be the one attached. An
    EVIDENCE reference points at something the platform already holds and copies nothing.
    """

    DOCUMENT = "document"
    EVIDENCE = "evidence"
    KINDS = [(DOCUMENT, DOCUMENT), (EVIDENCE, EVIDENCE)]

    task = models.ForeignKey(CaseTask, related_name="attachments",
                             on_delete=models.CASCADE)
    kind = models.CharField(max_length=16, choices=KINDS, db_index=True)
    label = models.CharField(max_length=255, blank=True)
    added_by = models.CharField(max_length=150, blank=True)
    # Document only.
    filename = models.CharField(max_length=255, blank=True)
    object_key = models.CharField(max_length=512, blank=True)
    content_type = models.CharField(max_length=128, blank=True)
    size_bytes = models.BigIntegerField(default=0)
    sha256 = models.CharField(max_length=64, blank=True)
    # Evidence reference only: what it points at, in the platform's own vocabulary.
    ref_type = models.CharField(max_length=32, blank=True)
    ref_id = models.IntegerField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]


class RuledOut(TimeStamped):
    """A hypothesis that was tested and rejected.

    "We checked the two USB devices; neither was the entry point" is a conclusion, and
    without a place to record it a report can only say what was found — never what was
    looked for. The second is what stops a reader inventing their own explanation.
    """

    investigation = models.ForeignKey(
        Investigation, related_name="ruled_out", on_delete=models.CASCADE)
    hypothesis = models.CharField(max_length=255)
    method = models.TextField(help_text="how it was tested")
    rationale = models.TextField(blank=True)
    tested_by = models.CharField(max_length=150, blank=True)
    # What the conclusion rests on, in the platform's own vocabulary: "finding:41",
    # "run:7". Free-form so a reference can name evidence held elsewhere.
    evidence_refs = models.JSONField(default=list, blank=True)
    concluded_at = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        ordering = ["-concluded_at"]

    def __str__(self):
        return f"ruled out: {self.hypothesis}"


class ReportTemplate(TimeStamped):
    """A named, versioned selection of sections. Templates are data, so a deployment's
    own report format is configuration rather than a release."""

    SUMMARY = "summary"
    TECHNICAL = "technical"
    KINDS = [(SUMMARY, SUMMARY), (TECHNICAL, TECHNICAL)]

    name = models.CharField(max_length=128, unique=True)
    kind = models.CharField(max_length=16, choices=KINDS, db_index=True)
    version = models.CharField(max_length=32, default="1.0")
    sections = models.JSONField(default=list)
    description = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ["kind", "name"]

    def __str__(self):
        return f"{self.name} v{self.version}"


class GeneratedReport(TimeStamped):
    """One render, recorded.

    A report is a statement about evidence at a moment, so `data_as_of` and the source
    manifest travel with it — a reader must be able to tell which moment, and a second
    render after new evidence is a different document rather than an update.
    """

    investigation = models.ForeignKey(
        Investigation, related_name="reports", on_delete=models.CASCADE)
    template = models.ForeignKey(ReportTemplate, related_name="renders",
                                 on_delete=models.PROTECT)
    template_version = models.CharField(max_length=32, blank=True)
    generated_by = models.CharField(max_length=150, blank=True)
    data_as_of = models.DateTimeField()
    fmt = models.CharField(max_length=8, default="md")
    object_key = models.CharField(max_length=512, blank=True)
    sha256 = models.CharField(max_length=64, blank=True)
    size_bytes = models.BigIntegerField(default=0)
    # Every table the render drew from, with row counts: the report's own provenance.
    sources = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.template_id} report of {self.investigation_id}"


class Presence(TimeStamped):
    """Where each analyst currently is, refreshed by a heartbeat from the open tab.

    One row per person, overwritten in place: presence is a current fact, not a history,
    and the audit ledger already holds what was actually done. Staleness is judged from
    `last_seen` at read time rather than by deleting rows on a timer, so a reader always
    sees the same answer whether or not a sweep has run.
    """

    user = models.OneToOneField(settings.AUTH_USER_MODEL,
                                related_name="presence", on_delete=models.CASCADE)
    investigation = models.ForeignKey(Investigation, related_name="presence", null=True,
                                      blank=True, on_delete=models.CASCADE)
    # The view being looked at, as the UI's own route. Free text on purpose: it is
    # displayed and compared, never dispatched on.
    location = models.CharField(max_length=255, blank=True)
    last_seen = models.DateTimeField(auto_now=True, db_index=True)

    class Meta:
        ordering = ["-last_seen"]

    def __str__(self):
        return f"{self.user_id} at {self.location}"


class ArtifactLock(TimeStamped):
    """An advisory "I am working on this" marker. It never blocks anyone.

    A hard lock in an incident-response platform means an analyst who shut their laptop can
    stop a live investigation, so this only ever informs: the UI warns, and the write still
    goes through. Locks expire on their own for the same reason.
    """

    user = models.ForeignKey(settings.AUTH_USER_MODEL, related_name="locks",
                             on_delete=models.CASCADE)
    investigation = models.ForeignKey(Investigation, related_name="locks",
                                      on_delete=models.CASCADE)
    ref_type = models.CharField(max_length=32, db_index=True)
    ref_id = models.IntegerField(db_index=True)
    expires_at = models.DateTimeField(db_index=True)

    class Meta:
        ordering = ["-created_at"]
        constraints = [
            # One live lock per artifact. A second holder is refused the LOCK, never the
            # edit — the model enforces who is shown as holder, not who may write.
            models.UniqueConstraint(fields=["ref_type", "ref_id"], name="uniq_artifact_lock"),
        ]

    def __str__(self):
        return f"{self.ref_type}:{self.ref_id} held by {self.user_id}"


class Notification(TimeStamped):
    """An in-app notice addressed to one person.

    Delivery is in-app only and pulled by the client. The enclave has no egress, and it is
    not gaining one so that a mention can become an email.
    """

    MENTION = "mention"
    ASSIGNMENT = "assignment"
    HANDOVER = "handover"
    KINDS = [(MENTION, MENTION), (ASSIGNMENT, ASSIGNMENT), (HANDOVER, HANDOVER)]

    user = models.ForeignKey(settings.AUTH_USER_MODEL,
                             related_name="notifications", on_delete=models.CASCADE)
    kind = models.CharField(max_length=16, choices=KINDS, db_index=True)
    actor = models.CharField(max_length=150, blank=True)
    investigation = models.ForeignKey(Investigation, related_name="notifications",
                                      null=True, blank=True, on_delete=models.CASCADE)
    ref_type = models.CharField(max_length=32, blank=True)
    ref_id = models.IntegerField(null=True, blank=True)
    body = models.TextField(blank=True)
    read_at = models.DateTimeField(null=True, blank=True, db_index=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["user", "read_at"])]

    def __str__(self):
        return f"{self.kind} for {self.user_id}"
