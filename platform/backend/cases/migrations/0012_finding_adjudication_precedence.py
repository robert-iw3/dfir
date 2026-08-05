"""S3/S4 — an automated pass may not quietly discard a human determination.

Adds ownership of a verdict (`adjudicated_by`), the pass that produced it
(`adjudication_run`), and the engine's disagreement where an analyst already ruled
(`adjudication_conflict`).

**The backfill is the point of this migration, not a courtesy.** Shipping the fields with
everything defaulted to "" would leave every verdict an analyst has already set looking
unowned, and the first engine pass afterwards would overwrite precisely the determinations
S4 exists to protect — the defect, deferred by one deploy rather than closed.

Ownership is recovered from evidence already in the store:

  * `raw->'adjudication'` is the stamp `_apply_to_findings` writes, so its presence means
    the engine reached this verdict.
  * a `FindingReclassification` names an actor. Every row that exists when this runs was
    written by the analyst path — the engine wrote none until now — so any actor other than
    the engine's own is a human, and a human's verdict wins over an engine stamp underneath
    it. Hence the analyst pass runs second and is not conditional.

`adjudication_run` stays null for existing rows: the stamp records what the engine
concluded but not which pass concluded it, and inventing an attribution would be worse than
admitting the record starts here.
"""

import django.db.models.deletion
from django.db import migrations, models

BACKFILL = """
UPDATE cases_finding SET adjudicated_by = 'engine'
 WHERE adjudicated_by = '' AND jsonb_exists(raw, 'adjudication');

UPDATE cases_finding SET adjudicated_by = 'analyst'
 WHERE id IN (SELECT DISTINCT finding_id FROM cases_findingreclassification
               WHERE actor <> 'investigation-engine');
"""


class Migration(migrations.Migration):

    dependencies = [
        ("cases", "0011_process_verdict_supersede"),
    ]

    operations = [
        migrations.AddField(
            model_name="finding",
            name="adjudicated_by",
            field=models.CharField(blank=True, default="", max_length=16),
        ),
        migrations.AddField(
            model_name="finding",
            name="adjudication_run",
            field=models.ForeignKey(
                blank=True, null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="adjudicated_findings",
                to="cases.memoryanalysisrun",
            ),
        ),
        migrations.AddField(
            model_name="finding",
            name="adjudication_conflict",
            field=models.JSONField(blank=True, default=dict),
        ),
        # Reverse is a no-op: dropping the columns discards the ownership anyway, and
        # re-deriving it is exactly what the forward step does.
        migrations.RunSQL(BACKFILL, migrations.RunSQL.noop),
    ]
