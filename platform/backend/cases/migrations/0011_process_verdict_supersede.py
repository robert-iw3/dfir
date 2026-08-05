"""S5 — a re-analysis supersedes the previous per-PID adjudication rather than deleting it.

Forward-only and safe on a populated table: every existing row is the current pass by
definition (there was no history before this), so the default of True is correct for them
and no data step is needed.

Also renames the index the S2 migration created under an explicit name to the one Django's
autodetector derives, so `makemigrations` stops proposing the rename on every run — a
migration the tree keeps regenerating is drift nobody reads.
"""

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("cases", "0010_host_identity_change"),
    ]

    operations = [
        migrations.RenameIndex(
            model_name="hostidentitychange",
            new_name="cases_hosti_host_id_91aaae_idx",
            old_name="cases_hostidc_host_field_idx",
        ),
        migrations.AddField(
            model_name="processverdict",
            name="is_current",
            field=models.BooleanField(default=True, db_index=True),
        ),
        migrations.AddField(
            model_name="processverdict",
            name="superseded_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="processverdict",
            name="superseded_by",
            field=models.ForeignKey(
                blank=True, null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="superseded_process_verdicts",
                to="cases.memoryanalysisrun",
            ),
        ),
        migrations.AddIndex(
            model_name="processverdict",
            index=models.Index(fields=["run", "is_current"],
                               name="cases_proce_run_id_5c9a54_idx"),
        ),
    ]
