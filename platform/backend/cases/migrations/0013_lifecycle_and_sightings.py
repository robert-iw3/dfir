from django.db import migrations, models

# Free-text status became a controlled vocabulary. Anything already stored that is not one of
# the four states is mapped rather than dropped: `closed`/`complete`/`done` were the words in
# use and all mean concluded, and `concluded_at` is seeded from the row's own last-write time
# because that is the closest defensible answer available — an invented timestamp would be
# worse than an approximate one, and a null would make every legacy case look stalled forever.
NORMALIZE = """
UPDATE cases_investigation SET status = 'concluded'
 WHERE lower(status) IN ('closed', 'complete', 'completed', 'done', 'resolved');
UPDATE cases_investigation SET status = 'contained'
 WHERE lower(status) IN ('containment', 'contained', 'mitigated');
UPDATE cases_investigation SET status = 'open'
 WHERE status NOT IN ('open', 'contained', 'concluded', 'archived');
UPDATE cases_investigation SET concluded_at = updated_at
 WHERE status = 'concluded' AND concluded_at IS NULL;
"""


class Migration(migrations.Migration):

    dependencies = [
        ("cases", "0012_finding_adjudication_precedence"),
    ]

    operations = [
        migrations.AddField(
            model_name="investigation",
            name="concluded_at",
            field=models.DateTimeField(blank=True, db_index=True, null=True),
        ),
        migrations.AlterField(
            model_name="investigation",
            name="status",
            field=models.CharField(
                choices=[("open", "open"), ("contained", "contained"),
                         ("concluded", "concluded"), ("archived", "archived")],
                db_index=True, default="open", max_length=32),
        ),
        migrations.RunSQL(NORMALIZE, migrations.RunSQL.noop),
        migrations.CreateModel(
            name="IndicatorSighting",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True,
                                           serialize=False, verbose_name="ID")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("ioc_type", models.CharField(db_index=True, max_length=64)),
                ("value", models.CharField(db_index=True, max_length=1024)),
                ("investigation_id", models.IntegerField(db_index=True)),
                ("incident_id", models.CharField(blank=True, db_index=True, max_length=128)),
                ("host_id", models.IntegerField(db_index=True)),
                ("hostname", models.CharField(db_index=True, max_length=255)),
                ("first_seen", models.DateTimeField(blank=True, null=True)),
                ("last_seen", models.DateTimeField(blank=True, null=True)),
                ("sighting_count", models.IntegerField(default=1)),
                ("context", models.JSONField(blank=True, default=dict)),
            ],
            options={"ordering": ["ioc_type", "value", "hostname"]},
        ),
        migrations.AddIndex(
            model_name="indicatorsighting",
            index=models.Index(fields=["ioc_type", "value"],
                               name="cases_indic_ioc_typ_pivot_idx"),
        ),
        migrations.AddIndex(
            model_name="indicatorsighting",
            index=models.Index(fields=["investigation_id", "ioc_type"],
                               name="cases_indic_inv_type_idx"),
        ),
        migrations.AddConstraint(
            model_name="indicatorsighting",
            constraint=models.UniqueConstraint(
                fields=("ioc_type", "value", "host_id", "investigation_id"),
                name="uniq_indicator_sighting"),
        ),
    ]
