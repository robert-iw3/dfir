import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    """L4 fingerprints and the L5 attribution/similarity records.

    `ActorProfile` is the one table here that is NOT scoped to a correlation run: it is a
    staged library, seeded offline like symbol tables, and it outlives the runs that read it.
    Everything else is derived and superseded on recompute.
    """

    dependencies = [
        ("correlation", "0004_confidence_bands"),
    ]

    operations = [
        migrations.CreateModel(
            name="ActorProfile",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True,
                                           serialize=False, verbose_name="ID")),
                ("key", models.CharField(max_length=64, unique=True)),
                ("name", models.CharField(db_index=True, max_length=255)),
                ("aliases", models.JSONField(blank=True, default=list)),
                ("techniques", models.JSONField(blank=True, default=list)),
                ("artifact_conventions", models.JSONField(blank=True, default=list)),
                ("c2_pattern", models.JSONField(blank=True, default=dict)),
                ("provenance", models.JSONField(blank=True, default=dict)),
            ],
            options={"ordering": ["name"]},
        ),
        migrations.CreateModel(
            name="CampaignFingerprint",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True,
                                           serialize=False, verbose_name="ID")),
                ("investigation_id", models.IntegerField(db_index=True)),
                ("techniques", models.JSONField(blank=True, default=list)),
                ("technique_ngrams", models.JSONField(blank=True, default=list)),
                ("artifact_conventions", models.JSONField(blank=True, default=list)),
                ("c2_pattern", models.JSONField(blank=True, default=dict)),
                ("account_chain", models.JSONField(blank=True, default=dict)),
                ("basis", models.JSONField(blank=True, default=dict)),
                ("campaign", models.OneToOneField(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="fingerprint", to="correlation.campaign")),
                ("run", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="fingerprints", to="correlation.correlationrun")),
            ],
            options={"ordering": ["-id"]},
        ),
        migrations.AddIndex(
            model_name="campaignfingerprint",
            index=models.Index(fields=["investigation_id"], name="corr_fp_inv_idx"),
        ),
        migrations.CreateModel(
            name="AttributionCandidate",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True,
                                           serialize=False, verbose_name="ID")),
                ("actor_key", models.CharField(db_index=True, max_length=64)),
                ("actor_name", models.CharField(max_length=255)),
                ("score", models.FloatField(default=0.0)),
                ("source", models.CharField(default="heuristic", max_length=16)),
                ("rationale", models.JSONField(blank=True, default=dict)),
                ("campaign", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="attributions", to="correlation.campaign")),
                ("run", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="attributions", to="correlation.correlationrun")),
            ],
            options={"ordering": ["-score"]},
        ),
        migrations.AddIndex(
            model_name="attributioncandidate",
            index=models.Index(fields=["campaign", "-score"], name="corr_attr_camp_score_idx"),
        ),
        migrations.CreateModel(
            name="CampaignSimilarity",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True,
                                           serialize=False, verbose_name="ID")),
                ("other_campaign_id", models.IntegerField(db_index=True)),
                ("other_investigation_id", models.IntegerField(db_index=True)),
                ("other_label", models.CharField(blank=True, max_length=255)),
                ("score", models.FloatField(default=0.0)),
                ("rationale", models.JSONField(blank=True, default=dict)),
                ("campaign", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="similar_to", to="correlation.campaign")),
                ("run", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="similarities", to="correlation.correlationrun")),
            ],
            options={"ordering": ["-score"]},
        ),
        migrations.AddIndex(
            model_name="campaignsimilarity",
            index=models.Index(fields=["campaign", "-score"], name="corr_sim_camp_score_idx"),
        ),
    ]
