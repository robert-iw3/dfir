import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("correlation", "0002_behavior_graph"),
    ]

    operations = [
        migrations.AddField(
            model_name="campaign",
            name="cohesion_min",
            field=models.FloatField(default=0.0),
        ),
        migrations.AddField(
            model_name="campaign",
            name="cohesion_mean",
            field=models.FloatField(default=0.0),
        ),
        migrations.CreateModel(
            name="HostLink",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("host_a", models.CharField(db_index=True, max_length=255)),
                ("host_b", models.CharField(db_index=True, max_length=255)),
                ("weight", models.FloatField(default=0.0)),
                ("linked", models.BooleanField(db_index=True, default=False)),
                ("factors", models.JSONField(blank=True, default=dict)),
                ("run", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="host_links", to="correlation.correlationrun")),
            ],
            options={"ordering": ["-weight"]},
        ),
        migrations.AddIndex(
            model_name="hostlink",
            index=models.Index(fields=["run", "linked"], name="corr_hlink_run_linked_idx"),
        ),
        migrations.AddConstraint(
            model_name="hostlink",
            constraint=models.UniqueConstraint(fields=["run", "host_a", "host_b"], name="uniq_host_link"),
        ),
    ]
