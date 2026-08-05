import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("correlation", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="BehaviorNode",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("kind", models.CharField(choices=[("host", "host"), ("account", "account"), ("indicator", "indicator"), ("technique", "technique"), ("artifact", "artifact")], db_index=True, max_length=16)),
                ("subkind", models.CharField(blank=True, db_index=True, max_length=32)),
                ("value", models.CharField(db_index=True, max_length=1024)),
                ("host_count", models.IntegerField(default=0)),
                ("hostnames", models.JSONField(blank=True, default=list)),
                ("run", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="behavior_nodes", to="correlation.correlationrun")),
            ],
            options={"ordering": ["kind", "subkind", "value"]},
        ),
        migrations.CreateModel(
            name="BehaviorEvent",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("hostname", models.CharField(db_index=True, max_length=255)),
                ("event", models.CharField(choices=[("dropped", "dropped"), ("beaconed", "beaconed"), ("persisted", "persisted"), ("staged", "staged"), ("moved", "moved"), ("authenticated", "authenticated"), ("executed", "executed"), ("observed", "observed")], db_index=True, max_length=16)),
                ("observed_at", models.DateTimeField(blank=True, null=True)),
                ("verdict", models.CharField(blank=True, max_length=32)),
                ("confidence", models.CharField(blank=True, max_length=16)),
                ("source_finding_id", models.IntegerField(blank=True, null=True)),
                ("detail", models.JSONField(blank=True, default=dict)),
                ("node", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="events", to="correlation.behaviornode")),
                ("run", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="behavior_events", to="correlation.correlationrun")),
            ],
            options={"ordering": ["observed_at", "id"]},
        ),
        migrations.AddIndex(
            model_name="behaviornode",
            index=models.Index(fields=["run", "kind", "subkind"], name="corr_bnode_run_kind_idx"),
        ),
        migrations.AddConstraint(
            model_name="behaviornode",
            constraint=models.UniqueConstraint(fields=["run", "kind", "subkind", "value"], name="uniq_behavior_node"),
        ),
        migrations.AddIndex(
            model_name="behaviorevent",
            index=models.Index(fields=["run", "hostname"], name="corr_bevent_run_host_idx"),
        ),
    ]
