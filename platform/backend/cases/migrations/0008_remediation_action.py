from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [("cases", "0007_component_health")]

    operations = [
        migrations.CreateModel(
            name="RemediationAction",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True,
                                           serialize=False, verbose_name="ID")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("action", models.CharField(max_length=64)),
                ("actor", models.CharField(db_index=True, max_length=128)),
                ("reason", models.TextField(blank=True, default="")),
                ("status", models.CharField(
                    choices=[("queued", "queued"), ("running", "running"),
                             ("succeeded", "succeeded"), ("failed", "failed"),
                             ("rejected", "rejected")],
                    default="queued", max_length=16)),
                ("output", models.TextField(blank=True, default="")),
                ("exit_code", models.IntegerField(blank=True, null=True)),
                ("claimed_at", models.DateTimeField(blank=True, null=True)),
                ("finished_at", models.DateTimeField(blank=True, null=True)),
                ("agent_host", models.CharField(blank=True, default="", max_length=128)),
            ],
            options={"ordering": ["-created_at"]},
        ),
    ]
