"""
Historise host identity so a rename stops erasing the name evidence was collected under.

`Host` keeps the current value; this keeps what it was, when the change was observed, and
which collection observed it. No data step: existing renames are already lost and cannot be
reconstructed — the table starts empty and records from here.
"""
import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("cases", "0009_schema_integrity"),
    ]

    operations = [
        migrations.CreateModel(
            name="HostIdentityChange",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("field", models.CharField(choices=[("hostname", "hostname"), ("machine_id", "machine_id"), ("platform", "platform")], db_index=True, max_length=32)),
                ("from_value", models.CharField(blank=True, max_length=255)),
                ("to_value", models.CharField(max_length=255)),
                ("observed_at", models.DateTimeField(blank=True, null=True)),
                ("source_stamp", models.CharField(blank=True, max_length=255)),
                ("actor", models.CharField(default="ingest", max_length=128)),
                ("host", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="identity_changes", to="cases.host")),
            ],
            options={"ordering": ["-created_at"]},
        ),
        migrations.AddIndex(
            model_name="hostidentitychange",
            index=models.Index(fields=["host", "field"], name="cases_hostidc_host_field_idx"),
        ),
    ]
