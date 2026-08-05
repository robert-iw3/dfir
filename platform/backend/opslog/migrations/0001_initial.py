from django.db import migrations, models


class Migration(migrations.Migration):
    """The operational log store. Its own database — see opslog/models.py for why."""

    initial = True
    dependencies = []

    operations = [
        migrations.CreateModel(
            name="RequestLog",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True,
                                           serialize=False, verbose_name="ID")),
                ("request_id", models.CharField(db_index=True, max_length=36)),
                ("at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("method", models.CharField(max_length=8)),
                ("path", models.CharField(db_index=True, max_length=512)),
                ("query", models.CharField(blank=True, max_length=1024)),
                ("status", models.IntegerField(db_index=True)),
                ("duration_ms", models.IntegerField(default=0)),
                ("username", models.CharField(blank=True, db_index=True, max_length=150)),
                ("role", models.CharField(blank=True, max_length=32)),
                ("source", models.CharField(blank=True, max_length=32)),
                ("user_agent", models.CharField(blank=True, max_length=256)),
                ("error_type", models.CharField(blank=True, max_length=128)),
                ("error_detail", models.TextField(blank=True)),
                ("response_bytes", models.IntegerField(default=0)),
            ],
            options={"ordering": ["-at"]},
        ),
        migrations.AddIndex(
            model_name="requestlog",
            index=models.Index(fields=["-at", "status"], name="opslog_at_status_idx"),
        ),
        migrations.AddIndex(
            model_name="requestlog",
            index=models.Index(fields=["username", "-at"], name="opslog_user_at_idx"),
        ),
        migrations.CreateModel(
            name="ClientError",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True,
                                           serialize=False, verbose_name="ID")),
                ("at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("request_id", models.CharField(blank=True, db_index=True, max_length=36)),
                ("username", models.CharField(blank=True, db_index=True, max_length=150)),
                ("where", models.CharField(blank=True, max_length=256)),
                ("url", models.CharField(blank=True, max_length=1024)),
                ("message", models.TextField(blank=True)),
                ("stack", models.TextField(blank=True)),
                ("component_stack", models.TextField(blank=True)),
                ("user_agent", models.CharField(blank=True, max_length=256)),
            ],
            options={"ordering": ["-at"]},
        ),
    ]
