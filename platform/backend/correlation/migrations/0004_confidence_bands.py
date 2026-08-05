from django.db import migrations, models


class Migration(migrations.Migration):
    """L3 — membership confidence bands on CampaignHost.

    No backfill. Correlation is a derived store rewritten wholesale on recompute, so rows
    from an earlier run keep the `indeterminate` default rather than being handed a band
    computed by logic that did not exist when they were written. A band is a conclusion about
    a specific run's evidence; inventing one for a prior run would be exactly the supersession
    violation this store is built to avoid.
    """

    dependencies = [
        ("correlation", "0003_weighted_linkage"),
    ]

    operations = [
        migrations.AddField(
            model_name="campaignhost",
            name="confidence_band",
            field=models.CharField(
                choices=[("confirmed", "confirmed"), ("probable", "probable"),
                         ("possible", "possible"), ("indeterminate", "indeterminate")],
                db_index=True, default="indeterminate", max_length=16),
        ),
        migrations.AddField(
            model_name="campaignhost",
            name="confidence_factors",
            field=models.JSONField(blank=True, default=dict),
        ),
    ]
