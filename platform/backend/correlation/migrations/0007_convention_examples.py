"""The collected value each naming convention was abstracted from.

A shape stored on its own is unfalsifiable to a reader: `EF-<digits>-Q<digits>` cannot be told
apart from placeholder text unless the record also says it came from `EF-2026-Q3`, seen on 9
hosts. Provenance only — matching stays on the shape, so scoring is unchanged.

Existing rows carry no examples and are recomputed by the next correlation run; the reader
shows the shape alone until then.
"""
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [("correlation", "0006_technique_sequence")]

    operations = [
        migrations.AddField(
            model_name="campaignfingerprint",
            name="convention_examples",
            field=models.JSONField(blank=True, default=dict),
        ),
    ]
