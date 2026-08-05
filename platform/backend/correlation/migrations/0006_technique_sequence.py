"""The ordered technique sequence, stored rather than derived.

The order was computed and discarded, so the only ordered thing a reader could be shown was
the set sorted by technique id — which is not an order. Existing rows keep an empty sequence
and are recomputed by the next correlation run; the reader falls back to the set and does not
call it an order.
"""
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [("correlation", "0005_fingerprint_attribution")]

    operations = [
        migrations.AddField(
            model_name="campaignfingerprint",
            name="technique_sequence",
            field=models.JSONField(blank=True, default=list),
        ),
    ]
