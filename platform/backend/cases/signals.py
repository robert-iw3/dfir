"""
Cross-database cleanup that no foreign key can perform.

`correlation` is a separate database holding `investigation_id` as a plain integer, so
deleting an investigation cascades nothing: its campaigns survive, keep `is_current=True`,
and PostgreSQL reuses the id — the next investigation created then inherits another
incident's hosts, and the UI presents them as its own.

A signal rather than a call in the delete view, because deletion happens through more than
one path (the API, `seed_campaign --reset`, the Django admin, a shell, any queryset delete)
and only the view was ever wired. Django sends post_delete per instance for queryset
deletes as well, so this covers all of them.
"""
from django.db.models.signals import post_delete
from django.dispatch import receiver

from .models import Investigation


@receiver(post_delete, sender=Investigation, dispatch_uid="cases.drop_correlation")
def drop_correlation(sender, instance, **kwargs):
    """Discard derived correlation for an investigation that no longer exists.

    Correlation is derived and rebuildable, so this costs nothing that a recompute cannot
    restore — and leaving it in place costs correctness.
    """
    from correlation.models import (
        Campaign, CampaignEdge, CampaignHost, CorrelationRun, SharedIndicator,
    )

    runs = list(CorrelationRun.objects.filter(investigation_id=instance.id)
                .values_list("id", flat=True))
    if not runs:
        return
    campaigns = list(Campaign.objects.filter(run_id__in=runs).values_list("id", flat=True))
    CampaignEdge.objects.filter(campaign_id__in=campaigns).delete()
    CampaignHost.objects.filter(campaign_id__in=campaigns).delete()
    SharedIndicator.objects.filter(run_id__in=runs).delete()
    Campaign.objects.filter(id__in=campaigns).delete()
    # BehaviorNode/BehaviorEvent cascade from CorrelationRun within the same database.
    CorrelationRun.objects.filter(id__in=runs).delete()
