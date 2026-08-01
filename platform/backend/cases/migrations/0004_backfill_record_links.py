"""Attach existing annotations to their investigation.

The link is now carried on the row rather than walked through foreign keys, so rows written
before that change have it empty and would be missing from the case record — the one place
the record is supposed to be complete. This derives it from the relationships that were
already there.
"""
from django.db import migrations


def link_to_investigations(apps, schema_editor):
    Note = apps.get_model("cases", "Note")
    Reclass = apps.get_model("cases", "FindingReclassification")
    RegionAnalysis = apps.get_model("cases", "RegionAnalysis")

    for note in Note.objects.filter(investigation__isnull=True).exclude(run__isnull=True):
        note.investigation_id = note.run.investigation_id
        note.host_id = note.host_id or note.run.host_id
        note.save(update_fields=["investigation", "host"])

    for r in Reclass.objects.filter(investigation__isnull=True).select_related("finding__run"):
        r.investigation_id = r.finding.run.investigation_id
        r.save(update_fields=["investigation"])

    for a in RegionAnalysis.objects.filter(
        investigation__isnull=True
    ).select_related("region__analysis__capture__run"):
        a.investigation_id = a.region.analysis.capture.run.investigation_id
        a.save(update_fields=["investigation"])


def unlink(apps, schema_editor):
    """Reversing drops the derived link; nothing else is lost."""
    for model in ("Note", "FindingReclassification", "RegionAnalysis"):
        apps.get_model("cases", model).objects.update(investigation=None)


class Migration(migrations.Migration):

    dependencies = [
        ("cases", "0003_findingreclassification_investigation_and_more"),
    ]

    operations = [
        migrations.RunPython(link_to_investigations, unlink),
    ]
