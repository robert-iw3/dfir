"""
Make two documented invariants enforceable by the database, and index what is queried.

Both invariants were previously honored only by application code that reads before it
writes — a race that duplicates a host or a run under concurrent arrivals, which for an
evidence store means one machine's history split in two, or one collection counted twice.

The data step runs first and is deliberately NON-DESTRUCTIVE. Adding a UNIQUE constraint to
a populated table fails if duplicates exist, and the tempting fix — delete the extras — is
not available here: these rows are evidence. Duplicate hosts are IDENTITY records and merge
(runs repoint to the survivor, the empty duplicate goes). Duplicate runs are EVIDENCE and are
disambiguated by suffixing the stamp, so both remain and the collision is visible.

Idempotent: re-running finds no duplicates and changes nothing.
"""
from django.contrib.postgres.indexes import GinIndex
from django.db import migrations, models


def merge_duplicate_hosts(apps, schema_editor):
    """Collapse hosts sharing a machine-id onto the earliest row.

    A duplicate here means the race already fired: the same machine was recorded twice and
    its evidence was split. Merging is the repair, and it is safe because a Host carries no
    evidence of its own — it is an identity that runs point at.
    """
    Host = apps.get_model("cases", "Host")
    CollectionRun = apps.get_model("cases", "CollectionRun")
    seen = {}
    for host in Host.objects.exclude(machine_id="").order_by("id"):
        survivor = seen.get(host.machine_id)
        if survivor is None:
            seen[host.machine_id] = host
            continue
        CollectionRun.objects.filter(host=host).update(host=survivor)
        # Keep whichever name was recorded most recently for the machine.
        if host.hostname and host.hostname != survivor.hostname:
            survivor.hostname = host.hostname
            survivor.save(update_fields=["hostname"])
        host.delete()


def disambiguate_duplicate_runs(apps, schema_editor):
    """Suffix the stamp of colliding runs so both survive the constraint.

    A run holds findings, captures and custody events. Deleting one to satisfy a constraint
    would destroy evidence to make a schema change convenient, which is never the trade to
    make; the collision is recorded in the stamp instead, where an analyst can see it.
    """
    CollectionRun = apps.get_model("cases", "CollectionRun")
    seen = set()
    for run in CollectionRun.objects.order_by("id"):
        key = (run.investigation_id, run.host_id, run.stamp)
        if key not in seen:
            seen.add(key)
            continue
        suffix = 2
        while (run.investigation_id, run.host_id, f"{run.stamp}+dup{suffix}") in seen:
            suffix += 1
        run.stamp = f"{run.stamp}+dup{suffix}"[:255]
        run.save(update_fields=["stamp"])
        seen.add((run.investigation_id, run.host_id, run.stamp))


class Migration(migrations.Migration):

    dependencies = [
        ("cases", "0008_remediation_action"),
    ]

    operations = [
        migrations.RunPython(merge_duplicate_hosts, migrations.RunPython.noop),
        migrations.RunPython(disambiguate_duplicate_runs, migrations.RunPython.noop),
        migrations.AddConstraint(
            model_name="host",
            constraint=models.UniqueConstraint(
                fields=["machine_id"],
                condition=models.Q(machine_id__gt=""),
                name="uniq_host_machine_id",
            ),
        ),
        migrations.AddConstraint(
            model_name="collectionrun",
            constraint=models.UniqueConstraint(
                fields=["investigation", "host", "stamp"],
                name="uniq_run_investigation_host_stamp",
            ),
        ),
        migrations.AddIndex(
            model_name="finding",
            index=GinIndex(fields=["mitre"], name="finding_mitre_gin"),
        ),
        migrations.AddIndex(
            model_name="finding",
            index=models.Index(fields=["source"], name="finding_source_idx"),
        ),
    ]
