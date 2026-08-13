"""
Case tree, curated tags and the task board.

The tree is a view over what already exists — investigation, host, run, capture, carved
region are a hierarchy the API previously only rendered as flat lists. Nothing is stored
for it.

Tags come from an admin-managed vocabulary rather than free text, so "malware" is one tag
rather than three spellings of one idea. Tasks move through the states an engagement
actually has, and every move is audited.
"""
import hashlib
import os

from django.db.models import Count
from django.http import HttpResponse
from django.utils import timezone
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.response import Response
from rest_framework.views import APIView

from . import audit, collab, storage
from .models import (CarvedRegion, CaseTag, CaseTagAssignment, CaseTask,
                     CaseTaskAttachment, CaseTaskNote, CollectionRun, Finding,
                     Investigation, MemoryCapture, Note)
from .rbac import (IsAnalystOrAdmin, may_see_investigation, role_of,
                   scope_investigations)


class CaseTreeView(APIView):
    """Investigation → host → run → capture → region, counted at each level.

    One request rather than a walk of four endpoints: the tree is the shape an analyst
    navigates, and issuing a request per node makes it feel like the platform is thinking.
    """

    def get(self, request, investigation_id):
        inv = Investigation.objects.filter(id=investigation_id).first()
        if not inv or not may_see_investigation(request.user, inv):
            return Response({"detail": "not found"}, status=404)

        runs = (CollectionRun.objects.filter(investigation=inv)
                .select_related("host")
                .annotate(finding_count=Count("findings", distinct=True))
                .order_by("host__hostname", "-collected_at"))
        caps = {}
        for cap in (MemoryCapture.objects.filter(run__investigation=inv)
                    .annotate(analysis_count=Count("analyses", distinct=True))):
            caps.setdefault(cap.run_id, []).append(cap)
        regions = {}
        for reg in CarvedRegion.objects.filter(
                analysis__capture__run__investigation=inv).values(
                "analysis__capture_id").annotate(n=Count("id")):
            regions[reg["analysis__capture_id"]] = reg["n"]

        hosts = {}
        for run in runs:
            node = hosts.setdefault(run.host_id, {
                "type": "host", "id": run.host_id, "label": run.host.hostname,
                "platform": run.host.platform, "children": []})
            node["children"].append({
                "type": "run", "id": run.id,
                "label": run.stamp or f"run {run.id}",
                "status": run.overall_status, "compromised": run.compromised,
                "finding_count": run.finding_count,
                "collected_at": (run.collected_at.isoformat()
                                 if run.collected_at else None),
                "children": [{
                    "type": "capture", "id": cap.id,
                    "label": cap.object_key.rsplit("/", 1)[-1] or f"capture {cap.id}",
                    "size_bytes": cap.size_bytes,
                    "retention_status": cap.retention_status,
                    "analysis_count": cap.analysis_count,
                    "region_count": regions.get(cap.id, 0),
                } for cap in caps.get(run.id, [])],
            })
        return Response({
            "type": "investigation", "id": inv.id, "label": inv.name,
            "incident_id": inv.incident_id, "status": inv.status,
            "compartment": inv.compartment,
            "children": list(hosts.values()),
        })


class CaseTagView(APIView):
    """The vocabulary. Admins curate it; anyone who can see cases may read it."""

    def get(self, request):
        rows = (CaseTag.objects.filter(retired=False)
                .annotate(uses=Count("assignments")))
        return Response({"tags": [
            {"id": t.id, "label": t.label, "category": t.category,
             "description": t.description, "uses": t.uses} for t in rows]})

    def post(self, request):
        if role_of(request.user) != "admin":
            return Response({"detail": "the tag vocabulary is admin-managed"}, status=403)
        label = (request.data.get("label") or "").strip()
        if not label:
            return Response({"detail": "label is required"}, status=400)
        tag, created = CaseTag.objects.get_or_create(
            label=label,
            defaults={"category": (request.data.get("category") or "").strip(),
                      "description": (request.data.get("description") or "").strip()})
        if not created and request.data.get("retire"):
            tag.retired = True
            tag.save(update_fields=["retired", "updated_at"])
        actor = getattr(request.user, "username", "") or "admin"
        audit.audit(actor, "tag.create" if created else "tag.update",
                    object_type="tag", object_id=str(tag.id),
                    detail={"label": tag.label, "retired": tag.retired})
        return Response({"id": tag.id, "label": tag.label, "retired": tag.retired},
                        status=201 if created else 200)


class CaseTagAssignView(APIView):
    """Apply or remove a curated tag on one case."""

    permission_classes = [IsAnalystOrAdmin]

    def get(self, request, investigation_id):
        inv = Investigation.objects.filter(id=investigation_id).first()
        if not inv or not may_see_investigation(request.user, inv):
            return Response({"detail": "not found"}, status=404)
        return Response({"tags": [
            {"id": link.tag_id, "label": link.tag.label,
             "category": link.tag.category, "applied_by": link.applied_by}
            for link in inv.tag_links.select_related("tag")]})

    def post(self, request, investigation_id):
        inv = Investigation.objects.filter(id=investigation_id).first()
        if not inv or not may_see_investigation(request.user, inv):
            return Response({"detail": "not found"}, status=404)
        tag = CaseTag.objects.filter(id=request.data.get("tag"), retired=False).first()
        if not tag:
            return Response({"detail": "unknown or retired tag — the vocabulary is "
                                       "curated, so a new label is an admin action"},
                            status=400)
        actor = getattr(request.user, "username", "") or ""
        if request.data.get("remove"):
            CaseTagAssignment.objects.filter(investigation=inv, tag=tag).delete()
            action = "tag.unapply"
        else:
            CaseTagAssignment.objects.get_or_create(
                investigation=inv, tag=tag, defaults={"applied_by": actor})
            action = "tag.apply"
        audit.audit(actor, action, object_type="investigation", object_id=str(inv.id),
                    detail={"tag": tag.label})
        return Response({"tags": [
            {"id": link.tag_id, "label": link.tag.label}
            for link in inv.tag_links.select_related("tag")]})


def _task_row(t, counts=None):
    counts = counts or {}
    return {"id": t.id, "title": t.title, "state": t.state, "assignee": t.assignee,
            "artifact_type": t.artifact_type, "artifact_id": t.artifact_id,
            "detail": t.detail, "created_by": t.created_by,
            "blocked": t.blocked, "blocked_reason": t.blocked_reason,
            "due_at": t.due_at.isoformat() if t.due_at else None,
            "created_at": t.created_at.isoformat(),
            "closed_at": t.closed_at.isoformat() if t.closed_at else None,
            "note_count": counts.get("notes", 0),
            "attachment_count": counts.get("attachments", 0)}


class CaseTaskView(APIView):
    """The board for one case: columns in state order, with their tasks."""

    permission_classes = [IsAnalystOrAdmin]

    def get(self, request, investigation_id):
        inv = Investigation.objects.filter(id=investigation_id).first()
        if not inv or not may_see_investigation(request.user, inv):
            return Response({"detail": "not found"}, status=404)
        tasks = list(CaseTask.objects.filter(investigation=inv)
                     .annotate(n_notes=Count("notes", distinct=True),
                               n_att=Count("attachments", distinct=True)))
        rows = {t.id: _task_row(t, {"notes": t.n_notes, "attachments": t.n_att})
                for t in tasks}
        return Response({
            "investigation": inv.id,
            "columns": [{"state": key, "label": label,
                         "intent": CaseTask.STATE_INTENT[key],
                         "tasks": [rows[t.id] for t in tasks if t.state == key]}
                        for key, label in CaseTask.STATES],
        })

    def post(self, request, investigation_id):
        inv = Investigation.objects.filter(id=investigation_id).first()
        if not inv or not may_see_investigation(request.user, inv):
            return Response({"detail": "not found"}, status=404)
        actor = getattr(request.user, "username", "") or ""
        task_id = request.data.get("id")
        states = dict(CaseTask.STATES)

        if task_id:
            task = CaseTask.objects.filter(id=task_id, investigation=inv).first()
            if not task:
                return Response({"detail": "no such task on this case"}, status=404)
            before = task.state
            target = request.data.get("state")
            if target and target not in states:
                return Response({"detail": f"state must be one of {list(states)}"},
                                status=400)
            if target:
                task.state = target
                task.closed_at = (timezone.now() if target == CaseTask.PRESENTATION
                                  else None)
            if "assignee" in request.data:
                was = task.assignee
                task.assignee = (request.data.get("assignee") or "").strip()
                if task.assignee and task.assignee != was:
                    collab.notify_assignment(task.assignee, actor, task)
            if "detail" in request.data:
                task.detail = request.data.get("detail") or ""
            if "blocked" in request.data:
                task.blocked = bool(request.data.get("blocked"))
                task.blocked_reason = (request.data.get("blocked_reason") or "").strip()
            if "title" in request.data:
                task.title = (request.data.get("title") or task.title).strip()
            task.save()
            audit.audit(actor, "task.update", object_type="task", object_id=str(task.id),
                        detail={"investigation": inv.id, "from": before,
                                "to": task.state, "assignee": task.assignee})
            return Response(_task_row(task))

        title = (request.data.get("title") or "").strip()
        if not title:
            return Response({"detail": "title is required"}, status=400)
        state = request.data.get("state") or CaseTask.IDENTIFICATION
        if state not in states:
            return Response({"detail": f"state must be one of {list(states)}"},
                            status=400)
        task = CaseTask.objects.create(
            investigation=inv, title=title, state=state,
            assignee=(request.data.get("assignee") or "").strip(),
            artifact_type=(request.data.get("artifact_type") or "").strip(),
            artifact_id=request.data.get("artifact_id") or None,
            detail=request.data.get("detail") or "", created_by=actor)
        if task.assignee:
            collab.notify_assignment(task.assignee, actor, task)
        audit.audit(actor, "task.create", object_type="task", object_id=str(task.id),
                    detail={"investigation": inv.id, "title": title, "state": state})
        return Response(_task_row(task), status=201)


class TaskBoardView(APIView):
    """Every open task the caller may see, for the handover view. Scoped like cases."""

    permission_classes = [IsAnalystOrAdmin]

    def get(self, request):
        visible = scope_investigations(Investigation.objects.all(), request.user)
        qs = (CaseTask.objects.filter(investigation__in=visible)
              .exclude(state=CaseTask.PRESENTATION)
              .select_related("investigation"))
        if request.query_params.get("assignee"):
            qs = qs.filter(assignee=request.query_params["assignee"])
        return Response({"tasks": [
            dict(_task_row(t), investigation=t.investigation_id,
                 investigation_name=t.investigation.name) for t in qs]})


# --- Task detail: notes and attachments ---------------------------------------------
# Uploaded bytes are kept apart from evidence: an analyst's memo is not a capture, and
# giving it its own bucket keeps evidence retention from applying to working documents.
ATTACHMENT_BUCKET = os.environ.get("IR_CASE_DOC_BUCKET", "ir-case-docs")
MAX_ATTACHMENT_BYTES = int(os.environ.get("IR_MAX_ATTACHMENT_BYTES", str(32 * 1024 * 1024)))

# What an evidence reference may point at, and how to resolve its label. Anything not
# named here is refused, so a reference cannot address an arbitrary table.
REF_RESOLVERS = {
    "host": lambda i: CollectionRun.objects.filter(host_id=i).first(),
    "run": lambda i: CollectionRun.objects.filter(id=i).first(),
    "finding": lambda i: Finding.objects.filter(id=i).first(),
    "capture": lambda i: MemoryCapture.objects.filter(id=i).first(),
    "region": lambda i: CarvedRegion.objects.filter(id=i).first(),
    "note": lambda i: Note.objects.filter(id=i).first(),
}


def _attachment_row(a):
    return {"id": a.id, "kind": a.kind, "label": a.label, "added_by": a.added_by,
            "filename": a.filename, "size_bytes": a.size_bytes,
            "sha256": a.sha256, "content_type": a.content_type,
            "ref_type": a.ref_type, "ref_id": a.ref_id,
            "created_at": a.created_at.isoformat()}


def _task_or_404(request, task_id):
    task = (CaseTask.objects.filter(id=task_id)
            .select_related("investigation").first())
    if not task or not may_see_investigation(request.user, task.investigation):
        return None
    return task


class CaseTaskDetailView(APIView):
    """One task with its working notes and everything attached to it."""

    permission_classes = [IsAnalystOrAdmin]

    def get(self, request, task_id):
        task = _task_or_404(request, task_id)
        if not task:
            return Response({"detail": "not found"}, status=404)
        notes = [{"id": n.id, "author": n.author, "body": n.body,
                  "created_at": n.created_at.isoformat()} for n in task.notes.all()]
        atts = [_attachment_row(a) for a in task.attachments.all()]
        return Response(dict(_task_row(task, {"notes": len(notes),
                                              "attachments": len(atts)}),
                             investigation=task.investigation_id,
                             investigation_name=task.investigation.name,
                             notes=notes, attachments=atts,
                             states=[{"state": k, "label": label,
                                      "intent": CaseTask.STATE_INTENT[k]}
                                     for k, label in CaseTask.STATES]))


class CaseTaskNoteView(APIView):
    """Working notes on a task. Append-only: a note is a record of what was thought at
    the time, and editing one would rewrite that."""

    permission_classes = [IsAnalystOrAdmin]

    def post(self, request, task_id):
        task = _task_or_404(request, task_id)
        if not task:
            return Response({"detail": "not found"}, status=404)
        body = (request.data.get("body") or "").strip()
        if not body:
            return Response({"detail": "body is required"}, status=400)
        actor = getattr(request.user, "username", "") or ""
        note = CaseTaskNote.objects.create(task=task, author=actor, body=body)
        mentioned = collab.notify_mentions(body, actor, task.investigation,
                                           ref_type="task", ref_id=task.id)
        audit.audit(actor, "task.note", object_type="task", object_id=str(task.id),
                    detail={"investigation": task.investigation_id,
                            "note": note.id, "chars": len(body),
                            "mentioned": mentioned})
        return Response({"id": note.id, "author": note.author, "body": note.body,
                         "mentioned": mentioned,
                         "created_at": note.created_at.isoformat()}, status=201)


class CaseTaskAttachmentView(APIView):
    """Attach a document (multipart) or a reference to evidence the platform holds."""

    permission_classes = [IsAnalystOrAdmin]
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def post(self, request, task_id):
        task = _task_or_404(request, task_id)
        if not task:
            return Response({"detail": "not found"}, status=404)
        actor = getattr(request.user, "username", "") or ""

        upload = request.FILES.get("file")
        if upload is None:
            ref_type = (request.data.get("ref_type") or "").strip()
            if ref_type not in REF_RESOLVERS:
                return Response({"detail": f"ref_type must be one of "
                                           f"{sorted(REF_RESOLVERS)}"}, status=400)
            try:
                ref_id = int(request.data.get("ref_id"))
            except (TypeError, ValueError):
                return Response({"detail": "ref_id must be an integer"}, status=400)
            if REF_RESOLVERS[ref_type](ref_id) is None:
                return Response({"detail": f"no {ref_type} {ref_id} on this platform"},
                                status=404)
            att = CaseTaskAttachment.objects.create(
                task=task, kind=CaseTaskAttachment.EVIDENCE, ref_type=ref_type,
                ref_id=ref_id, added_by=actor,
                label=(request.data.get("label") or f"{ref_type} {ref_id}").strip())
            audit.audit(actor, "task.attach", object_type="task", object_id=str(task.id),
                        detail={"kind": "evidence", "ref_type": ref_type,
                                "ref_id": ref_id})
            return Response(_attachment_row(att), status=201)

        if upload.size > MAX_ATTACHMENT_BYTES:
            return Response({"detail": f"attachment exceeds "
                                       f"{MAX_ATTACHMENT_BYTES} bytes"}, status=413)
        digest = hashlib.sha256()
        for chunk in upload.chunks():
            digest.update(chunk)
        sha = digest.hexdigest()
        upload.seek(0)
        key = f"cases/{task.investigation_id}/tasks/{task.id}/{sha[:16]}"
        storage.ensure_bucket_named(ATTACHMENT_BUCKET)
        storage.put_fileobj_to(ATTACHMENT_BUCKET, upload, key)
        att = CaseTaskAttachment.objects.create(
            task=task, kind=CaseTaskAttachment.DOCUMENT, added_by=actor,
            label=(request.data.get("label") or upload.name).strip(),
            filename=upload.name[:255], object_key=key,
            content_type=(upload.content_type or "")[:128],
            size_bytes=upload.size, sha256=sha)
        audit.audit(actor, "task.attach", object_type="task", object_id=str(task.id),
                    detail={"kind": "document", "filename": upload.name,
                            "sha256": sha, "bytes": upload.size})
        return Response(_attachment_row(att), status=201)

    def delete(self, request, task_id):
        task = _task_or_404(request, task_id)
        if not task:
            return Response({"detail": "not found"}, status=404)
        att = CaseTaskAttachment.objects.filter(
            id=request.query_params.get("id"), task=task).first()
        if not att:
            return Response({"detail": "no such attachment"}, status=404)
        actor = getattr(request.user, "username", "") or ""
        # The object is left in the bucket: its sha256 was audited when it arrived, and
        # deleting the bytes on a detach would erase what a reviewer may need to see.
        audit.audit(actor, "task.detach", object_type="task", object_id=str(task.id),
                    detail={"attachment": att.id, "kind": att.kind,
                            "sha256": att.sha256})
        att.delete()
        return Response(status=204)


class CaseTaskAttachmentDownloadView(APIView):
    """Serve an attached document back.

    Always as an ATTACHMENT with an opaque content type: an uploaded document rendered
    inline by the browser is stored cross-site scripting, and this platform renders
    hostile material by definition.
    """

    permission_classes = [IsAnalystOrAdmin]

    def get(self, request, task_id, attachment_id):
        task = _task_or_404(request, task_id)
        if not task:
            return Response({"detail": "not found"}, status=404)
        att = CaseTaskAttachment.objects.filter(
            id=attachment_id, task=task, kind=CaseTaskAttachment.DOCUMENT).first()
        if not att:
            return Response({"detail": "no such document"}, status=404)
        try:
            body = storage.get_object_bytes(ATTACHMENT_BUCKET, att.object_key)
        except Exception as exc:                       # noqa: BLE001
            return Response({"detail": f"object store: {exc}"}, status=502)
        actor = getattr(request.user, "username", "") or ""
        audit.audit(actor, "task.attachment.read", object_type="task",
                    object_id=str(task.id),
                    detail={"attachment": att.id, "filename": att.filename,
                            "sha256": att.sha256})
        resp = HttpResponse(body, content_type="application/octet-stream")
        safe = att.filename.replace('"', "").replace("\\", "")[:200] or "attachment"
        resp["Content-Disposition"] = f'attachment; filename="{safe}"'
        resp["X-Content-Type-Options"] = "nosniff"
        return resp


class HostOverviewView(APIView):
    """One endpoint's whole history — the "have we seen this box before?" answer.

    Deliberately CROSS-CASE: a host recurs across investigations and the point of the page
    is that recurrence. Cases the caller may not see are counted but not named, so the
    existence of a compartmented case is not disclosed through a host it touched.
    """

    def get(self, request, host_id):
        from .models import Finding, Host, HostIdentityChange
        from .rbac import visible_investigation_ids

        host = Host.objects.filter(id=host_id).first()
        if not host:
            return Response({"detail": "not found"}, status=404)

        visible = visible_investigation_ids(request.user)
        runs = (CollectionRun.objects.filter(host=host)
                .select_related("investigation")
                .annotate(finding_count=Count("findings", distinct=True))
                .order_by("-collected_at", "-id"))
        rows, hidden = [], 0
        for r in runs:
            inv = r.investigation
            if (visible is not None and inv
                    and inv.compartment == Investigation.RESTRICTED
                    and inv.id not in visible):
                hidden += 1
                continue
            rows.append({
                "run_id": r.id, "stamp": r.stamp,
                "investigation": inv.id if inv else None,
                "investigation_name": inv.name if inv else None,
                "collected_at": r.collected_at.isoformat() if r.collected_at else None,
                "overall_status": r.overall_status, "compromised": r.compromised,
                "tp_count": r.tp_count, "finding_count": r.finding_count,
                "custody_verified": r.custody_verified,
                "run_kind": r.run_kind, "toolkit_version": r.toolkit_version,
            })
        run_ids = [x["run_id"] for x in rows]
        verdicts = dict(Finding.objects.filter(run_id__in=run_ids)
                        .values_list("verdict").annotate(n=Count("id"))
                        .values_list("verdict", "n"))
        caps = list(MemoryCapture.objects.filter(run_id__in=run_ids)
                    .annotate(analysis_count=Count("analyses", distinct=True)))
        regions = CarvedRegion.objects.filter(
            analysis__capture__run_id__in=run_ids).count()
        return Response({
            "id": host.id, "hostname": host.hostname, "platform": host.platform,
            "machine_id": host.machine_id, "clock_context": host.clock_context,
            "identity_changes": [
                {"from_value": c.from_value, "to_value": c.to_value,
                 "field": c.field, "observed_at": c.created_at.isoformat()}
                for c in HostIdentityChange.objects.filter(host=host)],
            "runs": rows,
            "runs_hidden_by_compartment": hidden,
            "investigations": len({x["investigation"] for x in rows
                                   if x["investigation"]}),
            "verdicts": verdicts,
            "captures": [{"id": c.id, "object_key": c.object_key,
                          "size_bytes": c.size_bytes,
                          "retention_status": c.retention_status,
                          "analysis_count": c.analysis_count} for c in caps],
            "carved_regions": regions,
        })
