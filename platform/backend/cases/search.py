"""Global search across cases, findings, notes and indicators.

The search box is the easiest place in a platform to bypass its own access control: it
touches every table at once, and a result row leaks the existence of a case even when the
case itself cannot be opened. So scoping is not applied to the output here — every query
is CONSTRAINED to the caller's visible investigations before it runs, and each source is
reached through the investigation it belongs to. A source that cannot be tied back to an
investigation is not searched.

Matching is case-insensitive substring rather than Postgres full-text. Analysts search for
fragments of identifiers — a partial hash, `svc_`, half a filename — and a stemmed
lexeme index does not match inside a token. Every query is bounded and indexed by the
investigation filter that precedes it.
"""
from django.db.models import Q
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import IOC, CaseTask, Finding, Investigation, Note
from .rbac import IsAnalystOrAdmin, scope_by_investigation

MAX_PER_KIND = 25


class GlobalSearchView(APIView):
    """One query, several kinds of hit, all of them inside the caller's own cases."""

    permission_classes = [IsAnalystOrAdmin]

    def get(self, request):
        q = (request.query_params.get("q") or "").strip()
        if len(q) < 2:
            return Response({"query": q, "results": [], "truncated": False,
                             "detail": "a search needs at least two characters"})

        # `scope_by_investigation` is the whole rule: every open case, plus the restricted
        # ones this identity is a member of. `visible_investigation_ids` alone returns only
        # the restricted set, so using it here would hide every ordinary case from every
        # analyst the moment one compartment existed anywhere in the estate.
        def within(qs, path="investigation_id"):
            return scope_by_investigation(qs, request.user, path)

        results = []

        invs = within(Investigation.objects.all(), "id").filter(name__icontains=q)
        results += [{"kind": "investigation", "investigation": i.id, "title": i.name,
                     "subtitle": f"{i.incident_id} · {i.status}",
                     "url": f"/investigations/{i.id}"}
                    for i in invs[:MAX_PER_KIND]]

        incs = within(Investigation.objects.all(), "id").filter(
            incident_id__icontains=q).exclude(id__in=[r["investigation"] for r in results])
        results += [{"kind": "investigation", "investigation": i.id, "title": i.name,
                     "subtitle": f"{i.incident_id} · {i.status}",
                     "url": f"/investigations/{i.id}"}
                    for i in incs[:MAX_PER_KIND]]

        # A finding is searched by what it found and what it found it on: the type names the
        # behavior, the target and path name the artifact an analyst actually remembers.
        finds = within(Finding.objects.select_related("run__host"), "run__investigation_id")
        finds = finds.filter(
            Q(finding_type__icontains=q) | Q(target__icontains=q)
            | Q(subject_path__icontains=q))
        results += [{"kind": "finding", "investigation": f.run.investigation_id,
                     "title": f.finding_type,
                     "subtitle": " · ".join(x for x in (f.run.host.hostname, f.target,
                                                        f.confidence, f.verdict) if x)[:160],
                     "url": f"/findings?q={q}"}
                    for f in finds[:MAX_PER_KIND]]

        notes = within(Note.objects.all()).filter(
            Q(body__icontains=q) | Q(summary__icontains=q))
        results += [{"kind": "note", "investigation": n.investigation_id,
                     "title": (n.summary or n.body)[:120],
                     "subtitle": f"{n.kind} · {n.author}".strip(" ·"),
                     "url": f"/investigations/{n.investigation_id}"}
                    for n in notes[:MAX_PER_KIND]]

        tasks = within(CaseTask.objects.all()).filter(title__icontains=q)
        results += [{"kind": "task", "investigation": t.investigation_id, "title": t.title,
                     "subtitle": f"{t.state} · {t.assignee}".strip(" ·"),
                     "url": f"/investigations/{t.investigation_id}"}
                    for t in tasks[:MAX_PER_KIND]]

        iocs = within(IOC.objects.select_related("run"), "run__investigation_id")
        iocs = iocs.filter(value__icontains=q)
        results += [{"kind": "ioc", "investigation": i.run.investigation_id,
                     "title": i.value, "subtitle": i.ioc_type,
                     "url": f"/iocs?q={q}"}
                    for i in iocs[:MAX_PER_KIND]]

        return Response({
            "query": q,
            "results": results,
            # Said out loud, because a silently capped result set reads as "there is no
            # more" — the one thing a search must never imply when it is wrong.
            "truncated": any(len([r for r in results if r["kind"] == k]) >= MAX_PER_KIND
                             for k in ("investigation", "finding", "note", "task", "ioc")),
            "per_kind_limit": MAX_PER_KIND,
        })
