"""
Pagination for list endpoints.

Every list the UI renders is paged at the database, not in the browser. A run in a real
incident carries thousands of findings and the audit ledger grows without bound; returning
either in full is what turns a slow page into an unusable one.

`page_size` is client-settable so a table can request exactly what it displays, and capped
so a client cannot ask for the unbounded response the paging exists to prevent.
"""
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response


class StandardPagination(PageNumberPagination):
    page_size = 50
    page_size_query_param = "page_size"
    max_page_size = 500

    def get_paginated_response(self, data):
        # total_pages is included so the table can render paging controls without
        # deriving it from count and page_size on every render.
        return Response({
            "count": self.page.paginator.count,
            "total_pages": self.page.paginator.num_pages,
            "page": self.page.number,
            "page_size": self.get_page_size(self.request),
            "next": self.get_next_link(),
            "previous": self.get_previous_link(),
            "results": data,
        })
