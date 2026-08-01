import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";

/**
 * Drives a server-paged table and keeps its state in the URL.
 *
 * Search, sort, page and any extra filters are query parameters, so a view an analyst
 * arrives at can be bookmarked, shared, and walked back with the browser's Back button.
 *
 * `prefix` namespaces the parameters so two tables on one page do not collide.
 */
export function useServerTable(fetcher, { prefix = "", extra = {}, deps = [] } = {}) {
  const [params, setParams] = useSearchParams();
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [reloadKey, setReloadKey] = useState(0);

  const k = (name) => (prefix ? `${prefix}_${name}` : name);
  const q = params.get(k("q")) || "";
  const ordering = params.get(k("ordering")) || "";
  const page = parseInt(params.get(k("page")) || "1", 10);

  const extraKey = JSON.stringify(extra);

  useEffect(() => {
    const qs = new URLSearchParams();
    if (q) qs.set("search", q);
    if (ordering) qs.set("ordering", ordering);
    if (page > 1) qs.set("page", String(page));
    for (const [key, value] of Object.entries(extra)) {
      if (value !== "" && value != null) qs.set(key, String(value));
    }
    const suffix = qs.toString() ? `?${qs}` : "";

    let alive = true;
    setError(null);
    fetcher(suffix)
      .then((d) => alive && setData(d))
      .catch((e) => alive && setError(e.message));
    return () => { alive = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q, ordering, page, extraKey, reloadKey, ...deps]);

  const onQueryChange = ({ q: nextQ, ordering: nextOrdering, page: nextPage }) => {
    setParams((p) => {
      nextQ ? p.set(k("q"), nextQ) : p.delete(k("q"));
      nextOrdering ? p.set(k("ordering"), nextOrdering) : p.delete(k("ordering"));
      nextPage && nextPage > 1 ? p.set(k("page"), String(nextPage)) : p.delete(k("page"));
      return p;
    });
  };

  const setExtra = (name, value) =>
    setParams((p) => {
      value ? p.set(name, value) : p.delete(name);
      p.delete(k("page"));   // a changed filter invalidates the current page
      return p;
    });

  return {
    data, error, q, ordering, page,
    rows: data?.results ?? [],
    count: data?.count ?? null,
    totalPages: data?.total_pages ?? 1,
    onQueryChange, setExtra,
    reload: () => setReloadKey((n) => n + 1),
  };
}
