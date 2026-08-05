import { Fragment, useMemo, useState } from "react";

/**
 * Searchable, filterable, sortable table.
 *
 * Two modes:
 *   client — the caller passes every row; search/filter/sort happen in the browser. For
 *            small embedded tables where the whole set is already loaded.
 *   server — the caller passes one page plus `page`/`totalPages`/`count` and handles
 *            `onQueryChange`. Required for anything that grows with the incident:
 *            findings, runs, hosts, the audit ledger.
 *
 * columns: [{ key, label, render?(value,row), cellClass?, filter?, mono?, sortKey?, sortable? }]
 * `sortKey` is the field the API orders by when it differs from the display key.
 */
function cellValue(row, col) {
  const v = row[col.key];
  return v == null ? "" : v;
}

function classFor(col, value, row) {
  if (typeof col.cellClass === "function") return col.cellClass(value, row);
  if (typeof col.cellClass === "string") return col.cellClass;
  return col.mono ? "mono" : "";
}

function SortHeader({ col, sort, onSort }) {
  const key = col.sortKey || col.key;
  const active = sort === key || sort === `-${key}`;
  const descending = sort === `-${key}`;

  if (col.sortable === false) return <th scope="col" style={col.thStyle}>{col.label}</th>;

  return (
    <th scope="col" style={col.thStyle}
        aria-sort={active ? (descending ? "descending" : "ascending") : "none"}>
      <button type="button" className="th-sort" onClick={() => onSort(key, descending)}
              aria-label={`Sort by ${col.label}`}>
        {col.label}{" "}
        <span className="th-arrow" aria-hidden="true">
          {active ? (descending ? "▼" : "▲") : "↕"}
        </span>
      </button>
    </th>
  );
}

export default function DataTable({
  columns, rows, searchPlaceholder = "Search…", emptyText = "No rows.",
  // server mode
  serverMode = false, page = 1, totalPages = 1, count = null,
  query: extQuery, sort: extSort, onQueryChange,
  // selection (bulk triage)
  selectable = false, selected = [], onToggleRow, onToggleAll,
  // Per-row detail. Returns the node to show under a row, or null when it has none —
  // rows without detail get no expander, so the control never promises an empty panel.
  renderDetail,
}) {
  const [query, setQuery] = useState("");
  const [filters, setFilters] = useState({});
  const [sort, setSort] = useState("");
  const [expanded, setExpanded] = useState(null);

  const activeQuery = serverMode ? (extQuery ?? "") : query;
  const activeSort = serverMode ? (extSort ?? "") : sort;

  const emit = (patch) =>
    onQueryChange?.({ q: activeQuery, ordering: activeSort, page, ...patch });

  const setSearch = (value) => {
    if (serverMode) emit({ q: value, page: 1 });   // a new search restarts paging
    else setQuery(value);
  };

  const onSort = (key, wasDescending) => {
    const next = wasDescending ? key : `-${key}`;
    if (serverMode) emit({ ordering: next, page: 1 });
    else setSort(next);
  };

  const distinct = useMemo(() => {
    const out = {};
    for (const col of columns) {
      if (!col.filter) continue;
      out[col.key] = Array.from(
        new Set(rows.map((r) => String(cellValue(r, col))).filter((v) => v !== ""))
      ).sort();
    }
    return out;
  }, [columns, rows]);

  const filtered = useMemo(() => {
    if (serverMode) return rows;   // the database already applied search, filter and sort
    const q = query.trim().toLowerCase();
    let out = rows.filter((r) => {
      for (const [key, val] of Object.entries(filters)) {
        if (val && String(r[key] ?? "") !== val) return false;
      }
      if (!q) return true;
      return columns.some((c) => {
        const v = cellValue(r, c);
        return String(Array.isArray(v) ? v.join(" ") : v).toLowerCase().includes(q);
      });
    });
    if (sort) {
      const desc = sort.startsWith("-");
      const key = desc ? sort.slice(1) : sort;
      out = [...out].sort((a, b) => {
        const av = a[key] ?? "";
        const bv = b[key] ?? "";
        const cmp = typeof av === "number" && typeof bv === "number"
          ? av - bv : String(av).localeCompare(String(bv));
        return desc ? -cmp : cmp;
      });
    }
    return out;
  }, [rows, columns, query, filters, sort, serverMode]);

  const anyActive = Object.values(filters).some(Boolean) || activeQuery.trim() || activeSort;
  const shown = serverMode && count != null
    ? `${rows.length} of ${count}`
    : `${filtered.length}${filtered.length !== rows.length ? ` of ${rows.length}` : ""}`;

  const clear = () => {
    setFilters({});
    if (serverMode) emit({ q: "", ordering: "", page: 1 });
    else { setQuery(""); setSort(""); }
  };

  return (
    <>
      <div className="table-controls">
        <input className="table-search" value={activeQuery} placeholder={searchPlaceholder}
               aria-label={searchPlaceholder}
               onChange={(e) => setSearch(e.target.value)} />
        {!serverMode && columns.filter((c) => c.filter).map((c) => (
          <select key={c.key} value={filters[c.key] || ""} aria-label={`Filter by ${c.label}`}
                  onChange={(e) => setFilters((f) => ({ ...f, [c.key]: e.target.value }))}>
            <option value="">{c.label}: all</option>
            {distinct[c.key].map((v) => <option key={v} value={v}>{v}</option>)}
          </select>
        ))}
        <span className="table-count">{shown}</span>
        {anyActive && <button className="table-clear" onClick={clear}>clear</button>}
      </div>

      <div className="panel">
        <table>
          <thead>
            <tr>
              {selectable && (
                <th scope="col" style={{ width: 34 }}>
                  <input type="checkbox" aria-label="Select all rows on this page"
                         checked={rows.length > 0 && selected.length === rows.length}
                         onChange={(e) => onToggleAll?.(e.target.checked)} />
                </th>
              )}
              {renderDetail && <th scope="col" style={{ width: 28 }}><span className="sr-only">Detail</span></th>}
              {columns.map((c) => (
                <SortHeader key={c.key} col={c} sort={activeSort} onSort={onSort} />
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr><td colSpan={columns.length + (selectable ? 1 : 0) + (renderDetail ? 1 : 0)} className="empty">{emptyText}</td></tr>
            ) : filtered.map((row, i) => {
              // A row may carry more than its columns show — a finding's recovered
              // indicators, for one. Expanded detail is opt-in per row so the table stays
              // scannable and the evidence is one click away rather than in another view.
              const detail = renderDetail?.(row);
              const open = detail && expanded === (row.id ?? i);
              return (
              <Fragment key={row.id ?? i}>
              <tr className={selected.includes(row.id) ? "row-on" : ""}>
                {selectable && (
                  <td>
                    <input type="checkbox" aria-label={`Select row ${row.id}`}
                           checked={selected.includes(row.id)}
                           onChange={() => onToggleRow?.(row.id)} />
                  </td>
                )}
                {/* The cell is present whenever the table has a detail column, even when
                    THIS row has none — omitting it would shift every later cell into the
                    wrong column for that row only. */}
                {renderDetail && (
                  <td>
                    {detail && (
                      <button type="button" className="th-sort"
                              aria-expanded={open}
                              aria-label={open ? "Hide detail" : "Show detail"}
                              onClick={() => setExpanded(open ? null : (row.id ?? i))}>
                        {open ? "▾" : "▸"}
                      </button>
                    )}
                  </td>
                )}
                {columns.map((c) => {
                  const v = cellValue(row, c);
                  return (
                    <td key={c.key} className={classFor(c, v, row)}>
                      {c.render ? c.render(v, row) : String(v)}
                    </td>
                  );
                })}
              </tr>
              {open && (
                <tr className="rationale-row">
                  <td colSpan={columns.length + (selectable ? 1 : 0) + 1}>{detail}</td>
                </tr>
              )}
              </Fragment>
              );
            })}
          </tbody>
        </table>
      </div>

      {serverMode && totalPages > 1 && (
        <div className="pager">
          <button className="btn" disabled={page <= 1}
                  onClick={() => emit({ page: page - 1 })}>Previous</button>
          <span className="muted">Page {page} of {totalPages}</span>
          <button className="btn" disabled={page >= totalPages}
                  onClick={() => emit({ page: page + 1 })}>Next</button>
        </div>
      )}
    </>
  );
}
