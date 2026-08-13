import { Link } from "react-router-dom";
import { api } from "../api.js";
import DataTable from "../components/DataTable.jsx";
import { useServerTable } from "../components/useServerTable.js";

export default function Hosts() {
  const t = useServerTable(api.hosts);
  return (
    <>
      <h1>Hosts</h1>
      <p className="page-sub">Endpoints seen across all investigations — "have we seen this box before?"</p>
      {t.error ? <div className="empty">Error: {t.error}</div> : (
        <DataTable
          serverMode
          rows={t.rows}
          count={t.count}
          page={t.page}
          totalPages={t.totalPages}
          query={t.q}
          sort={t.ordering}
          onQueryChange={t.onQueryChange}
          searchPlaceholder="Search hosts…"
          emptyText={t.data ? "No hosts match." : "Loading…"}
          columns={[
            { key: "hostname", label: "Hostname", mono: true,
              render: (v, r) => <Link to={`/hosts/${r.id}`}>{v}</Link> },
            { key: "platform", label: "Platform" },
          ]}
        />
      )}
    </>
  );
}
