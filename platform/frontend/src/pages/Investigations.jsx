import { Link } from "react-router-dom";
import { api } from "../api.js";
import { useData, Loading, Empty } from "../components/common.jsx";
import DataTable from "../components/DataTable.jsx";

export default function Investigations() {
  const { data, error } = useData(() => api.investigations());
  const rows = data?.results ?? data ?? [];
  return (
    <>
      <h1>Investigations</h1>
      <p className="page-sub">Every incident engagement stored on the platform.</p>
      {!data ? <Loading error={error} /> : rows.length === 0 ? (
        <Empty>No investigations ingested yet.</Empty>
      ) : (
        <DataTable
          rows={rows}
          searchPlaceholder="Search investigations…"
          columns={[
            { key: "name", label: "Name", render: (v, r) => <Link to={`/investigations/${r.id}`}>{v}</Link> },
            { key: "incident_id", label: "Incident ID", mono: true, render: (v) => v || "—" },
            { key: "severity", label: "Severity", filter: true, render: (v) => v || "—" },
            // An archived case stays in this list with an explicit cold-storage state —
            // absent from it, archived would be indistinguishable from deleted.
            { key: "status", label: "Status", filter: true, render: (v, r) => (
                <span className="status-pill" title={r.archive
                    ? (r.archive.state === "restored"
                        ? `restored until ${new Date(r.archive.restored_until).toLocaleString()}`
                        : `in cold storage since ${new Date(r.archive.archived_at).toLocaleDateString()}`
                          + ` · ${Object.values(r.archive.row_counts || {}).reduce((a, b) => a + b, 0)} rows in the bundle`
                          + (r.archive.archived_while_open ? " · archived while still open" : ""))
                    : undefined}>
                  {v}{r.archive?.state === "restored" ? " · restored" : r.archive ? " · cold" : ""}
                </span>
            ) },
            { key: "run_count", label: "Runs" },
            { key: "created_at", label: "Created", cellClass: "muted", render: (v) => new Date(v).toLocaleString() },
          ]}
        />
      )}
    </>
  );
}
