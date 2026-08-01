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
            { key: "status", label: "Status", filter: true, render: (v) => <span className="status-pill">{v}</span> },
            { key: "run_count", label: "Runs" },
            { key: "created_at", label: "Created", cellClass: "muted", render: (v) => new Date(v).toLocaleString() },
          ]}
        />
      )}
    </>
  );
}
