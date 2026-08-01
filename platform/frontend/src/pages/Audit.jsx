import { api } from "../api.js";
import { useData, Loading } from "../components/common.jsx";
import DataTable from "../components/DataTable.jsx";

export default function Audit() {
  const { data, error } = useData(() => api.audit());
  if (!data) return <Loading error={error} />;
  return (
    <>
      <h1>Audit Trail</h1>
      <p className="page-sub">
        Append-only, hash-chained. Chain status:{" "}
        {data.chain_intact
          ? <span className="status-completed">✓ intact ({data.count} entries)</span>
          : <span className="sev-high">✗ BROKEN at #{data.first_broken_id}</span>}
      </p>
      <div className="table-controls">
        {/* The export carries the chain verification with it: an audit trail handed over
            without proof that it verifies is a list of claims. Taking one is itself
            recorded in the trail. */}
        <a className="btn" href={api.auditExportUrl("csv")} download>Export CSV</a>
        <a className="btn" href={api.auditExportUrl("json")} download>Export JSON</a>
        <span className="table-count">export is recorded in the trail</span>
      </div>
      <DataTable
        rows={data.entries}
        searchPlaceholder="Search audit entries…"
        columns={[
          { key: "created_at", label: "When", cellClass: "muted", render: (v) => new Date(v).toLocaleString() },
          { key: "actor", label: "Actor", filter: true },
          { key: "role", label: "Role", filter: true, render: (v) => v || "—" },
          { key: "action", label: "Action", filter: true, mono: true },
          { key: "object_type", label: "Object", mono: true, render: (v, r) => `${v}${r.object_id ? "#" + r.object_id : ""}` },
          { key: "entry_hash", label: "Hash", cellClass: "mono", render: (v) => <span title={v} style={{ fontSize: 11 }}>{v.slice(0, 12)}…</span> },
        ]}
      />
    </>
  );
}
