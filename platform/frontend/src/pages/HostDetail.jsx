/**
 * One endpoint, across every case that touched it.
 *
 * The question this page answers is "have we seen this box before?", so it is deliberately
 * cross-case: the recurrence IS the finding. Cases the viewer may not see are counted and
 * not named — the existence of a compartmented case must not leak through a shared host.
 */
import { Link, useParams } from "react-router-dom";
import { api } from "../api.js";
import { useData, Loading, Empty } from "../components/common.jsx";

function bytes(n) {
  if (!n) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = Number(n), i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`;
}

const VERDICT_TONE = {
  "True Positive": "var(--bad)", "Likely True Positive": "var(--warn)",
  Indeterminate: "var(--text-dim)", "Likely False Positive": "var(--accent-2)",
  "False Positive": "var(--good)",
};

export default function HostDetail() {
  const { id } = useParams();
  const { data, error } = useData(() => api.hostOverview(id), [id]);
  if (!data) return <Loading error={error} />;

  const runs = data.runs || [];
  const compromised = runs.filter((r) => r.compromised).length;
  const verdicts = Object.entries(data.verdicts || {}).filter(([, n]) => n > 0);
  const total = verdicts.reduce((a, [, n]) => a + n, 0);

  return (
    <>
      <h1 className="mono">{data.hostname}</h1>
      <p className="page-sub">
        {data.platform} · machine id <span className="mono">{data.machine_id || "—"}</span>
        {" · "}{runs.length} collection{runs.length === 1 ? "" : "s"} across{" "}
        {data.investigations} investigation{data.investigations === 1 ? "" : "s"}
        {compromised > 0 && <> · <span style={{ color: "var(--bad)" }}>
          {compromised} found compromised</span></>}
      </p>

      {data.runs_hidden_by_compartment > 0 && (
        <p className="muted">
          {data.runs_hidden_by_compartment} further collection(s) of this host belong to
          case(s) you are not assigned to and are not shown.
        </p>
      )}

      {data.identity_changes?.length > 0 && (
        <>
          <h2>Identity history</h2>
          <p className="page-sub">
            A hostname is a mutable label. A rename is history here, not a new machine.
          </p>
          <table className="tbl">
            <thead><tr><th>Field</th><th>From</th><th>To</th><th>Observed</th></tr></thead>
            <tbody>
              {data.identity_changes.map((c, i) => (
                <tr key={i}>
                  <td>{c.field}</td>
                  <td className="mono">{c.from_value || "—"}</td>
                  <td className="mono">{c.to_value || "—"}</td>
                  <td className="muted">{new Date(c.observed_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      <h2>Findings across every case</h2>
      {total === 0 ? <Empty>No findings recorded on this host.</Empty> : (
        <>
          <div style={{ display: "flex", height: 24, borderRadius: 6, overflow: "hidden",
                        background: "var(--bg-elev-2)", gap: 2, marginBottom: 8 }}>
            {verdicts.map(([v, n]) => (
              <div key={v} title={`${v}: ${n}`}
                   style={{ width: `${(n / total) * 100}%`,
                            background: VERDICT_TONE[v] || "var(--accent)" }} />
            ))}
          </div>
          <div style={{ display: "flex", gap: 16, flexWrap: "wrap", fontSize: 12 }}>
            {verdicts.map(([v, n]) => (
              <span key={v} style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <span style={{ width: 9, height: 9, borderRadius: 2,
                               background: VERDICT_TONE[v] || "var(--accent)" }} />
                {v} <span className="mono" style={{ color: "var(--text-dim)" }}>{n}</span>
              </span>
            ))}
          </div>
        </>
      )}

      <h2>Collections</h2>
      {runs.length === 0 ? <Empty>Nothing collected from this host.</Empty> : (
        <table className="tbl">
          <thead>
            <tr>
              <th>Run</th><th>Case</th><th>Collected</th><th>Kind</th>
              <th>Status</th><th>Compromised</th><th>TP</th><th>Findings</th>
              <th>Custody</th><th>Toolkit</th>
            </tr>
          </thead>
          <tbody>
            {runs.map((r) => (
              <tr key={r.run_id}>
                <td><Link to={`/runs/${r.run_id}`} className="mono">
                  {r.stamp || r.run_id}</Link></td>
                <td>{r.investigation
                  ? <Link to={`/investigations/${r.investigation}`}>{r.investigation_name}</Link>
                  : <span className="muted">—</span>}</td>
                <td className="muted">{r.collected_at
                  ? new Date(r.collected_at).toLocaleString() : "—"}</td>
                <td>{r.run_kind || "initial"}</td>
                <td><span className={`status-pill status-${r.overall_status}`}>
                  {r.overall_status || "—"}</span></td>
                <td>{r.compromised
                  ? <span className="sev-high">yes</span>
                  : <span className="status-completed">no</span>}</td>
                <td>{r.tp_count}</td>
                <td>{r.finding_count}</td>
                <td>{r.custody_verified
                  ? <span className="status-completed">✓</span>
                  : <span className="muted">—</span>}</td>
                <td className="mono muted">{r.toolkit_version || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h2>Memory captures</h2>
      {(data.captures || []).length === 0 ? (
        <Empty>No memory image was captured from this host.</Empty>
      ) : (
        <table className="tbl">
          <thead>
            <tr><th>Object</th><th>Size</th><th>Retention</th><th>Analyses</th></tr>
          </thead>
          <tbody>
            {data.captures.map((c) => (
              <tr key={c.id}>
                <td className="mono">{(c.object_key || "").split("/").pop()}</td>
                <td>{bytes(c.size_bytes)}</td>
                <td>{c.retention_status}</td>
                <td>{c.analysis_count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {data.carved_regions > 0 && (
        <p className="muted">
          {data.carved_regions} region(s) carved from this host's memory —{" "}
          <Link to="/reversing">reverse engineering</Link>.
        </p>
      )}
    </>
  );
}
