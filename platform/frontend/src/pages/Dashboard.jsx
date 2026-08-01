import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api.js";
import { useData, Loading } from "../components/common.jsx";

function Stat({ num, label, cls }) {
  return (
    <div className={`card ${cls || ""}`}>
      <div className="num">{num ?? "—"}</div>
      <div className="lbl">{label}</div>
    </div>
  );
}

// A drill-down panel: click rows to toggle selection (multi-select).
function FacetPanel({ title, items, getKey, getLabel, getMeta, selected, onToggle }) {
  return (
    <div className="facet-panel">
      <div className="facet-title">{title}</div>
      <div className="facet-list">
        {items.length === 0 && <div className="muted" style={{ padding: 8 }}>none</div>}
        {items.map((it) => {
          const key = String(getKey(it));
          const on = selected.includes(key);
          return (
            <button key={key} type="button" aria-pressed={on}
                    className={`facet-item ${on ? "on" : ""}`} onClick={() => onToggle(key)}>
              <span>{getLabel(it)}</span>
              <span className="facet-meta">{getMeta(it)}</span>
            </button>
          );
        })}
      </div>
    </div>
  );
}

export default function Dashboard() {
  const { data: stats, error } = useData(() => api.stats());
  const { data: facets } = useData(() => api.facets());
  const [sel, setSel] = useState({ investigations: [], hosts: [], verdicts: [], retention: [] });
  const [summary, setSummary] = useState(null);

  const toggle = (dim, key) =>
    setSel((s) => ({ ...s, [dim]: s[dim].includes(key) ? s[dim].filter((k) => k !== key) : [...s[dim], key] }));

  const anySelected = useMemo(() => Object.values(sel).some((a) => a.length), [sel]);

  useEffect(() => {
    api.summary(sel).then(setSummary).catch(() => setSummary(null));
  }, [sel]);

  if (!stats) return <Loading error={error} />;

  return (
    <>
      <h1>Dashboard</h1>
      <p className="page-sub">Cross-investigation forensic data — click panel items to drill down; the summary updates below.</p>

      <div className="cards">
        <Stat num={stats.investigations} label="Investigations" cls="accent" />
        <Stat num={stats.hosts} label="Hosts" />
        <Stat num={stats.runs} label="Collection Runs" />
        <Stat num={stats.findings} label="Findings" />
        <Stat num={stats.true_positives} label="True Positives" cls="bad" />
        <Stat num={stats.compromised_hosts} label="Compromised Hosts" cls="bad" />
        <Stat num={stats.captures_retained} label="Captures Retained" />
        <Stat num={stats.recurring_hosts} label="Recurring Hosts" cls="good" />
      </div>

      {facets && (
        <>
          <h2>Drill down {anySelected && <button className="table-clear" onClick={() => setSel({ investigations: [], hosts: [], verdicts: [], retention: [] })}>clear all</button>}</h2>
          <div className="facet-grid">
            <FacetPanel title="Investigations" items={facets.investigations}
              getKey={(i) => i.id} getLabel={(i) => i.name} getMeta={(i) => `${i.run_count} runs`}
              selected={sel.investigations} onToggle={(k) => toggle("investigations", k)} />
            <FacetPanel title="Hosts" items={facets.hosts}
              getKey={(h) => h.id} getLabel={(h) => h.hostname}
              getMeta={(h) => h.compromised ? "⚠ compromised" : "clean"}
              selected={sel.hosts} onToggle={(k) => toggle("hosts", k)} />
            <FacetPanel title="Verdicts" items={facets.verdicts}
              getKey={(v) => v.value} getLabel={(v) => v.value} getMeta={(v) => v.count}
              selected={sel.verdicts} onToggle={(k) => toggle("verdicts", k)} />
            <FacetPanel title="Capture Retention" items={facets.retention}
              getKey={(r) => r.value} getLabel={(r) => r.value} getMeta={(r) => r.count}
              selected={sel.retention} onToggle={(k) => toggle("retention", k)} />
          </div>
        </>
      )}

      {summary && (
        <>
          <h2>Summary {anySelected ? "(filtered selection)" : "(all data)"}</h2>
          <div className="cards">
            <Stat num={summary.totals.runs} label="Runs" cls="accent" />
            <Stat num={summary.totals.hosts} label="Hosts" />
            <Stat num={summary.totals.findings} label="Findings" />
            <Stat num={summary.totals.true_positives} label="True Positives" cls="bad" />
            <Stat num={summary.totals.compromised_runs} label="Compromised Runs" cls="bad" />
            <Stat num={summary.totals.iocs} label="IOCs" />
            <Stat num={summary.totals.captures} label="Captures" />
          </div>
          <div className="panel" style={{ marginTop: 16 }}>
            <table>
              <thead><tr><th>Host</th><th>Investigation</th><th>Kind</th><th>Status</th><th>Compromised</th><th>TPs</th></tr></thead>
              <tbody>
                {summary.runs.length === 0 ? (
                  <tr><td colSpan={6} className="empty">No runs match this selection.</td></tr>
                ) : summary.runs.map((r) => (
                  <tr key={r.id}>
                    <td><Link to={`/runs/${r.id}`}>{r.hostname}</Link></td>
                    <td><Link to={`/investigations/${r.investigation_id}`}>{r.investigation}</Link></td>
                    <td>{r.run_kind}</td>
                    <td><span className={`status-pill status-${r.overall_status}`}>{r.overall_status || "—"}</span></td>
                    <td>{r.compromised ? <span className="sev-high">yes</span> : <span className="status-completed">no</span>}</td>
                    <td>{r.tp_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </>
  );
}
