import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api.js";
import { useData, Loading } from "../components/common.jsx";
import { useNavigate } from "react-router-dom";
import { StatTiles, BacklogTrend } from "../components/charts.jsx";

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
  const navigate = useNavigate();
  const { data: stats, error } = useData(() => api.stats());
  const { data: facets } = useData(() => api.facets());
  // The dashboard answers "where should I be looking right now?", so every figure is a
  // server aggregate over the whole fleet rather than a sum of whatever this page loaded.
  const { data: backlog } = useData(() => api.findingsBacklog(30));
  const { data: funnel } = useData(() => api.findingsFunnel());
  const { data: stalled } = useData(() => api.stalledInvestigations(30));
  const { data: queue } = useData(() => api.queueDepth(), [], { refreshMs: 30000 });
  const [sel, setSel] = useState({ investigations: [], hosts: [], verdicts: [], retention: [] });
  const [summary, setSummary] = useState(null);

  const toggle = (dim, key) =>
    setSel((s) => ({ ...s, [dim]: s[dim].includes(key) ? s[dim].filter((k) => k !== key) : [...s[dim], key] }));

  const anySelected = useMemo(() => Object.values(sel).some((a) => a.length), [sel]);

  useEffect(() => {
    api.summary(sel).then(setSummary).catch(() => setSummary(null));
  }, [sel]);

  if (!stats) return <Loading error={error} />;
  // Collected minus adjudicated, from the funnel the platform computed — never a client
  // subtraction over two unrelated payloads.
  const fs = Object.fromEntries((funnel?.stages || []).map((st) => [st.stage, st.count]));
  const awaiting = fs.collected != null && fs.adjudicated != null
    ? fs.collected - fs.adjudicated : "—";

  return (
    <>
      <h1>Dashboard</h1>
      <p className="page-sub">Where to be looking right now, across every investigation.</p>

      <StatTiles tiles={[
        { label: "Investigations", value: stats.investigations, accent: "var(--accent)",
          onOpen: () => navigate("/investigations") },
        { label: "Compromised hosts", value: stats.compromised_hosts, accent: "var(--bad)",
          sub: `of ${stats.hosts} seen`, onOpen: () => navigate("/hosts") },
        { label: "Awaiting a verdict", value: awaiting, accent: "var(--warn)",
          sub: "collected, not adjudicated",
          onOpen: () => navigate("/findings?adjudicated=no") },
        { label: "Confirmed", value: stats.true_positives, accent: "var(--good)",
          sub: "true positive",
          onOpen: () => navigate(`/findings?verdict=${encodeURIComponent("True Positive")}`) },
        { label: "Seen before", value: stats.recurring_hosts, accent: "var(--accent-2, var(--accent))",
          sub: "hosts in more than one case", onOpen: () => navigate("/hosts") },
      ]} />

      <div className="panel" style={{ padding: 20 }}>
        <h3 style={{ margin: "0 0 4px" }}>Backlog</h3>
        <p className="chart-note">
          What has arrived and not yet been decided. Findings per day tracks the intrusion;
          this tracks the response — falling means the queue is being worked down, climbing
          means evidence is arriving faster than it is being judged. Click a day to open the
          findings still waiting from it.
        </p>
        <BacklogTrend backlog={backlog} funnel={funnel} />
      </div>

      <div className="panel-row" style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
        <div className="panel" style={{ flex: "1 1 380px", padding: 20 }}>
          <h3 style={{ margin: "0 0 4px" }}>Going quiet</h3>
          <p className="chart-note">
            Investigations past the age ceiling with nothing new landing. An abandoned case
            is not a closed one, and archival will take it either way.
          </p>
          {!(stalled?.stalled || []).length ? (
            <p className="muted">
              No open investigation has been quiet for {stalled?.age_ceiling_days ?? 30} days.
            </p>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {(stalled.stalled || []).slice(0, 8).map((inv) => (
                <div key={inv.id} {...{ role: "link", tabIndex: 0,
                       style: { cursor: "pointer", display: "flex",
                                justifyContent: "space-between", gap: 10,
                                padding: "8px 12px", borderRadius: 6,
                                background: "var(--bg-elev-2)",
                                borderLeft: "3px solid var(--warn)" },
                       onClick: () => navigate(`/investigations/${inv.id}`) }}>
                  <span style={{ fontSize: 12.5 }}>
                    {inv.name}
                    <span className="mono" style={{ color: "var(--text-dim)", fontSize: 11 }}>
                      {inv.incident_id ? `  ${inv.incident_id}` : ""}</span>
                  </span>
                  <span className="mono" style={{ fontSize: 11.5, color: "var(--text-dim)" }}>
                    {inv.last_activity
                      ? `${Math.max(0, Math.round((Date.now() - new Date(inv.last_activity)) / 86400000))}d quiet`
                      : inv.status}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* The platform's own health, beside the cases it is carrying. A console that shows
          the work moving while hiding that the analyser is falling behind flatters itself. */}
      <div className="panel" style={{ padding: 20 }}>
        <h3 style={{ margin: "0 0 4px" }}>Platform pulse</h3>
        <p className="chart-note">
          Whether the platform is keeping up with the evidence it is being given.
        </p>
        <div style={{ display: "flex", gap: 26, flexWrap: "wrap", alignItems: "center" }}>
          {[
            ["Queued", queue?.queued ?? 0, (queue?.queued ?? 0) > 0 ? "var(--warn)" : "var(--good)"],
            ["Running", queue?.running ?? 0, "var(--accent)"],
            ["Awaiting analysis", queue?.captures_awaiting_analysis ?? 0,
             (queue?.captures_awaiting_analysis ?? 0) > 0 ? "var(--warn)" : "var(--good)"],
            ["Oldest wait", queue?.oldest_waiting_seconds
              ? `${Math.round(queue.oldest_waiting_seconds / 60)}m` : "—",
             (queue?.oldest_waiting_seconds ?? 0) > 900 ? "var(--bad)" : "var(--text-dim)"],
          ].map(([label, value, color]) => (
            <div key={label} style={{ display: "flex", alignItems: "center", gap: 9 }}>
              <span style={{ width: 9, height: 9, borderRadius: 999, background: color }} />
              <span style={{ fontSize: 11.5, color: "var(--text-dim)" }}>{label}</span>
              <span className="mono" style={{ fontSize: 15, fontWeight: 700 }}>{value}</span>
            </div>
          ))}
          <button className="linkish" style={{ marginLeft: "auto" }}
                  onClick={() => navigate("/platform-health")}>platform health →</button>
        </div>
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
