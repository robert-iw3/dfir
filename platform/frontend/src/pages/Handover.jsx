/**
 * Shift handover — what the analyst coming on needs to know before they start.
 *
 * The window is stated and adjustable rather than inferred from who is looking, so two
 * people reading this at the same moment read the same shift.
 */
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api.js";

const WINDOWS = [
  { label: "last 8 hours", hours: 8 },
  { label: "last 12 hours", hours: 12 },
  { label: "last 24 hours", hours: 24 },
  { label: "last 3 days", hours: 72 },
];

function sinceISO(hours) {
  return new Date(Date.now() - hours * 3600 * 1000).toISOString();
}

function Section({ title, count, sub, children }) {
  return (
    <>
      <h2>
        {title} <span className="muted" style={{ fontWeight: 400 }}>({count}{sub ? ` · ${sub}` : ""})</span>
      </h2>
      {count === 0 ? <div className="empty">Nothing in this window.</div> : children}
    </>
  );
}

export default function Handover() {
  const [hours, setHours] = useState(12);
  const [data, setData] = useState(null);
  const [err, setErr] = useState("");

  useEffect(() => {
    setData(null);
    setErr("");
    api.handover(sinceISO(hours))
      .then(setData)
      .catch((e) => setErr(e.message || "could not load the handover"));
  }, [hours]);

  if (err) return <div className="empty">{err}</div>;
  if (!data) return <div className="empty">Reading the shift…</div>;

  const t = data.open_tasks;
  const c = data.new_criticals;
  const a = data.awaiting_verdict;
  const f = data.in_flight_analyses;
  const r = data.record_entries;

  return (
    <>
      <h1>Shift handover</h1>
      <p className="page-sub">
        What is open, what arrived, and what is still running. Read from the same rows the
        case pages show — nothing here is a separate record.
      </p>

      <div className="row" style={{ gap: 12, marginBottom: 18, alignItems: "center" }}>
        <label className="muted">
          Window{" "}
          <select value={hours} onChange={(e) => setHours(Number(e.target.value))}>
            {WINDOWS.map((w) => (
              <option key={w.hours} value={w.hours}>{w.label}</option>
            ))}
          </select>
        </label>
        <span className="muted mono">since {data.since.replace("T", " ").slice(0, 19)}Z</span>
      </div>

      <div className="cards">
        <div className="card bad"><div className="num">{c.total}</div>
          <div className="lbl">New criticals</div></div>
        <div className="card warn"><div className="num">{a.total}</div>
          <div className="lbl">Awaiting a verdict</div></div>
        <div className="card accent"><div className="num">{t.total}</div>
          <div className="lbl">Open tasks</div></div>
        <div className="card"><div className="num">{t.blocked}</div>
          <div className="lbl">Blocked</div></div>
        <div className="card"><div className="num">{f.total}</div>
          <div className="lbl">Analyses running</div></div>
        <div className="card"><div className="num">{data.unacknowledged}</div>
          <div className="lbl">Unread for you</div></div>
      </div>

      <Section title="New criticals" count={c.total}>
        <div className="panel scroll-y">
          <table>
            <thead><tr><th>When</th><th>Host</th><th>Severity</th><th>Finding</th><th>Case</th></tr></thead>
            <tbody>
              {c.rows.map((x) => (
                <tr key={x.id}>
                  <td className="mono">{x.at.replace("T", " ").slice(0, 19)}Z</td>
                  <td>{x.host}</td>
                  <td><span className={`badge s-${(x.severity || "").toLowerCase()}`}>{x.severity}</span></td>
                  <td>{x.finding_type}</td>
                  <td><Link to={`/investigations/${x.investigation}`}>{x.case || x.investigation}</Link></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Section>

      <Section title="Awaiting a verdict" count={a.total}>
        <div className="panel scroll-y">
          <table>
            <thead><tr><th>Host</th><th>Finding</th><th>Target</th><th>Confidence</th><th>Case</th></tr></thead>
            <tbody>
              {a.rows.map((x) => (
                <tr key={x.id}>
                  <td>{x.host}</td>
                  <td>{x.finding_type}</td>
                  <td className="mono">{x.target}</td>
                  <td>{x.confidence}</td>
                  <td><Link to={`/investigations/${x.investigation}`}>{x.case || x.investigation}</Link></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Section>

      <Section title="Open tasks" count={t.total} sub={`${t.blocked} blocked, ${t.overdue} overdue`}>
        <div className="panel scroll-y">
          <table>
            <thead><tr><th>Task</th><th>Stage</th><th>Assignee</th><th>State</th><th>Case</th></tr></thead>
            <tbody>
              {t.rows.map((x) => (
                <tr key={x.id}>
                  <td>{x.title}</td>
                  <td className="mono">{x.state}</td>
                  <td>{x.assignee || <span className="muted">unassigned</span>}</td>
                  <td>
                    {x.blocked
                      ? <span className="badge v-blocked" title={x.blocked_reason}>blocked</span>
                      : <span className="muted">—</span>}
                  </td>
                  <td><Link to={`/investigations/${x.investigation}`}>{x.case || x.investigation}</Link></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Section>

      <Section title="Analyses still running" count={f.total}>
        <div className="panel">
          <table>
            <thead><tr><th>Host</th><th>Engine</th><th>Status</th><th>Started</th></tr></thead>
            <tbody>
              {f.rows.map((x) => (
                <tr key={x.id}>
                  <td>{x.host}</td>
                  <td className="mono">{x.engine}</td>
                  <td>{x.status}</td>
                  <td className="mono">
                    {x.started_at ? `${x.started_at.replace("T", " ").slice(0, 19)}Z` : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Section>

      <Section title="Added to the record" count={r.total}>
        <div className="panel scroll-y">
          <table>
            <thead><tr><th>When</th><th>Who</th><th>Kind</th><th>Entry</th></tr></thead>
            <tbody>
              {r.rows.map((x) => (
                <tr key={x.id}>
                  <td className="mono">{x.at.replace("T", " ").slice(0, 19)}Z</td>
                  <td>{x.author}</td>
                  <td className="mono">{x.kind}</td>
                  <td className="wrap">{x.summary}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Section>
    </>
  );
}
