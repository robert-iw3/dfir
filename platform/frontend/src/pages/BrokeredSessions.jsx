/**
 * Brokered analyst sessions — the platform's access record.
 *
 * Analysts reach this platform through a Boundary session and no other way, so this list is
 * the only place that can answer who connected, from where, to what, and for how long. The
 * application tier never sees it: the connection terminates at the broker before a request
 * reaches Django.
 *
 * Admin and auditor, because it is an audit artifact rather than an operations panel. It is
 * read-only by construction — the credential behind it can list and read sessions and cannot
 * authorize or cancel one, so watching access is not a route to obtaining it.
 *
 * Terminated sessions are shown, not filtered away. An access record that keeps only what is
 * currently open answers the least interesting version of the question.
 */
import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";

const REFRESH_MS = 15000;

function when(ts) {
  if (!ts) return "—";
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? ts : d.toISOString().replace("T", " ").slice(0, 19) + "Z";
}

function duration(a, b) {
  if (!a) return "—";
  const start = new Date(a).getTime();
  const end = b ? new Date(b).getTime() : Date.now();
  if (Number.isNaN(start) || Number.isNaN(end)) return "—";
  const s = Math.max(0, Math.round((end - start) / 1000));
  if (s < 90) return `${s}s`;
  const m = Math.round(s / 60);
  return m < 90 ? `${m}m` : `${Math.round(m / 60)}h`;
}

function bytes(n) {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB"];
  let v = Number(n), i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i += 1; }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${u[i]}`;
}

export default function BrokeredSessions() {
  const [data, setData] = useState(null);
  const [err, setErr] = useState("");
  const [showClosed, setShowClosed] = useState(true);

  const load = useCallback(async () => {
    try { setData(await api.brokeredSessions()); setErr(""); }
    catch (e) { setErr(String(e.message || e)); }
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, REFRESH_MS);
    return () => clearInterval(t);
  }, [load]);

  if (err) return <div className="page"><h1>Brokered sessions</h1><div className="card bad">{err}</div></div>;
  if (!data) return <div className="page"><h1>Brokered sessions</h1><div className="muted">Reading the broker…</div></div>;

  if (!data.reachable) {
    return (
      <div className="page">
        <h1>Brokered sessions</h1>
        {/* An empty table would read as "nobody is connected", which is the most dangerous
            wrong answer this page can give. */}
        <div className="card bad" style={{ padding: 16 }}>
          <strong>The broker did not answer — this page is showing nothing, not proving nothing happened.</strong>
          <div className="muted" style={{ marginTop: 6 }}>{data.error}</div>
        </div>
      </div>
    );
  }

  const rows = showClosed ? data.sessions : data.sessions.filter((s) => s.active);

  return (
    <div className="page">
      <h1>Brokered sessions</h1>
      <p className="muted" style={{ maxWidth: 760 }}>
        Every analyst session Boundary has brokered into the enclave. Analysts have no other
        route in, so this is the platform's complete access record.
      </p>

      <div className="cards" style={{ marginBottom: 14 }}>
        <div className="card"><div className="num">{data.active}</div><div className="lbl">Active now</div></div>
        <div className="card"><div className="num">{data.total}</div><div className="lbl">Recorded</div></div>
        <div className="card">
          <div className="num">{new Set(data.sessions.map((s) => s.user_id)).size}</div>
          <div className="lbl">Principals</div>
        </div>
      </div>

      <label style={{ display: "inline-flex", gap: 8, alignItems: "center", marginBottom: 10 }}>
        <input type="checkbox" checked={showClosed} onChange={(e) => setShowClosed(e.target.checked)} />
        <span className="muted">include closed sessions</span>
      </label>

      <table className="tbl">
        <thead>
          <tr>
            <th>State</th><th>Principal</th><th>Reached</th><th>Endpoint</th>
            <th>Client address</th><th>Started</th><th>Duration</th><th>Transferred</th>
            <th>Ended because</th><th>Session</th>
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 && (
            <tr><td colSpan={10} className="muted">No sessions recorded.</td></tr>
          )}
          {rows.map((s) => (
            <tr key={s.id}>
              <td>
                <span className="health-dot" style={{
                  background: s.active ? "var(--good)" : "var(--muted)",
                }} />{" "}
                {s.status}
              </td>
              {/* Resolved names, not ids. "u_rAOgVpmcyW reached ttcp_wRSYiGwYZD" is a lookup
                  exercise handed to the reader; the id stays on hover for correlation with
                  Boundary's own logs. */}
              <td title={s.user_id || ""}>{s.principal || "—"}</td>
              <td title={s.target_id || ""}>{s.target || "—"}</td>
              <td className="muted"><code>{s.endpoint || "—"}</code></td>
              {/* Absent unless the session was detailed — "not retrieved" is shown as such
                  rather than as a blank that reads like "no client connected". */}
              <td><code>{s.client_address || (s.detailed ? "—" : "not retrieved")}</code></td>
              <td className="muted">{when(s.created_time)}</td>
              <td>{duration(s.created_time, s.active ? null : (s.ended_time || s.updated_time))}</td>
              <td className="muted">
                {s.bytes_up == null ? "—" : `↑${bytes(s.bytes_up)} ↓${bytes(s.bytes_down)}`}
                {s.connection_count ? ` · ${s.connection_count} conn` : ""}
              </td>
              <td className="muted">{s.termination_reason || (s.active ? "—" : "closed")}</td>
              <td className="muted"><code>{s.id}</code></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
