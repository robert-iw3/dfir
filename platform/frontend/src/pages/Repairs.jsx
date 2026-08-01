/**
 * Enclave repairs an admin can request from here.
 *
 * THE PLATFORM DOES NOT RUN THESE. Requesting one records a row; the remediation agent — an
 * isolated executor with no network, deployed by `deploy.sh agent` — polls, matches the action
 * NAME against its own allow-list, and runs its own command. Giving THIS container the runtime
 * socket instead would put a container-escape path in a request-serving web service — the
 * boundary the whole tier split defends.
 *
 * So every request here is a request, and its outcome is whatever the agent reported. If no
 * agent is running, requests stay queued and this page says so rather than appearing to have
 * fixed something.
 *
 * Each action came from a failure this deployment actually hit and diagnosed. That is the bar
 * for adding one: a repair nobody has needed is a privileged command nobody has reviewed.
 */
import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";

const REFRESH_MS = 5000;

function when(ts) {
  if (!ts) return "—";
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? ts : d.toISOString().replace("T", " ").slice(0, 19) + "Z";
}

function StatusPill({ status }) {
  const color =
    status === "succeeded" ? "var(--good)" :
    status === "running" ? "var(--accent)" :
    status === "queued" ? "var(--warn)" : "var(--bad)";
  return <span style={{ color }}>{status}</span>;
}

export default function Repairs() {
  const [data, setData] = useState(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState("");
  const [reason, setReason] = useState("");
  const [confirming, setConfirming] = useState(null);

  const load = useCallback(async () => {
    try { setData(await api.remediation()); setErr(""); }
    catch (e) { setErr(String(e.message || e)); }
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, REFRESH_MS);
    return () => clearInterval(t);
  }, [load]);

  async function request(action) {
    setBusy(action);
    try {
      await api.requestRemediation(action, reason);
      setReason("");
      setConfirming(null);
      await load();
    } catch (e) {
      setErr(String(e.message || e));
    } finally {
      setBusy("");
    }
  }

  if (err) return <div className="page"><h1>Enclave repairs</h1><div className="card bad">{err}</div></div>;
  if (!data) return <div className="page"><h1>Enclave repairs</h1><div className="muted">Loading…</div></div>;

  const queued = data.requests.filter((r) => r.status === "queued").length;
  // Nothing has ever been claimed → no agent has run against this deployment. Said plainly,
  // because a queue that silently never drains looks exactly like a repair that did nothing.
  const agentSeen = data.requests.some((r) => r.agent_host);

  return (
    <div className="page">
      <h1>Enclave repairs</h1>
      <p className="muted" style={{ maxWidth: 780 }}>
        These are requests. The platform records them; the remediation agent runs them from its
        own allow-list — the web tier holds no container runtime access, by design.
      </p>

      {queued > 0 && !agentSeen && (
        <div className="card bad" style={{ padding: 14, marginBottom: 14 }}>
          <strong>{queued} request(s) queued and no agent has ever claimed one.</strong>
          <div className="muted" style={{ marginTop: 6 }}>
            Deploy it on the enclave host: <code>deploy.sh agent</code>
          </div>
        </div>
      )}

      <h2>Available repairs</h2>
      <div className="cards" style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill,minmax(320px,1fr))", gap: 12 }}>
        {data.catalog.map((a) => (
          <div key={a.action} className="card" style={{ textAlign: "left", padding: 14 }}>
            <div style={{ fontWeight: 600 }}>
              {a.title}{" "}
              {a.disruptive && <span style={{ color: "var(--warn)", fontSize: 12 }}>· disruptive</span>}
            </div>
            <div className="muted" style={{ marginTop: 6 }}>{a.summary}</div>
            <div className="muted" style={{ marginTop: 6, fontSize: 12 }}><em>When:</em> {a.when}</div>

            {confirming === a.action ? (
              <div style={{ marginTop: 10 }}>
                <input
                  className="inp"
                  placeholder="reason (recorded in the audit trail)"
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  style={{ width: "100%", marginBottom: 8 }}
                />
                <button className="btn" disabled={busy === a.action} onClick={() => request(a.action)}>
                  {busy === a.action ? "requesting…" : a.disruptive ? "Yes — I accept the disruption" : "Confirm"}
                </button>{" "}
                <button className="btn ghost" onClick={() => { setConfirming(null); setReason(""); }}>Cancel</button>
              </div>
            ) : (
              // Confirmation on everything, not only the disruptive ones: each of these is a
              // privileged command on the tier that holds the evidence.
              <button className="btn" style={{ marginTop: 10 }} onClick={() => setConfirming(a.action)}>
                Request
              </button>
            )}
          </div>
        ))}
      </div>

      <h2 style={{ marginTop: 22 }}>History</h2>
      <table className="tbl">
        <thead>
          <tr><th>Requested</th><th>Action</th><th>By</th><th>Reason</th><th>Status</th><th>Agent</th><th>Result</th></tr>
        </thead>
        <tbody>
          {data.requests.length === 0 && (
            <tr><td colSpan={7} className="muted">No repairs have been requested.</td></tr>
          )}
          {data.requests.map((r) => (
            <tr key={r.id}>
              <td className="muted">{when(r.created_at)}</td>
              <td><code>{r.action}</code></td>
              <td>{r.actor}</td>
              <td className="muted">{r.reason || "—"}</td>
              <td><StatusPill status={r.status} /></td>
              <td className="muted"><code>{r.agent_host || "—"}</code></td>
              <td className="muted" style={{ maxWidth: 420 }}>
                {r.output
                  ? <details><summary>exit {r.exit_code ?? "?"}</summary>
                      <pre style={{ whiteSpace: "pre-wrap", fontSize: 11 }}>{r.output}</pre>
                    </details>
                  : "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
