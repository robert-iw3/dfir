/**
 * Admin operations console — is the platform itself healthy?
 *
 * Separate from the investigative views: nothing here is about what was found, only about
 * whether the machinery that found it is working. Every figure is measured when the page
 * loads or the operator refreshes, never cached — a stale health panel can report healthy
 * while the thing it describes is down.
 */
import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";

function bytes(n) {
  if (n == null) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = Number(n);
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`;
}

const pct = (v) => (v == null ? "—" : `${(v * 100).toFixed(2)}%`);

/** Horizontal bar — proportion of a row against the largest in its set. */
function Bar({ value, max, label, right }) {
  const w = max > 0 ? Math.max(2, (value / max) * 100) : 0;
  return (
    <div className="metric-row">
      <div className="metric-label">{label}</div>
      <div className="metric-track">
        <div className="metric-fill" style={{ width: `${w}%` }} />
      </div>
      <div className="metric-value mono">{right}</div>
    </div>
  );
}

/** Ratio gauge. `good` marks the threshold below which the value is a problem. */
function Gauge({ value, good = 0.99, label, note }) {
  const v = value ?? 0;
  const healthy = value == null || v >= good;
  return (
    <div className="card" style={{ minWidth: 150 }} title={note || undefined}>
      <div className="num" style={{ color: healthy ? "var(--good)" : "var(--warn)" }}>
        {pct(value)}
      </div>
      <div className="lbl">{label}</div>
    </div>
  );
}

function Dot({ ok }) {
  return <span className="health-dot" style={{ background: ok ? "var(--good)" : "var(--bad)" }} />;
}

function DatabasePanel({ db }) {
  const maxTable = Math.max(...(db.tables || []).map((t) => t.total_bytes), 1);
  return (
    <div className="panel" style={{ padding: 14, marginBottom: 16 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
        <Dot ok={db.reachable} />
        <strong>{db.alias === "default" ? "Collection store" : "Correlation store"}</strong>
        <span className="muted mono">{db.name || db.alias}</span>
        <span className="muted" style={{ marginLeft: "auto" }}>{db.latency_ms} ms</span>
      </div>

      {!db.reachable ? (
        <div className="empty">Unreachable: {db.error}</div>
      ) : (
        <>
          <div className="cards" style={{ marginBottom: 12 }}>
            <div className="card"><div className="num" style={{ fontSize: 20 }}>{bytes(db.size_bytes)}</div><div className="lbl">Size</div></div>
            <div className="card"><div className="num">{db.connections}</div><div className="lbl">Connections</div></div>
            <div className="card"><div className="num">{db.active}</div><div className="lbl">Active</div></div>
            {/* The threshold scales with the database.
                This ratio is cumulative since statistics were last reset, so a nearly EMPTY
                store scores LOWER than a busy one: start-up reads — migrations, the role seed,
                the first queries — are all cold misses, and with little traffic afterwards
                nothing dilutes them. A 12 MB database is entirely resident in shared_buffers
                and still reads ~97%. Warning at 99% there marks a healthy store amber on every
                fresh deployment, which is how a health page teaches people to ignore it. */}
            <Gauge
              value={db.cache_hit_ratio}
              good={db.size_bytes != null && db.size_bytes < 512 * 1024 * 1024 ? 0.9 : 0.99}
              label="Cache hit ratio"
              note="Cumulative since the last statistics reset. A small or newly deployed database reads lower because its start-up misses are never diluted."
            />
            <div className={`card ${db.deadlocks > 0 ? "bad" : ""}`}>
              <div className="num">{db.deadlocks}</div><div className="lbl">Deadlocks</div>
            </div>
            <div className={`card ${db.idle_in_transaction > 0 ? "bad" : ""}`}>
              <div className="num">{db.idle_in_transaction}</div><div className="lbl">Idle in txn</div>
            </div>
            <div className="card"><div className="num">{db.longest_query_s}s</div><div className="lbl">Longest query</div></div>
            <div className="card"><div className="num">{pct(db.rollback_ratio)}</div><div className="lbl">Rollback ratio</div></div>
          </div>

          <div className="muted" style={{ marginBottom: 6 }}>Largest tables</div>
          {(db.tables || []).map((t) => (
            <Bar key={t.name} value={t.total_bytes} max={maxTable} label={t.name}
                 right={`${bytes(t.total_bytes)} · ${t.live_rows} rows${
                   t.seq_scans > 0 && t.idx_scans === 0 && t.live_rows > 500
                     ? " · no index use" : ""}`} />
          ))}
        </>
      )}
    </div>
  );
}

export default function Admin() {
  const [data, setData] = useState(null);
  const [tasks, setTasks] = useState(null);
  const [symbols, setSymbols] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const [at, setAt] = useState(null);

  const refresh = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      const [m, t, sy] = await Promise.all([
        api.platformMetrics(), api.taskStatus(), api.symbolRequests(),
      ]);
      setData(m);
      setTasks(t);
      setSymbols(sy);
      setAt(new Date());
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  if (error) {
    return (
      <>
        <h1>Platform health</h1>
        <div className="empty">
          {error === "403" || error.includes("403")
            ? "Admin role required."
            : `Error: ${error}`}
        </div>
      </>
    );
  }
  if (!data) return (<><h1>Platform health</h1><div className="empty">Measuring…</div></>);

  const storeMax = Math.max(
    ...Object.values(data.storage?.retention || {}).map((r) => r.bytes), 1
  );

  return (
    <>
      <h1>Platform health</h1>
      <p className="page-sub">
        Live state of the platform itself — measured on each refresh, never cached.
      </p>

      <div className="table-controls">
        <button className="btn" onClick={refresh} disabled={busy}>
          {busy ? "Measuring…" : "Refresh metrics"}
        </button>
        <span className="table-count">
          {at ? `measured ${at.toISOString().slice(11, 19)}Z in ${data.collected_in_ms} ms` : ""}
        </span>
      </div>

      <h2>Components</h2>
      <div className="panel" style={{ padding: 14 }}>
        {data.components.map((c) => (
          <div key={c.name} className="metric-row">
            <div className="metric-label"><Dot ok={c.ok} /> {c.name}</div>
            <div className="metric-track">
              <div className="metric-fill"
                   style={{ width: `${Math.min(100, (c.latency_ms || 0) / 2)}%`,
                            background: c.ok ? "var(--good)" : "var(--bad)" }} />
            </div>
            <div className="metric-value mono">
              {c.ok ? `${c.latency_ms} ms${c.status ? ` · ${c.status}` : ""}`
                    : (c.error || "down")}
            </div>
          </div>
        ))}
      </div>

      <h2>Databases</h2>
      {data.databases.map((db) => <DatabasePanel key={db.alias} db={db} />)}

      <h2>Object storage</h2>
      <div className="panel" style={{ padding: 14 }}>
        <div className="cards" style={{ marginBottom: 12 }}>
          <div className="card">
            <div className="num" style={{ fontSize: 20 }}>{bytes(data.storage.total_bytes)}</div>
            <div className="lbl">Stored ({data.storage.backend})</div>
          </div>
          <div className="card"><div className="num">{data.storage.object_count ?? "—"}</div><div className="lbl">Objects</div></div>
        </div>
        {!data.storage.reachable && (
          <div className="empty">Object store unreachable: {data.storage.error}</div>
        )}
        <div className="muted" style={{ marginBottom: 6 }}>Capture retention</div>
        {Object.entries(data.storage.retention || {}).map(([status, r]) => (
          <Bar key={status} value={r.bytes} max={storeMax} label={status}
               right={`${r.captures} captures · ${bytes(r.bytes)}`} />
        ))}
      </div>

      <h2>Analysis queue</h2>
      <div className="cards">
        <div className={`card ${data.queue.reachable ? "" : "bad"}`}>
          <div className="num">{data.queue.queued ?? "—"}</div><div className="lbl">Queued</div>
        </div>
        <div className="card"><div className="num">{data.queue.workers ?? "—"}</div><div className="lbl">Workers</div></div>
        <div className="card"><div className="num">{data.queue.active_tasks ?? "—"}</div><div className="lbl">Active tasks</div></div>
        <div className={`card ${tasks?.failed ? "bad" : ""}`}>
          <div className="num">{tasks?.failed ?? "—"}</div><div className="lbl">Failed analyses</div>
        </div>
        <div className="card"><div className="num">{tasks?.pending ?? "—"}</div><div className="lbl">Pending</div></div>
      </div>

      <h2>Memory symbols</h2>
      <p className="page-sub">
        Volatility cannot parse a capture without a symbol table matching its kernel.
        Neither the collector nor the enclave may reach the internet, so acquiring one is
        an administrative task. Captures for a kernel with no table are analyzed at
        reduced depth until it arrives.
      </p>
      <div className="table-controls">
        <span className={symbols?.outstanding ? "table-count" : "muted"}>
          {symbols ? `${symbols.outstanding} outstanding` : "…"}
        </span>
        {symbols?.outstanding > 0 && (
          <a className="btn" href={api.symbolRequisitesUrl()}>Export requisites</a>
        )}
      </div>
      <div className="panel">
        <table>
          <thead>
            <tr><th scope="col">Kernel</th><th scope="col">Arch</th><th scope="col">Build ID</th>
                <th scope="col">Status</th><th scope="col">Captures waiting</th>
                <th scope="col">Age</th></tr>
          </thead>
          <tbody>
            {!symbols?.requests?.length ? (
              <tr><td colSpan={6} className="empty">
                No kernel is waiting on symbols.
              </td></tr>
            ) : symbols.requests.map((r) => (
              <tr key={r.symbol_key}>
                <td className="mono">{r.kernel_release || r.symbol_key}</td>
                <td>{r.arch || "—"}</td>
                <td className="mono">{r.build_id ? r.build_id.slice(0, 16) : "—"}</td>
                <td>
                  <span className={`status-pill status-${r.status}`}>{r.status}</span>
                </td>
                <td>{r.waiting_captures}</td>
                {/* Debug packages for superseded kernels get pruned, so an old request
                    can become impossible to satisfy — age is a real risk signal. */}
                <td className={r.status === "needed" && r.age_days >= 14 ? "sev-high" : "muted"}>
                  {r.age_days == null ? "—" : `${r.age_days}d`}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <h2>Audit integrity</h2>
      <div className="cards">
        <div className={`card ${data.audit.chain_intact ? "" : "bad"}`}>
          <div className="num" style={{ fontSize: 20, color: data.audit.chain_intact ? "var(--good)" : "var(--bad)" }}>
            {data.audit.chain_intact ? "verified" : "BROKEN"}
          </div>
          <div className="lbl">Hash chain (whole ledger)</div>
        </div>
        <div className="card"><div className="num">{data.audit.entries}</div><div className="lbl">Entries</div></div>
        {!data.audit.chain_intact && (
          <div className="card bad">
            <div className="num">{data.audit.first_broken_id}</div>
            <div className="lbl">First broken id</div>
          </div>
        )}
      </div>

      <h2>Recent analyses</h2>
      <div className="panel">
        <table>
          <thead><tr><th>Host</th><th>Status</th><th>Ruleset</th><th>Findings</th><th>Finished</th></tr></thead>
          <tbody>
            {!tasks?.analyses?.length ? (
              <tr><td colSpan={5} className="empty">No analyses yet.</td></tr>
            ) : tasks.analyses.map((a) => (
              <tr key={a.id}>
                <td className="mono">{a.hostname}</td>
                <td><span className={`status-pill status-${a.status}`}>{a.status}</span></td>
                <td className="mono">{a.ruleset_version || "—"}</td>
                <td>{a.finding_count ?? "—"}</td>
                <td className="muted mono">
                  {a.finished_at ? new Date(a.finished_at).toISOString().slice(0, 19) + "Z" : "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <p className="muted" style={{ marginTop: 18, fontSize: 12 }}>
        Probes run inside the enclave against the live services. Host-level diagnostics
        (<span className="mono">troubleshooting/diagnose.sh</span>) are run on the host by an
        operator — reaching them from the web tier would require the container runtime
        socket, which the segmentation model does not permit.
      </p>
    </>
  );
}
