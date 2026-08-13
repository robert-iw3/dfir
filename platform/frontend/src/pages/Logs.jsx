/**
 * Every tier's logs, readable from inside the platform.
 *
 * The point of this page is that troubleshooting must not require shell access to the host
 * running the containers — that access is precisely what the platform's design exists to
 * remove, and an operator who needs it to read a log will keep it for everything else.
 *
 * Three sources of truth, deliberately separate rather than merged into one stream:
 *   archive       what each tier wrote, moved to object storage and kept past the container
 *   requests      the API's own record of who called what and what it answered
 *   client errors what the browser reported about itself
 * Merging them would imply a single ordered timeline across four clocks that do not agree.
 */
import { useEffect, useState } from "react";
import { api } from "../api.js";

const TABS = [
  { id: "archive", label: "Shipped log archive" },
  { id: "requests", label: "API requests" },
  { id: "errors", label: "Browser errors" },
];

function bytes(n) {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i += 1; }
  return `${v.toFixed(v >= 10 || i === 0 ? 0 : 1)} ${u[i]}`;
}

function Archive() {
  const [sources, setSources] = useState(null);
  const [objects, setObjects] = useState(null);
  const [open, setOpen] = useState("");
  const [body, setBody] = useState(null);

  useEffect(() => {
    api.logSources().then(setSources).catch(() => setSources({ sources: [], available: false }));
  }, []);

  const pick = (source) => {
    setOpen(source);
    setBody(null);
    setObjects(null);
    api.logObjects(source).then(setObjects).catch(() => setObjects({ objects: [] }));
  };

  const read = (key) => {
    setBody({ loading: true });
    api.logObject(key).then(setBody).catch((e) => setBody({ error: String(e.message || e) }));
  };

  if (!sources) return <div className="empty">Reading the archive…</div>;
  if (!sources.available) {
    return (
      <div className="empty">
        No log archive yet. The shipper writes to <span className="mono">{sources.bucket}</span>{" "}
        once each tier has produced a log; this is empty on a stack that has just come up,
        not broken. {sources.detail ? <><br /><span className="mono">{sources.detail}</span></> : null}
      </div>
    );
  }

  return (
    <>
      <div className="panel">
        <table>
          <thead><tr><th>Source</th><th>Objects</th><th>Size</th><th>Latest</th><th /></tr></thead>
          <tbody>
            {sources.sources.map((s) => (
              <tr key={s.source} className={open === s.source ? "row-selected" : ""}>
                <td className="mono">{s.source}</td>
                <td>{s.objects}</td>
                <td>{bytes(s.bytes)}</td>
                <td className="mono">
                  {s.latest ? `${s.latest.replace("T", " ").slice(0, 19)}Z` : "—"}
                </td>
                <td><button className="btn-sm" onClick={() => pick(s.source)}>open</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {sources.sources.length === 0 && (
        <div className="empty">
          The bucket exists but holds nothing yet — the shipper runs on an interval.
        </div>
      )}

      {objects && (
        <>
          <h2>{open}</h2>
          <div className="panel scroll-y">
            <table>
              <thead><tr><th>Object</th><th>Size</th><th>Shipped</th><th /></tr></thead>
              <tbody>
                {objects.objects.map((o) => (
                  <tr key={o.key}>
                    <td className="mono">{o.key}</td>
                    <td>{bytes(o.bytes)}</td>
                    <td className="mono">
                      {o.at ? `${o.at.replace("T", " ").slice(0, 19)}Z` : "—"}
                    </td>
                    <td>
                      <button className="btn-sm" onClick={() => read(o.key)}>read</button>{" "}
                      <button className="btn-sm"
                              onClick={() => api.downloadBlob(api.logDownloadUrl(o.key),
                                                             o.key.replace(/\//g, "_"))}>
                        download
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {body && (
        <>
          <h2>
            {body.key || "Log"}{" "}
            {body.truncated && <span className="muted">· showing the last {bytes(body.bytes)}</span>}
          </h2>
          {body.loading && <div className="empty">Reading…</div>}
          {body.error && <div className="empty">{body.error}</div>}
          {body.note && <p className="page-sub">{body.note}</p>}
          {/* As text, never parsed: a log line is arbitrary content from arbitrary sources
              and must not be able to become markup in this origin. */}
          {body.text != null && <pre className="logview">{body.text}</pre>}
        </>
      )}
    </>
  );
}

function Requests() {
  const [rows, setRows] = useState(null);
  const [status, setStatus] = useState("");
  useEffect(() => {
    api.requestLog({ limit: 200, ...(status ? { status } : {}) })
      .then((d) => setRows(d.results || d.requests || []))
      .catch(() => setRows([]));
  }, [status]);
  if (!rows) return <div className="empty">Reading the request log…</div>;
  return (
    <>
      <div className="row" style={{ gap: 10, marginBottom: 12 }}>
        <label className="muted">
          Status{" "}
          <select value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">all</option>
            <option value="500">server errors</option>
            <option value="403">refused</option>
            <option value="404">not found</option>
          </select>
        </label>
      </div>
      <div className="panel scroll-y">
        <table>
          <thead>
            <tr><th>When</th><th>Who</th><th>Method</th><th>Path</th><th>Status</th><th>ms</th></tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id}>
                <td className="mono">
                  {(r.created_at || r.at || "").replace("T", " ").slice(0, 19)}Z
                </td>
                <td>{r.actor || r.user || <span className="muted">anonymous</span>}</td>
                <td className="mono">{r.method}</td>
                <td className="mono">{r.path}</td>
                <td className={r.status >= 500 ? "status-FAIL" : ""}>{r.status}</td>
                <td>{r.duration_ms ?? r.ms ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {rows.length === 0 && <div className="empty">Nothing recorded for this filter.</div>}
    </>
  );
}

function ClientErrors() {
  const [rows, setRows] = useState(null);
  useEffect(() => {
    api.clientErrors(100).then((d) => setRows(d.results || d.errors || []))
      .catch(() => setRows([]));
  }, []);
  if (!rows) return <div className="empty">Reading browser errors…</div>;
  if (!rows.length) return <div className="empty">No browser has reported an error.</div>;
  return (
    <div className="panel scroll-y">
      <table>
        <thead><tr><th>When</th><th>Who</th><th>Where</th><th>Error</th></tr></thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id}>
              <td className="mono">{(r.created_at || "").replace("T", " ").slice(0, 19)}Z</td>
              <td>{r.actor || <span className="muted">anonymous</span>}</td>
              <td className="mono">{r.where || r.path}</td>
              <td className="wrap">{r.message}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function Logs() {
  const [tab, setTab] = useState("archive");
  return (
    <>
      <h1>Logs</h1>
      <p className="page-sub">
        What every tier recorded, readable here rather than by shelling into the host.
        Operational records, not evidence — they are kept apart from it and are not
        custody-sealed. Reads and downloads are admin-only and audited.
      </p>
      <div className="row" style={{ gap: 8, marginBottom: 16 }}>
        {TABS.map((t) => (
          <button key={t.id} className="btn-sm" aria-pressed={tab === t.id}
                  style={tab === t.id ? { borderColor: "var(--accent)" } : undefined}
                  onClick={() => setTab(t.id)}>
            {t.label}
          </button>
        ))}
      </div>
      {tab === "archive" && <Archive />}
      {tab === "requests" && <Requests />}
      {tab === "errors" && <ClientErrors />}
    </>
  );
}
