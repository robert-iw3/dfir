import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api.js";

export default function IocSearch() {
  const [q, setQ] = useState("");
  const [res, setRes] = useState(null);
  const [busy, setBusy] = useState(false);

  const search = async (e) => {
    e.preventDefault();
    if (!q.trim()) return;
    setBusy(true);
    try { setRes(await api.iocSearch(q.trim())); }
    finally { setBusy(false); }
  };

  return (
    <>
      <h1>IOC Search</h1>
      <p className="page-sub">Cross-investigation indicator lookup. Indicators on more than one host rank first.</p>
      <form className="search" onSubmit={search}>
        <input value={q} onChange={(e) => setQ(e.target.value)}
               placeholder="IP, domain, hash, tool…" />
        <button className="btn" disabled={busy}>{busy ? "Searching…" : "Search"}</button>
      </form>
      {res && (
        res.results.length === 0 ? <div className="empty">No matches for “{res.query}”.</div> : (
          <div className="panel">
            <table>
              <thead><tr><th>Type</th><th>Value</th><th>Host</th><th>Investigation</th><th>Hosts</th></tr></thead>
              <tbody>
                {res.results.map((r, i) => (
                  <tr key={i}>
                    <td>{r.ioc_type}</td>
                    <td className="mono">{r.value}</td>
                    <td className="mono">{r.hostname}</td>
                    <td><Link to={`/investigations/${r.investigation_id}`}>{r.investigation}</Link></td>
                    <td>{r.host_count > 1 ? <span className="sev-high">{r.host_count} ⚠</span> : r.host_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      )}
    </>
  );
}
