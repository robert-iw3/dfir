import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api.js";
import { IndicatorSpread } from "../components/charts.jsx";

export default function IocSearch() {
  // ?q= seeds and RUNS the search: charts drill here by URL, and a drill that lands on an
  // empty form is a drill that did not happen. The URL stays the reproducible record.
  const [params, setParams] = useSearchParams();
  const [q, setQ] = useState(params.get("q") || "");
  const [res, setRes] = useState(null);
  const [busy, setBusy] = useState(false);

  const run = async (term) => {
    if (!term.trim()) return;
    setBusy(true);
    try { setRes(await api.iocSearch(term.trim())); }
    finally { setBusy(false); }
  };
  useEffect(() => {
    const seeded = params.get("q") || "";
    setQ(seeded);
    if (seeded) run(seeded);
  }, [params]);

  // The spread for whichever indicator the analyst opened: where else it appears, and
  // whether that makes it campaign-specific or environment.
  const [spread, setSpread] = useState(null);
  const openSpread = async (row) => {
    setSpread(null);
    try { setSpread(await api.iocSpread(row.ioc_type, row.value)); }
    catch { setSpread({ error: true }); }
  };

  const search = async (e) => {
    e.preventDefault();
    if (!q.trim()) return;
    setParams(q.trim() === (params.get("q") || "") ? params : { q: q.trim() });
    await run(q);
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
              <thead><tr><th>Type</th><th>Value</th><th>Host</th><th>Investigation</th><th>Hosts</th><th></th></tr></thead>
              <tbody>
                {res.results.map((r, i) => (
                  <tr key={i}>
                    <td>{r.ioc_type}</td>
                    <td className="mono">{r.value}</td>
                    <td className="mono">{r.hostname}</td>
                    <td><Link to={`/investigations/${r.investigation_id}`}>{r.investigation}</Link></td>
                    <td>{r.host_count > 1 ? <span className="sev-high">{r.host_count} ⚠</span> : r.host_count}</td>
                    <td>
                      <button className="linkish" onClick={() => openSpread(r)}>
                        where else?</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      )}
      {spread && (
        <div className="panel">
          <h2>Where else this appears</h2>
          {spread.error ? (
            <p className="muted">The spread could not be read for this indicator.</p>
          ) : (
            <>
              <p className="page-sub">
                <span className="mono">{spread.ioc_type}: {spread.value}</span> —{" "}
                {spread.host_count} host(s) across {spread.investigation_count}{" "}
                investigation(s), {spread.total_sightings} sighting(s).
              </p>
              <IndicatorSpread spread={spread} />
            </>
          )}
        </div>
      )}
    </>
  );
}
