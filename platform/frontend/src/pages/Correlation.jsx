/**
 * Cross-host correlation — the network-wide picture of an intrusion.
 *
 * Everything shown here is derived from collected evidence and held in a separate store,
 * so the header states when it was computed and by which algorithm version. A correlated
 * conclusion is never presented as if it were collected fact.
 */
import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api.js";
import { useData, Loading } from "../components/common.jsx";
import AttackGraph from "../components/AttackGraph.jsx";
import { can, useAuth } from "../auth.jsx";
import { Time, usePrefs, formatTime } from "../components/prefs.jsx";



export default function Correlation() {
  const { user } = useAuth();
  const { zone } = usePrefs();
  const [params, setParams] = useSearchParams();
  const { data: investigations } = useData(() => api.investigations());

  // View state lives in the URL so a correlated view can be shared or bookmarked.
  const invId = params.get("inv") || "";
  const campaignId = params.get("campaign") || "";
  const host = params.get("host") || "";

  const [corr, setCorr] = useState(null);
  const [graph, setGraph] = useState(null);
  const [timeline, setTimeline] = useState(null);
  const [busy, setBusy] = useState(false);
  const { data: indicators } = useData(() => api.sharedIndicators());

  const list = investigations?.results || investigations || [];

  useEffect(() => {
    if (!invId && list.length) {
      setParams((p) => { p.set("inv", String(list[0].id)); return p; }, { replace: true });
    }
  }, [list, invId, setParams]);

  useEffect(() => {
    if (!invId) return;
    setCorr(null); setGraph(null); setTimeline(null);
    api.correlation(invId).then((c) => {
      setCorr(c);
      const first = c.campaigns?.[0];
      if (first && !campaignId) {
        setParams((p) => { p.set("campaign", String(first.id)); return p; }, { replace: true });
      }
    }).catch(() => setCorr({ correlated: false, campaigns: [] }));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [invId]);

  useEffect(() => {
    if (!campaignId) return;
    api.campaignGraph(campaignId).then(setGraph).catch(() => setGraph(null));
    api.campaignTimeline(campaignId).then(setTimeline).catch(() => setTimeline(null));
  }, [campaignId]);

  const recompute = async () => {
    setBusy(true);
    try {
      await api.recorrelate(invId);
      const c = await api.correlation(invId);
      setCorr(c);
      if (c.campaigns?.[0]) {
        setParams((p) => { p.set("campaign", String(c.campaigns[0].id)); return p; });
      }
    } finally {
      setBusy(false);
    }
  };

  const setParam = (k, v) =>
    setParams((p) => { v ? p.set(k, v) : p.delete(k); return p; });

  const campaign = corr?.campaigns?.find((c) => String(c.id) === String(campaignId));

  return (
    <>
      <h1>Correlation</h1>
      <p className="page-sub">
        The multi-host picture derived from collected evidence — where an intrusion started,
        how it moved, and what it reached.
      </p>

      <div className="table-controls">
        <select value={invId} onChange={(e) => { setParams(new URLSearchParams({ inv: e.target.value })); }}>
          {list.map((i) => <option key={i.id} value={i.id}>{i.name}</option>)}
        </select>
        {corr?.campaigns?.length > 1 && (
          <select value={campaignId} onChange={(e) => setParam("campaign", e.target.value)}>
            {corr.campaigns.map((c) => (
              <option key={c.id} value={c.id}>{c.label} — {c.host_count} hosts</option>
            ))}
          </select>
        )}
        {can(user, "analyst", "admin") && (
          <button className="btn" onClick={recompute} disabled={busy}>
            {busy ? "Recomputing…" : "Recompute"}
          </button>
        )}
        {corr?.correlated && (
          <span className="table-count">
            computed {formatTime(corr.computed_at, zone)} · algorithm {corr.algorithm_version}
          </span>
        )}
      </div>

      {!corr ? <Loading /> : !corr.correlated ? (
        <div className="empty">
          Not correlated yet. Run a recompute to derive the multi-host picture.
        </div>
      ) : corr.campaigns.length === 0 ? (
        <div className="empty">
          No campaign found — no host in this investigation shares intrusion evidence with another.
        </div>
      ) : (
        <>
          {campaign && (
            <div className="cards">
              <div className="card crit">
                <div className="num" style={{ fontSize: 20 }}>{campaign.patient_zero || "—"}</div>
                <div className="lbl">Entry point</div>
              </div>
              <div className="card">
                <div className="num" style={{ fontSize: 20 }}>{campaign.initial_vector || "—"}</div>
                <div className="lbl">Initial vector</div>
              </div>
              <div className="card bad">
                <div className="num">{campaign.host_count}</div>
                <div className="lbl">Hosts affected</div>
              </div>
              <div className="card">
                <div className="num" style={{ fontSize: 20 }}>{campaign.confidence}</div>
                <div className="lbl">Confidence</div>
              </div>
            </div>
          )}

          <h2>Attack graph</h2>
          {graph ? (
            <AttackGraph nodes={graph.nodes} edges={graph.edges} selected={host}
                         onSelect={(h) => setParam("host", h === host ? "" : h)} />
          ) : <Loading />}

          {host && graph && (
            <>
              <h2>{host}</h2>
              <div className="panel" style={{ padding: 12 }}>
                {(() => {
                  const n = graph.nodes.find((x) => x.hostname === host);
                  if (!n) return <div className="muted">Not in this campaign.</div>;
                  const inbound = graph.edges.filter((e) => e.dst === host);
                  const outbound = graph.edges.filter((e) => e.src === host);
                  return (
                    <>
                      <div className="muted" style={{ marginBottom: 8 }}>
                        role <span className="tag">{n.role}</span> · {n.tp_count} true positives ·
                        techniques {n.techniques?.join(", ") || "—"}
                      </div>
                      <div>Reached by: {inbound.length
                        ? inbound.map((e) => `${e.src} via ${e.protocol} as ${e.account}`).join("; ")
                        : n.role === "patient_zero" ? "initial access" : "not observed"}</div>
                      <div>Moved to: {outbound.length
                        ? outbound.map((e) => e.dst).join(", ") : "—"}</div>
                    </>
                  );
                })()}
              </div>
            </>
          )}

          <h2>Timeline</h2>
          {timeline ? (
            <div className="panel">
              <table>
                <thead>
                  <tr><th>When</th><th>Host</th><th>Event</th><th>ATT&CK</th></tr>
                </thead>
                <tbody>
                  {timeline.events.length === 0 ? (
                    <tr><td colSpan={4} className="empty">No timed events.</td></tr>
                  ) : timeline.events.map((e, i) => (
                    <tr key={i} className={e.host === host ? "row-on" : ""}>
                      <td><Time value={e.at} /></td>
                      <td>{e.host}</td>
                      <td>{e.detail}</td>
                      <td className="mono">{e.technique || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : <Loading />}

          <h2>Shared indicators across hosts</h2>
          <div className="panel">
            <table>
              <thead><tr><th>Type</th><th>Value</th><th>Hosts</th><th>Seen on</th></tr></thead>
              <tbody>
                {!indicators?.indicators?.length ? (
                  <tr><td colSpan={4} className="empty">No indicator spans more than one host.</td></tr>
                ) : indicators.indicators.slice(0, 25).map((ind, i) => (
                  <tr key={i}>
                    <td>{ind.kind}</td>
                    <td className="mono">{ind.value}</td>
                    <td>{ind.host_count}</td>
                    <td className="muted">{ind.hostnames.join(", ")}</td>
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
