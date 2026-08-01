/**
 * Re-analysis diff — what a newer ruleset finds in a capture that an older one missed.
 *
 * This is the payoff for retaining captures and versioning rulesets. Without it a second
 * analysis is just another opaque result list and the gain is invisible.
 *
 * Findings are matched on type and detail, deliberately not on offset: the same artifact
 * sits at a different address in a different image, and matching on offset would report
 * everything as simultaneously removed and added.
 */
import { useEffect, useState } from "react";
import { useParams, useSearchParams } from "react-router-dom";
import { api } from "../api.js";
import { Loading } from "../components/common.jsx";

const SEV_CLASS = {
  Critical: "sev-high", High: "sev-high", Medium: "sev-medium", Low: "muted",
};

function Rows({ items, sign, cls }) {
  if (!items.length) return <div className="empty">none</div>;
  return (
    <table>
      <thead><tr><th style={{ width: 24 }}></th><th>Type</th><th>Severity</th><th>Detail</th></tr></thead>
      <tbody>
        {items.map((f, i) => (
          <tr key={i}>
            <td className={cls} style={{ fontWeight: 700 }}>{sign}</td>
            <td>{f.finding_type}</td>
            <td className={SEV_CLASS[f.severity] || ""}>{f.severity}</td>
            <td className="muted">{f.detail}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default function AnalysisDiff() {
  const { captureId } = useParams();
  const [params, setParams] = useSearchParams();
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  const a = params.get("a") || "";
  const b = params.get("b") || "";

  useEffect(() => {
    const qs = new URLSearchParams();
    if (a) qs.set("a", a);
    if (b) qs.set("b", b);
    setData(null);
    setError(null);
    api.analysisDiff(captureId, qs.toString() ? `?${qs}` : "")
      .then(setData)
      .catch((e) => setError(e.message));
  }, [captureId, a, b]);

  if (error) return (<><h1>Re-analysis diff</h1><div className="empty">Error: {error}</div></>);
  if (!data) return (<><h1>Re-analysis diff</h1><Loading /></>);

  if (!data.comparable) {
    return (
      <>
        <h1>Re-analysis diff</h1>
        <div className="empty">
          {data.reason}. Re-analyze this capture to compare rulesets.
        </div>
      </>
    );
  }

  const pick = (name, value) =>
    setParams((p) => { p.set(name, value); return p; });

  return (
    <>
      <h1>Re-analysis diff</h1>
      <p className="page-sub mono">{data.object_key}</p>

      <div className="table-controls">
        <label className="muted">Baseline</label>
        <select value={String(data.base.id)} aria-label="Baseline analysis run"
                onChange={(e) => pick("a", e.target.value)}>
          {data.runs.map((r) => (
            <option key={r.id} value={r.id}>ruleset {r.ruleset_version || "—"} (#{r.id})</option>
          ))}
        </select>
        <label className="muted">Compared to</label>
        <select value={String(data.head.id)} aria-label="Comparison analysis run"
                onChange={(e) => pick("b", e.target.value)}>
          {data.runs.map((r) => (
            <option key={r.id} value={r.id}>ruleset {r.ruleset_version || "—"} (#{r.id})</option>
          ))}
        </select>
      </div>

      <div className="cards">
        <div className="card bad">
          <div className="num">+{data.added.length}</div>
          <div className="lbl">Newly detected</div>
        </div>
        <div className="card">
          <div className="num">−{data.removed.length}</div>
          <div className="lbl">No longer reported</div>
        </div>
        <div className="card warn">
          <div className="num">{data.changed.length}</div>
          <div className="lbl">Severity changed</div>
        </div>
        <div className="card">
          <div className="num">{data.unchanged}</div>
          <div className="lbl">Unchanged</div>
        </div>
        <div className="card">
          <div className="num" style={{ fontSize: 18 }}>
            {data.base.ruleset_version} → {data.head.ruleset_version}
          </div>
          <div className="lbl">Ruleset</div>
        </div>
      </div>

      <h2>Newly detected</h2>
      <p className="page-sub">
        Present in ruleset {data.head.ruleset_version}, absent in {data.base.ruleset_version} —
        the evidence was always in the capture; only the detection is new.
      </p>
      <div className="panel"><Rows items={data.added} sign="+" cls="sev-high" /></div>

      <h2>No longer reported</h2>
      <div className="panel"><Rows items={data.removed} sign="−" cls="muted" /></div>

      <h2>Severity changed</h2>
      <div className="panel">
        {data.changed.length === 0 ? <div className="empty">none</div> : (
          <table>
            <thead><tr><th>Type</th><th>Was</th><th>Now</th><th>Detail</th></tr></thead>
            <tbody>
              {data.changed.map((c, i) => (
                <tr key={i}>
                  <td>{c.finding_type}</td>
                  <td className="muted">{c.from_severity}</td>
                  <td className={SEV_CLASS[c.to_severity] || ""}>{c.to_severity}</td>
                  <td className="muted">{c.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
