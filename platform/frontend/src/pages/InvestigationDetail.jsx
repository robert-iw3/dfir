import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api } from "../api.js";
import { can, useAuth } from "../auth.jsx";
import { useData, Loading, Empty } from "../components/common.jsx";
import { StatTiles, KillChainChord } from "../components/charts.jsx";
import { CaseTree, CaseTags, CaseTasks } from "../components/casework.jsx";
import { CaseReports } from "../components/reports.jsx";
import { CaseActivity, PresenceBar, usePresence } from "../components/collab.jsx";

const NOTE_KINDS = [
  ["observation", "Observation"], ["analysis", "Analysis"], ["decision", "Decision"],
  ["action", "Action taken"], ["containment", "Containment"], ["eradication", "Eradication"],
  ["handoff", "Handoff"], ["request", "Request"],
];

// What each entry in the record came from. A reader needs to tell an analyst's opinion
// apart from a verdict change and from a reverse engineer's determination.
const ENTRY_LABEL = {
  note: "Note",
  reclassification: "Verdict change",
  region_analysis: "Reverse engineering",
  region_purge: "Evidence purged",
};

function NewEntry({ investigationId, hosts, onAdd }) {
  const { user } = useAuth();
  const [form, setForm] = useState({
    kind: "observation", summary: "", body: "", occurred_at: "", confidence: "", host: "",
  });
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value });

  const add = async () => {
    if (!form.body.trim()) return;
    setBusy(true); setErr("");
    try {
      await api.addNote({
        investigation: investigationId,
        kind: form.kind,
        summary: form.summary || undefined,
        body: form.body,
        // Sent as an instant so the server stores an unambiguous point in time.
        occurred_at: form.occurred_at ? new Date(form.occurred_at).toISOString() : null,
        confidence: form.confidence || "",
        host: form.host || null,
      });
      setForm({ kind: "observation", summary: "", body: "", occurred_at: "",
                confidence: "", host: "" });
      onAdd();
    } catch (e) { setErr(String(e.message || e)); }
    finally { setBusy(false); }
  };

  if (!can(user, "analyst", "admin")) return null;
  return (
    <div className="panel entry-form">
      <div className="entry-row">
        <label>
          Kind
          <select value={form.kind} onChange={set("kind")}>
            {NOTE_KINDS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select>
        </label>
        <label>
          Host
          <select value={form.host} onChange={set("host")}>
            <option value="">— whole investigation —</option>
            {hosts.map((h) => <option key={h.id} value={h.id}>{h.hostname}</option>)}
          </select>
        </label>
        <label>
          {/* When it happened, not when it was typed: an incident timeline built from
              record-creation times describes the responders, not the intrusion. */}
          Occurred at
          <input type="datetime-local" value={form.occurred_at} onChange={set("occurred_at")} />
        </label>
        <label>
          Confidence
          <select value={form.confidence} onChange={set("confidence")}>
            <option value="">—</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </label>
      </div>
      <input className="entry-summary" value={form.summary} onChange={set("summary")}
             placeholder="One-line summary — this is what appears on the timeline" />
      <textarea rows={3} value={form.body} onChange={set("body")}
                placeholder="What you observed, concluded or did, and what it rests on…" />
      {err && <p className="sev-high">{err}</p>}
      <button className="btn" onClick={add} disabled={busy || !form.body.trim()}>
        Add to record
      </button>
    </div>
  );
}

function CaseRecord({ investigationId, hosts, record, onChange }) {
  const { user } = useAuth();
  const [filter, setFilter] = useState("");
  const [retracting, setRetracting] = useState(null);
  const [reason, setReason] = useState("");

  const retract = async (id) => {
    await api.retractNote(id, reason);
    setRetracting(null); setReason(""); onChange();
  };

  const entries = (record?.entries || []).filter((e) => !filter || e.type === filter);
  return (
    <>
      <h2>Investigation record</h2>
      <p className="page-sub">
        Everything anyone recorded on this incident — analyst notes, verdict changes and
        their stated reasons, reverse-engineering determinations, and evidence disposals.
        {record?.summary?.total ? ` ${record.summary.total} entries from ` +
          `${Object.keys(record.summary.contributors).length} contributor(s).` : ""}
      </p>

      <NewEntry investigationId={investigationId} hosts={hosts} onAdd={onChange} />

      <div className="table-controls">
        <select value={filter} onChange={(e) => setFilter(e.target.value)}>
          <option value="">All entries</option>
          {Object.entries(ENTRY_LABEL).map(([v, l]) => (
            <option key={v} value={v}>
              {l}{record?.summary?.by_type?.[v] ? ` (${record.summary.by_type[v]})` : ""}
            </option>
          ))}
        </select>
      </div>

      {entries.length === 0 ? <Empty>Nothing recorded yet.</Empty> : (
        <div className="panel">
          <table>
            <thead><tr>
              <th scope="col">When</th><th scope="col">Entry</th><th scope="col">Who</th>
              <th scope="col">Host</th><th scope="col">What</th><th scope="col"></th>
            </tr></thead>
            <tbody>
              {entries.map((e) => (
                <tr key={`${e.type}-${e.id}`} className={e.retracted ? "muted" : ""}>
                  <td className="mono">
                    {new Date(e.at).toLocaleString()}
                    {e.at !== e.recorded_at && (
                      <div className="facet-meta">recorded {new Date(e.recorded_at).toLocaleString()}</div>
                    )}
                  </td>
                  <td>
                    <span className="tag">{ENTRY_LABEL[e.type] || e.type}</span>
                    {e.kind && e.type === "note" && <div className="facet-meta">{e.kind}</div>}
                  </td>
                  <td>{e.actor}{e.role && <div className="facet-meta">{e.role}</div>}</td>
                  <td className="mono">{e.host || "—"}</td>
                  <td className="wrap">
                    <strong>{e.summary}</strong>
                    {e.body && <div>{e.body}</div>}
                    {e.retracted && (
                      <div className="sev-high">Retracted — {e.retraction_reason}</div>
                    )}
                    {e.evidence?.length > 0 && (
                      <div className="facet-meta">
                        cites {e.evidence.length} finding{e.evidence.length === 1 ? "" : "s"}
                        {e.evidence[0]?.type ? `: ${e.evidence[0].type}` : ""}
                      </div>
                    )}
                  </td>
                  <td>
                    {e.type === "note" && !e.retracted && can(user, "analyst", "admin") && (
                      retracting === e.id ? (
                        <div className="search">
                          <input value={reason} onChange={(ev) => setReason(ev.target.value)}
                                 placeholder="Reason (10+ chars)" />
                          <button className="btn" disabled={reason.trim().length < 10}
                                  onClick={() => retract(e.id)}>Confirm</button>
                          <button className="linkish" onClick={() => setRetracting(null)}>cancel</button>
                        </div>
                      ) : (
                        <button className="linkish" onClick={() => setRetracting(e.id)}>retract</button>
                      )
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

export default function InvestigationDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { user } = useAuth();
  const { data, error, reload } = useData(() => api.investigation(id), [id]);
  // The record is assembled server-side across four sources, so it is fetched rather than
  // stitched together from what the investigation payload happens to embed.
  const { data: record, reload: reloadRecord } = useData(
    () => api.investigationRecord(id), [id]);
  // Server aggregates, never client sums over paged rows — the charts render what the
  // platform computed and every mark drills to the filtered table behind it.
  const { data: stats } = useData(() => api.investigationStats(id), [id]);
  const { data: coverage } = useData(() => api.investigationCoverage(id), [id]);
  // Above the loading guard: a hook after an early return runs on some renders and not
  // others, which React treats as a changed hook order and refuses.
  const here = usePresence(data?.id, `/investigations/${id}`);
  if (!data) return <Loading error={error} />;
  const runs = data.runs ?? [];
  // Hosts an entry can be filed against — the ones this investigation actually collected.
  const hosts = Array.from(
    new Map(runs.filter((r) => r.host).map((r) => [r.host.id, r.host])).values());

  const requestRescan = async (run) => {
    await api.requestRescan({
      host: run.host.id, investigation: data.id,
      baseline_run: run.id, kind: "eradication",
    });
    alert(`Rescan requested for ${run.host.hostname}. The broker will fulfill it and diff against this run.`);
  };
  const del = async () => {
    if (!confirm("Delete this investigation and all its data? Admin action, audit-logged.")) return;
    await api.deleteInvestigation(data.id);
    navigate("/investigations");
  };

  return (
    <>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "start" }}>
        <div>
          <h1>{data.name}</h1>
          <p className="page-sub">
            {data.incident_id && <>Incident <span className="mono">{data.incident_id}</span> · </>}
            {data.severity || "unspecified severity"} · {data.status}
          </p>
        </div>
        {can(user, "admin") && <button className="btn" style={{ background: "var(--bad)" }} onClick={del}>Delete</button>}
      </div>

      {/* Who else has this case open. Advisory: it changes nothing about what anyone may do. */}
      <PresenceBar here={here} />

      <h2>Shape of the intrusion</h2>
      <StatTiles tiles={stats && [
        { label: "Findings", value: stats.total_findings, accent: "var(--accent)",
          onOpen: () => navigate(`/findings?investigation=${id}`) },
        { label: "Confirmed", value: stats.confirmed_findings, accent: "var(--good)",
          sub: "true + likely true positive",
          onOpen: () => navigate(`/findings?investigation=${id}&verdict=${encodeURIComponent("True Positive,Likely True Positive")}`) },
        { label: "Indeterminate", value: stats.indeterminate_findings, accent: "var(--warn)",
          sub: "not decided — not confirmed",
          onOpen: () => navigate(`/findings?investigation=${id}&verdict=Indeterminate`) },
        { label: "Hosts affected", value: (stats.hosts || []).length, accent: "var(--accent-2, var(--accent))",
          onOpen: () => navigate("/hosts") },
        coverage && { label: "Never collected", value: (coverage.implicated_not_collected || []).length,
          accent: (coverage.implicated_not_collected || []).length ? "var(--bad)" : "var(--text-dim)",
          sub: "implicated by evidence" },
      ]} />

      <div className="panel" style={{ padding: 20 }}>
        <h3 style={{ margin: "0 0 4px" }}>Kill chain</h3>
        <p className="chart-note">
          Every host against every attack stage it reached. Ribbon width is how much of the
          evidence that pairing carries; stage color runs cool-to-hot as the intrusion
          progresses. Hover an arc to isolate it, click a ribbon for the findings behind it.
        </p>
        <KillChainChord stats={stats} investigationId={id} />
      </div>

      {(coverage?.implicated_not_collected || []).length > 0 && (
        <div className="panel" style={{ padding: 20 }}>
          <h3 style={{ margin: "0 0 4px" }}>Never collected</h3>
          <p className="chart-note">
            The evidence on other machines implicates these hosts and nobody collected them,
            so they have no row below and nothing here rests on their own data. This is the
            most expensive place in an investigation to be wrong.
          </p>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
            {coverage.implicated_not_collected.map((name) => (
              <span key={name} className="mono"
                    style={{ padding: "5px 10px", borderRadius: 6, fontSize: 12,
                             border: "1px dashed var(--bad)", color: "var(--bad)" }}>
                {name}</span>
            ))}
          </div>
        </div>
      )}

      <h2>Collection Runs</h2>
      {runs.length === 0 ? <Empty>No runs.</Empty> : (
        <div className="panel">
          <table>
            <thead>
              <tr><th>Host</th><th>Membership</th><th>Kind</th><th>Status</th><th>Compromised</th><th>TPs</th><th>Findings</th><th>Custody</th>{can(user, "analyst", "admin") && <th></th>}</tr>
            </thead>
            <tbody>
              {runs.map((r) => (
                <tr key={r.id}>
                  <td><Link to={`/runs/${r.id}`}>{r.host.hostname}</Link></td>
                  <td>{(() => {
                    // How certain this host's campaign membership is, from the same
                    // aggregate the chord reads — a host outside every campaign carries no
                    // claim rather than a low one.
                    const band = (stats?.hosts || [])
                      .find((h) => h.host === r.host.hostname)?.confidence_band || "";
                    const color = { confirmed: "var(--good)", probable: "var(--accent)",
                                    possible: "var(--warn)" }[band] || "var(--text-dim)";
                    return (
                      <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
                        <span style={{ width: 8, height: 8, borderRadius: 2, background: color }} />
                        <span style={{ color: band ? "var(--text)" : "var(--text-dim)" }}>
                          {band || "no claim"}</span>
                      </span>
                    );
                  })()}</td>
                  <td>{r.run_kind || "initial"}</td>
                  <td><span className={`status-pill status-${r.overall_status}`}>{r.overall_status || "—"}</span></td>
                  <td>{r.compromised ? <span className="sev-high">yes</span> : <span className="status-completed">no</span>}</td>
                  <td>{r.tp_count}</td>
                  <td>{r.finding_count}</td>
                  <td>{r.custody_verified ? <span className="status-completed">✓</span> : <span className="muted">—</span>}</td>
                  {can(user, "analyst", "admin") && (
                    <td><button className="btn" style={{ padding: "4px 10px", fontSize: 12 }} onClick={() => requestRescan(r)}>Rescan</button></td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <h2>Case tree</h2>
      <p className="page-sub">Everything collected on this case, in the shape it was collected.</p>
      <CaseTree investigationId={data.id} />

      <h2>Tags</h2>
      <CaseTags investigationId={data.id} canEdit={can(user, "analyst", "admin")} />

      <h2>Tasks</h2>
      <CaseTasks investigationId={data.id} canEdit={can(user, "analyst", "admin")} />

      <h2>Activity</h2>
      <p className="page-sub">
        Every recorded action on this case, read from the signed audit ledger itself.
      </p>
      <CaseActivity investigationId={data.id} />

      <h2>Reports</h2>
      <CaseReports investigationId={data.id}
                   canEdit={can(user, "analyst", "admin")}
                   canExport={Boolean(user?.may_export)} />

      <CaseRecord investigationId={data.id} hosts={hosts} record={record}
                  onChange={() => { reloadRecord(); reload(); }} />
    </>
  );
}
