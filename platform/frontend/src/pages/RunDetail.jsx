import { Fragment, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api.js";
import { can, useAuth } from "../auth.jsx";
import { useData, Loading, Empty, verdictBadge } from "../components/common.jsx";
import DataTable from "../components/DataTable.jsx";

function fmtBytes(n) {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(n) / Math.log(1024));
  return `${(n / Math.pow(1024, i)).toFixed(1)} ${u[i]}`;
}

/**
 * The engine's reasoning, whether for a process verdict or an attack chain.
 *
 * Both open with the conclusion — the verdict and the arithmetic behind it, or the lineage
 * and the stages observed — and then enumerate everything that fed it. That enumeration is
 * unbounded: a root carrying a full-image YARA sweep accumulates over a thousand entries,
 * and the engine writes them into the same string. So the conclusion is always shown and
 * the supporting detail is collapsed behind a count.
 *
 * The two formats differ in how they separate the parts, so neither is assumed: the
 * conclusion is the leading lines, and the detail is everything from the first indented
 * bracketed entry onwards, which is how the engine writes both.
 */
function Rationale({ text, pid, label = "contributing signal" }) {
  const [open, setOpen] = useState(false);
  if (!text) return <span className="muted">Nothing recorded.</span>;

  const lines = text.split("\n");
  const first = lines.findIndex((l) => /^\s+\[/.test(l));
  const head = (first === -1 ? lines : lines.slice(0, first)).join("\n").trim();
  const detail = (first === -1 ? [] : lines.slice(first))
    .map((l) => l.trim()).filter(Boolean);

  return (
    <div className="rationale">
      <div className="rationale-conclusion">{head || text.slice(0, 400)}</div>
      {detail.length > 0 && (
        <>
          <button className="linkish" onClick={() => setOpen(!open)}
                  aria-expanded={open} aria-controls={`detail-${pid}`}>
            {open ? "Hide" : "Show"} {detail.length} {label}{detail.length === 1 ? "" : "s"}
          </button>
          {open && (
            <ul id={`detail-${pid}`} className="rationale-signals">
              {detail.slice(0, 200).map((s, i) => <li key={i}>{s}</li>)}
              {detail.length > 200 && (
                <li className="muted">…and {detail.length - 200} more.</li>
              )}
            </ul>
          )}
        </>
      )}
    </div>
  );
}

function retentionPill(status) {
  const map = {
    retained: ["Retained (evidence)", "sev-high"],
    legal_hold: ["Legal hold", "sev-high"],
    purged: ["Purged from storage", "muted"],
    pending: ["Pending analysis", "sev-medium"],
  };
  const [label, cls] = map[status] || [status, "muted"];
  return <span className={cls} style={{ fontSize: 12 }}>{label}</span>;
}

function MemoryCapture({ cap, onReanalyze }) {
  const { user } = useAuth();
  const [busy, setBusy] = useState(false);
  const purged = cap.retention_status === "purged";
  const doReanalyze = async () => {
    setBusy(true);
    try { await api.reanalyze(cap.id); setTimeout(onReanalyze, 1500); }
    finally { setBusy(false); }
  };
  const doPurge = async () => {
    setBusy(true);
    try { await api.purgeCapture(cap.id, "admin manual purge"); setTimeout(onReanalyze, 800); }
    finally { setBusy(false); }
  };
  return (
    <div className="panel" style={{ padding: 16 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div>
          <span className="mono">{cap.object_key}</span>{" "}
          {cap.is_synthetic && <span className="pill-synthetic">SYNTHETIC SAMPLE</span>}
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          {/* Only meaningful once a capture has been analyzed more than once. */}
          {(cap.analyses?.length || 0) > 1 && (
            <Link className="btn" to={`/captures/${cap.id}/diff`}>Compare analyses</Link>
          )}
          {can(user, "analyst", "admin") && !purged && (
            <button className="btn" onClick={doReanalyze} disabled={busy}>
              {busy ? "Queued…" : "Re-analyze"}
            </button>
          )}
          {can(user, "admin") && !purged && (
            <button className="btn" style={{ background: "var(--bad)" }} onClick={doPurge} disabled={busy}>
              Purge
            </button>
          )}
        </div>
      </div>
      <dl className="kv" style={{ marginTop: 12 }}>
        <dt>Store</dt><dd>{cap.store_backend} · {cap.bucket}</dd>
        <dt>Size</dt><dd>{fmtBytes(cap.size_bytes)}</dd>
        <dt>Format / tool</dt><dd>{cap.image_format} · {cap.capture_tool || "—"}</dd>
        <dt>Retention</dt><dd>{retentionPill(cap.retention_status)}{cap.retention_reason ? ` · ${cap.retention_reason}` : ""}</dd>
        <dt>SHA-256</dt><dd className="mono">{cap.sha256 || "—"}</dd>
      </dl>

      <h2 style={{ marginTop: 18 }}>Memory Analysis ({cap.analyses?.length || 0} run{cap.analyses?.length === 1 ? "" : "s"})</h2>
      {(!cap.analyses || cap.analyses.length === 0) ? <Empty>No analysis yet.</Empty> :
        cap.analyses.map((a) => (
          <div key={a.id} style={{ marginBottom: 14 }}>
            <div className="muted" style={{ marginBottom: 6 }}>
              #{a.id} · {a.engine} v{a.engine_version || "?"} · ruleset {a.ruleset_version} ·{" "}
              <span className={`status-${a.status}`}>{a.status}</span>
              {a.error && <span className="sev-high"> · {a.error}</span>}
            </div>
            {a.summary && Object.keys(a.summary).length > 0 && (
              <div style={{ marginBottom: 8 }}>
                {Object.entries(a.summary).map(([k, v]) => (
                  <span className="tag" key={k}>{k}: {String(v)}</span>
                ))}
              </div>
            )}
            {a.top_findings?.length > 0 && cap.is_synthetic && (
              /* The capture badge is easy to scroll past, and these rows read exactly like
                 real detections — a C2 URL, a reverse-shell token, a routable address. They
                 are the sample's planted content. Say so next to the findings themselves,
                 not only beside the capture. */
              <p className="pill-synthetic" style={{ display: "inline-block", marginBottom: 8 }}>
                Planted content from a synthetic sample — not observations of this host, and
                excluded from its compromise assessment.
              </p>
            )}
            {a.top_findings?.length > 0 && (
              <table>
                <thead><tr><th>Type</th><th>Severity</th><th>Detail</th><th>Offset</th></tr></thead>
                <tbody>
                  {a.top_findings.map((f) => (
                    <tr key={f.id}>
                      <td>{f.finding_type}</td>
                      <td className={`sev-${(f.severity || "").toLowerCase()}`}>{f.severity}</td>
                      <td className="mono" style={{ fontSize: 12 }}>{f.detail}</td>
                      <td className="mono">{f.offset ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        ))}
    </div>
  );
}

export default function RunDetail() {
  const { id } = useParams();
  // A run changes while it is being looked at: a memory pass finishes, findings are
  // promoted, the engine adjudicates. Refreshing means an analyst watching a host sees
  // that happen instead of reading a page that quietly went out of date.
  const { data, error, reload } = useData(() => api.run(id), [id], { refreshMs: 20000 });
  // Adjudication is the investigation engine's output, stored per process when the
  // analysis ran. It is fetched separately from the run summary because it is the surface
  // an analyst works from, and it is bounded where the finding list is not.
  const { data: adj } = useData(() => api.runAdjudication(id), [id], { refreshMs: 20000 });
  // One chain's events at a time — the list only carries counts.
  const [chain, setChain] = useState(null);
  const openChain = (rootPid) =>
    api.runAdjudicationChain(id, rootPid).then(setChain).catch(() => setChain(null));
  if (!data) return <Loading error={error} />;
  return (
    <>
      <h1>{data.host.hostname}</h1>
      <p className="page-sub">
        Run <span className="mono">{data.stamp || data.id}</span> ·{" "}
        <span className={`status-${data.overall_status}`}>{data.overall_status || "—"}</span> ·{" "}
        {data.tp_count} TP · {data.custody_verified ? "custody ✓" : "custody unverified"}
      </p>

      <h2>Findings</h2>
      {!data.finding_summary ? <Empty>No findings.</Empty> : (
        <>
          <div className="cards">
            <div className="card">
              <div className="num">{data.finding_summary.total}</div>
              <div className="lbl">Findings</div>
            </div>
            {/* Nothing has judged these yet. This is the number that should fall to zero
                once an analysis has run. */}
            <div className={`card ${data.finding_summary.needs_adjudication ? "warn" : ""}`}>
              <div className="num">{data.finding_summary.needs_adjudication}</div>
              <div className="lbl">Not yet judged</div>
            </div>
            {/* The engine judged these and could not conclude. They are worked, not
                ignored — but the capture alone does not settle them. */}
            <div className="card">
              <div className="num">{data.finding_summary.awaiting_corroboration || 0}</div>
              <div className="lbl">Awaiting corroboration</div>
            </div>
            <div className="card bad">
              <div className="num">{data.finding_summary.by_verdict?.["True Positive"] || 0}</div>
              <div className="lbl">True positive</div>
            </div>
            <div className="card">
              <div className="num">{data.finding_summary.by_source?.memory || 0}</div>
              <div className="lbl">From memory</div>
            </div>
            <div className="card">
              <div className="num">{data.finding_summary.by_source?.collector || 0}</div>
              <div className="lbl">From collector</div>
            </div>
          </div>

          {/* Adjudication first. A rule name is not a verdict; the engine's judgement of a
              process — what converged on it and why — is what an analyst acts on. */}
          <h2>Adjudication</h2>
          {!adj ? <div className="muted">Loading…</div> :
           !adj.adjudicated ? (
            <Empty>
              No adjudication for this host yet. It runs automatically when a memory
              analysis completes; a reduced-depth pass produces no report folder to
              adjudicate.
            </Empty>
          ) : (
            <>
              <p className="page-sub">
                The investigation engine judged {adj.summary.total_pids} process
                {adj.summary.total_pids === 1 ? "" : "es"}:{" "}
                <strong className="sev-high">{adj.summary.true_positive} true positive</strong>,{" "}
                {adj.summary.undetermined} undetermined, {adj.summary.false_positive} false
                positive, {adj.summary.noise_closed} closed as noise.
                {adj.summary.potential_misses > 0 && (
                  <> {adj.summary.potential_misses} disagree with the on-host adjudication.</>
                )}
              </p>
              <div className="panel">
                <table>
                  <thead><tr>
                    <th scope="col">PID</th><th scope="col">Process</th>
                    <th scope="col">Verdict</th><th scope="col">Weight</th>
                    <th scope="col">Agreed on by</th><th scope="col">Signals</th>
                  </tr></thead>
                  <tbody>
                    {adj.processes.map((p) => (
                      /* Two rows per process: the verdict, then the reasoning beneath it
                         at full width. The rationale is prose — on a busy PID it runs to
                         thousands of words as the engine lists every signal it weighed —
                         and inside a cell it forces the row taller than the screen and
                         squeezes the columns that identify the process to nothing. */
                      <Fragment key={p.id}>
                        <tr className="verdict-row">
                          <td className="mono">{p.pid}</td>
                          <td className="mono">{p.process || "—"}</td>
                          <td className={p.engine_label === "True Positive" ? "sev-high"
                                       : p.engine_label === "Undetermined" ? "sev-medium" : ""}>
                            {p.engine_label}
                          </td>
                          <td>{p.positive_weight}</td>
                          {/* The engine reports sources as a count per detection source —
                              "memory ×9" says nine memory signals landed on this PID. */}
                          <td>
                            {Object.entries(p.sources || {})
                                   .map(([src, n]) => `${src} ×${n}`).join(", ") || "—"}
                          </td>
                          <td>
                            {p.positive_dims?.length > 0
                              ? `${p.positive_dims.length} positive`
                              : <span className="muted">none positive</span>}
                          </td>
                        </tr>
                        <tr className="rationale-row">
                          <td colSpan={6}>
                            <Rationale text={p.rationale} pid={p.pid} />
                            {p.mitre?.length > 0 && (
                              <div className="facet-meta">
                                {(Array.isArray(p.mitre) ? p.mitre : [p.mitre]).join(", ")}
                              </div>
                            )}
                          </td>
                        </tr>
                      </Fragment>
                    ))}
                  </tbody>
                </table>
              </div>
              {adj.process_count > adj.processes.length && (
                <p className="page-sub">
                  Showing {adj.processes.length} of {adj.process_count} adjudicated processes.
                </p>
              )}
              {adj.attack_chains?.length > 0 && (
                <>
                  <h2>Attack chains</h2>
                  <p className="page-sub">
                    Lineage the engine reconstructed across the findings — the sequence, not
                    the individual hits.
                  </p>
                  <div className="panel">
                    <table>
                      <thead><tr>
                        <th scope="col">Root</th><th scope="col">Verdict</th>
                        <th scope="col">Stages</th><th scope="col">Events</th>
                      </tr></thead>
                      <tbody>
                        {adj.attack_chains.map((c) => (
                          /* Same shape as the verdicts above: the chain on one row, its
                             narrative on the next at full width. The engine writes every
                             event it correlated into that narrative, so on a busy root it
                             is thousands of lines and cannot live in a column. */
                          <Fragment key={c.root_pid}>
                            <tr className="verdict-row">
                              <td className="mono">{c.root_process} ({c.root_pid})</td>
                              <td className={c.verdict === "TRUE_POSITIVE" ? "sev-high" : ""}>
                                {c.verdict}
                              </td>
                              <td>{(c.stages_present || []).join(" → ")}</td>
                              <td>
                                {/* Events are fetched per chain: one chain on a real
                                    capture held over a thousand. */}
                                <button className="linkish" onClick={() => openChain(c.root_pid)}>
                                  {c.event_count}
                                </button>
                              </td>
                            </tr>
                            <tr className="rationale-row">
                              <td colSpan={4}>
                                <Rationale text={c.narrative} pid={`chain-${c.root_pid}`}
                                           label="event" />
                              </td>
                            </tr>
                          </Fragment>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  {chain && (
                    <>
                      <h3>
                        Chain events — {chain.root_process} ({chain.root_pid})
                        <button className="linkish" onClick={() => setChain(null)}>close</button>
                      </h3>
                      <p className="page-sub">
                        Lineage: {(chain.lineage || []).join(" → ") || "—"}
                      </p>
                      <div className="panel scroll-y">
                        <table>
                          <thead><tr>
                            <th scope="col">When</th><th scope="col">PID</th>
                            <th scope="col">Process</th><th scope="col">Stage</th>
                            <th scope="col">Source</th><th scope="col">Description</th>
                          </tr></thead>
                          <tbody>
                            {(chain.events || []).slice(0, 500).map((e, i) => (
                              <tr key={i}>
                                <td className="mono">{e.timestamp || "—"}</td>
                                <td className="mono">{e.pid}</td>
                                <td className="mono">{e.process}</td>
                                <td>{e.stage}</td>
                                <td>{e.source}</td>
                                <td className="wrap">{e.description}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                      {(chain.events || []).length > 500 && (
                        <p className="page-sub">
                          Showing the first 500 of {chain.events.length} events.
                        </p>
                      )}
                    </>
                  )}
                </>
              )}
            </>
          )}

          <h2>Highest-priority findings</h2>
          <p className="page-sub">
            Confirmed and probable first. The full set is paginated —{" "}
            <Link to={`/findings?run=${data.id}`}>open all {data.finding_summary.total} findings</Link>.
          </p>
          <div className="panel">
            <table>
              <thead><tr>
                <th scope="col">Type</th><th scope="col">Target</th>
                <th scope="col">Verdict</th><th scope="col">Source</th>
              </tr></thead>
              <tbody>
                {(data.top_findings || []).map((f) => (
                  <tr key={f.id}>
                    <td>{f.finding_type}</td>
                    <td className="mono">{f.target}</td>
                    <td>{verdictBadge(f.verdict)}</td>
                    <td>{f.source}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      <h2>Memory Captures ({data.captures?.length || 0})</h2>
      {(!data.captures || data.captures.length === 0) ? <Empty>No captures.</Empty> :
        data.captures.map((c) => <MemoryCapture key={c.id} cap={c} onReanalyze={reload} />)}

      <h2>IOCs ({data.iocs?.length || 0})</h2>
      {(!data.iocs || data.iocs.length === 0) ? <Empty>No IOCs.</Empty> : (
        <DataTable
          rows={data.iocs}
          searchPlaceholder="Search IOCs…"
          columns={[
            { key: "ioc_type", label: "Type", filter: true },
            { key: "value", label: "Value", mono: true },
          ]}
        />
      )}
    </>
  );
}
