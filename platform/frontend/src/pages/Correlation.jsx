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
import { EvidenceKindBars, RarityScatter, CohesionStrip } from "../components/charts.jsx";
import { can, useAuth } from "../auth.jsx";
import { Time, usePrefs, formatTime } from "../components/prefs.jsx";



// ATT&CK ids alone are a lookup task. The name is what makes a sequence readable as a story.
const TECHNIQUE_NAMES = {
  T1003: "Credential dumping", T1005: "Data from local system", T1014: "Rootkit",
  T1018: "Remote system discovery", T1021: "Remote services", T1027: "Obfuscated files",
  T1037: "Boot/logon script", T1041: "Exfiltration over C2",
  T1048: "Exfiltration over alternative protocol",
  T1053: "Scheduled task", T1057: "Process discovery",
  T1059: "Command interpreter", T1068: "Privilege escalation exploit", T1070: "Indicator removal",
  T1071: "Application layer protocol", T1078: "Valid accounts", T1087: "Account discovery",
  T1090: "Proxy", T1105: "Ingress tool transfer", T1110: "Brute force",
  T1190: "Exploit public-facing app", T1204: "User execution", T1486: "Data encrypted for impact",
  T1489: "Service stop", T1490: "Inhibit system recovery", T1496: "Resource hijacking",
  T1543: "Create/modify system process", T1547: "Boot/logon autostart", T1548: "Elevation control",
  T1550: "Alternate authentication", T1552: "Unsecured credentials", T1560: "Archive collected data",
  T1562: "Impair defenses", T1566: "Phishing", T1567: "Exfiltration over web service",
  T1568: "Dynamic resolution", T1573: "Encrypted channel",
};

const techniqueLabel = (id) =>
  TECHNIQUE_NAMES[id] ? `${id} ${TECHNIQUE_NAMES[id]}` : id;

// Component keys are storage names. These are what an analyst calls the same thing.
const COMPONENT_LABEL = {
  artifact_conventions: "Naming conventions",
  technique_ngrams: "Technique order",
  techniques: "Techniques",
  c2_pattern: "Movement",
  account_chain: "Accounts",
};

const SUBKEY_LABEL = {
  movement_protocols: "protocol",
  movement_techniques: "technique",
  beacon_kinds: "beacon",
  "account reuse": "reuse",
  domain: "domain",
};

/** "key: value" -> [label, value]; anything else -> [null, whole string]. */
function splitLabelled(item) {
  const text = asText(item);
  const at = text.indexOf(": ");
  if (at < 0) return [null, text];
  const head = text.slice(0, at);
  return [SUBKEY_LABEL[head] || head.replace(/_/g, " "), text.slice(at + 2)];
}

/**
 * Group a similarity rationale by component: [{key, label, score, items}].
 *
 * This is the evidence for saying two intrusions are the same actor, so it is grouped and
 * labelled rather than joined into one string.
 *
 * Written to survive any shape. Correlation supersedes rather than migrates, so a row from an
 * earlier algorithm version is still there to be read — `shared` was a dict for two components
 * before it was a list for all of them. A renderer that assumes today's shape throws on
 * yesterday's row, which unmounts the view and hides every campaign behind one stale record.
 */
function sharedByComponent(rationale) {
  const groups = [];
  for (const [key, comp] of Object.entries(rationale?.components || {})) {
    const shared = comp?.shared;
    let items = [];
    if (Array.isArray(shared)) {
      items = shared.map(asText);
    } else if (shared && typeof shared === "object") {
      // A row written before `shared` was a flat list everywhere. Still readable, by design.
      items = Object.entries(shared).map(
        ([k, v]) => `${k}: ${Array.isArray(v) ? v.join(", ") : asText(v)}`);
    } else if (shared) {
      items = [asText(shared)];
    }
    if (items.length) {
      groups.push({ key, label: COMPONENT_LABEL[key] || key.replace(/_/g, " "),
                    score: comp?.score, items });
    }
  }
  return groups;
}

function asText(v) {
  if (v === null || v === undefined) return "—";
  if (typeof v === "object") {
    try { return JSON.stringify(v); } catch { return String(v); }
  }
  return String(v);
}

/** What two campaigns share, grouped by component and strongest first. */
function SharedEvidence({ rationale }) {
  const groups = sharedByComponent(rationale);
  if (rationale?.declined) return <span className="muted">{rationale.declined}</span>;
  if (!groups.length) return <span className="muted">—</span>;
  const carried = rationale?.carried_by;
  return (
    <div style={{ display: "grid", gap: 4 }}>
      {groups
        .slice()
        .sort((a, b) => (b.score ?? 0) - (a.score ?? 0))
        .map((g) => (
          <div key={g.key} style={{ display: "flex", gap: 10, alignItems: "baseline" }}>
            <span style={{ minWidth: 132, flexShrink: 0 }}>
              {g.label}
              {g.key === carried && (
                <span className="muted" style={{ fontSize: "0.82em" }}> · strongest</span>
              )}
            </span>
            <span style={{ display: "flex", flexWrap: "wrap", gap: "3px 6px", minWidth: 0 }}>
              {g.items.map((item, i) => {
                const [sub, value] = splitLabelled(item);
                return (
                  <span key={`${g.key}-${i}`} className="tag">
                    {sub && <span className="muted">{sub} </span>}
                    {value}
                  </span>
                );
              })}
            </span>
          </div>
        ))}
    </div>
  );
}

/** A varying slot in a name shape — dimmed, so the literal text reads as the choice. */
function Slot({ children }) {
  return (
    <span className="muted" style={{ opacity: 0.75, fontStyle: "italic" }}>{children}</span>
  );
}

/**
 * A naming convention, with the fixed and varying parts told apart visually.
 *
 * A shape rendered as one string reads as a parse failure — the question it always drew was
 * "what is `<name>`?". The literal characters are the operator's habit and the slots are what
 * they change; showing them the same way hides the only thing the row is saying.
 */
function Shape({ shape }) {
  const parts = String(shape).split(/(<[a-z]+>)/g).filter(Boolean);
  return (
    <code>
      {parts.map((p, i) =>
        /^<[a-z]+>$/.test(p)
          ? <Slot key={i}>{p}</Slot>
          : <strong key={i}>{p}</strong>)}
    </code>
  );
}

/** A labelled fact with its value indented beside it, so the panel scans as a list. */
function Fact({ label, hint, children }) {
  return (
    <div style={{ display: "flex", gap: 12, marginTop: 10, alignItems: "baseline",
                  flexWrap: "wrap" }}>
      <div style={{ minWidth: 148, flexShrink: 0 }}>
        <strong>{label}</strong>
        {hint && <div className="muted" style={{ fontSize: "0.82em" }}>{hint}</div>}
      </div>
      <div style={{ flex: "1 1 320px", minWidth: 0 }}>{children}</div>
    </div>
  );
}

function TradecraftFacts({ fingerprint }) {
  // The ordered sequence where the engine recorded one; the id-sorted set is a fallback for
  // rows written before the order was kept, and is NOT an order — so it is not called one.
  const sequence = fingerprint.technique_sequence || [];
  const set = fingerprint.techniques || [];
  const conventions = fingerprint.artifact_conventions || [];
  const examples = fingerprint.convention_examples || {};
  const chain = fingerprint.account_chain || {};
  const protocols = fingerprint.c2_pattern?.movement_protocols || [];

  return (
    <div style={{ marginTop: 10 }}>
      <Fact
        label={sequence.length ? "Technique sequence" : "Techniques"}
        hint={sequence.length ? "first observed to last" : "no order recorded"}
      >
        {(sequence.length ? sequence : set).length ? (
          <div style={{ display: "flex", flexWrap: "wrap", gap: "4px 6px" }}>
            {(sequence.length ? sequence : set).map((t, i) => (
              <span key={`${t}-${i}`}>
                <span className="tag" title={TECHNIQUE_NAMES[t] || t}>{techniqueLabel(t)}</span>
                {i < (sequence.length ? sequence : set).length - 1 && (
                  <span className="muted" style={{ margin: "0 2px" }}>›</span>
                )}
              </span>
            ))}
          </div>
        ) : "—"}
      </Fact>

      <Fact label="Naming conventions" hint="the habit, and what it was read from">
        <div className="muted" style={{ marginBottom: 6, fontSize: "0.88em" }}>
          Highlighted text is what the operator chose and reuses;{" "}
          <Slot>&lt;name&gt;</Slot> and <Slot>&lt;number&gt;</Slot> are the parts that change
          between engagements. Matching on the habit survives the rename.
        </div>
        {conventions.length ? (
          <table style={{ margin: 0 }}>
            <tbody>
              {conventions.map((c) => {
                const at = c.indexOf(":");
                const kind = at > 0 ? c.slice(0, at) : "artifact";
                const shape = at > 0 ? c.slice(at + 1) : c;
                const ex = examples[c];
                return (
                  <tr key={c}>
                    <td className="muted" style={{ paddingRight: 12, whiteSpace: "nowrap" }}>
                      {kind.replace(/_/g, " ")}
                    </td>
                    <td><Shape shape={shape} /></td>
                    {/* The collected value behind the shape. Without it the abstraction is
                        indistinguishable from placeholder text. */}
                    <td className="muted" style={{ paddingLeft: 14 }}>
                      {ex?.example ? (
                        <>from <code>{ex.example}</code>
                          {ex.hosts > 1 && ` on ${ex.hosts} hosts`}</>
                      ) : null}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        ) : "none observed"}
      </Fact>

      <Fact label="Movement">
        {protocols.length ? protocols.join(", ") : "no movement observed"}
        {" — "}
        {chain.reuses_single_account
          ? "one account reused across every hop"
          : `${chain.distinct_accounts ?? 0} distinct account${
              (chain.distinct_accounts ?? 0) === 1 ? "" : "s"}${
              chain.max_hosts_per_account > 1
                ? `, the widest reaching ${chain.max_hosts_per_account} hosts` : ""}`}
      </Fact>
    </div>
  );
}

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
  const [tradecraft, setTradecraft] = useState(null);
  const [history, setHistory] = useState(null);
  const [busy, setBusy] = useState(false);
  // Off by default. Declined candidates are the answer to a question an analyst asks
  // deliberately, and drawing every refused pair by default buries the intrusion.
  const [showDeclined, setShowDeclined] = useState(false);
  const [showBehavioral, setShowBehavioral] = useState(true);
  const [edge, setEdge] = useState(null);
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
    setEdge(null);
    api.campaignGraph(campaignId).then(setGraph).catch(() => setGraph(null));
    api.campaignTimeline(campaignId).then(setTimeline).catch(() => setTimeline(null));
    api.campaignTradecraft(campaignId).then(setTradecraft).catch(() => setTradecraft(null));
    api.correlationHistory(invId).then(setHistory).catch(() => setHistory(null));
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
            <>
              <div style={{ display: "flex", gap: 20, marginBottom: 10, flexWrap: "wrap",
                            alignItems: "center" }}>
                <label className="muted"
                       style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
                  <input type="checkbox" checked={showBehavioral}
                         onChange={(e) => setShowBehavioral(e.target.checked)} />
                  shared tradecraft ({graph.behavioral_edges?.length || 0})
                </label>
                <label className="muted"
                       style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
                  <input type="checkbox" checked={showDeclined}
                         onChange={(e) => setShowDeclined(e.target.checked)} />
                  declined candidates ({graph.declined_edges?.length || 0})
                </label>
                <span className="muted">
                  link threshold {graph.thresholds?.link ?? "—"} · border weight = membership band
                </span>
              </div>
              <AttackGraph nodes={graph.nodes} edges={graph.edges}
                           behavioralEdges={graph.behavioral_edges}
                           declinedEdges={graph.declined_edges}
                           showBehavioral={showBehavioral} showDeclined={showDeclined}
                           selected={host}
                           onSelect={(h) => setParam("host", h === host ? "" : h)}
                           onSelectEdge={setEdge} />
              {edge && (
                <div className="panel" style={{ padding: 12, marginTop: 8 }}>
                  <div className="row" style={{ justifyContent: "space-between" }}>
                    <strong>{edge.src} ~ {edge.dst}</strong>
                    <button className="btn-sm" onClick={() => setEdge(null)}>close</button>
                  </div>
                  <div className="muted" style={{ marginTop: 6 }}>
                    <span className="tag">{edge.kind}</span>
                    {edge.weight != null ? ` weight ${edge.weight}` : ""}
                    {edge.protocol ? ` · ${edge.protocol}` : ""}
                    {edge.account ? ` · ${edge.account}` : ""}
                  </div>
                  {edge.why && <div style={{ marginTop: 6 }}>{edge.why}</div>}
                  {edge.top_factor && Object.keys(edge.top_factor).length > 0 && (
                    <div style={{ marginTop: 6 }}>
                      strongest factor: {edge.top_factor.subkind || edge.top_factor.kind}
                      {" — "}type {edge.top_factor.type_weight}, rarity {edge.top_factor.rarity},
                      {" "}verdict {edge.top_factor.verdict_weight}, temporal {edge.top_factor.temporal}
                      {edge.top_factor.value ? ` (${edge.top_factor.value})` : ""}
                    </div>
                  )}
                  {edge.source_finding_id && (
                    <div className="muted" style={{ marginTop: 6 }}>
                      from finding #{edge.source_finding_id}
                    </div>
                  )}
                  {(edge.corroboration?.length > 0 || edge.evidence_kinds?.length > 0) && (
                    <div style={{ marginTop: 10 }}>
                      <div className="chart-note">What carries this link — a link riding one
                        shared address dies when the actor rotates; one riding several kinds
                        does not. Click a bar to search that value everywhere.</div>
                      <EvidenceKindBars edge={edge} />
                    </div>
                  )}
                </div>
              )}
            </>
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
                      {n.confidence_band && (
                        <div style={{ marginBottom: 8 }}>
                          membership <span className="tag">{n.confidence_band}</span>
                          {n.confidence_factors?.why && (
                            <span className="muted"> — {n.confidence_factors.why}</span>
                          )}
                          {n.confidence_factors?.evidence_kinds?.length > 0 && (
                            <div className="muted">
                              carried by: {n.confidence_factors.evidence_kinds.join(", ")}
                            </div>
                          )}
                        </div>
                      )}
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

          <h2>Tradecraft</h2>
          {tradecraft?.fingerprint ? (
            <div className="panel" style={{ padding: 12 }}>
              <div className="muted">
                {tradecraft.fingerprint.basis?.sufficient
                  ? "Computed from behavior, not indicators — what an actor carries between engagements."
                  : "Too little tradecraft observed to compare against anything. Shown, not scored."}
              </div>
              <TradecraftFacts fingerprint={tradecraft.fingerprint} />

              {tradecraft.attribution_candidates?.length > 0 && (
                <>
                  <h3 style={{ marginTop: 14 }}>Attribution candidates</h3>
                  <div className="muted" style={{ marginBottom: 6 }}>
                    Advisory only. Ranked by shared tradecraft; nothing here is assigned to
                    the case, and the decision stays with you.
                  </div>
                  <table>
                    <thead><tr><th>Actor</th><th>Score</th><th>Because</th></tr></thead>
                    <tbody>
                      {tradecraft.attribution_candidates.map((a) => (
                        <tr key={a.actor_key}>
                          <td>{a.actor_name}</td>
                          <td>{a.score}</td>
                          <td className="muted">
                            {Object.entries(a.rationale?.components || {})
                              .map(([k, v]) => `${k} ${v.score}`).join(" · ") || "—"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </>
              )}

              {tradecraft.similar_campaigns?.length > 0 && (
                <>
                  <h3 style={{ marginTop: 14 }}>Seen before</h3>
                  <table>
                    <thead>
                      <tr><th>Campaign</th><th>Score</th><th>Shared</th></tr>
                    </thead>
                    <tbody>
                      {tradecraft.similar_campaigns.map((s) => (
                        <tr key={s.campaign_id}>
                          <td>{s.label || `campaign ${s.campaign_id}`}</td>
                          <td>{s.score}</td>
                          <td><SharedEvidence rationale={s.rationale} /></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </>
              )}
            </div>
          ) : (
            <div className="panel" style={{ padding: 12 }}>
              <span className="muted">No fingerprint for this campaign yet — recompute correlation.</span>
            </div>
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

          <h2>Signal or environment</h2>
          <div className="panel" style={{ padding: "14px 18px" }}>
            <p className="chart-note">Each dot is a shared indicator: the further right, the
              more hosts carry it and the less it can link anyone. Weights are the engine's
              own, over the deployment population of {indicators?.population ?? "?"}. Click
              a dot to search it everywhere it appears.</p>
            <RarityScatter indicators={indicators?.indicators} />
          </div>

          <h2>Cohesion</h2>
          <div className="panel" style={{ padding: "14px 18px" }}>
            <p className="chart-note">Whether each campaign is tightening or fragmenting as
              evidence lands. A campaign that fragments is one the evidence is arguing with.</p>
            <CohesionStrip history={history} />
          </div>

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
