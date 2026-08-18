/**
 * Reverse-engineering workflow — carved regions and what they turned out to be.
 *
 * A reverse engineer works on extracted bytes rather than on cases, so this page shows the
 * queue of regions and a form to record a determination. The determination is not a note:
 * a malicious or suspicious verdict raises a finding on the run the capture came from, so
 * it reaches the incident the analyst is working and correlates across hosts like any
 * other evidence.
 */
import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api.js";
import DataTable from "../components/DataTable.jsx";
import { useServerTable } from "../components/useServerTable.js";
import { useData } from "../components/common.jsx";
import { can, useAuth } from "../auth.jsx";

const VERDICTS = [
  ["malicious", "Malicious — raises a True Positive on the incident"],
  ["suspicious", "Suspicious — raises a Likely True Positive"],
  ["benign", "Benign — closes the region, raises nothing"],
  ["inconclusive", "Inconclusive — closes the region, raises nothing"],
];

const STATUS_CLASS = {
  unanalyzed: "sev-high", in_progress: "sev-medium", analyzed: "muted", benign: "muted",
};

function bytes(n) {
  if (!n) return "—";
  const u = ["B", "KB", "MB"];
  let v = Number(n), i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i += 1; }
  return `${v.toFixed(i ? 1 : 0)} ${u[i]}`;
}

/**
 * The signature hits that caused a region to be carved.
 *
 * Shown before the determination form because it is the question being asked. A rule name
 * on its own is not enough: the matched strings say what was found, and the memory
 * permissions say whether it was found in data or in code — which is usually what settles
 * whether a hit is worth pursuing.
 */
function TriggerPanel({ trigger }) {
  const hits = trigger?.hits || [];
  if (hits.length === 0) {
    return (
      <p className="muted" style={{ fontSize: 12, marginBottom: 10 }}>
        No signature context recorded for this region — it predates trigger capture, or the
        carve was not attributable to a rule.
      </p>
    );
  }
  // Memory that is writable but not executable holds data. Saying so plainly saves the
  // reverse engineer from deducing it from a permissions string.
  const dataOnly = hits.every((h) => h.memory && !h.memory.includes("x"));
  return (
    <div className="panel" style={{ padding: 12, marginBottom: 12 }}>
      <div style={{ fontWeight: 600, marginBottom: 6 }}>
        Why this was carved — {hits.length} signature hit{hits.length === 1 ? "" : "s"}
      </div>
      <table>
        <thead><tr>
          <th scope="col">Rule</th><th scope="col">Severity</th>
          <th scope="col">Memory</th><th scope="col">What matched</th>
        </tr></thead>
        <tbody>
          {hits.map((h, i) => (
            <tr key={i}>
              <td className="mono" style={{ fontSize: 12 }}>{h.rule}</td>
              <td className={`sev-${(h.severity || "").toLowerCase()}`}>{h.severity || "—"}</td>
              <td className="mono" style={{ fontSize: 12 }}>{h.memory || "—"}</td>
              <td>
                {/* The identifier names the slot in the rule; the content is what the
                    determination rests on. Both are shown, content first. */}
                {(h.matches || []).length > 0 ? (
                  <div>
                    {h.matches.map((m, j) => (
                      <div key={j} style={{ marginBottom: 3 }}>
                        <span className="mono" style={{ fontSize: 11.5 }}>
                          {m.id} @ {m.offset}
                        </span>
                        <div className="mono wrap" style={{ fontSize: 11.5 }}>{m.text}</div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <span className="mono" style={{ fontSize: 12 }}>
                    {h.matched_strings || "—"}
                    <div className="muted" style={{ fontSize: 11 }}>
                      identifier only — re-analyze to capture the matched bytes
                    </div>
                  </span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {dataOnly && (
        <p className="muted" style={{ fontSize: 12, margin: "8px 0 0" }}>
          Every hit landed in non-executable memory. Rules matched <strong>data</strong>,
          not code — a signature's own strings appearing in a buffer is a common reason,
          and is not by itself evidence of execution.
        </p>
      )}
    </div>
  );
}

function AnalyzeForm({ region, onDone, onCancel }) {
  const [verdict, setVerdict] = useState("");
  const [family, setFamily] = useState("");
  const [capability, setCapability] = useState("");
  const [indicators, setIndicators] = useState("");
  const [mitre, setMitre] = useState("");
  const [notes, setNotes] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const submit = async () => {
    if (!verdict) return;
    setBusy(true);
    setError(null);
    try {
      // "type=value" per line — indicators recovered by hand join the corpus and
      // correlate across hosts exactly like collector-derived ones.
      const parsed = indicators.split("\n").map((l) => l.trim()).filter(Boolean)
        .map((line) => {
          const [type, ...rest] = line.split("=");
          return rest.length
            ? { type: type.trim(), value: rest.join("=").trim() }
            : { type: "unknown", value: line };
        });
      const res = await api.analyzeRegion(region.id, {
        verdict, malware_family: family, capability, notes,
        indicators: parsed,
        mitre: mitre.split(",").map((m) => m.trim()).filter(Boolean),
      });
      onDone(res);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="panel" style={{ padding: 14, marginBottom: 16 }}>
      <h2 style={{ marginTop: 0 }}>Record a determination</h2>
      <p className="muted mono" style={{ fontSize: 12 }}>{region.object_key}</p>
      <div className="muted" style={{ fontSize: 12, marginBottom: 10 }}>
        {region.hostname} · {bytes(region.size_bytes)} · carved by {region.carved_by || "—"}
        {region.source_pid ? ` · pid ${region.source_pid}` : ""}
        {region.source_process ? ` (${region.source_process})` : ""}
      </div>

      {/* What flagged this region. A verdict is being asked for on two megabytes of memory,
          and the rule that fired — with the strings it matched and the permissions of the
          memory it matched in — is the statement of what to look for. Permissions carry as
          much weight as the rule name: a hit in anonymous rw- memory is matching data,
          while the same rule on anonymous rwx is matching code nothing on disk accounts
          for. */}
      <TriggerPanel trigger={region.trigger} />

      <div style={{ display: "grid", gap: 10, maxWidth: 720 }}>
        <label>
          <div className="muted" style={{ fontSize: 12 }}>Verdict</div>
          <select value={verdict} onChange={(e) => setVerdict(e.target.value)}
                  aria-label="Verdict" style={{ width: "100%" }}>
            <option value="">Select…</option>
            {VERDICTS.map(([v, label]) => <option key={v} value={v}>{label}</option>)}
          </select>
        </label>

        <label>
          <div className="muted" style={{ fontSize: 12 }}>Malware family</div>
          <input className="table-search" style={{ width: "100%" }} value={family}
                 placeholder="e.g. Cobalt Strike, XMRig — leave blank if unattributed"
                 onChange={(e) => setFamily(e.target.value)} />
        </label>

        <label>
          <div className="muted" style={{ fontSize: 12 }}>Capability</div>
          <input className="table-search" style={{ width: "100%" }} value={capability}
                 placeholder="what it does: beacon, loader, credential theft…"
                 onChange={(e) => setCapability(e.target.value)} />
        </label>

        <label>
          <div className="muted" style={{ fontSize: 12 }}>
            Indicators — one per line as <span className="mono">type=value</span>
          </div>
          <textarea className="table-search" rows={3} style={{ width: "100%" }}
                    value={indicators} placeholder={"ip=198.51.100.23\\ndomain=c2.example.net"}
                    onChange={(e) => setIndicators(e.target.value)} />
        </label>

        <label>
          <div className="muted" style={{ fontSize: 12 }}>ATT&CK techniques (comma separated)</div>
          <input className="table-search" style={{ width: "100%" }} value={mitre}
                 placeholder="T1055, T1071.001"
                 onChange={(e) => setMitre(e.target.value)} />
        </label>

        <label>
          <div className="muted" style={{ fontSize: 12 }}>Notes</div>
          <textarea className="table-search" rows={4} style={{ width: "100%" }} value={notes}
                    placeholder="How it was identified — strings, structure, behavior."
                    onChange={(e) => setNotes(e.target.value)} />
        </label>

        {error && <div className="notice">Error: {error}</div>}

        <div style={{ display: "flex", gap: 8 }}>
          <button className="btn" onClick={submit} disabled={busy || !verdict}>
            {busy ? "Recording…" : "Record determination"}
          </button>
          <button className="table-clear" onClick={onCancel}>cancel</button>
        </div>
        <p className="muted" style={{ fontSize: 12, margin: 0 }}>
          A malicious or suspicious verdict raises a finding on the incident and adds any
          indicators to the corpus. Benign and inconclusive close the region without
          asserting anything about the case.
        </p>
      </div>
    </div>
  );
}


/**
 * The commands that open a region on a reverse-engineering workstation.
 *
 * The platform cannot start the disassembler: the workstation is air-gapped, on its own
 * hardware, and reaching into it would defeat the reason it exists. What it can do is name
 * exactly which regions the session is for and hand over the two commands that stage them,
 * so nothing has to be looked up by hand.
 */
function SessionCommands({ session, onClose }) {
  const [copied, setCopied] = useState(false);
  const text = (session.commands || []).join("\n");

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // A kiosk without clipboard permission still has to be usable, so the block stays
      // selectable and says so rather than failing silently.
      setCopied(false);
    }
  };

  return (
    <div className="panel" style={{ padding: 14, marginBottom: 16 }}>
      <h2 style={{ marginTop: 0 }}>Open in {session.tool === "ghidra" ? "Ghidra" : "Binary Ninja"}</h2>
      <p className="page-sub" style={{ margin: "0 0 14px" }}>
        Workset <code>{session.workset}</code> · {session.host} · {session.regions} region
        {session.regions === 1 ? "" : "s"} · case {session.investigation}
      </p>

      <div className="row-actions" style={{ justifyContent: "flex-start", marginBottom: 18 }}>
        <a className="btn" href={session.kit} download>download session kit</a>
        <button className="btn-sm" onClick={copy}>{copied ? "copied" : "copy commands"}</button>
        <button className="btn-sm" onClick={onClose}>close</button>
      </div>

      <p className="page-sub" style={{ margin: "0 0 16px", maxWidth: "72ch" }}>
        The kit carries the scripts and a <code>run.sh</code> pinned to this workset. It holds
        no evidence: the regions are pulled by the mediator, verified against the hash recorded
        when they were carved, and wiped when the session ends.
      </p>

      {(session.steps || []).map((st) => (
        <div key={st.step} style={{ marginBottom: 18 }}>
          <div className="page-sub" style={{ margin: "0 0 8px", maxWidth: "72ch" }}>
            <strong>{st.step}. {st.where}</strong> — {st.why}
          </div>
          <pre className="mono" style={{ whiteSpace: "pre-wrap", userSelect: "all",
                                         padding: "12px 14px", margin: 0, lineHeight: 1.7 }}>
            {st.commands.join("\n")}
          </pre>
        </div>
      ))}
    </div>
  );
}

/**
 * Worksets that have been assembled or staged — what is in session, where, and by whom.
 *
 * Advisory, never a lock: two people may examine the same region, and the platform says so
 * rather than preventing it.
 */
function OpenSessions({ rows, onClose, mayAnalyze }) {
  if (!rows.length) return null;
  return (
    <div className="panel" style={{ padding: 14, marginBottom: 16 }}>
      <h2 style={{ marginTop: 0 }}>Reverse-engineering sessions</h2>
      <table className="table">
        <thead>
          <tr><th>Workset</th><th>Host</th><th>Regions</th><th>State</th>
            <th>Assembled by</th><th>Staged</th><th /></tr>
        </thead>
        <tbody>
          {rows.map((w) => (
            <tr key={w.slug}>
              <td className="mono">{w.slug}</td>
              <td>{w.hostname}</td>
              <td>{w.region_count}</td>
              <td><span className={`status-pill status-${w.state}`}>{w.state}</span></td>
              <td>{w.created_by}</td>
              <td>{w.staged_at ? new Date(w.staged_at).toLocaleString() : "—"}</td>
              <td>{mayAnalyze && (
                <button className="btn-sm" onClick={() => onClose(w.slug)}>close</button>
              )}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function Reversing() {
  const { user } = useAuth();
  const [params] = useSearchParams();
  const status = params.get("status") || "";
  const host = params.get("host") || "";

  const t = useServerTable(api.regions, { extra: { status, host } });
  const [selected, setSelected] = useState(null);
  // The queue fills as captures finish analysis, so it refreshes — but never while a
  // region is open for determination. Redrawing the queue under a reverse engineer who is
  // writing up evidence is exactly the disruption this is supposed to avoid.
  const { data: queue, reload: reloadQueue } = useData(
    () => api.regionQueue(), [], { refreshMs: 30000, paused: Boolean(selected) });
  const [result, setResult] = useState(null);
  const [picked, setPicked] = useState([]);
  const [tool, setTool] = useState("binja");
  const [session, setSession] = useState(null);
  const [opening, setOpening] = useState(false);

  const mayAnalyze = can(user, "reverse_engineer", "admin");

  const { data: sessions, reload: reloadSessions } = useData(
    () => api.worksets("?page_size=25"), [], { refreshMs: 60000, paused: Boolean(selected) });
  const openSessions = (sessions?.results || []).filter((w) => w.state !== "closed");

  const toggle = (id) =>
    setPicked((cur) => (cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id]));

  // One click from a region to a running disassembler: assemble the workset, then ask for
  // the commands that stage it. Both steps are the platform's; running them is the
  // operator's, on the workstation.
  const openInRE = async (ids) => {
    setOpening(true);
    setResult(null);
    try {
      const ws = await api.createWorkset({ region_ids: ids });
      const cmd = await api.worksetStageCommand(ws.slug, { tool });
      setSession(cmd);
      setPicked([]);
      reloadSessions();
    } catch (e) {
      setResult(`Could not open a session: ${e.message}`);
    } finally {
      setOpening(false);
    }
  };

  const closeSession = async (slug) => {
    try {
      await api.closeWorkset(slug);
      reloadSessions();
    } catch (e) {
      setResult(e.message);
    }
  };

  const done = (res) => {
    setResult(res.raised_finding
      ? `Recorded. Raised finding #${res.raised_finding} on the incident.`
      : "Recorded. No finding raised — the region was not assessed as hostile.");
    setSelected(null);
    t.reload();
    reloadQueue();
  };

  return (
    <>
      <h1>Reverse engineering</h1>
      <p className="page-sub">
        Memory regions carved out of captures because they matched a rule. Each one is
        extracted malware until shown otherwise; what you record here reaches the incident.
      </p>

      {queue && (
        <div className="cards">
          <div className={`card ${queue.unanalyzed ? "bad" : ""}`}>
            <div className="num">{queue.unanalyzed}</div><div className="lbl">Unanalyzed</div>
          </div>
          <div className="card warn">
            <div className="num">{queue.in_progress}</div><div className="lbl">In progress</div>
          </div>
          <div className="card"><div className="num">{queue.analyzed}</div><div className="lbl">Analyzed</div></div>
          <div className="card"><div className="num">{queue.benign}</div><div className="lbl">Benign</div></div>
          <div className="card"><div className="num">{queue.hosts?.length || 0}</div><div className="lbl">Hosts</div></div>
        </div>
      )}

      {result && <div className="notice">{result}</div>}

      {session && <SessionCommands session={session} onClose={() => setSession(null)} />}

      <OpenSessions rows={openSessions} onClose={closeSession} mayAnalyze={mayAnalyze} />

      {selected && mayAnalyze && (
        <AnalyzeForm region={selected} onDone={done} onCancel={() => setSelected(null)} />
      )}

      <div className="table-controls">
        <select value={status} aria-label="Filter by triage status"
                onChange={(e) => t.setExtra("status", e.target.value)}>
          <option value="">Status: all</option>
          <option value="unanalyzed">unanalyzed</option>
          <option value="in_progress">in progress</option>
          <option value="analyzed">analyzed</option>
          <option value="benign">benign</option>
        </select>
        <select value={host} aria-label="Filter by host"
                onChange={(e) => t.setExtra("host", e.target.value)}>
          <option value="">Host: all</option>
          {(queue?.hosts || []).map((h) => <option key={h} value={h}>{h}</option>)}
        </select>
        {mayAnalyze && (
          <>
            <select value={tool} aria-label="Disassembler"
                    onChange={(e) => setTool(e.target.value)}>
              <option value="binja">Binary Ninja</option>
              <option value="ghidra">Ghidra</option>
            </select>
            <button className="btn" disabled={!picked.length || opening}
                    onClick={() => openInRE(picked)}>
              {opening ? "opening…" : `open ${picked.length || ""} in RE session`}
            </button>
          </>
        )}
        {!mayAnalyze && (
          <span className="muted">read-only — the reverse engineer role records determinations</span>
        )}
      </div>

      {t.error ? <div className="empty">Error: {t.error}</div> : (
        <DataTable
          serverMode
          rows={t.rows}
          count={t.count}
          page={t.page}
          totalPages={t.totalPages}
          query={t.q}
          sort={t.ordering}
          onQueryChange={t.onQueryChange}
          searchPlaceholder="Search regions by key, host, rule…"
          emptyText={t.data
            ? "No carved regions. They appear once a capture is analyzed with symbols."
            : "Loading…"}
          columns={[
            ...(mayAnalyze ? [{
              key: "select", label: "", sortable: false,
              render: (_v, r) => (
                <input type="checkbox" checked={picked.includes(r.id)}
                       aria-label={`Select region ${r.id}`}
                       disabled={r.triage_status === "purged"}
                       onChange={() => toggle(r.id)} />
              ),
            }] : []),
            { key: "hostname", label: "Host", mono: true, sortable: false },
            { key: "object_key", label: "Region", mono: true, sortable: false,
              cellClass: () => "cell-key",
              render: (v) => v.split("/").pop() },
            { key: "size_bytes", label: "Size", render: (v) => bytes(v) },
            { key: "carved_by", label: "Carved by", sortable: false,
              render: (v) => v || "—" },
            // The rule is what tells a reverse engineer whether a region is worth opening.
            // Naming it in the queue means that judgment happens before the 2 MB download.
            { key: "trigger", label: "Triggered by", sortable: false,
              render: (v) => {
                const hits = v?.hits || [];
                if (hits.length === 0) return <span className="muted">—</span>;
                const rules = [...new Set(hits.map((h) => h.rule))];
                return (
                  <span className="mono" style={{ fontSize: 11.5 }} title={rules.join("\n")}>
                    {rules[0]}
                    {rules.length > 1 && ` +${rules.length - 1}`}
                  </span>
                );
              } },
            { key: "source_pid", label: "PID", render: (v) => v || "—" },
            { key: "source_process", label: "Process", mono: true, sortable: false,
              render: (v) => v || "—" },
            { key: "triage_status", label: "Status", sortable: false,
              cellClass: (v) => STATUS_CLASS[v] || "",
              render: (v) => <span className={`status-pill status-${v}`}>{v}</span> },
            { key: "investigation", label: "Investigation", sortable: false,
              render: (v, r) => (r.investigation_id
                ? <Link to={`/investigations/${r.investigation_id}`}>{v}</Link> : v) },
            { key: "id", label: "", sortable: false,
              render: (_v, r) => (mayAnalyze
                ? (
                  // Opening a session and recording what it found are opposite ends of the
                  // work, so each is named for its end. Kept on one line: stacked at the
                  // table's edge they wrap and clip.
                  <div className="row-actions">
                    <button className="btn-sm" disabled={r.triage_status === "purged"}
                            title="Stage this region for a reverse-engineering session"
                            onClick={() => openInRE([r.id])}>
                      open in RE
                    </button>
                    <button className="btn-sm" title="Record determination — what this region is"
                            onClick={() => { setSelected(r); setResult(null); }}>
                      record
                    </button>
                  </div>
                )
                : null) },
          ]}
        />
      )}
    </>
  );
}
