/**
 * Case tree, curated tags and the task board.
 *
 * The tree renders the hierarchy the API already serves in one request — expanding a node
 * reveals what was fetched, never a new round trip, so navigating a case does not feel
 * like the platform is thinking.
 *
 * Tags come from the curated vocabulary only; there is no free-text path here, because a
 * field that accepts one produces three spellings of the same idea.
 */
import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api.js";
import { LockNotice, useSoftLock } from "./collab.jsx";

function bytes(n) {
  if (!n) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = Number(n), i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`;
}

const CARET = { display: "inline-block", width: 14, color: "var(--text-dim)" };

function Node({ node, depth, openIds, toggle }) {
  const kids = node.children || [];
  const open = openIds.has(`${node.type}:${node.id}`);
  const label = {
    host: <Link to={`/hosts/${node.id}`}>{node.label}</Link>,
    run: <Link to={`/runs/${node.id}`}>{node.label}</Link>,
    capture: <span className="mono">{node.label}</span>,
  }[node.type] || node.label;

  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "3px 0",
                    paddingLeft: depth * 18 }}>
        <span role={kids.length ? "button" : undefined}
              tabIndex={kids.length ? 0 : undefined}
              onClick={() => kids.length && toggle(`${node.type}:${node.id}`)}
              onKeyDown={(e) => {
                if (kids.length && (e.key === "Enter" || e.key === " ")) {
                  e.preventDefault(); toggle(`${node.type}:${node.id}`);
                }
              }}
              style={{ ...CARET, cursor: kids.length ? "pointer" : "default" }}>
          {kids.length ? (open ? "▾" : "▸") : "·"}
        </span>
        <span style={{ fontSize: 10, letterSpacing: ".06em", textTransform: "uppercase",
                       color: "var(--text-dim)", width: 62 }}>{node.type}</span>
        <span>{label}</span>
        <span className="mono" style={{ fontSize: 11.5, color: "var(--text-dim)" }}>
          {node.type === "host" && node.platform}
          {node.type === "run" && `${node.finding_count} findings${node.compromised ? " · compromised" : ""}`}
          {node.type === "capture" && `${bytes(node.size_bytes)} · ${node.analysis_count} analyses`
            + (node.region_count ? ` · ${node.region_count} regions` : "")}
        </span>
      </div>
      {open && kids.map((k) => (
        <Node key={`${k.type}:${k.id}`} node={k} depth={depth + 1}
              openIds={openIds} toggle={toggle} />
      ))}
    </div>
  );
}

export function CaseTree({ investigationId }) {
  const [tree, setTree] = useState(null);
  const [err, setErr] = useState("");
  const [openIds, setOpenIds] = useState(new Set());

  useEffect(() => {
    let live = true;
    api.caseTree(investigationId)
      .then((d) => { if (live) { setTree(d); setErr(""); } })
      .catch((e) => live && setErr(String(e.message || e)));
    return () => { live = false; };
  }, [investigationId]);

  const toggle = useCallback((key) => {
    setOpenIds((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key); else next.add(key);
      return next;
    });
  }, []);

  if (err) return <p className="muted">Could not load the case tree: {err}</p>;
  if (!tree) return <p className="muted">Reading the case tree…</p>;
  const hosts = tree.children || [];
  if (!hosts.length) return <p className="muted">No collections on this case yet.</p>;

  return (
    <div>
      <div style={{ display: "flex", gap: 10, marginBottom: 8 }}>
        <button className="btn" style={{ padding: "3px 10px", fontSize: 12 }}
                onClick={() => setOpenIds(new Set(hosts.flatMap((h) => [
                  `host:${h.id}`, ...(h.children || []).map((r) => `run:${r.id}`)])))}>
          Expand all
        </button>
        <button className="btn" style={{ padding: "3px 10px", fontSize: 12 }}
                onClick={() => setOpenIds(new Set())}>Collapse</button>
      </div>
      {hosts.map((h) => (
        <Node key={`host:${h.id}`} node={h} depth={0} openIds={openIds} toggle={toggle} />
      ))}
    </div>
  );
}

export function CaseTags({ investigationId, canEdit }) {
  const [applied, setApplied] = useState([]);
  const [vocab, setVocab] = useState([]);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    api.caseTags(investigationId).then((d) => setApplied(d.tags || [])).catch(() => {});
    api.tagVocabulary().then((d) => setVocab(d.tags || [])).catch(() => {});
  }, [investigationId]);
  useEffect(load, [load]);

  const apply = async (tagId, remove) => {
    setBusy(true);
    try { await api.applyCaseTag(investigationId, tagId, remove); load(); }
    finally { setBusy(false); }
  };

  const appliedIds = new Set(applied.map((t) => t.id));
  const available = vocab.filter((t) => !appliedIds.has(t.id));

  return (
    <div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 8 }}>
        {applied.length === 0 && <span className="muted">No tags on this case.</span>}
        {applied.map((t) => (
          <span key={t.id} className="status-pill" style={{ display: "inline-flex", gap: 6 }}>
            {t.label}
            {canEdit && (
              <button onClick={() => apply(t.id, true)} disabled={busy} aria-label={`remove ${t.label}`}
                      style={{ background: "none", border: 0, color: "var(--text-dim)",
                               cursor: "pointer", padding: 0 }}>×</button>
            )}
          </span>
        ))}
      </div>
      {canEdit && available.length > 0 && (
        <select value="" disabled={busy} onChange={(e) => e.target.value && apply(e.target.value, false)}>
          <option value="">Add a tag…</option>
          {available.map((t) => (
            <option key={t.id} value={t.id}>
              {t.category ? `${t.category} · ` : ""}{t.label}
            </option>
          ))}
        </select>
      )}
      {canEdit && vocab.length === 0 && (
        <p className="muted" style={{ margin: 0 }}>
          The tag vocabulary is empty and is curated by an admin — tags are chosen, never typed.
        </p>
      )}
    </div>
  );
}

const STATE_TONE = {
  identification: "#38bdf8", preservation: "#2dd4bf",
  analysis: "var(--accent)", documentation: "var(--warn)",
  presentation: "var(--good)",
};

const REF_TYPES = ["host", "run", "finding", "capture", "region", "note"];

function fmtWhen(iso) {
  return iso ? new Date(iso).toLocaleString() : "";
}

/** The task drawer: everything about one unit of work, including the reasoning behind it.
 *
 * Stage movement is a full picker rather than a next-step button — evidence arriving late
 * legitimately sends work back to Analysis, and a board that only advances would record
 * that as progress. */
function TaskDrawer({ taskId, onClose, onChanged, canEdit }) {
  const [task, setTask] = useState(null);
  const [err, setErr] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [ref, setRef] = useState({ ref_type: "finding", ref_id: "", label: "" });

  const load = useCallback(() => {
    api.task(taskId).then((d) => { setTask(d); setErr(""); })
      .catch((e) => setErr(String(e.message || e)));
  }, [taskId]);
  useEffect(load, [load]);
  // Held only while the drawer is open, and released when it closes. Advisory throughout:
  // the notice below never disables anything.
  const heldBy = useSoftLock(task?.investigation, "task", task?.id);

  const patch = async (body) => {
    setBusy(true);
    try {
      await api.saveCaseTask(task.investigation, { id: task.id, ...body });
      load(); onChanged?.();
    } finally { setBusy(false); }
  };

  const upload = async (file) => {
    if (!file) return;
    setBusy(true);
    try { await api.uploadTaskDocument(task.id, file); load(); onChanged?.(); }
    catch (e) { setErr(String(e.message || e)); }
    finally { setBusy(false); }
  };

  if (err && !task) return (
    <div className="panel" style={{ padding: 14 }}>
      <p className="muted">Could not open the task: {err}</p>
      <button className="btn" onClick={onClose}>Close</button>
    </div>
  );
  if (!task) return <div className="panel" style={{ padding: 14 }}>Opening…</div>;

  return (
    <div className="panel" style={{ padding: 16, marginTop: 12 }}>
      <LockNotice heldBy={heldBy} />
      <div style={{ display: "flex", justifyContent: "space-between", gap: 12 }}>
        <div>
          <h3 style={{ margin: 0 }}>{task.title}</h3>
          <p className="muted" style={{ margin: "4px 0 0", fontSize: 12 }}>
            opened by <span className="mono">{task.created_by || "unknown"}</span>
            {" · "}{fmtWhen(task.created_at)}
            {task.closed_at && <> · closed {fmtWhen(task.closed_at)}</>}
          </p>
        </div>
        <button className="btn" onClick={onClose}>Close</button>
      </div>

      <div style={{ display: "flex", gap: 18, flexWrap: "wrap", margin: "14px 0",
                    alignItems: "center" }}>
        <label style={{ fontSize: 12, color: "var(--text-dim)" }}>
          Stage{" "}
          <select value={task.state} disabled={!canEdit || busy}
                  onChange={(e) => patch({ state: e.target.value })}>
            {(task.states || []).map((s) => (
              <option key={s.state} value={s.state}>{s.label}</option>
            ))}
          </select>
        </label>
        <span className="muted" style={{ fontSize: 12 }}>
          {(task.states || []).find((s) => s.state === task.state)?.intent}
        </span>
        <label style={{ fontSize: 12, color: "var(--text-dim)" }}>
          Assignee{" "}
          <input defaultValue={task.assignee} disabled={!canEdit || busy}
                 placeholder="unassigned"
                 onBlur={(e) => e.target.value !== task.assignee
                   && patch({ assignee: e.target.value })} />
        </label>
        <label style={{ fontSize: 12, color: task.blocked ? "var(--bad)" : "var(--text-dim)" }}>
          <input type="checkbox" checked={task.blocked} disabled={!canEdit || busy}
                 onChange={(e) => patch({ blocked: e.target.checked,
                                          blocked_reason: e.target.checked
                                            ? task.blocked_reason : "" })} />
          {" "}Blocked
        </label>
        {task.blocked && (
          <input defaultValue={task.blocked_reason} disabled={!canEdit || busy}
                 placeholder="what is it waiting on?" style={{ flex: 1, minWidth: 200 }}
                 onBlur={(e) => e.target.value !== task.blocked_reason
                   && patch({ blocked: true, blocked_reason: e.target.value })} />
        )}
      </div>

      <h4 style={{ margin: "16px 0 6px" }}>Working notes</h4>
      {(task.notes || []).length === 0 && (
        <p className="muted" style={{ marginTop: 0 }}>
          Nothing recorded yet. Notes are append-only — what was thought at the time stays
          as it was written.
        </p>
      )}
      {(task.notes || []).map((n) => (
        <div key={n.id} style={{ padding: "8px 0", borderBottom: "1px solid var(--border-soft)" }}>
          <div style={{ fontSize: 12, color: "var(--text-dim)" }}>
            <span className="mono">{n.author || "unknown"}</span> · {fmtWhen(n.created_at)}
          </div>
          <div style={{ whiteSpace: "pre-wrap", marginTop: 3 }}>{n.body}</div>
        </div>
      ))}
      {canEdit && (
        <form style={{ marginTop: 10 }}
              onSubmit={async (e) => {
                e.preventDefault();
                if (!note.trim()) return;
                setBusy(true);
                try { await api.addTaskNote(task.id, note); setNote(""); load(); }
                finally { setBusy(false); }
              }}>
          <textarea value={note} onChange={(e) => setNote(e.target.value)} rows={3}
                    placeholder="What you did, what you found, what it rests on…"
                    style={{ width: "100%" }} />
          <button className="btn" type="submit" disabled={busy || !note.trim()}
                  style={{ marginTop: 6 }}>Add note</button>
        </form>
      )}

      <h4 style={{ margin: "18px 0 6px" }}>Attachments</h4>
      {(task.attachments || []).length === 0 && (
        <p className="muted" style={{ marginTop: 0 }}>
          Nothing attached. Documents are stored with their sha256; evidence references
          point at what the platform already holds and copy nothing.
        </p>
      )}
      {(task.attachments || []).map((a) => (
        <div key={a.id} style={{ display: "flex", alignItems: "center", gap: 10,
                                 padding: "5px 0",
                                 borderBottom: "1px solid var(--border-soft)" }}>
          <span style={{ fontSize: 10, letterSpacing: ".06em", textTransform: "uppercase",
                         color: "var(--text-dim)", width: 66 }}>{a.kind}</span>
          {a.kind === "document" ? (
            <a href={api.taskAttachmentUrl(task.id, a.id)}>{a.label || a.filename}</a>
          ) : (
            <span>{a.label}<span className="mono" style={{ color: "var(--text-dim)" }}>
              {" "}({a.ref_type} {a.ref_id})</span></span>
          )}
          <span className="mono" style={{ fontSize: 11, color: "var(--text-dim)",
                                          marginLeft: "auto" }}>
            {a.kind === "document" ? `${a.size_bytes} B · ${a.sha256.slice(0, 12)}…` : ""}
            {" "}{a.added_by}
          </span>
          {canEdit && (
            <button className="linkish" disabled={busy}
                    onClick={async () => {
                      setBusy(true);
                      try { await api.detachTaskAttachment(task.id, a.id); load(); }
                      finally { setBusy(false); }
                    }}
                    style={{ background: "none", border: 0, cursor: "pointer",
                             color: "var(--text-dim)" }}>detach</button>
          )}
        </div>
      ))}
      {canEdit && (
        <div style={{ display: "flex", gap: 16, flexWrap: "wrap", marginTop: 10 }}>
          <label className="btn" style={{ cursor: "pointer" }}>
            Upload document
            <input type="file" style={{ display: "none" }} disabled={busy}
                   onChange={(e) => upload(e.target.files?.[0])} />
          </label>
          <form style={{ display: "flex", gap: 6, alignItems: "center" }}
                onSubmit={async (e) => {
                  e.preventDefault();
                  if (!ref.ref_id) return;
                  setBusy(true);
                  try {
                    await api.attachEvidence(task.id, ref);
                    setRef({ ...ref, ref_id: "", label: "" });
                    load();
                  } catch (x) { setErr(String(x.message || x)); }
                  finally { setBusy(false); }
                }}>
            <select value={ref.ref_type}
                    onChange={(e) => setRef({ ...ref, ref_type: e.target.value })}>
              {REF_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
            <input value={ref.ref_id} placeholder="id" style={{ width: 70 }}
                   onChange={(e) => setRef({ ...ref, ref_id: e.target.value })} />
            <input value={ref.label} placeholder="label (optional)"
                   onChange={(e) => setRef({ ...ref, label: e.target.value })} />
            <button className="btn" type="submit" disabled={busy || !ref.ref_id}>
              Link evidence</button>
          </form>
        </div>
      )}
      {err && <p style={{ color: "var(--bad)", marginTop: 8 }}>{err}</p>}
    </div>
  );
}

export function CaseTasks({ investigationId, canEdit }) {
  const [board, setBoard] = useState(null);
  const [title, setTitle] = useState("");
  const [busy, setBusy] = useState(false);
  const [openTask, setOpenTask] = useState(null);
  const [dragging, setDragging] = useState(null);

  const load = useCallback(() => {
    api.caseTasks(investigationId).then(setBoard).catch(() => setBoard(null));
  }, [investigationId]);
  useEffect(load, [load]);

  const save = async (body) => {
    setBusy(true);
    try { await api.saveCaseTask(investigationId, body); load(); }
    finally { setBusy(false); }
  };

  if (!board) return <p className="muted">Reading the task board…</p>;
  const columns = board.columns || [];
  const total = columns.reduce((a, c) => a + c.tasks.length, 0);

  return (
    <div>
      {canEdit && (
        <form style={{ display: "flex", gap: 8, marginBottom: 12 }}
              onSubmit={(e) => { e.preventDefault(); if (title.trim()) { save({ title }); setTitle(""); } }}>
          <input value={title} onChange={(e) => setTitle(e.target.value)}
                 placeholder="New task — what needs doing on this case?"
                 style={{ flex: 1 }} />
          <button className="btn" type="submit" disabled={busy || !title.trim()}>Add</button>
        </form>
      )}
      {total === 0 && <p className="muted">No tasks on this case yet.</p>}
      {/* Horizontal scroll rather than wrapping: the stages are an ordered process, and a
          column that wraps to a second row stops reading as one. */}
      <div style={{ display: "flex", gap: 12, overflowX: "auto", paddingBottom: 6 }}>
        {columns.map((col) => (
          <div key={col.state} className="panel"
               onDragOver={(e) => { if (canEdit) e.preventDefault(); }}
               onDrop={(e) => {
                 e.preventDefault();
                 if (canEdit && dragging) save({ id: dragging, state: col.state });
                 setDragging(null);
               }}
               style={{ padding: 10, flex: "1 0 210px", minWidth: 210 }}>
            <div style={{ borderBottom: `2px solid ${STATE_TONE[col.state]}`,
                          paddingBottom: 6, marginBottom: 8 }}>
              <div style={{ display: "flex", justifyContent: "space-between" }}>
                <span style={{ fontSize: 11, letterSpacing: ".06em",
                               textTransform: "uppercase" }}>{col.label}</span>
                <span className="mono" style={{ color: "var(--text-dim)", fontSize: 12 }}>
                  {col.tasks.length}</span>
              </div>
              <div style={{ fontSize: 10.5, color: "var(--text-dim)", marginTop: 2 }}>
                {col.intent}</div>
            </div>
            {col.tasks.map((t) => (
              <div key={t.id} draggable={canEdit}
                   onDragStart={() => setDragging(t.id)}
                   onDragEnd={() => setDragging(null)}
                   onClick={() => setOpenTask(t.id)}
                   role="button" tabIndex={0}
                   onKeyDown={(e) => {
                     if (e.key === "Enter" || e.key === " ") {
                       e.preventDefault(); setOpenTask(t.id);
                     }
                   }}
                   style={{ padding: "6px 0", cursor: "pointer",
                            borderBottom: "1px solid var(--border-soft)",
                            opacity: dragging === t.id ? 0.4 : 1 }}>
                <div style={{ fontSize: 13 }}>
                  {t.blocked && <span title={t.blocked_reason || "blocked"}
                                      style={{ color: "var(--bad)" }}>⊘ </span>}
                  {t.title}
                </div>
                <div style={{ display: "flex", gap: 8, marginTop: 4, fontSize: 11,
                              color: "var(--text-dim)" }}>
                  <span className="mono">{t.assignee || "unassigned"}</span>
                  <span style={{ marginLeft: "auto" }}>
                    {t.note_count > 0 && <>{t.note_count} note{t.note_count === 1 ? "" : "s"}</>}
                    {t.note_count > 0 && t.attachment_count > 0 && " · "}
                    {t.attachment_count > 0 && <>{t.attachment_count} attached</>}
                  </span>
                </div>
              </div>
            ))}
          </div>
        ))}
      </div>
      <p className="chart-note">
        Drag a card, or open one and pick its stage — movement is free in both directions,
        because evidence arriving late genuinely sends work back. Every move is audited.
      </p>
      {openTask && (
        <TaskDrawer taskId={openTask} canEdit={canEdit}
                    onClose={() => setOpenTask(null)} onChanged={load} />
      )}
    </div>
  );
}
