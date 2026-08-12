/**
 * Findings across every investigation — searched, filtered, sorted and paged at the
 * database, with bulk adjudication and export.
 *
 * This is the view that has to survive incident scale: one run can carry thousands of
 * findings, so nothing here loads the full set into the browser.
 */
import { useState } from "react";
import FindingEvidence, { hasEvidence } from "../components/FindingEvidence.jsx";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api.js";
import DataTable from "../components/DataTable.jsx";
import { useServerTable } from "../components/useServerTable.js";
import { verdictBadge } from "../components/common.jsx";
import { TypeVerdictMatrix, TriageRings } from "../components/charts.jsx";
import { useData } from "../components/common.jsx";
import { can, useAuth } from "../auth.jsx";

const VERDICTS = ["True Positive", "Likely True Positive", "Indeterminate",
                  "Likely False Positive", "False Positive"];

export default function Findings() {
  const { user } = useAuth();
  const [params] = useSearchParams();
  const verdict = params.get("verdict") || "";
  const source = params.get("source") || "";
  const technique = params.get("technique") || "";
  const investigation = params.get("investigation") || "";
  const host = params.get("host") || "";
  // Every param a chart mark can arrive with is read HERE, or the drill is a lie: the ring
  // and backlog drills set these, and a URL parameter the table ignores filters nothing.
  const findingType = params.get("finding_type") || "";
  const adjudicated = params.get("adjudicated") || "";
  const day = params.get("day") || "";
  const tactic = params.get("tactic") || "";
  const cellsParam = params.get("cells") || "";

  const t = useServerTable(api.findings,
    { extra: { verdict, source, technique, investigation, host,
               finding_type: findingType, adjudicated, day, tactic, cells: cellsParam } });

  // Heatmap selection lives in the same URL parameter the API reads, so a composed working
  // set is bookmarkable and the back button walks it. Order within the set is meaningless;
  // a stable sort keeps the URL stable for the same selection.
  const selectedCells = new Set(cellsParam.split("|").filter(Boolean));
  const toggleCell = (ft, v) => {
    const key = `${ft}::${v}`;
    const next = new Set(selectedCells);
    next.has(key) ? next.delete(key) : next.add(key);
    t.setExtra("cells", [...next].sort().join("|"));
  };
  const FILTER_KEYS = ["cells", "verdict", "source", "technique", "investigation", "host",
                       "finding_type", "adjudicated", "day", "tactic"];
  const activeFilters = FILTER_KEYS.filter((key) => params.get(key));
  const clearFilters = () => FILTER_KEYS.forEach((key) => t.setExtra(key, ""));

  // Server aggregate: the matrix reflects the whole filtered set, never the page on screen.
  const { data: matrix } = useData(
    () => api.findingsMatrix(investigation || undefined), [investigation]);

  const [selected, setSelected] = useState([]);
  const [bulkVerdict, setBulkVerdict] = useState("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);

  const mayTriage = can(user, "analyst", "admin");

  const toggleRow = (id) =>
    setSelected((s) => (s.includes(id) ? s.filter((x) => x !== id) : [...s, id]));
  const toggleAll = (on) => setSelected(on ? t.rows.map((r) => r.id) : []);

  const applyVerdict = async () => {
    if (!bulkVerdict || selected.length === 0) return;
    setBusy(true);
    setResult(null);
    try {
      const r = await api.bulkVerdict(selected, bulkVerdict, reason);
      // A verdict change alters compromise state, so the page is re-read rather than
      // patched locally — the derived fields must come from the server.
      setResult(`${r.changed} of ${r.requested} findings set to "${r.verdict}".`);
      setSelected([]);
      setReason("");
      t.reload();
    } catch (e) {
      setResult(`Failed: ${e.message}`);
    } finally {
      setBusy(false);
    }
  };

  const exportParams = { investigation, verdict };

  return (
    <>
      <h1>Findings</h1>
      <p className="page-sub">
        Adjudicated findings across all investigations. Filtering and ordering are applied
        by the database, so the view stays responsive at incident scale.
      </p>

      <div className="panel" style={{ padding: 20 }}>
        <h3 style={{ margin: "0 0 4px" }}>Type against verdict</h3>
        <p className="chart-note">Click cells to filter the table below to exactly those
          findings — click again to remove one, and combine as many as needed. The
          Indeterminate column is where the backlog actually sits.</p>
        <TypeVerdictMatrix matrix={matrix} investigationId={investigation}
                           selected={selectedCells} onToggle={toggleCell} />
      </div>
      <div className="panel" style={{ padding: 20 }}>
        <h3 style={{ margin: "0 0 4px" }}>Triage progress</h3>
        <p className="chart-note">How much of each type a person has decided. The number is
          what still waits; the first ring is the one to open first. Click a ring to open
          exactly those findings.</p>
        <TriageRings matrix={matrix} />
      </div>

      {activeFilters.length > 0 && (
        <div className="table-controls" style={{ alignItems: "center" }}>
          <span style={{ fontSize: 12, color: "var(--text-dim)" }}>Filtered by</span>
          {[...selectedCells].sort().map((key) => {
            const [ft, v] = key.split("::");
            return (
              <button key={key} type="button" onClick={() => toggleCell(ft, v)}
                      title="Remove this filter"
                      style={{ fontSize: 12, padding: "3px 10px", borderRadius: 999,
                               border: "1px solid var(--border)", cursor: "pointer",
                               background: "var(--bg-elev-2)", color: "var(--text)" }}>
                {ft} — {v} ✕
              </button>
            );
          })}
          {activeFilters.filter((key) => key !== "cells").map((key) => (
            <button key={key} type="button" onClick={() => t.setExtra(key, "")}
                    title="Remove this filter"
                    style={{ fontSize: 12, padding: "3px 10px", borderRadius: 999,
                             border: "1px solid var(--border)", cursor: "pointer",
                             background: "var(--bg-elev-2)", color: "var(--text)" }}>
              {key.replace("_", " ")}: {params.get(key)} ✕
            </button>
          ))}
          <button type="button" onClick={clearFilters}
                  style={{ fontSize: 12, padding: "3px 12px", borderRadius: 999,
                           border: "1px solid var(--accent)", cursor: "pointer",
                           background: "transparent", color: "var(--accent)" }}>
            Clear filters
          </button>
        </div>
      )}

      <div className="table-controls">
        <select value={verdict} aria-label="Filter by verdict"
                onChange={(e) => t.setExtra("verdict", e.target.value)}>
          <option value="">Verdict: all</option>
          {VERDICTS.map((v) => <option key={v} value={v}>{v}</option>)}
        </select>
        <select value={source} aria-label="Filter by source"
                onChange={(e) => t.setExtra("source", e.target.value)}>
          <option value="">Source: all</option>
          <option value="collector">collector</option>
          <option value="memory">memory</option>
        </select>
        <input className="table-search" style={{ maxWidth: 170 }} value={technique}
               placeholder="ATT&CK id (T1021)" aria-label="Filter by ATT&CK technique"
               onChange={(e) => t.setExtra("technique", e.target.value.trim())} />
        <span style={{ marginLeft: "auto" }} className="muted">Export:</span>
        <a className="btn" href={api.exportUrl("csv", exportParams)}>CSV</a>
        <a className="btn" href={api.exportUrl("json", exportParams)}>JSON</a>
        <a className="btn" href={api.exportUrl("ioc", exportParams)}>IOC bundle</a>
      </div>

      {mayTriage && selected.length > 0 && (
        <div className="bulk-bar">
          <strong>{selected.length} selected</strong>
          <select value={bulkVerdict} aria-label="Verdict to apply"
                  onChange={(e) => setBulkVerdict(e.target.value)}>
            <option value="">Set verdict…</option>
            {VERDICTS.map((v) => <option key={v} value={v}>{v}</option>)}
          </select>
          <input className="table-search" style={{ maxWidth: 300 }} value={reason}
                 placeholder="Reason (recorded in the audit trail)"
                 aria-label="Reason for the verdict change"
                 onChange={(e) => setReason(e.target.value)} />
          <button className="btn" onClick={applyVerdict} disabled={busy || !bulkVerdict}>
            {busy ? "Applying…" : "Apply"}
          </button>
          <button className="table-clear" onClick={() => setSelected([])}>cancel</button>
        </div>
      )}

      {result && <div className="notice">{result}</div>}

      {t.error ? <div className="empty">Error: {t.error}</div> : (
        <DataTable
          serverMode
          selectable={mayTriage}
          selected={selected}
          onToggleRow={toggleRow}
          onToggleAll={toggleAll}
          rows={t.rows}
          count={t.count}
          page={t.page}
          totalPages={t.totalPages}
          query={t.q}
          sort={t.ordering}
          onQueryChange={t.onQueryChange}
          searchPlaceholder="Search findings by type, target, verdict…"
          emptyText={t.data ? "No findings match." : "Loading…"}
          columns={[
            { key: "hostname", label: "Host", mono: true, sortKey: "run__host__hostname" },
            { key: "finding_type", label: "Type" },
            { key: "target", label: "Target", mono: true },
            { key: "verdict", label: "Verdict", render: (v) => verdictBadge(v) },
            { key: "confidence", label: "Conf" },
            { key: "mitre", label: "ATT&CK", sortable: false, mono: true,
              render: (v) => (Array.isArray(v) && v.length ? v.join(", ") : "—") },
            { key: "source", label: "Source" },
            { key: "run", label: "Run", sortable: false,
              render: (v) => (v ? <Link to={`/runs/${v}`}>view</Link> : "—") },
          ]}
          renderDetail={(row) => (hasEvidence(row.raw) ? <FindingEvidence raw={row.raw} /> : null)}
        />
      )}
    </>
  );
}
