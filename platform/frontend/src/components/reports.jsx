/**
 * Case reports — generate, read, and take out.
 *
 * Generating and exporting are separate acts and separate rights: rendering evidence
 * inside the enclave is reading, removing it is egress, and the download button is the
 * only one that needs the export right.
 *
 * The rendered Markdown is displayed as TEXT, never as parsed HTML. The report contains
 * indicators recovered from a compromised machine, and a renderer that interprets them is
 * a way for hostile content to execute in an analyst's browser.
 */
import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";

function bytes(n) {
  if (!n) return "—";
  return n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB`
    : `${(n / 1048576).toFixed(1)} MB`;
}

export function CaseReports({ investigationId, canEdit, canExport }) {
  const [templates, setTemplates] = useState([]);
  const [reports, setReports] = useState([]);
  const [preview, setPreview] = useState(null);
  const [busy, setBusy] = useState("");
  const [err, setErr] = useState("");

  const load = useCallback(() => {
    api.reportTemplates().then((d) => setTemplates(d.templates || [])).catch(() => {});
    api.caseReports(investigationId).then((d) => setReports(d.reports || []))
      .catch((e) => setErr(String(e.message || e)));
  }, [investigationId]);
  useEffect(load, [load]);

  const generate = async (kind, fmt) => {
    setBusy(`${kind}-${fmt}`);
    setErr("");
    try {
      await api.generateReport(investigationId, { kind, fmt });
      load();
    } catch (e) {
      setErr(String(e.message || e));
    } finally { setBusy(""); }
  };

  const show = async (id) => {
    setErr("");
    try { setPreview({ id, text: await api.reportMarkdown(id) }); }
    catch (e) { setErr(`${e.message || e} — reading a report still needs the export right`); }
  };

  return (
    <div>
      <p className="page-sub">
        Two documents come out of a case: the plain-language summary for the people
        affected, and the technical analysis that is the evidentiary record. Both are
        rendered from this case&apos;s own rows — nothing here is typed into a template.
      </p>

      {canEdit && (
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 12 }}>
          {templates.map((t) => (
            <span key={t.id} style={{ display: "flex", gap: 6 }}>
              <button className="btn" disabled={!!busy}
                      onClick={() => generate(t.kind, "md")}>
                {busy === `${t.kind}-md` ? "Generating…" : `Generate ${t.kind}`}
              </button>
              <button className="btn" disabled={!!busy} title="rendered inside the enclave, offline"
                      onClick={() => generate(t.kind, "pdf")}
                      style={{ background: "var(--bg-elev-2)" }}>
                {busy === `${t.kind}-pdf` ? "…" : "PDF"}
              </button>
            </span>
          ))}
        </div>
      )}

      {err && <p style={{ color: "var(--bad)" }}>{err}</p>}

      {reports.length === 0 ? (
        <p className="muted">No report has been generated for this case.</p>
      ) : (
        <table className="tbl">
          <thead>
            <tr>
              <th>Report</th><th>Format</th><th>Generated</th><th>By</th>
              <th>Data as of</th><th>sha256</th><th>Size</th><th></th>
            </tr>
          </thead>
          <tbody>
            {reports.map((r) => (
              <tr key={r.id}>
                <td>{r.template}<span className="muted"> v{r.version}</span></td>
                <td className="mono">{r.fmt}</td>
                <td className="muted">{new Date(r.generated_at).toLocaleString()}</td>
                <td className="mono">{r.generated_by || "—"}</td>
                {/* The moment the data was read, not the moment someone clicked: a report
                    is a statement about evidence at a point in time. */}
                <td className="muted">{new Date(r.data_as_of).toLocaleString()}</td>
                <td className="mono" title={r.sha256}>{r.sha256.slice(0, 12)}…</td>
                <td className="mono">{bytes(r.size_bytes)}</td>
                <td style={{ display: "flex", gap: 8 }}>
                  {r.fmt === "md" && (
                    <button className="linkish" onClick={() => show(r.id)}
                            style={{ background: "none", border: 0, cursor: "pointer",
                                     color: "var(--accent)" }}>read</button>
                  )}
                  {canExport
                    ? <button className="linkish"
                              style={{ background: "none", border: 0, cursor: "pointer",
                                       color: "var(--accent)", padding: 0 }}
                              onClick={async () => {
                                setErr("");
                                try {
                                  await api.downloadBlob(
                                    api.reportDownloadUrl(r.id),
                                    `${r.kind}-${investigationId}.${r.fmt}`);
                                } catch (e) { setErr(String(e.message || e)); }
                              }}>export</button>
                    : <span className="muted" title="export is a separate right from reading">
                        export ✕</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {preview && (
        <div className="panel" style={{ padding: 14, marginTop: 12 }}>
          <div style={{ display: "flex", justifyContent: "space-between",
                        marginBottom: 8 }}>
            <strong>Report {preview.id}</strong>
            <button className="btn" onClick={() => setPreview(null)}>Close</button>
          </div>
          <pre style={{ whiteSpace: "pre-wrap", maxHeight: 620, overflow: "auto",
                        fontSize: 12, lineHeight: 1.55, margin: 0 }}>
            {preview.text}
          </pre>
        </div>
      )}
    </div>
  );
}
