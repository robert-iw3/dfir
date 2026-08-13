/**
 * One search box over cases, findings, notes, tasks and indicators.
 *
 * The results are already scoped by the server — a case you cannot open never appears
 * here — so this component does no filtering of its own. Anything it hides would be a
 * second, weaker copy of a rule that has to hold in one place.
 */
import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api.js";

const KIND_LABEL = {
  investigation: "case",
  finding: "finding",
  note: "record",
  task: "task",
  ioc: "indicator",
};

export default function GlobalSearch() {
  const [q, setQ] = useState("");
  const [data, setData] = useState(null);
  const [open, setOpen] = useState(false);
  const box = useRef(null);
  const navigate = useNavigate();

  // Debounced: an analyst types a hostname faster than the server can answer each letter.
  useEffect(() => {
    if (q.trim().length < 2) { setData(null); return undefined; }
    const t = setTimeout(() => {
      api.search(q.trim()).then((d) => { setData(d); setOpen(true); }).catch(() => setData(null));
    }, 220);
    return () => clearTimeout(t);
  }, [q]);

  useEffect(() => {
    const away = (e) => { if (box.current && !box.current.contains(e.target)) setOpen(false); };
    document.addEventListener("mousedown", away);
    return () => document.removeEventListener("mousedown", away);
  }, []);

  const go = (r) => {
    setOpen(false);
    setQ("");
    navigate(r.url);
  };

  return (
    <div className="gsearch" ref={box}>
      <input
        type="search"
        value={q}
        placeholder="Search cases, findings, notes, indicators…"
        aria-label="Search everything you have access to"
        onChange={(e) => setQ(e.target.value)}
        onFocus={() => data && setOpen(true)}
      />
      {open && data && (
        <div className="gsearch-panel panel">
          {data.results.length === 0 && (
            <div className="empty" style={{ padding: 10 }}>
              Nothing matches “{data.query}” in the cases you have access to.
            </div>
          )}
          {data.results.map((r, i) => (
            <button key={i} className="gsearch-row" onClick={() => go(r)}>
              <span className="tag">{KIND_LABEL[r.kind] || r.kind}</span>
              <span className="gsearch-title">{r.title}</span>
              <span className="muted">{r.subtitle}</span>
            </button>
          ))}
          {data.truncated && (
            <div className="muted" style={{ padding: "6px 10px" }}>
              Showing the first {data.per_kind_limit} of each kind — narrow the search to see more.
            </div>
          )}
        </div>
      )}
    </div>
  );
}
