import { useEffect, useState } from "react";

/**
 * Data-loading hook shared by every page.
 *
 * `refreshMs` keeps the view current in the background. A refresh differs from the first
 * load in the way that matters: it must not blank the screen. Existing data stays on show
 * until new data replaces it, and a failed refresh is marked rather than thrown — a
 * backend restarting underneath an analyst should not discard the page they were reading.
 * Only the initial load reports an error.
 *
 * `paused` suspends refreshing. Callers pass it while the user is mid-edit: re-rendering
 * a table under someone typing a justification is worse than data a minute old.
 */
export function useData(fn, deps = [], { refreshMs = 0, paused = false } = {}) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [stale, setStale] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    let alive = true;
    setData(null);
    setError(null);
    setStale(false);
    fn().then((d) => alive && setData(d)).catch((e) => alive && setError(e.message));
    return () => { alive = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, reloadKey]);

  useEffect(() => {
    if (!refreshMs || paused) return undefined;
    let alive = true;
    const tick = () => {
      // A hidden tab is not being read; polling it only costs the backend.
      if (document.hidden) return;
      fn()
        .then((d) => { if (alive) { setData(d); setStale(false); } })
        .catch(() => { if (alive) setStale(true); });
    };
    const id = setInterval(tick, refreshMs);
    return () => { alive = false; clearInterval(id); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, reloadKey, refreshMs, paused]);

  return { data, error, stale, reload: () => setReloadKey((k) => k + 1) };
}

export function verdictBadge(v) {
  if (!v) return <span className="muted">—</span>;
  const cls = "v-" + v.toLowerCase().replace(/\s+/g, "-");
  return <span className={`badge ${cls}`}>{v}</span>;
}

// Twelve dots because the ring reads as motion rather than as a countdown: nothing being
// waited on here reports progress, so a determinate bar would be inventing one.
export function Ring() {
  return (
    <span className="ring" aria-hidden="true">
      {Array.from({ length: 12 }, (_, i) => <i key={i} />)}
    </span>
  );
}

export function Loading({ error, label = "Loading…" }) {
  if (error) return <div className="empty">Error: {error}</div>;
  return (
    <div className="empty">
      <span className="waiting" role="status" aria-live="polite">
        <Ring /><span>{label}</span>
      </span>
    </div>
  );
}

export function Empty({ children }) {
  return <div className="empty">{children}</div>;
}
