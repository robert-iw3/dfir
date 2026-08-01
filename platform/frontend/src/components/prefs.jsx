/**
 * Per-analyst display preferences, persisted locally.
 *
 * Density and time zone are working preferences, not settings that affect data, so they
 * live in the browser rather than the platform. They persist per workstation so an
 * analyst's chosen layout survives a reload.
 *
 * Time zone matters in forensics: an analyst reasons in UTC when correlating across
 * hosts and in local time when talking to the people who were on shift. Both must be
 * available, and which one is shown must never be ambiguous — every rendered timestamp
 * carries its zone.
 */
import { createContext, useContext, useEffect, useMemo, useState } from "react";

const PrefsCtx = createContext(null);
const KEY = "ir_prefs";

const DEFAULTS = { density: "comfortable", zone: "utc" };

function load() {
  try {
    return { ...DEFAULTS, ...JSON.parse(localStorage.getItem(KEY) || "{}") };
  } catch {
    return { ...DEFAULTS };
  }
}

export function PrefsProvider({ children }) {
  const [prefs, setPrefs] = useState(load);

  useEffect(() => {
    try { localStorage.setItem(KEY, JSON.stringify(prefs)); } catch { /* private mode */ }
    document.documentElement.dataset.density = prefs.density;
  }, [prefs]);

  const value = useMemo(() => ({
    ...prefs,
    set: (patch) => setPrefs((p) => ({ ...p, ...patch })),
  }), [prefs]);

  return <PrefsCtx.Provider value={value}>{children}</PrefsCtx.Provider>;
}

export const usePrefs = () => useContext(PrefsCtx) || { ...DEFAULTS, set: () => {} };

/** Absolute timestamp in the analyst's chosen zone, always labelled. */
export function formatTime(value, zone = "utc") {
  if (!value) return "—";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  if (zone === "utc") return `${d.toISOString().slice(0, 19).replace("T", " ")}Z`;
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
         `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())} local`;
}

/** Elapsed time, for scanning. Paired with the absolute value, never replacing it. */
export function relativeTime(value) {
  if (!value) return "";
  const then = new Date(value).getTime();
  if (Number.isNaN(then)) return "";
  const secs = Math.round((Date.now() - then) / 1000);
  const future = secs < 0;
  const s = Math.abs(secs);
  const units = [["y", 31536000], ["mo", 2592000], ["d", 86400],
                 ["h", 3600], ["m", 60]];
  for (const [label, size] of units) {
    if (s >= size) {
      const n = Math.floor(s / size);
      return future ? `in ${n}${label}` : `${n}${label} ago`;
    }
  }
  return future ? "soon" : "just now";
}

/** Timestamp with the elapsed value as a title, so both readings are available. */
export function Time({ value }) {
  const { zone } = usePrefs();
  if (!value) return <span className="muted">—</span>;
  return (
    <span className="mono" title={relativeTime(value)}>
      {formatTime(value, zone)}
    </span>
  );
}
