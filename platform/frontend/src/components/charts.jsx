/**
 * Hand-built SVG charts — the visualization tracks (V1–V7).
 *
 * The rules these obey are in planning/VISUALIZATION.md and they are constraints, not
 * style: no library (the enclave builds everything it serves), every mark drills to the
 * filtered table behind it by a URL the table already accepts, nothing is computed
 * client-side that the API did not serve, verdict is a dimension in every count, and
 * "empty" states say WHICH empty they are.
 *
 * Every mark is a real focusable element (role=link, tabIndex, Enter/Space), and color is
 * never the only encoding — counts, labels or position always carry the same fact.
 */
import { useState } from "react";
import { useNavigate } from "react-router-dom";

// One drill mechanism for every chart: navigate to the target with the params the mark
// represents. The params must be ones the destination already reads from its URL —
// a chart that invents a filter produces a view nobody can reproduce by hand.
function useDrill() {
  const navigate = useNavigate();
  return (path, params) => {
    const qs = new URLSearchParams(
      Object.fromEntries(Object.entries(params).filter(([, v]) => v !== "" && v != null)));
    navigate(`${path}?${qs.toString()}`);
  };
}

function markProps(onOpen, title) {
  return {
    role: "link", tabIndex: 0, style: { cursor: "pointer" },
    onClick: onOpen,
    onKeyDown: (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onOpen(); } },
  };
}

const BAND_STYLE = {
  // Confidence bands double-encoded: color AND stroke pattern, so the band survives
  // monochrome printing and color-blind reading.
  confirmed: { fill: "var(--good)", dash: "" },
  probable:  { fill: "var(--accent)", dash: "" },
  possible:  { fill: "var(--warn)", dash: "4 3" },
  "":        { fill: "var(--text-dim)", dash: "2 3" },
};

/* ------------------------------------------------------------------ V2: stat tiles */

export function StatTiles({ tiles }) {
  // The headline numbers, each a drill. A stat tile is the correct "chart" for a single
  // figure — a plot around one number is decoration.
  return (
    <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 12 }}>
      {(tiles || []).filter(Boolean).map((t) => (
        <div key={t.label}
             {...(t.onOpen ? markProps(t.onOpen) : {})}
             className="panel"
             style={{ flex: "1 1 150px", minWidth: 150, padding: "10px 14px",
                      borderLeft: `3px solid ${t.accent || "var(--accent)"}` }}>
          <div style={{ fontSize: 10, letterSpacing: ".08em", textTransform: "uppercase",
                        color: "var(--text-dim)" }}>{t.label}</div>
          <div className="mono" style={{ fontSize: 26, fontWeight: 700, lineHeight: 1.3 }}>
            {t.value}</div>
          {t.sub && <div style={{ fontSize: 10.5, color: "var(--text-dim)" }}>{t.sub}</div>}
        </div>
      ))}
    </div>
  );
}

/* --------------------------------------------------- shared geometry for radial forms */

const TAU = Math.PI * 2;
const polar = (cx, cy, r, a) => [cx + r * Math.cos(a - Math.PI / 2),
                                 cy + r * Math.sin(a - Math.PI / 2)];

function arcTo(cx, cy, r, a0, a1) {
  const [x, y] = polar(cx, cy, r, a1);
  return `A ${r} ${r} 0 ${a1 - a0 > Math.PI ? 1 : 0} 1 ${x} ${y}`;
}

function ringSlice(cx, cy, rIn, rOut, a0, a1) {
  const [x0, y0] = polar(cx, cy, rOut, a0);
  const [x1, y1] = polar(cx, cy, rIn, a1);
  const large = a1 - a0 > Math.PI ? 1 : 0;
  return `M ${x0} ${y0} ${arcTo(cx, cy, rOut, a0, a1)} L ${x1} ${y1} `
       + `A ${rIn} ${rIn} 0 ${large} 0 ${polar(cx, cy, rIn, a0).join(" ")} Z`;
}

// Kill-chain position as color: early stages cool, late stages hot. The ramp is ORDINAL —
// it encodes how far through the intrusion a stage sits, which is real information — and
// every arc is labeled, so color is never carrying identity alone.
const STAGE_RAMP = ["#38bdf8", "#22d3ee", "#2dd4bf", "#34d399", "#a3e635", "#facc15",
                    "#fb923c", "#f97316", "#f43f5e", "#e11d48", "#be123c", "#9f1239"];
const stageColor = (i, n) => STAGE_RAMP[Math.min(STAGE_RAMP.length - 1,
                                                 Math.floor((i / Math.max(n - 1, 1)) * (STAGE_RAMP.length - 1)))];

/* ------------------------------------------------- V2: host x tactic chord diagram */

export function KillChainChord({ stats, investigationId }) {
  const drill = useDrill();
  const [focus, setFocus] = useState(null);
  const pairs = stats?.host_tactics || [];
  if (!pairs.length) return <p className="muted">No findings carry a technique yet.</p>;

  const order = (stats?.killchain_stages || []).map((s) => s.tactic);
  const tacticName = Object.fromEntries(
    (stats?.killchain_stages || []).map((s) => [s.tactic, s.name]));

  const hostTotals = {}, tacticTotals = {};
  for (const p of pairs) {
    hostTotals[p.host] = (hostTotals[p.host] || 0) + p.count;
    tacticTotals[p.tactic] = (tacticTotals[p.tactic] || 0) + p.count;
  }
  // A ring carries only so many labelled arcs before labels collide and ribbons become a hairball,
  // so the smallest hosts FOLD into one named bucket — the fleet is 50+ machines and this must
  // stay readable at that size. Folding is a last resort: labels are decluttered with leader lines
  // first, and the bucket names its members on hover.
  const MAX_ARCS = 28;
  const ranked = Object.keys(hostTotals).sort((a, b) => hostTotals[b] - hostTotals[a]);
  const folded = ranked.length > MAX_ARCS ? ranked.slice(MAX_ARCS - 1) : [];
  const OTHERS = folded.length ? `${folded.length} smallest hosts` : null;
  const hosts = folded.length ? [...ranked.slice(0, MAX_ARCS - 1), OTHERS] : ranked;
  const foldedSet = new Set(folded);
  const arcHost = (h) => (foldedSet.has(h) ? OTHERS : h);
  if (OTHERS) {
    hostTotals[OTHERS] = folded.reduce((n, h) => n + hostTotals[h], 0);
    for (const h of folded) delete hostTotals[h];
  }
  const tactics = order.filter((t) => tacticTotals[t]);
  const grand = pairs.reduce((n, p) => n + p.count, 0);

  // Hosts fill the left half, tactics the right, each proportional to its own total. A
  // bipartite split keeps every ribbon crossing the middle, so the picture reads as
  // "machines on one side, what they did on the other" rather than as a hairball.
  const PAD = 0.022;
  const seg = (keys, totals, from, to) => {
    const span = (to - from) - PAD * keys.length;
    const sum = keys.reduce((n, k) => n + totals[k], 0) || 1;
    let a = from + PAD / 2;
    const out = {};
    for (const k of keys) {
      const w = (totals[k] / sum) * span;
      out[k] = [a, a + w];
      a += w + PAD;
    }
    return out;
  };
  const hostArc = seg(hosts, hostTotals, TAU / 2, TAU);
  const tacticArc = seg(tactics, tacticTotals, 0, TAU / 2);

  // Ribbons stack inside each arc in a stable order, so the same pair keeps its place.
  const hostCur = Object.fromEntries(hosts.map((h) => [h, hostArc[h][0]]));
  const tacticCur = Object.fromEntries(tactics.map((t) => [t, tacticArc[t][0]]));
  const sorted = [...pairs].sort(
    (a, b) => hosts.indexOf(arcHost(a.host)) - hosts.indexOf(arcHost(b.host))
           || tactics.indexOf(a.tactic) - tactics.indexOf(b.tactic));

  const S = 680, PADX = 190, cx = S / 2, cy = S / 2, rOut = 244, rIn = 224;
  const LABEL_GAP = 15;      // px — the least vertical room a label needs
  const short = (t) => (t.length > 22 ? t.slice(0, 21) + "\u2026" : t);
  const ribbons = sorted.map((p) => {
    const ah = arcHost(p.host);
    const hw = (p.count / hostTotals[ah]) * (hostArc[ah][1] - hostArc[ah][0]);
    const tw = (p.count / tacticTotals[p.tactic])
             * (tacticArc[p.tactic][1] - tacticArc[p.tactic][0]);
    const h0 = hostCur[ah], h1 = h0 + hw;
    const t0 = tacticCur[p.tactic], t1 = t0 + tw;
    hostCur[ah] = h1; tacticCur[p.tactic] = t1;
    const [sx, sy] = polar(cx, cy, rIn, h0);
    const [tx, ty] = polar(cx, cy, rIn, t0);
    const d = `M ${sx} ${sy} ${arcTo(cx, cy, rIn, h0, h1)} `
            + `Q ${cx} ${cy} ${tx} ${ty} ${arcTo(cx, cy, rIn, t0, t1)} `
            + `Q ${cx} ${cy} ${sx} ${sy} Z`;
    return { ...p, d, color: stageColor(tactics.indexOf(p.tactic), tactics.length) };
  });

  // Labels are placed by DECLUTTERING rather than by trusting each arc's angle: adjacent
  // small arcs point at nearly the same spot, so their names overlap however large the
  // circle is. Each side is sorted by preferred height and then pushed apart to a minimum
  // gap, and a leader line ties every label back to its own arc.
  const rawLabels = [
    ...tactics.map((t, i) => {
      const [a0, a1] = tacticArc[t];
      const mid = (a0 + a1) / 2;
      return { key: t, text: tacticName[t] || t, mid,
               pct: Math.round((tacticTotals[t] / grand) * 100),
               onOpen: () => drill("/findings", { investigation: investigationId, tactic: t }) };
    }),
    ...hosts.map((h) => {
      const [a0, a1] = hostArc[h];
      const mid = (a0 + a1) / 2;
      return { key: h, text: h, mid,
               pct: Math.round((hostTotals[h] / grand) * 100),
               onOpen: () => drill("/hosts", h === OTHERS ? {} : { q: h }) };
    }),
  ];
  const labels = [];
  for (const right of [true, false]) {
    const side = rawLabels
      .filter((L) => (Math.cos(L.mid - Math.PI / 2) >= 0) === right)
      .map((L) => {
        const [ax, ay] = polar(cx, cy, rOut + 2, L.mid);
        const [bx, by] = polar(cx, cy, rOut + 16, L.mid);
        return { ...L, ax, ay, bx, by, right, ty: by,
                 tx: right ? cx + rOut + 46 : cx - rOut - 46 };
      })
      .sort((a, b) => a.ty - b.ty);
    for (let i = 1; i < side.length; i += 1) {
      if (side[i].ty - side[i - 1].ty < LABEL_GAP) side[i].ty = side[i - 1].ty + LABEL_GAP;
    }
    // Pushed off the bottom, walk back up so the column stays inside the canvas.
    for (let i = side.length - 2; i >= 0; i -= 1) {
      if (side[i + 1].ty - side[i].ty < LABEL_GAP) side[i].ty = side[i + 1].ty - LABEL_GAP;
    }
    labels.push(...side);
  }

  const lit = (p) => !focus || arcHost(p.host) === focus || p.tactic === focus;
  const focusPairs = focus
    ? pairs.filter((p) => arcHost(p.host) === focus || p.tactic === focus) : [];
  const focusTotal = focusPairs.reduce((n, p) => n + p.count, 0);

  return (
    <div style={{ display: "flex", gap: 20, flexWrap: "wrap", alignItems: "flex-start" }}>
      <svg role="img"
           aria-label={`Chord diagram: ${hosts.length} hosts against ${tactics.length} attack stages`}
           viewBox={`${-PADX} 0 ${S + PADX * 2} ${S}`}
           style={{ width: "100%", maxWidth: S + PADX * 2, minWidth: 320 }}
           onMouseLeave={() => setFocus(null)}>
        {ribbons.map((p) => (
          <path key={`${p.host}|${p.tactic}`} d={p.d} fill={p.color}
                fillOpacity={lit(p) ? (focus ? 0.62 : 0.34) : 0.05}
                stroke={p.color} strokeOpacity={lit(p) ? 0.5 : 0.04} strokeWidth="0.5"
                style={{ cursor: "pointer", transition: "fill-opacity .12s" }}
                tabIndex={0} role="link"
                onClick={() => drill("/findings", { investigation: investigationId,
                                                    tactic: p.tactic, host: p.host_id })}
                onKeyDown={(e) => { if (e.key === "Enter") drill("/findings", {
                  investigation: investigationId, tactic: p.tactic, host: p.host_id }); }}
                onMouseEnter={() => setFocus(ah)}>
            <title>{`${p.host} — ${p.name}\n${p.count} finding(s), ${p.confirmed} confirmed · ${p.pct_of_host}% of this host's findings\nOpen them.`}</title>
          </path>
        ))}

        {labels.map((L) => (
          <g key={`lead-${L.key}`} pointerEvents="none">
            {/* A leader line, because the label sits where it FITS rather than where its arc
                happens to point. Without it a decluttered label is attached to nothing. */}
            <polyline points={`${L.ax},${L.ay} ${L.bx},${L.by} ${L.tx},${L.ty}`}
                      fill="none" stroke="var(--border)" strokeWidth="1"
                      opacity={!focus || focus === L.key ? 0.7 : 0.15} />
          </g>
        ))}
        {labels.map((L) => (
          <text key={`lab-${L.key}`} x={L.tx + (L.right ? 5 : -5)} y={L.ty}
                fontSize="12" fill="var(--text)" dominantBaseline="middle"
                textAnchor={L.right ? "start" : "end"}
                opacity={!focus || focus === L.key ? 1 : 0.3}
                style={{ cursor: "pointer" }}
                onMouseEnter={() => setFocus(L.key)}
                onClick={() => L.onOpen()}>
            {short(L.text)}<tspan fill="var(--text-dim)"> {L.pct}%</tspan>
          </text>
        ))}

        {tactics.map((t, i) => {
          const [a0, a1] = tacticArc[t];
          const pct = Math.round((tacticTotals[t] / grand) * 100);
          return (
            <g key={t} onMouseEnter={() => setFocus(t)} style={{ cursor: "pointer" }}
               tabIndex={0} role="link"
               onClick={() => drill("/findings", { investigation: investigationId, tactic: t })}>
              <title>{`${tacticName[t] || t} — ${tacticTotals[t]} finding(s), ${pct}% of the intrusion. Open them.`}</title>
              <path d={ringSlice(cx, cy, rIn + 3, rOut, a0, a1)}
                    fill={stageColor(i, tactics.length)}
                    fillOpacity={!focus || focus === t ? 0.95 : 0.25} />

            </g>
          );
        })}

        {hosts.map((h) => {
          const [a0, a1] = hostArc[h];
          const pct = Math.round((hostTotals[h] / grand) * 100);
          return (
            <g key={h} onMouseEnter={() => setFocus(h)} style={{ cursor: "pointer" }}
               tabIndex={0} role="link"
               onClick={() => drill("/hosts", h === OTHERS ? {} : { q: h })}>
              <title>{h === OTHERS
                ? `${folded.length} hosts with the least evidence, ${hostTotals[h]} finding(s) between them (${pct}%):\n${folded.join(", ")}\nOpen the host list.`
                : `${h} — ${hostTotals[h]} finding(s), ${pct}% of the intrusion. Open this host.`}</title>
              <path d={ringSlice(cx, cy, rIn + 3, rOut, a0, a1)}
                    fill="var(--text-dim)"
                    fillOpacity={!focus || focus === h ? 0.85 : 0.2} />

            </g>
          );
        })}

      </svg>

      <div style={{ flex: "1 1 260px", minWidth: 240 }}>
        <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 2 }}>
          {focus || `${hosts.length} hosts · ${tactics.length} stages`}</div>
        <div className="chart-note" style={{ marginTop: 0, marginBottom: 8 }}>
          {focus ? `${focusTotal} findings` : "strongest pairings — hover an arc to isolate"}
        </div>
        <table className="tbl" style={{ fontSize: 11.5 }}>
          <thead>
            <tr>
              <th style={{ textAlign: "left" }}>Host</th>
              <th style={{ textAlign: "left" }}>Stage</th>
              <th style={{ textAlign: "right" }}>n</th>
              <th style={{ textAlign: "right" }}>of host</th>
            </tr>
          </thead>
          <tbody>
            {(focus ? focusPairs : pairs).slice(0, 14).map((p) => (
              <tr key={`${p.host}|${p.tactic}`}>
                <td className="mono">{p.host}</td>
                <td>{p.name}</td>
                <td style={{ textAlign: "right" }} className="mono">{p.count}</td>
                <td style={{ textAlign: "right", color: "var(--text-dim)" }}>{p.pct_of_host}%</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ----------------------------------------------------------------- donut, reusable */

export function Donut({ slices, centerTop, centerSub, onSlice }) {
  const [focus, setFocus] = useState(null);
  const rows = (slices || []).filter((s) => s.value > 0);
  if (!rows.length) return <p className="muted">Nothing to show.</p>;
  const total = rows.reduce((n, s) => n + s.value, 0);
  const S = 250, cx = S / 2, cy = S / 2, rOut = 108, rIn = 66;
  let a = 0;
  const arcs = rows.map((s) => {
    const w = (s.value / total) * TAU;
    const seg = { ...s, a0: a, a1: a + w, pct: Math.round((s.value / total) * 100) };
    a += w;
    return seg;
  });
  return (
    <div style={{ display: "flex", gap: 18, alignItems: "center", flexWrap: "wrap" }}>
      <svg viewBox={`0 0 ${S} ${S}`} role="img" style={{ width: 250, minWidth: 200 }}
           aria-label={rows.map((s) => `${s.label}: ${s.value}`).join(", ")}
           onMouseLeave={() => setFocus(null)}>
        {arcs.map((s) => (s.a1 - s.a0 >= TAU - 1e-6 ? (
          <circle key={s.label} cx={cx} cy={cy} r={(rIn + rOut) / 2}
                  fill="none" stroke={s.color} strokeWidth={rOut - rIn}
                  style={{ cursor: onSlice ? "pointer" : "default" }}
                  onMouseEnter={() => setFocus(s.label)} onClick={() => onSlice?.(s)}>
            <title>{`${s.label}: ${s.value} (100%)`}</title>
          </circle>
        ) : (
          <path key={s.label}
                d={ringSlice(cx, cy, rIn, focus === s.label ? rOut + 6 : rOut, s.a0, s.a1)}
                fill={s.color} fillOpacity={!focus || focus === s.label ? 0.92 : 0.3}
                stroke="var(--bg)" strokeWidth="2"
                style={{ cursor: onSlice ? "pointer" : "default", transition: "d .1s" }}
                tabIndex={onSlice ? 0 : -1} role={onSlice ? "link" : undefined}
                onMouseEnter={() => setFocus(s.label)}
                onClick={() => onSlice?.(s)}
                onKeyDown={(e) => { if (e.key === "Enter") onSlice?.(s); }}>
            <title>{`${s.label}: ${s.value} (${s.pct}%)`}</title>
          </path>
        )))}
        <text x={cx} y={cy - 4} textAnchor="middle" fontSize="26" fontWeight="700"
              fill="var(--text)" className="mono">
          {focus ? arcs.find((s) => s.label === focus)?.pct + "%" : centerTop}</text>
        <text x={cx} y={cy + 16} textAnchor="middle" fontSize="10.5" fill="var(--text-dim)">
          {focus || centerSub}</text>
      </svg>
      <div style={{ flex: "1 1 180px", minWidth: 170, display: "flex",
                    flexDirection: "column", gap: 6 }}>
        {arcs.map((s) => (
          <div key={s.label} onMouseEnter={() => setFocus(s.label)}
               onMouseLeave={() => setFocus(null)}
               onClick={() => onSlice?.(s)}
               style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12,
                        cursor: onSlice ? "pointer" : "default",
                        opacity: !focus || focus === s.label ? 1 : 0.5 }}>
            <span style={{ width: 10, height: 10, borderRadius: 2, background: s.color,
                           flex: "0 0 auto" }} />
            <span style={{ flex: 1 }}>{s.label}</span>
            <span className="mono">{s.value}</span>
            <span style={{ color: "var(--text-dim)", width: 34, textAlign: "right" }}>
              {s.pct}%</span>
          </div>
        ))}
      </div>
    </div>
  );
}


/* -------------------------------------------------------- V5: evidence kinds per link */

export function EvidenceKindBars({ edge }) {
  // Which evidence CARRIED the link: one riding a single shared address dies when the actor
  // rotates, one riding mutex + JA3 + campaign id does not. That distinction has to be readable
  // without opening the factors JSON.
  const drill = useDrill();
  // The engine stores the strongest contribution as `top` and keeps ranks 2..6 (plus any
  // contradicted row, whatever it ranks) as `corroboration` — the top is deliberately not
  // duplicated there. The bars re-join them in rank order.
  const rows = [edge?.top_factor, ...(edge?.corroboration || [])].filter((r) => r && r.kind);
  if (!rows.length) {
    const kinds = edge?.evidence_kinds || [];
    return <p className="muted">
      {kinds.length
        ? `Carried by: ${kinds.join(", ")} — the per-contribution detail was not kept for this link.`
        : "This link carries no factor breakdown."}
    </p>;
  }
  const max = Math.max(...rows.map((r) => r.weight ?? 0), 0.001);
  return (
    <svg viewBox={`0 0 420 ${rows.length * 22 + 6}`} role="img"
         aria-label={`Contributions carrying this link: ${rows.map((r) => r.subkind || r.kind).join(", ")}`}
         style={{ width: "100%", maxWidth: 420 }}>
      {rows.map((r, i) => {
        const label = r.subkind || r.kind;
        const w = Math.max(3, ((r.weight ?? 0) / max) * 190);
        return (
          <g key={`${label}|${r.value}|${i}`}
             {...markProps(() => drill("/ioc-search", { q: r.value }))}
             aria-label={`${label} ${r.value}: weight ${(r.weight ?? 0).toFixed(3)}`}>
            <title>{`${label}: ${r.value}
contributed ${(r.weight ?? 0).toFixed(3)} — search everywhere this appears.`}</title>
            <text x={104} y={i * 22 + 15} textAnchor="end" fontSize="11.5" fill="var(--text)">{label}</text>
            <rect x={110} y={i * 22 + 5} width={w} height={12} rx={2}
                  fill="var(--accent)" fillOpacity="0.8" />
            <text x={116 + w} y={i * 22 + 15} fontSize="10.5" fill="var(--text-dim)">
              {(r.weight ?? 0).toFixed(3)} · {String(r.value).slice(0, 30)}</text>
          </g>
        );
      })}
    </svg>
  );
}

/* ------------------------------------------------------------------ V5: rarity scatter */

export function RarityScatter({ indicators }) {
  const drill = useDrill();
  const [hover, setHover] = useState(null);
  const rows = (indicators || []).filter((r) => r.host_count != null);
  if (!rows.length) return <p className="chart-note">No shared indicators recorded.</p>;

  const W = 860, H = 340, left = 56, right = 24, top = 26, bottom = H - 44;
  const maxHosts = Math.max(...rows.map((r) => r.host_count));
  const maxW = Math.max(...rows.map((r) => r.link_weight ?? 0), 0.001);
  const x = (h) => left + 12 + ((h - 1) / Math.max(maxHosts - 1, 1)) * (W - left - right - 24);
  const y = (w) => bottom - 8 - (w / maxW) * (bottom - top - 12);

  // Signal is the point of the chart, so it is said, not implied: an indicator carrying at
  // least 60% of the strongest weight is drawn in the accent and counted in the headline.
  // The threshold is presentation — the weights themselves are the engine's, never rescaled.
  const isSignal = (r) => (r.link_weight ?? 0) >= 0.6 * maxW;
  const nSignal = rows.filter(isSignal).length;

  // Direct labels on the strongest indicators, decluttered vertically so names never stack.
  const labeled = [...rows].sort((a, b) => (b.link_weight ?? 0) - (a.link_weight ?? 0)).slice(0, 5)
    .map((r) => ({ r, ly: y(r.link_weight ?? 0) }))
    .sort((a, b) => a.ly - b.ly);
  // Clamped off the plot's top edge so the first label is never clipped.
  if (labeled.length) labeled[0].ly = Math.max(labeled[0].ly, top + 8);
  for (let i = 1; i < labeled.length; i++) {
    if (labeled[i].ly - labeled[i - 1].ly < 15) labeled[i].ly = labeled[i - 1].ly + 15;
  }
  const labelOf = (r) => (r.value.length > 26 ? r.value.slice(0, 25) + "…" : r.value);

  const at = hover != null ? rows[hover] : null;
  return (
    <div>
      {/* The legend IS the headline: swatch, count, and what the color means, in one line.
          Written up here rather than inside the plot, where sooner or later data lands on
          top of any caption — the top-left corner belongs to the strongest indicators. */}
      <div style={{ display: "flex", gap: 26, alignItems: "baseline", flexWrap: "wrap",
                    marginBottom: 6 }}>
        <span style={{ fontSize: 13, display: "inline-flex", alignItems: "center", gap: 7 }}>
          <span aria-hidden="true" style={{ width: 10, height: 10, borderRadius: "50%",
                                            background: "var(--accent)" }} />
          <span className="mono" style={{ fontWeight: 700, color: "var(--accent)" }}>{nSignal}</span>
          <span style={{ color: "var(--text-dim)" }}>signal — rare, heavily weighted</span>
        </span>
        <span style={{ fontSize: 13, display: "inline-flex", alignItems: "center", gap: 7 }}>
          <span aria-hidden="true" style={{ width: 10, height: 10, borderRadius: "50%",
                                            background: "var(--text-dim)", opacity: 0.55 }} />
          <span className="mono" style={{ fontWeight: 700, color: "var(--text-dim)" }}>{rows.length - nSignal}</span>
          <span style={{ color: "var(--text-dim)" }}>environment — common, weightless</span>
        </span>
        {at && (
          <span className="mono" style={{ fontSize: 12, marginLeft: "auto", color: "var(--text-dim)" }}>
            {at.kind}: {labelOf(at)} · {at.host_count} hosts · {(at.link_weight ?? 0).toFixed(3)}
          </span>
        )}
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} role="img"
           aria-label={`Rarity scatter: ${rows.length} indicators, ${nSignal} weighted as signal`}
           style={{ width: "100%" }}>
        {/* Grid first, so everything data-bearing sits on top of it. */}
        {[0.25, 0.5, 0.75, 1].map((f) => (
          <line key={`gy${f}`} x1={left} x2={W - right} y1={y(f * maxW)} y2={y(f * maxW)}
                stroke="var(--border)" strokeWidth="1" strokeOpacity="0.45" />
        ))}
        {[1, Math.ceil(maxHosts / 2), maxHosts].filter((v, i, a) => a.indexOf(v) === i).map((h) => (
          <line key={`gx${h}`} x1={x(h)} x2={x(h)} y1={top - 4} y2={bottom}
                stroke="var(--border)" strokeWidth="1" strokeOpacity="0.45" />
        ))}
        <line x1={left} y1={bottom} x2={W - right} y2={bottom} stroke="var(--border)" />
        <line x1={left} y1={top - 8} x2={left} y2={bottom} stroke="var(--border)" />
        {[1, Math.ceil(maxHosts / 2), maxHosts].filter((v, i, a) => a.indexOf(v) === i).map((h) => (
          <text key={h} x={x(h)} y={bottom + 16} textAnchor="middle" fontSize="10.5"
                fill="var(--text-dim)" className="mono">{h}</text>
        ))}
        <text x={(W + left - right) / 2} y={H - 8} textAnchor="middle" fontSize="11"
              fill="var(--text-dim)">hosts carrying the indicator →</text>
        <text x={16} y={(bottom + top) / 2} fontSize="11" fill="var(--text-dim)"
              transform={`rotate(-90 16 ${(bottom + top) / 2})`} textAnchor="middle">
          link weight →</text>
        {rows.slice(0, 120).map((r, i) => {
          const open = () => drill("/ioc-search", { q: r.value });
          const signal = isSignal(r);
          return (
            <g key={`${r.kind}|${r.value}`} {...markProps(open)}
               onMouseEnter={() => setHover(i)} onMouseLeave={() => setHover(null)}
               aria-label={`${r.kind} ${r.value}: ${r.host_count} hosts, weight ${(r.link_weight ?? 0).toFixed(3)}`}>
              <title>{`${r.kind}: ${r.value}\n${r.host_count} host(s) · weight ${(r.link_weight ?? 0).toFixed(3)} — search everywhere it appears.`}</title>
              <circle cx={x(r.host_count)} cy={y(r.link_weight ?? 0)}
                      r={hover === i ? 7 : signal ? 5.5 : 4.5}
                      fill={signal ? "var(--accent)" : "var(--text-dim)"}
                      fillOpacity={signal ? 0.85 : 0.45}
                      stroke="var(--bg)" strokeWidth="1.5" />
            </g>
          );
        })}
        {/* Labels LAST, with a surface halo: they must stay readable over dots and grid. */}
        {labeled.map(({ r, ly }) => {
          // A label leads away from the nearer edge, so a heavily-weighted indicator sitting
          // far right cannot run its name off the canvas.
          const px = x(r.host_count), flip = px > (W - right) - 240;
          return (
            <g key={`lbl|${r.kind}|${r.value}`} style={{ pointerEvents: "none" }}>
              <line x1={px + (flip ? -8 : 8)} y1={y(r.link_weight ?? 0)}
                    x2={px + (flip ? -26 : 26)} y2={ly}
                    stroke="var(--text-dim)" strokeWidth="0.75" strokeOpacity="0.6" />
              <text x={px + (flip ? -30 : 30)} y={ly + 4} fontSize="11" fill="var(--text)"
                    textAnchor={flip ? "end" : "start"} className="mono"
                    stroke="var(--bg-elev)" strokeWidth="3.5" paintOrder="stroke">
                {labelOf(r)}</text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

/* ------------------------------------------------------------------ V5: cohesion strip */

// The question is a DIRECTION — tightening or fragmenting — and below four runs there is no
// curve worth drawing, so the standing is stated per campaign instead.
export function CohesionStrip({ history }) {
  const runs = history?.runs || [];
  if (runs.length === 0) return <p className="chart-note">No correlation runs recorded.</p>;

  const labels = [...new Set(runs.flatMap((r) => r.campaigns.map((c) => c.label)))];
  const series = labels.map((lbl) => ({
    label: lbl,
    points: runs.map((r) => {
      const c = r.campaigns.find((x) => x.label === lbl);
      return c ? { at: r.at, v: c.cohesion_mean, hosts: c.hosts, current: r.is_current } : null;
    }),
  }));

  if (runs.length < 4) {
    return (
      <div style={{ display: "flex", flexDirection: "column", gap: 12, padding: "4px 2px" }}>
        {series.map((s) => {
          const present = s.points.filter(Boolean);
          const now = present[present.length - 1];
          const prev = present.length > 1 ? present[present.length - 2] : null;
          const delta = prev ? now.v - prev.v : null;
          const moved = delta != null && Math.abs(delta) >= 0.005;
          const tone = !moved ? "var(--text-dim)" : delta > 0 ? "var(--good)" : "var(--bad)";
          const word = !prev ? "one run so far"
            : !moved ? `unchanged across ${present.length} runs`
            : delta > 0 ? `tightening — up ${delta.toFixed(2)} since ${prev.at.slice(5, 10)}`
            : `fragmenting — down ${Math.abs(delta).toFixed(2)} since ${prev.at.slice(5, 10)}`;
          return (
            <div key={s.label} style={{ display: "flex", alignItems: "baseline", gap: 16,
                                        flexWrap: "wrap" }}>
              <span style={{ fontSize: 13, minWidth: 150 }}>{s.label}</span>
              <span className="mono" style={{ fontSize: 24, fontWeight: 700, color: tone }}>
                {now.v.toFixed(2)}</span>
              <span style={{ fontSize: 12, color: tone }}>
                {moved ? (delta > 0 ? "▲ " : "▼ ") : ""}{word}</span>
              <span style={{ fontSize: 11.5, color: "var(--text-dim)" }}>· {now.hosts} hosts</span>
            </div>
          );
        })}
        <p className="chart-note" style={{ margin: "2px 0 0" }}>
          Mean within-campaign cohesion, current run last. A curve appears once four runs
          exist — below that a slope would be drawn through noise.
        </p>
      </div>
    );
  }

  // Enough runs for a shape: one line per campaign, 0–1 domain, direct-labeled at the end.
  const W = 860, H = 240, left = 46, right = 170, top = 14, bottom = H - 30;
  const x = (j) => left + (j / (runs.length - 1)) * (W - left - right);
  const y = (v) => bottom - v * (bottom - top);
  const TONES = ["var(--accent)", "var(--accent-2)", "var(--warn)", "var(--good)"];
  const ends = series.map((s, i) => {
    const lastIdx = s.points.map((p, j) => (p ? j : -1)).reduce((a, b) => Math.max(a, b), -1);
    return { s, i, lastIdx, ly: lastIdx >= 0 ? y(s.points[lastIdx].v) : 0 };
  }).sort((a, b) => a.ly - b.ly);
  for (let i = 1; i < ends.length; i++) {
    if (ends[i].ly - ends[i - 1].ly < 15) ends[i].ly = ends[i - 1].ly + 15;
  }
  return (
    <svg viewBox={`0 0 ${W} ${H}`} role="img" style={{ width: "100%" }}
         aria-label={`Cohesion across ${runs.length} correlation runs, ${labels.length} campaigns`}>
      {[0, 0.5, 1].map((v) => (
        <g key={v}>
          <line x1={left} x2={W - right} y1={y(v)} y2={y(v)} stroke="var(--border)" strokeWidth="1" />
          <text x={left - 8} y={y(v) + 4} textAnchor="end" fontSize="10.5"
                fill="var(--text-dim)" className="mono">{v.toFixed(1)}</text>
        </g>
      ))}
      {runs.map((r, j) => (
        <text key={r.run_id} x={x(j)} y={H - 10} textAnchor="middle" fontSize="10"
              fill={r.is_current ? "var(--text)" : "var(--text-dim)"} className="mono">
          {r.at.slice(5, 10)}{r.is_current ? " •" : ""}</text>
      ))}
      {ends.map(({ s, i, lastIdx, ly }) => {
        const tone = TONES[i % TONES.length];
        const pts = s.points.map((p, j) => (p ? `${j ? "L" : "M"} ${x(j)} ${y(p.v)}` : "")).join(" ");
        if (lastIdx < 0) return null;
        return (
          <g key={s.label}>
            <title>{`${s.label} — cohesion per run`}</title>
            <path d={pts} fill="none" stroke={tone} strokeWidth="2" strokeLinejoin="round" />
            {s.points.map((p, j) => p && (
              <circle key={j} cx={x(j)} cy={y(p.v)} r="3.5" fill={tone}
                      stroke="var(--bg)" strokeWidth="1.5">
                <title>{`${s.label} @ ${p.at.slice(0, 10)}: ${p.v.toFixed(3)} · ${p.hosts} hosts`}</title>
              </circle>
            ))}
            <line x1={x(lastIdx) + 6} y1={y(s.points[lastIdx].v)} x2={W - right + 14} y2={ly}
                  stroke={tone} strokeWidth="0.75" strokeOpacity="0.6" />
            <text x={W - right + 18} y={ly + 4} fontSize="11" fill="var(--text)">
              {s.label.length > 20 ? s.label.slice(0, 19) + "…" : s.label}
              <tspan fill={tone} className="mono"> {s.points[lastIdx].v.toFixed(2)}</tspan></text>
          </g>
        );
      })}
    </svg>
  );
}

/* ---------------------------------------------------------- V4: type x verdict matrix */

// Verdict order is the ladder's, strongest first — never alphabetical, and never the
// server's arbitrary key order. The columns read left-to-right as certainty decreases.
const VERDICT_ORDER = ["True Positive", "Likely True Positive", "Indeterminate",
                       "Likely False Positive", "False Positive", "unset"];

// With `onToggle`, a cell click SELECTS rather than navigates: the page owning the table
// filters it in place and accumulates cells, so an analyst composes a working set instead of
// being bounced to a new view per click. Without it, a cell drills as before.
export function TypeVerdictMatrix({ matrix, investigationId, selected, onToggle }) {
  const drill = useDrill();
  const cells = matrix?.cells || [];
  if (!cells.length) return <p className="muted">No findings to summarize.</p>;
  const isOn = (ft, v) => selected instanceof Set && selected.has(`${ft}::${v}`);

  const byType = {};
  for (const c of cells) {
    const t = (byType[c.finding_type] ||= { finding_type: c.finding_type, total: 0, v: {} });
    t.v[c.verdict] = (t.v[c.verdict] || 0) + c.count;
    t.total += c.count;
  }
  const rows = Object.values(byType).sort((a, b) => b.total - a.total).slice(0, 14);
  const cols = VERDICT_ORDER.filter((v) => cells.some((c) => c.verdict === v));
  const max = Math.max(...cells.map((c) => c.count));
  // A heat CELL is magnitude, so it is one hue light-to-dark — never a rainbow. The
  // Indeterminate column is the one an analyst is hunting, so it carries the warn hue.
  const hue = (v) => (v === "Indeterminate" ? "var(--warn)"
    : v.includes("False") ? "var(--text-dim)" : "var(--good)");

  return (
    <div style={{ overflowX: "auto" }}>
      <table className="tbl" style={{ minWidth: 560 }}>
        <thead>
          <tr>
            <th scope="col" style={{ textAlign: "left" }}>Finding type</th>
            {cols.map((v) => <th key={v} scope="col" style={{ textAlign: "right" }}>{v}</th>)}
            <th scope="col" style={{ textAlign: "right" }}>Total</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.finding_type}>
              <td>{r.finding_type}</td>
              {cols.map((v) => {
                const n = r.v[v] || 0;
                if (!n) return <td key={v} className="muted" style={{ textAlign: "right" }}>—</td>;
                const open = onToggle
                  ? () => onToggle(r.finding_type, v)
                  : () => drill("/findings", {
                      investigation: investigationId, finding_type: r.finding_type,
                      verdict: v === "unset" ? "" : v,
                    });
                const on = isOn(r.finding_type, v);
                return (
                  <td key={v} style={{ textAlign: "right", padding: 0 }}>
                    <button className="linkish" onClick={open} aria-pressed={onToggle ? on : undefined}
                            title={`${n} ${r.finding_type} finding(s) at ${v}` +
                                   (onToggle ? (on ? " — selected, click to remove"
                                                   : " — click to filter the table")
                                             : " — open them")}
                            style={{ display: "block", width: "100%", padding: "6px 10px",
                                     textAlign: "right", background: hue(v),
                                     opacity: on ? 1 : 0.15 + 0.85 * (n / max),
                                     color: "var(--text)", cursor: "pointer",
                                     // The selection has to survive the opacity ramp: a faint
                                     // cell's outline at its own opacity would be invisible.
                                     border: on ? "2px solid var(--accent)" : "2px solid transparent" }}>
                      {n}
                    </button>
                  </td>
                );
              })}
              <td style={{ textAlign: "right" }} className="mono">{r.total}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/* ------------------------------------------------------------- V4: triage progress rings */

// One ring per finding type: the arc is the share decided, the number is what still waits. Rings
// because the question is a fraction of a whole, and one ring says both how big and how far
// along.
export function TriageRings({ matrix }) {
  const drill = useDrill();
  const rows = (matrix?.types || []).filter((t) => t.total > 0).slice(0, 12);
  if (!rows.length) return <p className="chart-note">No findings have been collected yet.</p>;

  const R = 34, STROKE = 7, C = 2 * Math.PI * R;
  return (
    <div style={{ display: "flex", flexWrap: "wrap", gap: "18px 26px", padding: "6px 2px" }}>
      {rows.map((t) => {
        const done = t.total - t.open;
        const frac = done / t.total;
        const tone = t.open === 0 ? "var(--good)" : frac >= 0.5 ? "var(--accent)" : "var(--warn)";
        const open = () => drill("/findings", t.params);
        return (
          <div key={t.finding_type} {...markProps(open)}
               aria-label={`${t.finding_type}: ${done} of ${t.total} decided, ${t.open} open`}
               style={{ width: 118, textAlign: "center", cursor: "pointer" }}>
            <svg viewBox="0 0 88 88" width="88" height="88" role="img" style={{ display: "block", margin: "0 auto" }}>
              <title>{`${t.finding_type} — ${done} of ${t.total} decided. Open the ${t.open} still waiting.`}</title>
              <circle cx="44" cy="44" r={R} fill="none" stroke="var(--bg-elev-2)" strokeWidth={STROKE} />
              {frac > 0 && (
                <circle cx="44" cy="44" r={R} fill="none" stroke={tone} strokeWidth={STROKE}
                        strokeLinecap="round" strokeDasharray={`${frac * C} ${C}`}
                        transform="rotate(-90 44 44)" />
              )}
              <text x="44" y="42" textAnchor="middle" fontSize="17" fontWeight="700"
                    fill={t.open ? "var(--text)" : "var(--good)"} className="mono">
                {t.open || "✓"}</text>
              <text x="44" y="57" textAnchor="middle" fontSize="9" fill="var(--text-dim)">
                {t.open ? "open" : "done"}</text>
            </svg>
            <div style={{ fontSize: 11, color: "var(--text)", lineHeight: 1.3, marginTop: 4 }}>
              {t.finding_type.length > 30 ? t.finding_type.slice(0, 29) + "…" : t.finding_type}</div>
            <div className="mono" style={{ fontSize: 10, color: "var(--text-dim)" }}>
              {Math.round(frac * 100)}% decided</div>
          </div>
        );
      })}
    </div>
  );
}

/* --------------------------------------------------------------- V6: indicator spread */

export function IndicatorSpread({ spread }) {
  const drill = useDrill();
  const rows = spread?.investigations || [];
  if (!rows.length) return <p className="muted">This indicator has no recorded sightings.</p>;
  const max = Math.max(...rows.map((r) => r.host_count));
  const rowH = 28, left = 210, barW = 240, W = left + barW + 220;
  const fleetWide = rows.length > 1;
  return (
    <div>
      <p className="chart-note">
        {fleetWide
          ? `Seen in ${rows.length} investigations — an indicator recurring across engagements is either the same actor or environment, and the host spread below is what tells them apart.`
          : "Seen in one investigation — campaign-specific so far."}
      </p>
      <svg viewBox={`0 0 ${W} ${rows.length * rowH + 6}`} role="img"
           aria-label={`Indicator spread across ${rows.length} investigations`}
           style={{ width: "100%", maxWidth: W }}>
        {rows.map((r, i) => {
          const y = i * rowH + 4;
          const w = Math.max(6, (r.host_count / max) * barW);
          return (
            <g key={r.investigation_id}
               {...markProps(() => drill("/findings", { investigation: r.investigation_id }))}
               aria-label={`${r.incident_id || r.investigation_id}: ${r.host_count} hosts, ${r.sightings} sightings`}>
              <title>{`${r.incident_id || `investigation ${r.investigation_id}`} — ${r.host_count} host(s), ${r.sightings} sighting(s), first seen ${String(r.first_seen || "").slice(0, 10)}. Open its findings.`}</title>
              <text x={left - 10} y={y + 14} textAnchor="end" fontSize="11.5" fill="var(--text)">
                {r.incident_id || `#${r.investigation_id}`}</text>
              <rect x={left} y={y} width={w} height={16} rx={4} fill="var(--accent)" fillOpacity="0.75" />
              <text x={left + barW + 12} y={y + 13} fontSize="11.5" fill="var(--text)">
                {r.host_count} host{r.host_count === 1 ? "" : "s"}
                <tspan fill="var(--text-dim)" fontSize="11">
                  {"  ·  "}{r.sightings} sighting{r.sightings === 1 ? "" : "s"}
                  {r.first_seen ? ` · from ${String(r.first_seen).slice(0, 10)}` : ""}</tspan>
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

/* --------------------------------------------------------- V3: activity, by source */

export function ActivityArea({ timeline }) {
  const [hover, setHover] = useState(null);
  const events = (timeline?.events || []).filter((e) => e.at);
  if (!events.length) {
    return <p className="muted">No finding on this run carries a timestamp.</p>;
  }
  const SOURCES = [["collection", "collector", "#38bdf8"],
                   ["memory", "memory", "#a78bfa"],
                   ["reverse", "reverse engineering", "#34d399"]];
  const laneOf = (src) => Math.max(0, SOURCES.findIndex(([k]) => String(src || "").startsWith(k)));

  const stamps = events.map((e) => new Date(e.at).getTime()).filter((t) => !Number.isNaN(t));
  const t0 = Math.min(...stamps), t1 = Math.max(...stamps);
  const totals = SOURCES.map((_, i) => events.filter((e) => laneOf(e.source) === i).length);
  const grand = events.length;

  // A curve needs a distribution. One collection is a single moment from a single source,
  // and an area chart over it draws a rectangle that says nothing the count does not — so
  // below a real spread the same data is stated as a composition instead of plotted.
  const plottable = (t1 - t0) >= 60000 && events.length >= 8;

  if (!plottable) {
    return (
      <div>
        <div style={{ display: "flex", height: 26, borderRadius: 6, overflow: "hidden",
                      border: "1px solid var(--border)" }}>
          {SOURCES.map(([, label, color], i) => totals[i] > 0 && (
            <div key={label} title={`${label}: ${totals[i]} of ${grand}`}
                 onMouseEnter={() => setHover(label)} onMouseLeave={() => setHover(null)}
                 style={{ width: `${(totals[i] / grand) * 100}%`, background: color,
                          opacity: !hover || hover === label ? 0.9 : 0.35 }} />
          ))}
        </div>
        <div style={{ display: "flex", gap: 18, flexWrap: "wrap", marginTop: 10,
                      fontSize: 11.5 }}>
          {SOURCES.map(([, label, color], i) => (
            <span key={label} style={{ display: "flex", alignItems: "center", gap: 7,
                                       opacity: totals[i] ? 1 : 0.45 }}>
              <span style={{ width: 10, height: 10, borderRadius: 2, background: color }} />
              {label}
              <span className="mono" style={{ color: "var(--text-dim)" }}>
                {totals[i]}{totals[i] ? ` · ${Math.round((totals[i] / grand) * 100)}%` : ""}</span>
            </span>
          ))}
        </div>
        <p className="chart-note" style={{ marginBottom: 0 }}>
          {grand} finding{grand === 1 ? "" : "s"}
          {t1 - t0 < 60000
            ? " recorded within one minute of each other — too little spread to plot over time."
            : " — too few to read as a distribution."}
          {totals[1] === 0 && totals[0] > 0 &&
            " Nothing from memory corroborates the collector here."}
        </p>
      </div>
    );
  }

  const BUCKETS = 24;
  const grid = Array.from({ length: BUCKETS }, () => SOURCES.map(() => 0));
  events.forEach((e) => {
    const t = new Date(e.at).getTime();
    const b = Math.min(BUCKETS - 1, Math.floor(((t - t0) / Math.max(t1 - t0, 1)) * BUCKETS));
    grid[b][laneOf(e.source)] += 1;
  });
  const peak = Math.max(1, ...grid.map((b) => b.reduce((a, c) => a + c, 0)));
  const W = 720, H = 210, left = 42, bottom = H - 34, top = 12;
  const x = (i) => left + (i / (BUCKETS - 1)) * (W - left - 18);
  const y = (v) => bottom - (v / peak) * (bottom - top);

  let below = grid.map(() => 0);
  const bands = SOURCES.map(([, label, color], si) => {
    const lower = [...below];
    const upper = grid.map((b, i) => lower[i] + b[si]);
    below = upper;
    const d = upper.map((v, i) => `${i ? "L" : "M"} ${x(i)} ${y(v)}`).join(" ") + " "
            + lower.map((_, i) => `L ${x(BUCKETS - 1 - i)} ${y(lower[BUCKETS - 1 - i])}`).join(" ")
            + " Z";
    return { label, color, d, total: totals[si] };
  });

  return (
    <div>
      <svg viewBox={`0 0 ${W} ${H}`} role="img" style={{ width: "100%", maxWidth: W }}
           aria-label={`Activity: ${events.length} findings by source over time`}
           onMouseLeave={() => setHover(null)}>
        {[0, 0.5, 1].map((f) => (
          <g key={f}>
            <line x1={left} x2={W - 18} y1={y(peak * f)} y2={y(peak * f)}
                  stroke="var(--border)" strokeWidth="0.6" strokeDasharray="2 4" />
            <text x={left - 8} y={y(peak * f) + 3} textAnchor="end" fontSize="10"
                  fill="var(--text-dim)">{Math.round(peak * f)}</text>
          </g>
        ))}
        {bands.filter((b) => b.total > 0).map((b) => (
          <path key={b.label} d={b.d} fill={b.color}
                fillOpacity={!hover || hover === b.label ? 0.5 : 0.1}
                stroke={b.color} strokeWidth="1.8"
                strokeOpacity={!hover || hover === b.label ? 1 : 0.2} />
        ))}
        <text x={left} y={H - 10} fontSize="10" fill="var(--text-dim)">
          {new Date(t0).toISOString().replace("T", " ").slice(0, 16)}Z</text>
        <text x={W - 18} y={H - 10} fontSize="10" fill="var(--text-dim)" textAnchor="end">
          {new Date(t1).toISOString().replace("T", " ").slice(0, 16)}Z</text>
      </svg>
      <div style={{ display: "flex", gap: 18, flexWrap: "wrap", marginTop: 4, fontSize: 11.5 }}>
        {bands.map((b) => (
          <span key={b.label} onMouseEnter={() => setHover(b.label)}
                onMouseLeave={() => setHover(null)}
                style={{ display: "flex", alignItems: "center", gap: 7,
                         opacity: b.total ? 1 : 0.45 }}>
            <span style={{ width: 10, height: 10, borderRadius: 2, background: b.color }} />
            {b.label}<span className="mono" style={{ color: "var(--text-dim)" }}>{b.total}</span>
          </span>
        ))}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------- V2: host map */

export function HostMap({ stats, coverage }) {
  const drill = useDrill();
  const [focus, setFocus] = useState(null);
  const collected = stats?.hosts || [];
  const missing = coverage?.implicated_not_collected || [];
  if (!collected.length && !missing.length) {
    return <p className="muted">No hosts are implicated yet.</p>;
  }

  // Tile area carries evidence weight, so the machines the case actually rests on are the
  // ones that dominate the picture. sqrt, because area reads as magnitude and a linear
  // side length would exaggerate a host with twice the findings into four times the tile.
  const max = Math.max(...collected.map((h) => h.findings), 1);
  const side = (n) => 74 + Math.round(Math.sqrt(n / max) * 66);

  const BAND = {
    confirmed: ["var(--good)", "Confirmed member"],
    probable: ["var(--accent)", "Probable member"],
    possible: ["var(--warn)", "Possible member"],
    "": ["var(--text-dim)", "Outside every campaign"],
  };
  const order = ["confirmed", "probable", "possible", ""];
  const sorted = [...collected].sort(
    (a, b) => order.indexOf(a.confidence_band || "") - order.indexOf(b.confidence_band || "")
           || b.findings - a.findings);

  return (
    <div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 20, marginBottom: 12,
                    fontSize: 11.5 }}>
        {order.filter((b) => sorted.some((h) => (h.confidence_band || "") === b)).map((b) => (
          <span key={b || "none"} style={{ display: "flex", alignItems: "center", gap: 7 }}
                onMouseEnter={() => setFocus(b)} onMouseLeave={() => setFocus(null)}>
            <span style={{ width: 10, height: 10, borderRadius: 2, background: BAND[b][0] }} />
            {BAND[b][1]}
            <span className="mono" style={{ color: "var(--text-dim)" }}>
              {sorted.filter((h) => (h.confidence_band || "") === b).length}</span>
          </span>
        ))}
        {missing.length > 0 && (
          <span style={{ display: "flex", alignItems: "center", gap: 7 }}>
            <span style={{ width: 10, height: 10, borderRadius: 2,
                           border: "1px dashed var(--bad)" }} />
            Implicated, never collected
            <span className="mono" style={{ color: "var(--bad)" }}>{missing.length}</span>
          </span>
        )}
      </div>

      <div style={{ display: "flex", flexWrap: "wrap", gap: 8, alignItems: "flex-start" }}>
        {sorted.map((h) => {
          const band = h.confidence_band || "";
          const [color] = BAND[band];
          const s = side(h.findings);
          const pct = h.findings ? Math.round((h.confirmed / h.findings) * 100) : 0;
          const dim = focus && focus !== band;
          return (
            <div key={h.host_id} {...markProps(() => drill("/hosts", { q: h.host }))}
                 title={`${h.host} — ${h.confirmed} confirmed of ${h.findings} finding(s) (${pct}%); membership: ${BAND[band][1].toLowerCase()}; first seen ${h.first_seen}. Open this host.`}
                 style={{ width: s, height: s, borderRadius: 8, padding: 10,
                          display: "flex", flexDirection: "column",
                          justifyContent: "space-between",
                          background: "var(--bg-elev-2)",
                          border: `1px solid var(--border)`,
                          borderTop: `3px solid ${color}`,
                          opacity: dim ? 0.28 : 1, transition: "opacity .12s" }}>
              <div className="mono" style={{ fontSize: 12, fontWeight: 600,
                                             wordBreak: "break-all", lineHeight: 1.25 }}>
                {h.host}</div>
              <div>
                {/* Share confirmed, drawn as a fill from the bottom: the tile itself
                    carries how much is decided, not only how much was found. */}
                <div style={{ height: 4, borderRadius: 2, background: "var(--text-dim)",
                              opacity: 0.3 }}>
                  <div style={{ width: `${Math.max(3, pct)}%`, height: 4, borderRadius: 2,
                                background: color }} />
                </div>
                <div style={{ fontSize: 10.5, color: "var(--text-dim)", marginTop: 4 }}>
                  {h.confirmed}/{h.findings}</div>
              </div>
            </div>
          );
        })}

        {/* The blind spots, in the same picture rather than in a separate percentage: a
            host nobody collected is a gap in this map, not a statistic somewhere else. */}
        {missing.map((name) => (
          <div key={name}
               title={`${name} — implicated by evidence on other machines, never collected. Nothing here rests on its own data.`}
               style={{ width: 74, height: 74, borderRadius: 8, padding: 10,
                        display: "flex", flexDirection: "column",
                        justifyContent: "space-between",
                        border: "1px dashed var(--bad)", opacity: focus ? 0.28 : 0.8 }}>
            <div className="mono" style={{ fontSize: 11.5, color: "var(--bad)",
                                           wordBreak: "break-all", lineHeight: 1.25 }}>
              {name}</div>
            <div style={{ fontSize: 10, color: "var(--text-dim)" }}>not collected</div>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ------------------------------------------------------- V1: backlog over time */

// Open backlog — the one series that moves with the team's work: findings per day measures the
// intrusion, arrived-minus-decided measures the response. Two points are not a trend, so below
// the threshold the standing is stated rather than drawn as a slope.
export function BacklogTrend({ backlog, funnel }) {
  const drill = useDrill();
  const [hover, setHover] = useState(null);
  if (!backlog) return null;

  const days = backlog.days || [];
  const open = backlog.open_now || 0;
  const decided = backlog.decided_total || 0;
  const total = backlog.total || 0;
  const pct = total ? Math.round((decided / total) * 100) : 0;
  const openParams = { adjudicated: "no" };

  if (!total) return <p className="chart-note">No findings have been collected yet.</p>;

  // The funnel stages, beside the chart rather than in a second panel: they count the same
  // rows this chart does.
  const stages = Object.fromEntries((funnel?.stages || []).map((s) => [s.stage, s]));
  const memory = funnel?.memory_share;
  const Stat = ({ label, value, tone, params }) => (
    <button type="button" className="linkish"
            onClick={() => drill && params && drill("findings", params)}
            style={{ background: "none", border: 0, padding: 0, textAlign: "left",
                     cursor: drill && params ? "pointer" : "default" }}>
      <div style={{ fontSize: 10, letterSpacing: ".08em", textTransform: "uppercase",
                    color: "var(--text-dim)" }}>{label}</div>
      <div className="mono" style={{ fontSize: 19, fontWeight: 700, color: tone || "var(--text)" }}>
        {value}</div>
    </button>
  );
  const stageRow = (
    <div style={{ display: "flex", gap: 34, flexWrap: "wrap", margin: "18px 0 2px",
                  paddingTop: 16, borderTop: "1px solid var(--border)" }}>
      {stages.collected && <Stat label="Collected" value={stages.collected.count} params={{}} />}
      {stages.adjudicated && <Stat label="Decided" value={stages.adjudicated.count}
                                   tone="var(--good)" params={stages.adjudicated.params} />}
      {stages.confirmed && <Stat label="Confirmed" value={stages.confirmed.count}
                                 tone="var(--bad)" params={stages.confirmed.params} />}
      {memory && <Stat label="From memory" value={memory.count} params={memory.params} />}
    </div>
  );

  if (days.length < 2 || (backlog.activity_days || 0) < 2) {
    return (
      <div>
        <div style={{ display: "flex", gap: 28, alignItems: "baseline", flexWrap: "wrap" }}>
          <span className="mono" style={{ fontSize: 34, fontWeight: 700,
                                          color: open ? "var(--warn)" : "var(--good)" }}>{open}</span>
          <span style={{ fontSize: 13, color: "var(--text-dim)" }}>
            awaiting a decision, of {total} collected
          </span>
        </div>
        <div style={{ display: "flex", height: 26, borderRadius: 6, overflow: "hidden",
                      background: "var(--bg-elev-2)", marginTop: 16, gap: 2 }}>
          {decided > 0 && (
            <div title={`${decided} decided`}
                 style={{ width: `${(decided / total) * 100}%`, background: "var(--good)" }} />
          )}
          {open > 0 && (
            <div role="button" tabIndex={0} title={`${open} awaiting a decision`}
                 onClick={() => drill && drill("findings", openParams)}
                 style={{ width: `${(open / total) * 100}%`, background: "var(--warn)",
                          cursor: drill ? "pointer" : "default" }} />
          )}
        </div>
        <div style={{ display: "flex", justifyContent: "space-between", marginTop: 10,
                      fontSize: 12, color: "var(--text-dim)" }}>
          <span><span style={{ color: "var(--good)" }}>■</span> {decided} decided ({pct}%)</span>
          <span><span style={{ color: "var(--warn)" }}>■</span> {open} open</span>
        </div>
        <p className="chart-note" style={{ marginTop: 14 }}>
          Anything moved on {backlog.activity_days || 0} day
          {(backlog.activity_days || 0) === 1 ? "" : "s"} in this window — too few to read a
          direction from, so the standing is shown instead of a slope through two points.
        </p>
        {stageRow}
      </div>
    );
  }

  const peak = Math.max(1, ...days.map((d) => d.open));
  const W = 980, H = 260, left = 54, right = 74, bottom = H - 42, top = 18;
  const x = (i) => left + (i / (days.length - 1)) * (W - left - right);
  const y = (v) => bottom - (v / peak) * (bottom - top);
  const line = days.map((d, i) => `${i ? "L" : "M"} ${x(i)} ${y(d.open)}`).join(" ");
  const area = `${line} L ${x(days.length - 1)} ${bottom} L ${x(0)} ${bottom} Z`;
  const band = (W - left - right) / days.length;

  const first = days[0].open, last = days[days.length - 1].open;
  const better = last < first, worse = last > first;
  const tone = better ? "var(--good)" : worse ? "var(--bad)" : "var(--text-dim)";
  const at = hover != null ? days[hover] : null;

  return (
    <div>
      <div style={{ display: "flex", gap: 28, alignItems: "baseline", flexWrap: "wrap",
                    marginBottom: 10 }}>
        <span className="mono" style={{ fontSize: 34, fontWeight: 700, color: tone }}>{open}</span>
        <span style={{ fontSize: 13, color: "var(--text-dim)" }}>
          awaiting a decision ·{" "}
          <span style={{ color: tone }}>
            {better ? `down ${first - last}` : worse ? `up ${last - first}` : "level"} over{" "}
            {backlog.window_days} days
          </span>{" "}
          · <span style={{ color: "var(--good)" }}>{decided} decided</span>
        </span>
        {at && (
          <span className="mono" style={{ fontSize: 12, marginLeft: "auto",
                                          color: "var(--text-dim)" }}>
            {at.day}: {at.open} open · +{at.arrived} in · −{at.decided} decided
          </span>
        )}
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} role="img" style={{ width: "100%" }}
           aria-label={`Open backlog over ${backlog.window_days} days, now ${open}`}>
        <defs>
          <linearGradient id="backlog-fill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={tone} stopOpacity="0.30" />
            <stop offset="100%" stopColor={tone} stopOpacity="0.02" />
          </linearGradient>
        </defs>
        {[0, peak].map((v) => (
          <g key={v}>
            <line x1={left} x2={W - right} y1={y(v)} y2={y(v)} stroke="var(--border)"
                  strokeWidth="1" />
            <text x={left - 10} y={y(v) + 4} textAnchor="end" fontSize="11"
                  fill="var(--text-dim)" className="mono">{v}</text>
          </g>
        ))}
        <path d={area} fill="url(#backlog-fill)" />
        <path d={line} fill="none" stroke={tone} strokeWidth="2" strokeLinejoin="round" />
        {at && <line x1={x(hover)} x2={x(hover)} y1={top} y2={bottom} stroke="var(--text-dim)"
                     strokeWidth="1" strokeDasharray="3 3" />}
        <circle cx={x(days.length - 1)} cy={y(last)} r="4.5" fill={tone}
                stroke="var(--bg)" strokeWidth="2" />
        <text x={x(days.length - 1) + 12} y={y(last) + 4} fontSize="12" fill={tone}
              className="mono">{last}</text>
        {days.map((d, i) => (
          <rect key={d.day} x={x(i) - band / 2} y={top} width={band} height={bottom - top}
                fill="transparent"
                onMouseEnter={() => setHover(i)} onMouseLeave={() => setHover(null)}
                onClick={() => drill && drill("findings", { ...openParams, day: d.day })}
                style={{ cursor: drill ? "pointer" : "default" }} />
        ))}
        <text x={left} y={H - 14} fontSize="11" fill="var(--text-dim)" className="mono">
          {days[0].day}</text>
        <text x={W - right} y={H - 14} textAnchor="end" fontSize="11" fill="var(--text-dim)"
              className="mono">{days[days.length - 1].day}</text>
      </svg>
      <p className="chart-note">
        Arrived minus decided, on the wall clock, carried across quiet days. Falling is the
        queue being worked down; climbing is evidence arriving faster than it is being judged.
      </p>
      {stageRow}
    </div>
  );
}

/* -------------------------------------------------------- V7: analysis queue depth */

function fmtBytes(n) {
  if (n == null) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = Number(n), i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`;
}

function fmtWait(seconds) {
  if (!seconds) return "none waiting";
  if (seconds < 90) return `${seconds}s`;
  const m = Math.round(seconds / 60);
  if (m < 90) return `${m}m`;
  return `${(m / 60).toFixed(1)}h`;
}

// Counts on one axis; the oldest wait is a DURATION and gets stated as text instead of a
// second scale on the same plot.
const QUEUE_SERIES = [
  ["queued",   "queued",            "var(--warn)",     ""],
  ["running",  "running",           "var(--accent)",   ""],
  ["awaiting", "captures unstarted", "var(--accent-2)", "5 4"],
];

export function QueueDepthTrend({ depth }) {
  const [hover, setHover] = useState(null);
  if (!depth) return null;

  const samples = (depth.samples || []).filter((s) => s.sampled_at);
  const everyMin = Math.round((depth.sample_interval_seconds || 900) / 60);
  const now = [depth.queued || 0, depth.running || 0, depth.captures_awaiting_analysis || 0];

  const standing = (
    <div style={{ display: "flex", gap: 28, alignItems: "baseline", flexWrap: "wrap" }}>
      {QUEUE_SERIES.map(([, label, color], i) => (
        <span key={label} style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
          <span className="mono" style={{ fontSize: 26, fontWeight: 700,
                                          color: now[i] ? color : "var(--text-dim)" }}>
            {now[i]}</span>
          <span style={{ fontSize: 12, color: "var(--text-dim)" }}>{label}</span>
        </span>
      ))}
      <span style={{ fontSize: 12, color: "var(--text-dim)", marginLeft: "auto" }}>
        {depth.oldest_waiting_seconds ? (
          <>oldest has waited{" "}
            <span className="mono"
                  style={{ color: depth.oldest_waiting_seconds > 3600 ? "var(--warn)" : "var(--text)" }}>
              {fmtWait(depth.oldest_waiting_seconds)}</span></>
        ) : "nothing waiting"}
      </span>
    </div>
  );

  if (samples.length < 3) {
    return (
      <div>
        {standing}
        <p className="chart-note" style={{ marginTop: 12 }}>
          {samples.length === 0
            ? `No samples recorded yet — one lands every ${everyMin} minutes while the backend runs, so the trend appears within the hour.`
            : `${samples.length} sample${samples.length === 1 ? "" : "s"} so far — the standing is shown until there are enough to read a direction from.`}
        </p>
      </div>
    );
  }

  const peak = Math.max(1, ...samples.map((s) => Math.max(s.queued, s.running, s.awaiting)));
  const W = 720, H = 200, left = 42, right = 24, bottom = H - 30, top = 12;
  const x = (i) => left + (i / (samples.length - 1)) * (W - left - right);
  const y = (v) => bottom - (v / peak) * (bottom - top);
  const band = (W - left - right) / samples.length;
  const at = hover != null ? samples[hover] : null;
  const t = (iso) => new Date(iso).toISOString().replace("T", " ").slice(0, 16) + "Z";
  // Deduped: at a small peak, 0/50%/100% round to the same integer and print twice.
  const ticks = [...new Set([0, Math.round(peak / 2), peak])];

  return (
    <div>
      {standing}
      {at && (
        <div className="mono" style={{ fontSize: 12, color: "var(--text-dim)", marginTop: 4 }}>
          {t(at.sampled_at)}: {at.queued} queued · {at.running} running · {at.awaiting} unstarted
          · oldest {fmtWait(at.oldest_waiting_seconds)}
        </div>
      )}
      <svg viewBox={`0 0 ${W} ${H}`} role="img" style={{ width: "100%", maxWidth: W, marginTop: 8 }}
           aria-label={`Analysis queue over time, ${samples.length} samples`}
           onMouseLeave={() => setHover(null)}>
        {ticks.map((v) => (
          <g key={v}>
            <line x1={left} x2={W - right} y1={y(v)} y2={y(v)}
                  stroke="var(--border)" strokeWidth="0.6" strokeDasharray="2 4" />
            <text x={left - 8} y={y(v) + 3} textAnchor="end" fontSize="10"
                  fill="var(--text-dim)" className="mono">{v}</text>
          </g>
        ))}
        {/* No end-of-line labels: the three series usually share a final value (an idle
            queue is all zeros), and three labels at one point overprint into noise. The
            headline row above is the legend — colored count beside its name. */}
        {QUEUE_SERIES.map(([key, , color, dash]) => {
          const d = samples.map((s, i) => `${i ? "L" : "M"} ${x(i)} ${y(s[key])}`).join(" ");
          const last = samples[samples.length - 1][key];
          return (
            <g key={key}>
              <path d={d} fill="none" stroke={color} strokeWidth="2"
                    strokeDasharray={dash} strokeLinejoin="round" />
              <circle cx={x(samples.length - 1)} cy={y(last)} r="3.5" fill={color}
                      stroke="var(--bg)" strokeWidth="1.5" />
            </g>
          );
        })}
        {at && <line x1={x(hover)} x2={x(hover)} y1={top} y2={bottom}
                     stroke="var(--text-dim)" strokeWidth="1" strokeDasharray="3 3" />}
        {samples.map((s, i) => (
          <rect key={s.sampled_at} x={x(i) - band / 2} y={top} width={band}
                height={bottom - top} fill="transparent"
                onMouseEnter={() => setHover(i)} onMouseLeave={() => setHover(null)} />
        ))}
        <text x={left} y={H - 8} fontSize="10" fill="var(--text-dim)" className="mono">
          {t(samples[0].sampled_at)}</text>
        <text x={W - right} y={H - 8} fontSize="10" fill="var(--text-dim)" textAnchor="end"
              className="mono">{t(samples[samples.length - 1].sampled_at)}</text>
      </svg>
      <p className="chart-note">
        Sampled every {everyMin} minutes on the health-report beat, so the record keeps
        accruing while nobody watches. A climbing dashed line is captures arriving faster
        than analyses start; a flat solid line at capacity is the workers saturated.
      </p>
    </div>
  );
}

/* ----------------------------------------------------- V7: object store allocation */

const RETENTION_COLORS = {
  pending:  "var(--accent)",
  retained: "var(--good)",
  eligible: "var(--warn)",
  purged:   "var(--text-dim)",
};

export function StorageAllocation({ alloc }) {
  const [hover, setHover] = useState(null);
  if (!alloc) return null;

  const states = (alloc.evidence_bucket?.states || []).filter((s) => s.bytes > 0 || s.count > 0);
  const evTotal = alloc.evidence_bucket?.bytes || 0;
  const carved = alloc.carved_buckets || [];
  const carvedMax = Math.max(1, ...carved.map((c) => c.bytes || 0));
  const shown = carved.slice(0, 8);
  const colorOf = (st) => RETENTION_COLORS[st] || "var(--accent-2)";

  if (!states.length && !carved.length) {
    return (
      <p className="chart-note" style={{ margin: 0 }}>
        The object store holds nothing the platform accounts for — no captures and no carved
        regions have been stored yet.
      </p>
    );
  }

  return (
    <div>
      {states.length > 0 && (
        <>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12,
                        color: "var(--text-dim)", marginBottom: 6 }}>
            <span>evidence bucket · {alloc.evidence_bucket.count} captures</span>
            <span className="mono">{fmtBytes(evTotal)}</span>
          </div>
          <div style={{ display: "flex", height: 26, borderRadius: 6, overflow: "hidden",
                        background: "var(--bg-elev-2)", gap: 2 }}>
            {states.map((s) => (
              <div key={s.retention_status}
                   title={`${s.retention_status}: ${s.count} capture(s), ${fmtBytes(s.bytes)}`}
                   onMouseEnter={() => setHover(s.retention_status)}
                   onMouseLeave={() => setHover(null)}
                   style={{ width: `${Math.max(1, (s.bytes / Math.max(evTotal, 1)) * 100)}%`,
                            background: colorOf(s.retention_status),
                            opacity: !hover || hover === s.retention_status ? 0.9 : 0.35 }} />
            ))}
          </div>
          <div style={{ display: "flex", gap: 18, flexWrap: "wrap", marginTop: 8,
                        fontSize: 11.5 }}>
            {states.map((s) => (
              <span key={s.retention_status}
                    onMouseEnter={() => setHover(s.retention_status)}
                    onMouseLeave={() => setHover(null)}
                    style={{ display: "flex", alignItems: "center", gap: 7 }}>
                <span style={{ width: 10, height: 10, borderRadius: 2,
                               background: colorOf(s.retention_status) }} />
                {s.retention_status}
                <span className="mono" style={{ color: "var(--text-dim)" }}>
                  {s.count} · {fmtBytes(s.bytes)}</span>
              </span>
            ))}
          </div>
        </>
      )}

      {shown.length > 0 && (
        <div style={{ marginTop: states.length ? 18 : 0 }}>
          <div style={{ fontSize: 12, color: "var(--text-dim)", marginBottom: 6 }}>
            carved-region buckets · one per host
          </div>
          {shown.map((c) => (
            <div key={c.bucket} style={{ display: "flex", alignItems: "center", gap: 10,
                                         marginBottom: 5 }}>
              <span className="mono" style={{ fontSize: 11.5, width: 180, overflow: "hidden",
                                              textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                    title={c.bucket}>{c.bucket}</span>
              <span style={{ flex: 1, height: 10, background: "var(--bg-elev-2)",
                             borderRadius: 4, overflow: "hidden" }}>
                <span style={{ display: "block", height: "100%", borderRadius: 4,
                               width: `${Math.max(2, (c.bytes / carvedMax) * 100)}%`,
                               background: "var(--accent-2)" }} />
              </span>
              <span className="mono" style={{ fontSize: 11.5, color: "var(--text-dim)",
                                              width: 130, textAlign: "right" }}>
                {fmtBytes(c.bytes)} · {c.count}</span>
            </div>
          ))}
          {carved.length > shown.length && (
            <p className="chart-note" style={{ margin: "4px 0 0" }}>
              …and {carved.length - shown.length} more bucket(s), smallest last — the figures
              above cover the largest by stored bytes.
            </p>
          )}
        </div>
      )}
      <p className="chart-note" style={{ marginBottom: 0 }}>
        Sizes are the platform&apos;s own records, not a bucket listing — the two disagreeing
        would mean the store holds something the platform never wrote.
      </p>
    </div>
  );
}

