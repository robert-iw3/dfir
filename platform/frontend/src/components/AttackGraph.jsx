/**
 * Attack graph — the intrusion laid out left to right in the order it spread.
 *
 * Rendered as hand-built SVG: the analyst kiosk has no internet path, so no charting
 * library can be fetched and none is bundled.
 *
 * Layout is by "hop depth" — how many moves from the entry point a host sits — rather
 * than by wall-clock time, so a host reached late by a short path stays near its parent
 * and the shape of the intrusion reads correctly.
 *
 * An edge here is a MOVEMENT, carrying the pivot vector that got them there — the technique,
 * the protocol it rode, and the account it used. That triple is the question an analyst
 * brings to this graph.
 *
 * Shared-tradecraft links are deliberately NOT drawn: undirected similarity at
 * near-complete-graph density crosses every node while saying nothing about sequence. They
 * belong to the tradecraft and linkage panels, which show them at a density that reads.
 *
 * Declined candidates stay available behind a toggle, off by default: a graph drawing only
 * what linked cannot answer "why aren't these two the same intrusion?".
 */
// The gap between a node's right edge and the next column's left edge is where an edge label has
// to fit. At COL_W 210 / NODE_W 168 that gap was 42px and every protocol label rendered on top
// of a node box.
const LABEL_LANE = 112;
const NODE_W = 176;
const COL_W = NODE_W + LABEL_LANE;
const ROW_H = 92;
const NODE_H = 62;

const ROLE_FILL = {
  patient_zero: "var(--crit)",
  pivot: "var(--warn)",
  affected: "var(--bad)",
};

// Membership confidence, as the node's border. Deliberately not a color ramp: the bands
// are ordered but not continuous, and a gradient invites reading exactly the precision
// that banding exists to avoid.
const BAND_STROKE = {
  confirmed: { width: 3, dash: "" },
  probable: { width: 2, dash: "" },
  possible: { width: 1.5, dash: "4 3" },
  indeterminate: { width: 1, dash: "2 4" },
};

// Link weight to stroke width, bounded. An unbounded scale lets one strong link render as
// a slab that hides everything near it.
const strokeFor = (w) => (w == null ? 1.5 : Math.max(1, Math.min(5, 1 + w * 4)));

function depths(nodes, edges) {
  const parents = new Map();
  edges.forEach((e) => {
    if (!parents.has(e.dst)) parents.set(e.dst, e.src);
  });
  const out = new Map();
  const resolve = (host, seen = new Set()) => {
    if (out.has(host)) return out.get(host);
    if (seen.has(host)) return 0; // defensive: evidence could describe a cycle
    seen.add(host);
    const parent = parents.get(host);
    const d = parent ? resolve(parent, seen) + 1 : 0;
    out.set(host, d);
    return d;
  };
  nodes.forEach((n) => resolve(n.hostname));
  return out;
}

export default function AttackGraph({
  nodes,
  edges,
  declinedEdges = [],
  showDeclined = false,
  onSelect,
  onSelectEdge,
  selected,
}) {
  if (!nodes?.length) return <div className="empty">No correlated hosts.</div>;

  const depth = depths(nodes, edges);
  const columns = new Map();
  nodes.forEach((n) => {
    const d = depth.get(n.hostname) ?? 0;
    if (!columns.has(d)) columns.set(d, []);
    columns.get(d).push(n);
  });

  const pos = new Map();
  [...columns.keys()].sort((a, b) => a - b).forEach((d) => {
    columns.get(d).forEach((n, i) => {
      pos.set(n.hostname, { x: 20 + d * COL_W, y: 20 + i * ROW_H });
    });
  });

  const width = 40 + (Math.max(...columns.keys()) + 1) * COL_W;
  const height = 40 + Math.max(...[...columns.values()].map((c) => c.length)) * ROW_H;

  // Both endpoints must be on screen. A declined pair often reaches a host in another
  // campaign, and half an edge pointing into empty space reads as a rendering fault.
  const drawable = (e) => pos.has(e.src) && pos.has(e.dst);

  const curve = (e) => {
    const a = pos.get(e.src);
    const b = pos.get(e.dst);
    const x1 = a.x + NODE_W;
    const y1 = a.y + NODE_H / 2;
    const x2 = b.x;
    const y2 = b.y + NODE_H / 2;
    const mx = (x1 + x2) / 2;
    return {
      d: `M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`,
      x1, y1, x2, y2,
    };
  };

  // A label is drawn on a chip so it stays readable wherever it lands — over the panel, over
  // an edge, or over another label. Sized from the text because SVG has no text metrics here.
  const Label = ({ x, y, lines, muted }) => {
    const rows = (Array.isArray(lines) ? lines : [lines]).filter(Boolean);
    if (!rows.length) return null;
    const w = Math.max(...rows.map((t) => String(t).length)) * 6.2 + 12;
    const h = rows.length * 12 + 6;
    return (
      <g>
        <rect x={x - w / 2} y={y - h / 2} width={w} height={h} rx="3"
              fill="var(--bg-elev-2)" stroke="var(--border)" strokeWidth="0.5"
              opacity="0.95" />
        {rows.map((t, i) => (
          <text key={i} x={x} y={y - h / 2 + 12 + i * 12} textAnchor="middle" fontSize="10"
                fontFamily={i === 0 ? "var(--mono)" : undefined}
                fill={i === 0 && !muted ? "var(--accent-strong)" : "var(--text-dim)"}>
            {t}
          </text>
        ))}
      </g>
    );
  };

  const declined = showDeclined ? declinedEdges.filter(drawable) : [];
  const movement = (edges || []).filter(drawable);

  // The label rides the edge just BEFORE its destination: a host fanning out to six others
  // gives six edges one shared origin, which stacked all six chips into one pile. The
  // counter only handles two hosts reaching the same target.
  const arrivals = new Map();
  const drawn = movement.map((e) => {
    const c = curve(e);
    const seen = arrivals.get(e.dst) || 0;
    arrivals.set(e.dst, seen + 1);
    return {
      e, c,
      at: { x: c.x2 - LABEL_LANE / 2, y: c.y2 + seen * 26 },
      // The domain prefix repeats on every edge and costs the width the technique needs.
      account: e.account ? String(e.account).split("\\").pop() : "",
    };
  });

  return (
    <div className="panel" style={{ overflowX: "auto", padding: 8 }}>
      <svg
        width={width}
        height={height}
        role="img"
        aria-label={
          `Attack graph: ${nodes.length} hosts, ${movement.length} observed movements ` +
          `with their pivot technique, ${declined.length} declined candidates`
        }
      >
        <defs>
          <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5"
                  markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="var(--text-dim)" />
          </marker>
        </defs>

        {/* Declined first, so it sits beneath everything the engine accepted. */}
        {declined.map((e, i) => {
          const c = curve(e);
          return (
            <g key={`x${i}`} onClick={() => onSelectEdge?.({ ...e, kind: "declined" })}
               style={{ cursor: onSelectEdge ? "pointer" : "default" }}>
              <title>{`declined ${e.src} ~ ${e.dst} (${e.weight}) — ${e.why || ""}`}</title>
              <path d={c.d} fill="none" stroke="var(--text-dim)" strokeWidth="1"
                    strokeDasharray="2 5" opacity="0.3" />
            </g>
          );
        })}

        {/* Paths and labels are two passes, not one group per edge: interleaved, every edge
            drawn after a label painted over it. */}
        {drawn.map(({ e, c }, i) => (
          <g key={`m${i}`} onClick={() => onSelectEdge?.({ ...e, kind: "movement" })}
             style={{ cursor: onSelectEdge ? "pointer" : "default" }}>
            <title>
              {`${e.src} -> ${e.dst}` +
               `${e.technique ? ` — ${e.technique}` : ""}` +
               ` via ${e.protocol || "?"}` +
               `${e.account ? ` as ${e.account}` : ""}` +
               `${e.weight != null ? ` (${e.weight})` : ""}`}
            </title>
            <path d={c.d} fill="none" stroke="var(--text-dim)" opacity="0.4"
                  strokeWidth={strokeFor(e.weight)} markerEnd="url(#arrow)" />
          </g>
        ))}

        {/* The pivot vector: what was used, over what, as whom. Transparent to the pointer so
            the edge underneath stays the click target. */}
        <g style={{ pointerEvents: "none" }}>
          {drawn.map(({ e, at, account }, i) => (
            <Label key={`l${i}`} x={at.x} y={at.y}
                   lines={[e.technique, [e.protocol, account].filter(Boolean).join(" · ")]} />
          ))}
        </g>

        {nodes.map((n) => {
          const p = pos.get(n.hostname);
          const on = selected === n.hostname;
          const band = BAND_STROKE[n.confidence_band] || BAND_STROKE.indeterminate;
          return (
            <g key={n.hostname} transform={`translate(${p.x},${p.y})`}
               onClick={() => onSelect?.(n.hostname)}
               style={{ cursor: onSelect ? "pointer" : "default" }}>
              <title>
                {`${n.hostname} — ${n.role}` +
                 (n.confidence_band ? `, membership ${n.confidence_band}` : "") +
                 (n.confidence_factors?.why ? `: ${n.confidence_factors.why}` : "")}
              </title>
              <rect width={NODE_W} height={NODE_H} rx="8"
                    fill="var(--bg-elev-2)"
                    stroke={on ? "var(--accent)" : ROLE_FILL[n.role] || "var(--border)"}
                    strokeWidth={on ? 2.5 : band.width}
                    strokeDasharray={on ? "" : band.dash} />
              <circle cx="14" cy="17" r="5" fill={ROLE_FILL[n.role] || "var(--text-dim)"} />
              <text x="26" y="21" fill="var(--text)" fontSize="12" fontWeight="600">
                {n.hostname}
              </text>
              <text x="26" y="36" fill="var(--text-dim)" fontSize="10">
                {n.role === "patient_zero" ? "entry point" : n.role}
                {n.entry_account ? ` · ${n.entry_account.split("\\").pop()}` : ""}
              </text>
              {/* Inside the box with room for descenders — at NODE_H 54 this was clipped. */}
              {n.confidence_band && (
                <text x="26" y="52" fontSize="9"
                      fill={n.confidence_band === "confirmed" ? "var(--good)" : "var(--text-dim)"}>
                  {n.confidence_band}
                </text>
              )}
            </g>
          );
        })}
      </svg>
    </div>
  );
}
