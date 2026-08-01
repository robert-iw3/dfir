/**
 * Attack graph — the intrusion laid out left to right in the order it spread.
 *
 * Rendered as hand-built SVG: the analyst kiosk has no internet path, so no charting
 * library can be fetched and none is bundled.
 *
 * Layout is by "hop depth" — how many moves from the entry point a host sits — rather
 * than by wall-clock time, so a host reached late by a short path stays near its parent
 * and the shape of the intrusion reads correctly.
 */
const COL_W = 210;
const ROW_H = 74;
const NODE_W = 168;
const NODE_H = 46;

const ROLE_FILL = {
  patient_zero: "var(--crit)",
  pivot: "var(--warn)",
  affected: "var(--bad)",
};

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

export default function AttackGraph({ nodes, edges, onSelect, selected }) {
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

  return (
    <div className="panel" style={{ overflowX: "auto", padding: 8 }}>
      <svg width={width} height={height} role="img"
           aria-label={`Attack graph: ${nodes.length} hosts, ${edges.length} movements`}>
        <defs>
          <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5"
                  markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="var(--text-dim)" />
          </marker>
        </defs>

        {edges.map((e, i) => {
          const a = pos.get(e.src);
          const b = pos.get(e.dst);
          if (!a || !b) return null;
          const x1 = a.x + NODE_W;
          const y1 = a.y + NODE_H / 2;
          const x2 = b.x;
          const y2 = b.y + NODE_H / 2;
          const mx = (x1 + x2) / 2;
          return (
            <g key={i}>
              <path d={`M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`}
                    fill="none" stroke="var(--text-dim)" strokeWidth="1.5"
                    markerEnd="url(#arrow)" />
              <text x={mx} y={(y1 + y2) / 2 - 5} textAnchor="middle"
                    fill="var(--text-dim)" fontSize="10">
                {e.protocol}
              </text>
            </g>
          );
        })}

        {nodes.map((n) => {
          const p = pos.get(n.hostname);
          const on = selected === n.hostname;
          return (
            <g key={n.hostname} transform={`translate(${p.x},${p.y})`}
               onClick={() => onSelect?.(n.hostname)}
               style={{ cursor: onSelect ? "pointer" : "default" }}>
              <rect width={NODE_W} height={NODE_H} rx="8"
                    fill="var(--bg-elev-2)"
                    stroke={on ? "var(--accent)" : ROLE_FILL[n.role] || "var(--border)"}
                    strokeWidth={on ? 2.5 : 1.5} />
              <circle cx="14" cy="16" r="5" fill={ROLE_FILL[n.role] || "var(--text-dim)"} />
              <text x="26" y="20" fill="var(--text)" fontSize="12" fontWeight="600">
                {n.hostname}
              </text>
              <text x="26" y="35" fill="var(--text-dim)" fontSize="10">
                {n.role === "patient_zero" ? "entry point" : n.role}
                {n.entry_account ? ` · ${n.entry_account.split("\\").pop()}` : ""}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
