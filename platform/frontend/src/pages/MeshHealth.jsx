/**
 * The service mesh — what is in it, and what it authorizes.
 *
 * Two questions, deliberately on one page, because answering only the first is how a mesh
 * looks healthy while enforcing nothing:
 *
 *   REGISTERED   which services are in the catalog and have a live proxy in front of them
 *   AUTHORIZED   which service may reach which — the policy that decides whether a
 *                compromised container can reach the evidence
 *
 * A service in the catalog WITHOUT a sidecar is the dangerous state: it is up, it looks fine,
 * and its traffic bypasses every intention. This platform shipped exactly that once, so it is
 * called out at the top rather than left for someone to notice in a table.
 *
 * The matrix is the policy as CONSUL HOLDS IT, not as the repository's files describe it. The
 * two can differ — an intention edited in a file never reaches a cluster whose data predates
 * the edit — and when they do, this is the half that is actually enforcing.
 */
import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";

const REFRESH_MS = 15000;

function StatusDot({ status }) {
  const color =
    status === "passing" ? "var(--good)" :
    status === "warning" ? "var(--warn)" :
    status === "critical" ? "var(--bad)" :
    // "unchecked" means the registration defines no health check — the mesh is not watching
    // this service's liveness, which the Platform Health page covers instead. Distinct from
    // "unknown", which means a check exists and has not reported.
    status === "unchecked" ? "var(--accent)" : "var(--text-dim)";
  const label =
    status === "unchecked" ? "in the mesh; liveness is not checked here" : status;
  return <span className="health-dot" style={{ background: color }} title={label} />;
}

/** One cell of the authorization matrix: the policy, plus what the source's own sidecar
 * counted where a component testifies. Policy says who MAY connect; the counter says who
 * TRIED and what happened, which turns a default-deny cell from an assumption into an
 * observation. */
function Cell({ action, self, obs }) {
  if (self) {
    return <td className="mesh-cell mesh-self" title="a service reaching itself is not a mesh decision">·</td>;
  }
  const fails = obs?.connect_fail || 0;
  const ok = Math.max(0, (obs?.cx_total || 0) - fails);
  if (action === "allow") {
    // The counter is CUMULATIVE since the sidecar started, so it cannot by itself say
    // anything is failing now. A service that starts before its upstream is ready loses a
    // connection or two and then runs for days; reading that as a current fault paints a
    // healthy pair red permanently and teaches everyone to ignore the colour.
    //
    // Never succeeded is the only thing this evidence supports calling failure.
    if (fails > 0 && ok === 0) {
      return <td className="mesh-cell mesh-warn"
                 title={`allowed, but never observed connecting — all ${fails} attempt(s) from the source's own sidecar failed`}>
               ✓<span className="mesh-obs">{fails}✕</span></td>;
    }
    if (ok > 0) {
      return <td className="mesh-cell mesh-allow"
                 title={fails > 0
                   ? `allowed and carrying traffic — ${ok} connection(s) counted, and ${fails} earlier attempt(s) failed since this sidecar started (usually the upstream not yet being ready)`
                   : `allowed, and observed carrying traffic — ${ok} connection(s) counted by the source's own sidecar`}>
               ✓<span className="mesh-obs">{ok}</span>
               {fails > 0 && <span className="mesh-obs-stale" title={`${fails} earlier failure(s)`}>·{fails}✕</span>}
             </td>;
    }
    return <td className="mesh-cell mesh-allow" title="allowed by an explicit rule; no traffic observed">✓</td>;
  }
  // A successful connection on a pair the policy does not allow is the divergence this page
  // exists to surface — it outranks whatever the rule claims.
  if (ok > 0) {
    return <td className="mesh-cell mesh-breach"
               title={`POLICY DIVERGENCE — ${ok} connection(s) succeeded on a pair the policy does not allow`}>
             !<span className="mesh-obs">{ok}</span></td>;
  }
  if (fails > 0) {
    const base = action === "deny"
      ? "denied by an explicit rule"
      : "no rule names this pair — the destination's default applies";
    return <td className={`mesh-cell ${action === "deny" ? "mesh-deny" : "mesh-default"}`}
               title={`${base} — and denied in practice: the source's sidecar counted ${fails} refused attempt(s)`}>
             {action === "deny" ? "✕" : "–"}<span className="mesh-obs">{fails}</span></td>;
  }
  if (action === "deny") {
    return <td className="mesh-cell mesh-deny" title="denied by an explicit rule">✕</td>;
  }
  // No rule names this pair, so the destination's trailing `*` rule decides it. Shown as
  // distinct from an explicit deny: the outcome is the same, the reason is not, and only one
  // of them survives someone adding a rule above it.
  return <td className="mesh-cell mesh-default" title="no rule names this pair — the destination's default applies">–</td>;
}

export default function MeshHealth() {
  const [data, setData] = useState(null);
  const [err, setErr] = useState("");

  const load = useCallback(async () => {
    try {
      setData(await api.meshHealth());
      setErr("");
    } catch (e) {
      setErr(String(e.message || e));
    }
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, REFRESH_MS);
    return () => clearInterval(t);
  }, [load]);

  if (err) return <div className="page"><h1>Service mesh</h1><div className="card bad">{err}</div></div>;
  if (!data) return <div className="page"><h1>Service mesh</h1><div className="muted">Reading the control plane…</div></div>;

  if (!data.reachable) {
    return (
      <div className="page">
        <h1>Service mesh</h1>
        {/* Distinguished from an empty mesh on purpose: "cannot reach Consul" and "Consul
            says nothing is registered" render identically as no rows, and they call for
            opposite responses. */}
        <div className="card bad" style={{ padding: 16 }}>
          <strong>The mesh control plane did not answer.</strong>
          <div className="muted" style={{ marginTop: 6 }}>{data.error}</div>
          <div className="muted" style={{ marginTop: 6 }}>
            This is not the same as an empty mesh — nothing here can be trusted until Consul answers.
          </div>
        </div>
      </div>
    );
  }

  const names = data.services.map((s) => s.name);
  // Only a rule naming BOTH services is an explicit decision. A destination's trailing `*`
  // rule is its default, and showing that as an explicit deny would hide the difference
  // between a pair someone considered and a pair nobody has.
  const ruleFor = (src, dst) =>
    data.intentions.find((r) => r.source === src && r.destination === dst)?.action ?? null;

  return (
    <div className="page">
      <h1>Service mesh</h1>
      <p className="muted" style={{ maxWidth: 760 }}>
        Read live from Consul in <code>{data.datacenter}</code>. The catalog is what is in the
        mesh; the matrix is the policy actually enforced on every connection.
      </p>

      {data.unproxied?.length > 0 && (
        <div className="card bad" style={{ padding: 14, marginBottom: 14 }}>
          <strong>{data.unproxied.length} service(s) are registered without a sidecar:</strong>{" "}
          {data.unproxied.join(", ")}
          <div className="muted" style={{ marginTop: 6 }}>
            Their traffic does not pass an intention check. A service without a proxy is not in
            the mesh, however healthy it looks.
          </div>
        </div>
      )}

      <div className="cards" style={{ marginBottom: 16 }}>
        <div className="card"><div className="num">{data.registered}</div><div className="lbl">Services</div></div>
        <div className="card"><div className="num">{data.proxies}</div><div className="lbl">Sidecars</div></div>
        <div className={`card ${data.unproxied?.length ? "bad" : ""}`}>
          <div className="num">{data.unproxied?.length || 0}</div><div className="lbl">Unproxied</div>
        </div>
        <div className="card"><div className="num">{data.intentions.length}</div><div className="lbl">Rules</div></div>
      </div>

      <h2>Registered services</h2>
      <table className="tbl">
        <thead>
          <tr><th></th><th>Service</th><th>Address</th><th>In mesh</th><th>Checks</th></tr>
        </thead>
        <tbody>
          {data.services.map((s) => (
            <tr key={s.name}>
              <td><StatusDot status={s.status} /></td>
              <td><code>{s.name}</code></td>
              <td className="muted"><code>{s.address}:{s.port}</code></td>
              <td>
                {s.proxied
                  ? <span style={{ color: "var(--good)" }}>proxied</span>
                  : <span style={{ color: "var(--bad)" }}>NO SIDECAR</span>}
              </td>
              <td className="muted">
                {s.checks.length === 0 ? "—" :
                  s.checks.map((c) => `${c.name}: ${c.status}`).join(" · ")}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2 style={{ marginTop: 22 }}>Authorization — who may reach whom</h2>
      <p className="muted" style={{ maxWidth: 760 }}>
        Rows are sources, columns are destinations. Read a row as “this service may reach…”.
      </p>
      {!data.intentions_readable && (
        <div className="card bad" style={{ padding: 12, marginBottom: 10 }}>
          The intentions could not be read — the matrix below is empty because of a permission
          problem, not because the mesh allows everything.
        </div>
      )}
      <div style={{ overflowX: "auto" }}>
        <table className="tbl mesh-matrix">
          <thead>
            <tr>
              <th style={{ textAlign: "right" }}>source ╲ destination</th>
              {names.map((n) => <th key={n} className="mesh-col">{n.replace(/^ir-/, "")}</th>)}
            </tr>
          </thead>
          <tbody>
            {names.map((src) => (
              <tr key={src}>
                <th style={{ textAlign: "right", whiteSpace: "nowrap" }}>{src.replace(/^ir-/, "")}</th>
                {names.map((dst) => (
                  <Cell key={dst} self={src === dst} action={ruleFor(src, dst)}
                        obs={data.observed?.[src]?.[dst]} />
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="muted" style={{ marginTop: 8 }}>
        <span className="mesh-key mesh-allow">✓</span> explicit allow ·{" "}
        <span className="mesh-key mesh-deny">✕</span> explicit deny ·{" "}
        <span className="mesh-key mesh-default">–</span> no rule; the destination’s default
        applies (default-deny) ·{" "}
        <span className="mesh-key mesh-warn">✓n✕</span> allowed but never connected ·{" "}
        <span className="mesh-key mesh-breach">!</span> traffic where policy allows none
      </p>
      <p className="muted" style={{ marginTop: 4 }}>
        {Object.keys(data.observed || {}).length > 0 ? (
          <>A count beside a glyph is first-person evidence — connections the source&apos;s own
          sidecar counted. Rows that testify: {Object.keys(data.observed).sort().map((s, i) => (
            <span key={s}>{i > 0 && ", "}<code>{s}</code></span>
          ))}; every other cell carries policy only.</>
        ) : (
          <>No component has reported first-person sidecar counters yet — every cell above is
          policy only, not an observation of traffic.</>
        )}
      </p>
    </div>
  );
}
