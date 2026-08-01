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
    status === "unchecked" ? "var(--accent)" : "var(--muted)";
  const label =
    status === "unchecked" ? "in the mesh; liveness is not checked here" : status;
  return <span className="health-dot" style={{ background: color }} title={label} />;
}

/** One cell of the authorization matrix. */
function Cell({ action, self }) {
  if (self) {
    return <td className="mesh-cell mesh-self" title="a service reaching itself is not a mesh decision">·</td>;
  }
  if (action === "allow") {
    return <td className="mesh-cell mesh-allow" title="allowed by an explicit rule">✓</td>;
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
                  <Cell key={dst} self={src === dst} action={ruleFor(src, dst)} />
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
        applies (default-deny)
      </p>
    </div>
  );
}
