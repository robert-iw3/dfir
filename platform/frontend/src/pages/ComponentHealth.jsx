/**
 * Component health — will the next collection succeed?
 *
 * Platform Health answers whether each service is reachable, which is what gets asked once
 * something has already broken. This answers the question worth asking first: a memory image
 * is the size of the endpoint's RAM, so the figure that matters is not how full a volume is
 * but whether what is coming will fit on it.
 *
 * Every number here is self-reported by the component it describes, because a container's
 * real limits are only visible from inside it — the cgroup ceiling is not the host's RAM, and
 * one component's filesystem is not another's. The DMZ receiver has no route inward, so its
 * report arrives the way its bundles do, carried outbound by the puller.
 *
 * Reports arrive on an interval, which makes a reporter that has gone quiet as important to
 * show as one reporting a problem. A stale row is not a healthy one.
 */
import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";
import { QueueDepthTrend, StorageAllocation } from "../components/charts.jsx";

function bytes(n) {
  if (n == null) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = Number(n);
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`;
}

function age(seconds) {
  if (seconds == null) return "—";
  if (seconds < 90) return `${seconds}s ago`;
  const m = Math.round(seconds / 60);
  if (m < 90) return `${m}m ago`;
  return `${Math.round(m / 60)}h ago`;
}

/** Usage bar. `pct` is 0–100; anything at or above `warn` reads as a problem.
 *
 * The figure sits beside the track rather than on top of it. Centered over the fill it lands
 * exactly where the fill edge crosses at mid-range values, so the character under the edge —
 * usually the decimal point — is the one that becomes unreadable. */
function UsageBar({ pct, warn = 85 }) {
  if (pct == null) return <span className="mono dim">—</span>;
  const state = pct >= 95 ? "critical" : pct >= warn ? "warning" : "ok";
  return (
    <span className="ch-bar-wrap">
      <span className="ch-bar" title={`${pct}% used`}>
        <span className={`ch-bar-fill ch-${state}`} style={{ width: `${Math.min(100, pct)}%` }} />
      </span>
      <span className="ch-bar-pct mono">{pct}%</span>
    </span>
  );
}

function Alert({ alert }) {
  return (
    <li className={`ch-alert ch-${alert.level}`}>
      <span className="ch-alert-level">{alert.level}</span>
      <span className="ch-alert-component mono">{alert.component}</span>
      <span className="ch-alert-message">{alert.message}</span>
      {/* The action is the point: a warning that does not say which volume to grow makes an
          admin go and find out, which is the delay this page exists to remove. */}
      {alert.action && <span className="ch-alert-action">→ {alert.action}</span>}
    </li>
  );
}

/** A titled group whose headline is a single bar, with the detail lines beneath it.
 *
 * The bar carries the worst case in the group, because that is what fails first and what an
 * admin is scanning for. Detail lines stay text: a bar per row turns a card into a wall of
 * tracks with no shape, and the eye has nowhere to land. */
function Group({ title, pct, summary, children }) {
  return (
    <div className="ch-metric-group">
      <div className="ch-group-head">
        <h4>{title}</h4>
        {pct != null
          ? <UsageBar pct={pct} />
          : <span className="ch-group-summary">{summary}</span>}
      </div>
      {children}
    </div>
  );
}

function Row({ label, value, mono = true, warn = false }) {
  return (
    <div className="ch-metric">
      <span className={`ch-metric-label${mono ? " mono" : ""}`}>{label}</span>
      <span className={`ch-metric-value mono${warn ? " ch-warning-text" : ""}`}>{value}</span>
    </div>
  );
}

function Component({ row }) {
  const disks = Object.entries(row.disk || {});
  const mem = row.memory || {};
  const cpu = row.cpu || {};
  const proc = row.process || {};
  const logs = row.logs || {};
  const ls = row.log_storage || {};
  const nets = Object.entries(row.network || {});
  const netTrouble = nets.filter(([, n]) =>
    (n.rx_errors || 0) + (n.tx_errors || 0) + (n.rx_dropped || 0) + (n.tx_dropped || 0) > 0);

  // Each group's headline is its worst case, since that is what runs out first. A component
  // with one comfortable volume and one nearly full is not comfortable.
  const diskPcts = disks.map(([, d]) => d.percent_used).filter((v) => v != null);
  const worstDiskPct = diskPcts.length ? Math.max(...diskPcts) : null;
  // The cgroup ceiling where there is one, because that is what an OOM kill is measured
  // against; the host figure only when the container is uncapped.
  const memPct = mem.cgroup_limit_bytes ? mem.cgroup_percent_used : mem.host_percent_used;
  // Load per CPU as a proportion of saturation — 1.0 per CPU is fully busy — so it reads on
  // the same 0–100 scale as the rest without pretending load is a percentage of anything.
  const loadPct = cpu.load_per_cpu != null
    ? Math.min(100, Math.round(cpu.load_per_cpu * 100)) : null;

  return (
    <section className={`ch-card${row.stale ? " ch-card-stale" : ""}`}>
      <header className="ch-card-head">
        <div>
          <h3 className="mono">{row.component}</h3>
          <span className="ch-tier">{row.tier || "—"}</span>
        </div>
        <div className="ch-reported">
          {row.stale && <span className="ch-stale-badge">stale</span>}
          <span className="dim">reported {age(row.age_seconds)}</span>
        </div>
      </header>

      {row.stale ? (
        <p className="ch-stale-note">
          No report in over two intervals. The figures below are the last it sent and no
          longer describe the running component.
        </p>
      ) : null}

      <div className="ch-metrics">
        <Group title="Storage" pct={worstDiskPct}>
          {disks.length === 0 && <p className="dim">no volumes reported</p>}
          {disks.map(([path, d]) => (
            <Row key={path} label={path}
                 value={<>{bytes(d.free_bytes)} free<span className="dim"> · {d.percent_used ?? "\u2014"}%</span></>} />
          ))}
        </Group>

        {/* Only the log shipper reports this: bucket consumption against the declared
            allocation, the figure its 75% warning is measured on. */}
        {ls.alloc_bytes ? (
          <Group title="Log storage"
                 pct={Math.min(100, Math.round((ls.used_bytes || 0) * 100 / ls.alloc_bytes))}>
            <Row label={ls.bucket || "bucket"}
                 value={<>{bytes(ls.used_bytes)} of {bytes(ls.alloc_bytes)} allocated</>} />
          </Group>
        ) : null}

        <Group title="Memory" pct={memPct}>
          {mem.cgroup_limit_bytes ? (
            <Row label="cgroup limit" mono={false}
                 value={`${bytes(mem.cgroup_used_bytes)} / ${bytes(mem.cgroup_limit_bytes)}`} />
          ) : (
            /* No cgroup ceiling means the container may use whatever the host has, so the
               host figure is the one that predicts an OOM here. */
            <Row label="host (uncapped)" mono={false}
                 value={`${bytes(mem.host_available_bytes)} free`} />
          )}
          {mem.swap_total_bytes ? (
            <Row label="swap" mono={false}
                 value={`${bytes(mem.swap_free_bytes)} free of ${bytes(mem.swap_total_bytes)}`} />
          ) : null}
        </Group>

        <Group title="Load" pct={loadPct}>
          <Row label="1m / 5m / 15m" mono={false}
               value={`${cpu.load_1m ?? "\u2014"} / ${cpu.load_5m ?? "\u2014"} / ${cpu.load_15m ?? "\u2014"}`} />
          <Row label="cpus" mono={false}
               value={<>{cpu.count ?? "\u2014"}{cpu.load_per_cpu != null && <span className="dim"> · {cpu.load_per_cpu} per cpu</span>}</>} />
          <Row label="processes" mono={false}
               value={<>{proc.pids_current ?? "\u2014"}{proc.pids_max ? ` / ${proc.pids_max}` : ""}{proc.open_fds != null && <span className="dim"> · {proc.open_fds} fds</span>}</>} />
        </Group>

        <Group title="Network & logs"
               summary={netTrouble.length || logs.errors_since_last_report ? "attention" : "clean"}>
          {netTrouble.length === 0 ? (
            <Row label="interfaces" mono={false} value="no errors or drops" />
          ) : netTrouble.map(([iface, n]) => (
            <Row key={iface} label={iface} warn
                 value={`${(n.rx_errors || 0) + (n.tx_errors || 0)} err · ${(n.rx_dropped || 0) + (n.tx_dropped || 0)} dropped`} />
          ))}
          <Row label="errors since last report" mono={false}
               warn={Boolean(logs.errors_since_last_report)}
               value={<>{logs.errors_since_last_report ?? 0}<span className="dim"> ({logs.errors_total ?? 0} total)</span></>} />
          {logs.last_error && <p className="ch-last-error mono">{logs.last_error}</p>}
        </Group>
      </div>
    </section>
  );
}

export default function ComponentHealth() {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [depth, setDepth] = useState(null);
  const [alloc, setAlloc] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setData(await api.componentHealth());
      setError("");
    } catch (e) {
      setError(String(e.message || e));
    } finally {
      setLoading(false);
    }
    // Separately and tolerantly: the queue and storage panels are additions to this page,
    // and storage is admin-only — a 403 hides that panel rather than failing the page.
    try { setDepth(await api.queueDepth()); } catch { setDepth(null); }
    try { setAlloc(await api.storageAllocation()); } catch { setAlloc(null); }
  }, []);

  useEffect(() => { load(); }, [load]);

  // Refreshed on the reporting interval rather than continuously: polling faster than the
  // components report only redraws the same numbers.
  useEffect(() => {
    if (!data?.report_interval_seconds) return undefined;
    const id = setInterval(load, data.report_interval_seconds * 1000);
    return () => clearInterval(id);
  }, [data?.report_interval_seconds, load]);

  if (loading && !data) return <div className="page"><p>Loading component health…</p></div>;
  if (error) return <div className="page"><p className="error">Could not load: {error}</p></div>;

  const alerts = data?.alerts || [];
  const declarations = data?.declarations || [];

  return (
    <div className="page ch-page">
      <header className="page-head">
        <div>
          <h2>Component Health</h2>
          <p className="dim">
            Resources, container limits and error counts, reported by each component about
            itself every {Math.round((data?.report_interval_seconds || 900) / 60)} minutes.
          </p>
        </div>
        <button onClick={load} disabled={loading}>{loading ? "Refreshing…" : "Refresh"}</button>
      </header>

      <section className={`ch-summary ch-${data?.worst_level || "ok"}`}>
        {alerts.length === 0 ? (
          <p>No capacity or resource problems. Every component is reporting and within limits.</p>
        ) : (
          <>
            <h3>{alerts.length} thing{alerts.length === 1 ? "" : "s"} to act on</h3>
            <ul className="ch-alerts">
              {alerts.map((a, i) => <Alert key={`${a.component}-${a.kind}-${i}`} alert={a} />)}
            </ul>
          </>
        )}
      </section>

      {depth && (
        <section className="ch-declarations">
          <h3>Analysis queue</h3>
          <p className="dim">
            Whether the backlog is being worked down or growing — depth alone cannot say,
            so the record over time is the figure that matters.
          </p>
          <QueueDepthTrend depth={depth} />
        </section>
      )}

      {alloc && (
        <section className="ch-declarations">
          <h3>Object store allocation</h3>
          <p className="dim">
            What the platform accounts for in the object store, with each capture&apos;s
            retention state visible — the storage that policy has already released is the
            first place to reclaim space.
          </p>
          <StorageAllocation alloc={alloc} />
        </section>
      )}

      {declarations.length > 0 && (
        <section className="ch-declarations">
          <h3>Declared by collected endpoints</h3>
          <p className="dim">
            Each endpoint computes what its next collection will need from its own RAM and
            declares it before capturing. It is told nothing back — the comparison against
            free space happens here, so a compromised host cannot map this platform&apos;s
            storage by asking.
          </p>
          <table className="ch-table">
            <thead>
              <tr><th>Host</th><th>RAM</th><th>Image</th><th>Bundle</th></tr>
            </thead>
            <tbody>
              {declarations.map((d) => (
                <tr key={d.hostname}>
                  <td className="mono">{d.hostname}</td>
                  <td className="mono">{bytes(d.host_ram_bytes)}</td>
                  <td className="mono">{bytes(d.expected_raw_bytes)}</td>
                  <td className="mono">{bytes(d.expected_bundle_bytes)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      <div className="ch-grid">
        {(data?.components || []).map((row) => <Component key={row.component} row={row} />)}
      </div>

      {(data?.components || []).length === 0 && (
        <p className="dim">
          No component has reported yet. Reports begin when the backend, workers, puller and
          receiver start; the first arrives within a minute of a restart.
        </p>
      )}
    </div>
  );
}
