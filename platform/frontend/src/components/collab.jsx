/**
 * Working alongside other analysts: presence, soft locks, mentions and the case feed.
 *
 * Everything here is advisory, and the UI has to say so. A lock badge that looks like a
 * closed padlock will be read as one, and someone will wait for a colleague who went home
 * instead of doing the work. So a held artifact shows who has it and still lets you type.
 *
 * All of it polls. The enclave has no websocket path and does not need one for a roster
 * that changes on the order of minutes.
 */
import { useEffect, useRef, useState } from "react";
import { api } from "../api.js";
import { IconBell } from "./icons.jsx";

const HEARTBEAT_MS = 30000;

/** Announce where you are and learn who else is here. Failure is silent by design. */
export function usePresence(investigationId, location) {
  const [here, setHere] = useState([]);
  useEffect(() => {
    let alive = true;
    const beat = () => {
      api.heartbeat(investigationId, location)
        .then((d) => { if (alive) setHere(d.here || []); })
        .catch(() => {});
    };
    beat();
    const t = setInterval(beat, HEARTBEAT_MS);
    return () => { alive = false; clearInterval(t); };
  }, [investigationId, location]);
  return here;
}

export function PresenceBar({ here }) {
  if (!here?.length) return null;
  return (
    <div className="presence-bar">
      <span className="muted">also here:</span>
      {here.map((p) => (
        <span key={p.username} className="tag" title={`${p.username} · ${p.location || ""}`}>
          <span className="presence-dot" /> {p.username}
        </span>
      ))}
    </div>
  );
}

/**
 * A soft lock on one artifact. Claimed on mount, released on unmount.
 *
 * Returns the holder when it is someone else — never a boolean the caller could mistake
 * for permission. There is no state in which this component's answer should disable an
 * input.
 */
export function useSoftLock(investigationId, refType, refId) {
  const [heldBy, setHeldBy] = useState(null);
  const mine = useRef(false);
  useEffect(() => {
    if (!investigationId || !refType || !refId) return undefined;
    let alive = true;
    api.claimLock(investigationId, refType, refId)
      .then((d) => {
        if (!alive) return;
        mine.current = !!d.acquired;
        setHeldBy(d.acquired ? null : d.held_by);
      })
      .catch(() => {});
    return () => {
      alive = false;
      if (mine.current) api.releaseLock(refType, refId).catch(() => {});
    };
  }, [investigationId, refType, refId]);
  return heldBy;
}

export function LockNotice({ heldBy }) {
  if (!heldBy) return null;
  return (
    <div className="lock-notice">
      <strong>{heldBy}</strong> is working on this right now. You can still edit — this is a
      heads-up, not a lock.
    </div>
  );
}

/** Unread count in the app chrome, with the list behind it. */
export function NotificationBell() {
  const [open, setOpen] = useState(false);
  const [rows, setRows] = useState([]);
  const [unread, setUnread] = useState(0);

  useEffect(() => {
    let alive = true;
    const poll = () => api.hereNow()
      .then((d) => { if (alive) setUnread(d.unread || 0); })
      .catch(() => {});
    poll();
    const t = setInterval(poll, HEARTBEAT_MS);
    return () => { alive = false; clearInterval(t); };
  }, []);

  const show = () => {
    setOpen((v) => !v);
    if (!open) api.notifications().then((d) => setRows(d.notifications || [])).catch(() => {});
  };

  const markRead = () => {
    api.markNotificationsRead([]).then(() => {
      setUnread(0);
      setRows((rs) => rs.map((r) => ({ ...r, read_at: r.read_at || "now" })));
    }).catch(() => {});
  };

  return (
    <div className="bell-wrap">
      <button className="bell" onClick={show} aria-label={`${unread} unread notifications`}>
        <IconBell />
        {unread > 0 && <span className="bell-count">{unread}</span>}
      </button>
      {open && (
        <div className="bell-panel panel">
          <div className="row" style={{ justifyContent: "space-between", padding: "8px 10px" }}>
            <strong>Notifications</strong>
            <button className="btn-sm" onClick={markRead}>mark all read</button>
          </div>
          {rows.length === 0 && <div className="empty" style={{ padding: 10 }}>Nothing yet.</div>}
          {rows.map((n) => (
            <div key={n.id} className={`bell-row${n.read_at ? "" : " unread"}`}>
              <div>
                <span className="tag">{n.kind}</span> {n.actor}
              </div>
              <div className="muted">{n.body}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/** What has happened on this case, read from the audit ledger. */
export function CaseActivity({ investigationId }) {
  const [events, setEvents] = useState([]);
  useEffect(() => {
    if (!investigationId) return;
    api.caseActivity(investigationId, 60)
      .then((d) => setEvents(d.events || []))
      .catch(() => setEvents([]));
  }, [investigationId]);

  if (!events.length) return <div className="empty">No recorded activity yet.</div>;
  return (
    <div className="panel scroll-y">
      <table>
        <thead>
          <tr><th>When</th><th>Who</th><th>Did</th><th>To</th></tr>
        </thead>
        <tbody>
          {events.map((e) => (
            <tr key={e.id}>
              <td className="mono">{e.at.replace("T", " ").slice(0, 19)}Z</td>
              <td>{e.actor}</td>
              <td className="mono">{e.action}</td>
              <td className="mono">{e.object_type}{e.object_id ? ` ${e.object_id}` : ""}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
