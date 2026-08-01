import { useEffect, useRef, useState } from "react";

/**
 * Notice when the platform underneath this tab has been redeployed.
 *
 * A single-page app loads its bundle once and then never asks for it again. An admin who
 * rebuilds the frontend mid-shift changes nothing for anyone already looking at it: the
 * open tab keeps running the old code indefinitely, calling endpoints that may no longer
 * exist, and the symptom looks like a broken feature rather than a stale page.
 *
 * Two things are watched, because they fail differently:
 *
 *   - the bundle. `index.html` is served no-store, so re-fetching it reveals the asset
 *     the server would hand a fresh visitor. A different asset means this tab is running
 *     superseded code.
 *   - the API process. Its start time changes on restart, which is how a tab learns the
 *     backend went away and came back rather than inferring it from a failed request.
 *
 * Nothing reloads on its own. An analyst may be part-way through a justification or an RE
 * through a determination, and discarding that to pick up a new build would be a worse
 * outcome than the stale build. The tab says what happened and lets them choose — except
 * for the transient case of the API simply being unreachable, which resolves itself and
 * is reported without asking anything of anyone.
 */
const POLL_MS = 30000;

async function currentAsset() {
  // Cache-busted so a proxy in front of nginx cannot answer from its own copy.
  const r = await fetch(`/index.html?_=${Date.now()}`, { cache: "no-store" });
  if (!r.ok) throw new Error(String(r.status));
  const html = await r.text();
  const m = html.match(/src="([^"]*\/assets\/index-[^"]+\.js)"/);
  return m ? m[1] : "";
}

function loadedAsset() {
  // Whatever this tab actually booted from.
  const el = document.querySelector('script[type="module"][src*="/assets/index-"]');
  return el ? new URL(el.src, window.location.origin).pathname : "";
}

export default function DeployWatch() {
  const [state, setState] = useState({ frontend: false, backend: false, offline: false });
  const boot = useRef({ asset: "", started: "" });

  useEffect(() => {
    let alive = true;
    boot.current.asset = loadedAsset();

    const check = async () => {
      if (document.hidden) return;

      try {
        const asset = await currentAsset();
        // The first successful read establishes the baseline when the script tag could
        // not be identified (dev server, or a bundler that inlines the entry).
        if (!boot.current.asset) boot.current.asset = asset;
        if (alive && asset && asset !== boot.current.asset) {
          setState((s) => ({ ...s, frontend: true }));
        }
      } catch {
        /* the bundle check failing on its own is not worth reporting */
      }

      try {
        const r = await fetch("/api/version/", { cache: "no-store" });
        if (!r.ok) throw new Error(String(r.status));
        const v = await r.json();
        if (!boot.current.started) boot.current.started = v.started_at;
        if (!alive) return;
        setState((s) => ({
          ...s,
          offline: false,
          backend: Boolean(v.started_at && v.started_at !== boot.current.started),
        }));
      } catch {
        if (alive) setState((s) => ({ ...s, offline: true }));
      }
    };

    check();
    const id = setInterval(check, POLL_MS);
    // Coming back to a tab left open over lunch is exactly when this matters.
    const onVisible = () => { if (!document.hidden) check(); };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      alive = false;
      clearInterval(id);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, []);

  if (state.frontend) {
    return (
      <div className="deploy-banner" role="status">
        <strong>A newer version of the platform is deployed.</strong>{" "}
        This tab is still running the previous one. Reload when you have finished what you
        are recording — nothing you have already submitted is affected.
        <button className="btn" onClick={() => window.location.reload()}>Reload</button>
      </div>
    );
  }
  if (state.backend) {
    return (
      <div className="deploy-banner" role="status">
        <strong>The API was restarted.</strong>{" "}
        Anything you submitted before it went down was saved; anything you were part-way
        through was not sent. Reload to be certain of what you are looking at.
        <button className="btn" onClick={() => window.location.reload()}>Reload</button>
      </div>
    );
  }
  if (state.offline) {
    return (
      <div className="deploy-banner offline" role="status">
        <strong>Cannot reach the API.</strong>{" "}
        It is probably being restarted. This page is still showing the data it last
        loaded; it will update by itself once the API answers again.
      </div>
    );
  }
  return null;
}
