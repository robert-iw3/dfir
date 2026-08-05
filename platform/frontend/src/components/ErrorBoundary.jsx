import { Component } from "react";

/**
 * Catches a render crash and shows it, instead of unmounting the app.
 *
 * React's default on an unhandled render error is to tear the whole tree down, which paints
 * a blank page. For an analyst that is indistinguishable from "this investigation has no
 * data" — the two most different outcomes the UI can have, rendered identically. A blank
 * screen also carries nothing to report: no component, no message, no failing request.
 *
 * So the boundary keeps the shell alive, names what failed, and hands over the detail an
 * analyst can quote. `onError` forwards the same record to the API so the failure exists
 * somewhere other than one person's console.
 */
export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { error: null, info: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    this.setState({ info });
    try {
      this.props.onError?.({
        where: this.props.where || "unknown",
        message: String(error?.message || error),
        stack: String(error?.stack || "").slice(0, 4000),
        component_stack: String(info?.componentStack || "").slice(0, 4000),
        url: typeof window !== "undefined" ? window.location.href : "",
      });
    } catch {
      // Reporting must never be the reason a page stays broken.
    }
  }

  render() {
    const { error, info } = this.state;
    if (!error) return this.props.children;

    return (
      <div className="panel" style={{ padding: 16, borderColor: "var(--bad)" }}>
        <h2 style={{ marginTop: 0 }}>This view failed to render</h2>
        <p className="muted">
          The rest of the application is still working — the failure is contained to{" "}
          <span className="mono">{this.props.where || "this view"}</span>. The evidence behind
          it is unaffected; this is a display fault, not a data one.
        </p>
        <div className="mono" style={{ marginTop: 8 }}>{String(error.message || error)}</div>
        <details style={{ marginTop: 10 }}>
          <summary className="linkish">Show detail for a bug report</summary>
          <pre style={{ whiteSpace: "pre-wrap", fontSize: 11, marginTop: 8 }}>
            {String(error.stack || "")}
            {info?.componentStack || ""}
          </pre>
        </details>
        <button className="btn" style={{ marginTop: 10 }}
                onClick={() => this.setState({ error: null, info: null })}>
          Try this view again
        </button>
      </div>
    );
  }
}
