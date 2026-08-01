import { useState } from "react";
import { useAuth } from "../auth.jsx";

export default function Login() {
  const { login } = useAuth();
  const [u, setU] = useState("");
  const [p, setP] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true); setErr("");
    try { await login(u, p); }
    catch { setErr("Invalid credentials"); }
    finally { setBusy(false); }
  };

  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", minHeight: "100vh", width: "100%" }}>
      <form onSubmit={submit} className="panel" style={{ padding: 32, width: 340 }}>
        <div className="brand" style={{ marginBottom: 4 }}><span className="dot" /> IR Platform</div>
        <div className="brand-sub" style={{ marginBottom: 22 }}>Forensic Analysis · sign in</div>
        <div className="search" style={{ display: "block" }}>
          <input placeholder="Username" value={u} onChange={(e) => setU(e.target.value)}
                 style={{ width: "100%", marginBottom: 12 }} />
          <input placeholder="Password" type="password" value={p} onChange={(e) => setP(e.target.value)}
                 style={{ width: "100%", marginBottom: 16 }} />
        </div>
        {err && <div className="sev-high" style={{ marginBottom: 12 }}>{err}</div>}
        <button className="btn" style={{ width: "100%" }} disabled={busy}>
          {busy ? "Signing in…" : "Sign in"}
        </button>
        <div className="muted" style={{ fontSize: 11, marginTop: 16 }}>
          Roles: admin · analyst · auditor
        </div>
      </form>
    </div>
  );
}
