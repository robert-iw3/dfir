import { useState } from "react";
import { api } from "../api.js";
import { useData, Loading, Empty } from "../components/common.jsx";
import DataTable from "../components/DataTable.jsx";

export default function Users() {
  const { data, error, reload } = useData(() => api.listUsers());
  const [form, setForm] = useState({ username: "", email: "", role: "analyst", password: "" });
  const [msg, setMsg] = useState(null);
  const [busy, setBusy] = useState(false);

  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }));

  const create = async (e) => {
    e.preventDefault();
    setBusy(true); setMsg(null);
    try {
      const r = await api.createUser(form);
      setMsg({ ok: true, text: `Provisioned ${r.username} (${r.role}) in Keycloak.` });
      setForm({ username: "", email: "", role: "analyst", password: "" });
      reload();
    } catch (err) {
      setMsg({ ok: false, text: err.message });
    } finally { setBusy(false); }
  };

  const users = data?.users ?? [];

  return (
    <>
      <h1>Users</h1>
      <p className="page-sub">Create platform accounts — provisioned in Keycloak for SSO, in the group matching their role.</p>

      <div className="panel" style={{ padding: 18, marginBottom: 20 }}>
        <h2 style={{ marginTop: 0 }}>Create user</h2>
        <form onSubmit={create} style={{ display: "grid", gridTemplateColumns: "1fr 1fr 160px 1fr auto", gap: 10, alignItems: "center" }}>
          <input placeholder="username" value={form.username} onChange={set("username")} className="table-search" />
          <input placeholder="email" type="email" value={form.email} onChange={set("email")} className="table-search" />
          <select value={form.role} onChange={set("role")}>
            <option value="admin">admin</option>
            <option value="analyst">analyst</option>
            <option value="auditor">auditor</option>
          </select>
          <input placeholder="temp password" type="text" value={form.password} onChange={set("password")} className="table-search" />
          <button className="btn" disabled={busy}>{busy ? "Provisioning…" : "Create"}</button>
        </form>
        {msg && <div style={{ marginTop: 12 }} className={msg.ok ? "status-completed" : "sev-high"}>{msg.text}</div>}
      </div>

      <h2>Existing users</h2>
      {!data ? <Loading error={error} /> : users.length === 0 ? <Empty>No users.</Empty> : (
        <DataTable
          rows={users.map((u, i) => ({ id: i, ...u, role: (u.roles || []).join(", ") }))}
          searchPlaceholder="Search users…"
          columns={[
            { key: "username", label: "Username", mono: true },
            { key: "email", label: "Email", mono: true },
            { key: "role", label: "Role(s)", filter: true },
            { key: "enabled", label: "Enabled", render: (v) => v ? <span className="status-completed">yes</span> : <span className="muted">no</span> },
          ]}
        />
      )}
    </>
  );
}
