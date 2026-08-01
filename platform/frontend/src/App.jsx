import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import { AuthProvider, can, useAuth } from "./auth.jsx";
import { PrefsProvider, usePrefs } from "./components/prefs.jsx";
import DeployWatch from "./components/DeployWatch.jsx";
import {
  IconAudit, IconComponents, IconCorrelation, IconDashboard, IconFindings, IconHealth, IconHosts,
  IconInvestigations, IconReversing, IconSearch, IconUsers,
} from "./components/icons.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import Investigations from "./pages/Investigations.jsx";
import InvestigationDetail from "./pages/InvestigationDetail.jsx";
import RunDetail from "./pages/RunDetail.jsx";
import Hosts from "./pages/Hosts.jsx";
import IocSearch from "./pages/IocSearch.jsx";
import Correlation from "./pages/Correlation.jsx";
import Findings from "./pages/Findings.jsx";
import Reversing from "./pages/Reversing.jsx";
import Admin from "./pages/Admin.jsx";
import ComponentHealth from "./pages/ComponentHealth.jsx";
import MeshHealth from "./pages/MeshHealth.jsx";
import BrokeredSessions from "./pages/BrokeredSessions.jsx";
import Repairs from "./pages/Repairs.jsx";
import AnalysisDiff from "./pages/AnalysisDiff.jsx";
import Audit from "./pages/Audit.jsx";
import Users from "./pages/Users.jsx";
import Login from "./pages/Login.jsx";

function DisplayPrefs() {
  const { density, zone, set } = usePrefs();
  return (
    <div className="prefs" role="group" aria-label="Display preferences">
      <button type="button" className="pref-btn"
              aria-pressed={density === "compact"}
              onClick={() => set({ density: density === "compact" ? "comfortable" : "compact" })}>
        {density === "compact" ? "Compact" : "Comfortable"}
      </button>
      <button type="button" className="pref-btn"
              aria-pressed={zone === "local"}
              onClick={() => set({ zone: zone === "utc" ? "local" : "utc" })}>
        {zone === "utc" ? "UTC" : "Local"}
      </button>
    </div>
  );
}

function Sidebar() {
  const { user, logout } = useAuth();
  return (
    <aside className="sidebar">
      <div className="brand"><span className="dot" /> IR Platform</div>
      <div className="brand-sub">Forensic Analysis</div>
      <nav className="nav">
        <NavLink to="/" end><IconDashboard />Dashboard</NavLink>
        <NavLink to="/investigations"><IconInvestigations />Investigations</NavLink>
        <NavLink to="/hosts"><IconHosts />Hosts</NavLink>
        <NavLink to="/findings"><IconFindings />Findings</NavLink>
        <NavLink to="/correlation"><IconCorrelation />Correlation</NavLink>
        {can(user, "reverse_engineer", "admin") && (
          <NavLink to="/reversing"><IconReversing />Reverse Engineering</NavLink>
        )}
        <NavLink to="/ioc-search"><IconSearch />IOC Search</NavLink>
        {can(user, "auditor", "admin") && <NavLink to="/audit"><IconAudit />Audit Trail</NavLink>}
        {can(user, "admin") && <NavLink to="/users"><IconUsers />Users</NavLink>}
        {/* Not /admin: the ingress denies that prefix outright to keep Keycloak's admin
            console off the analyst origin, and the deny happens before any role is
            considered — so an admin clicking this got a bare "Forbidden". The security
            rule is right; the application path was the thing in the wrong place. */}
        {can(user, "admin") && <NavLink to="/platform-health"><IconHealth />Platform Health</NavLink>}
        {can(user, "admin") && <NavLink to="/component-health"><IconComponents />Component Health</NavLink>}
        {can(user, "admin") && <NavLink to="/mesh-health"><IconComponents />Service Mesh</NavLink>}
        {can(user, "auditor", "admin") && <NavLink to="/brokered-sessions"><IconAudit />Brokered Sessions</NavLink>}
        {can(user, "admin") && <NavLink to="/repairs"><IconHealth />Enclave Repairs</NavLink>}
      </nav>
      <div style={{ position: "absolute", bottom: 20, left: 14, right: 14 }}>
        <DisplayPrefs />
        <div className="muted" style={{ fontSize: 12, marginBottom: 6 }}>
          {user.username} · <span className="tag">{user.role}</span>
        </div>
        <button className="btn ghost" style={{ width: "100%" }} onClick={logout}>
          Sign out
        </button>
      </div>
    </aside>
  );
}

function Shell() {
  const { user, ready } = useAuth();
  if (!ready) return <div className="app"><div className="main"><div className="empty">Loading…</div></div></div>;
  if (!user) return <Login />;
  return (
    <div className="app">
      <Sidebar />
      <main className="main">
        {/* Sits above every view: a redeployment is something the person reading the page
            needs to be told about, whatever page they are on. */}
        <DeployWatch />
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/investigations" element={<Investigations />} />
          <Route path="/investigations/:id" element={<InvestigationDetail />} />
          <Route path="/runs/:id" element={<RunDetail />} />
          <Route path="/hosts" element={<Hosts />} />
          <Route path="/findings" element={<Findings />} />
          <Route path="/correlation" element={<Correlation />} />
          <Route path="/reversing" element={<Reversing />} />
          <Route path="/ioc-search" element={<IocSearch />} />
          <Route path="/audit" element={<Audit />} />
          <Route path="/users" element={<Users />} />
          <Route path="/platform-health" element={<Admin />} />
          <Route path="/component-health" element={<ComponentHealth />} />
          <Route path="/mesh-health" element={<MeshHealth />} />
          <Route path="/brokered-sessions" element={<BrokeredSessions />} />
          <Route path="/repairs" element={<Repairs />} />
          {/* Catches in-app navigation to the old path, which react-router resolves
              without a server request. A fresh page load at /admin still never reaches
              here — the ingress refuses it first, which is the point of that rule. */}
          <Route path="/admin" element={<Navigate to="/platform-health" replace />} />
          <Route path="/captures/:captureId/diff" element={<AnalysisDiff />} />
        </Routes>
      </main>
    </div>
  );
}

export default function App() {
  return (
    <PrefsProvider>
      <AuthProvider>
        <Shell />
      </AuthProvider>
    </PrefsProvider>
  );
}
