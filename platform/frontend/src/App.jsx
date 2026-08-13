import { NavLink, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { api } from "./api.js";
import { AuthProvider, can, useAuth } from "./auth.jsx";
import { PrefsProvider, usePrefs } from "./components/prefs.jsx";
import DeployWatch from "./components/DeployWatch.jsx";
import ErrorBoundary from "./components/ErrorBoundary.jsx";
import { Loading, Ring } from "./components/common.jsx";
import {
  IconAudit, IconComponents, IconCorrelation, IconDashboard, IconFindings, IconHandover,
  IconHealth, IconHosts, IconInvestigations, IconReversing, IconSearch, IconUsers,
} from "./components/icons.jsx";
import GlobalSearch from "./components/GlobalSearch.jsx";
import { NotificationBell } from "./components/collab.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import Investigations from "./pages/Investigations.jsx";
import InvestigationDetail from "./pages/InvestigationDetail.jsx";
import RunDetail from "./pages/RunDetail.jsx";
import Hosts from "./pages/Hosts.jsx";
import HostDetail from "./pages/HostDetail.jsx";
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
import Handover from "./pages/Handover.jsx";
import Logs from "./pages/Logs.jsx";
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
      <div className="brand">
        <img src="/logo.svg" alt="" className="brand-mark" width="26" height="26" />
        DFIR Framework
      </div>
      <div className="brand-sub">Forensic Analysis</div>
      <nav className="nav">
        <NavLink to="/" end><IconDashboard />Dashboard</NavLink>
        <NavLink to="/investigations"><IconInvestigations />Investigations</NavLink>
        <NavLink to="/hosts"><IconHosts />Hosts</NavLink>
        <NavLink to="/findings"><IconFindings />Findings</NavLink>
        <NavLink to="/correlation"><IconCorrelation />Correlation</NavLink>
        <NavLink to="/handover"><IconHandover />Shift Handover</NavLink>
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
        {can(user, "admin") && <NavLink to="/logs"><IconAudit />Logs</NavLink>}
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

function PlatformDown() {
  return (
    <div className="app">
      <div className="main">
        <div className="panel" style={{ maxWidth: 520, margin: "12vh auto", padding: 24 }}>
          <h2 style={{ marginTop: 0 }}>The platform is not answering</h2>
          <p>
            It is restarting or briefly unreachable. You are still signed in — this is not a
            sign-out, and nothing you submitted has been lost.
          </p>
          <div className="waiting" style={{ marginTop: 18 }} role="status" aria-live="polite">
            <Ring />
            <span className="chart-note" style={{ margin: 0 }}>
              Reconnecting automatically every few seconds. This page returns on its own.
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}

function Shell() {
  const { user, ready, down } = useAuth();
  const { pathname } = useLocation();
  if (!ready) return <div className="app"><div className="main"><Loading /></div></div>;
  // Unreachable is not unauthenticated. On a kiosk the analyst has no local password, so a
  // sign-in form here would be a dead end; this says what is actually wrong and keeps
  // retrying on its own.
  if (down && !user) return <PlatformDown />;
  if (!user) return <Login />;
  return (
    <div className="app">
      <Sidebar />
      <main className="main">
        {/* Sits above every view: a redeployment is something the person reading the page
            needs to be told about, whatever page they are on. */}
        {/* One row above every view: what you are looking for, and what is waiting for
            you. Both are global, so neither belongs to a page. */}
        <div className="topbar">
          <GlobalSearch />
          <NotificationBell />
        </div>
        <DeployWatch />
        {/* Inside the shell, not around it: a view that fails keeps the navigation usable,
            so an analyst can move to another page rather than reload a blank window. Keyed
            on the path so leaving a broken view clears the error. */}
        <ErrorBoundary key={pathname} where={pathname} onError={api.reportClientError}>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/investigations" element={<Investigations />} />
          <Route path="/investigations/:id" element={<InvestigationDetail />} />
          <Route path="/runs/:id" element={<RunDetail />} />
          <Route path="/hosts" element={<Hosts />} />
          <Route path="/hosts/:id" element={<HostDetail />} />
          <Route path="/findings" element={<Findings />} />
          <Route path="/correlation" element={<Correlation />} />
          <Route path="/handover" element={<Handover />} />
          <Route path="/reversing" element={<Reversing />} />
          <Route path="/ioc-search" element={<IocSearch />} />
          <Route path="/audit" element={<Audit />} />
          <Route path="/users" element={<Users />} />
          <Route path="/platform-health" element={<Admin />} />
          <Route path="/component-health" element={<ComponentHealth />} />
          <Route path="/mesh-health" element={<MeshHealth />} />
          <Route path="/brokered-sessions" element={<BrokeredSessions />} />
          <Route path="/repairs" element={<Repairs />} />
          <Route path="/logs" element={<Logs />} />
          {/* Catches in-app navigation to the old path, which react-router resolves
              without a server request. A fresh page load at /admin still never reaches
              here — the ingress refuses it first, which is the point of that rule. */}
          <Route path="/admin" element={<Navigate to="/platform-health" replace />} />
          <Route path="/captures/:captureId/diff" element={<AnalysisDiff />} />
        </Routes>
        </ErrorBoundary>
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
