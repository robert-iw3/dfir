// Thin fetch wrapper with token auth. Same-origin /api in prod (nginx) and dev (vite).
const BASE = "/api";

export function getToken() { return localStorage.getItem("ir_token") || ""; }
export function setToken(t) { localStorage.setItem("ir_token", t); }
export function clearToken() { localStorage.removeItem("ir_token"); }

function headers(extra) {
  const h = { "Content-Type": "application/json", ...(extra || {}) };
  const t = getToken();
  if (t) h["Authorization"] = `Token ${t}`;
  return h;
}

async function req(method, path, body) {
  const r = await fetch(`${BASE}${path}`, {
    method,
    headers: headers(),
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (r.status === 401) throw new Error("unauthorized");
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  return r.status === 204 ? null : r.json();
}

const get = (p) => req("GET", p);
const post = (p, b) => req("POST", p, b || {});
const del = (p) => req("DELETE", p);

export const api = {
  login: async (username, password) => {
    const r = await fetch(`${BASE}/auth/token/`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    if (!r.ok) throw new Error("login failed");
    return r.json(); // { token }
  },
  me: () => get("/me/"),
  // Admin operations. Mesh and remediation are admin-only; brokered sessions are also
  // readable by an auditor, because they ARE the access record for this platform.
  meshHealth: () => get("/admin/mesh-health/"),
  brokeredSessions: () => get("/brokered-sessions/"),
  remediation: () => get("/admin/remediation/"),
  requestRemediation: (action, reason) => post("/admin/remediation/", { action, reason }),
  stats: () => get("/stats/"),
  facets: () => get("/facets/"),
  summary: (params) => {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(params || {})) if (v?.length) qs.set(k, v.join(","));
    return get(`/summary/?${qs.toString()}`);
  },
  investigations: () => get("/investigations/"),
  investigation: (id) => get(`/investigations/${id}/`),
  run: (id) => get(`/runs/${id}/`),
  runAdjudication: (id, verdict = "") =>
    get(`/runs/${id}/adjudication/${verdict ? `?verdict=${encodeURIComponent(verdict)}` : ""}`),
  runAdjudicationChain: (id, rootPid) =>
    get(`/runs/${id}/adjudication/chain/?root_pid=${rootPid}`),
  memoryFindings: (qs = "") => get(`/memory-findings/${qs}`),
  reclassify: (id, body) => post(`/findings/${id}/reclassify/`, body),
  hosts: (qs = "") => get(`/hosts/${qs}`),
  findings: (qs = "") => get(`/findings/${qs}`),
  hostRuns: (id) => get(`/hosts/${id}/runs/`),
  iocSearch: (q) => get(`/ioc-search/?q=${encodeURIComponent(q)}`),
  reanalyze: (captureId) => post(`/captures/${captureId}/reanalyze/`),
  purgeCapture: (captureId, reason) => post(`/captures/${captureId}/purge/`, { reason }),
  addNote: (body) => post("/notes/", body),
  retractNote: (id, reason) => post(`/notes/${id}/retract/`, { reason }),
  // The full incident record: notes, verdict changes, RE determinations, evidence purges.
  investigationRecord: (id, type = "") =>
    get(`/investigations/${id}/record/${type ? `?type=${type}` : ""}`),
  requestRescan: (body) => post("/rescans/", body),
  audit: (qs = "") => get(`/audit/${qs}`),
  // The export carries the hash-chain verification with the entries.
  auditExportUrl: (fmt = "csv", params = {}) => {
    const qs = new URLSearchParams({ fmt });
    for (const [k, v] of Object.entries(params)) if (v) qs.set(k, v);
    return `/api/audit/export/?${qs}`;
  },
  deleteInvestigation: (id) => del(`/investigations/${id}/`),
  bulkVerdict: (ids, verdict, reason) =>
    post("/findings/bulk-verdict/", { ids, verdict, reason }),
  exportUrl: (fmt, params = {}) => {
    const qs = new URLSearchParams({ fmt });
    for (const [k, v] of Object.entries(params)) if (v) qs.set(k, v);
    return `/api/findings/export/?${qs}`;
  },
  analysisDiff: (captureId, qs = "") => get(`/captures/${captureId}/diff/${qs}`),
  regions: (qs = "") => get(`/regions/${qs}`),
  regionQueue: () => get("/regions/queue/"),
  analyzeRegion: (id, body) => post(`/regions/${id}/analyze/`, body),
  claimRegion: (id) => post(`/regions/${id}/claim/`),
  purgeRegion: (id, body) => post(`/regions/${id}/purge/`, body),
  platformMetrics: () => get("/admin/metrics/"),
  componentHealth: () => get("/admin/component-health/"),
  symbolRequests: () => get("/admin/symbols/"),
  symbolRequisitesUrl: () => "/api/admin/symbols/requisites/",
  taskStatus: () => get("/tasks/"),
  listUsers: () => get("/users/"),
  createUser: (body) => post("/users/", body),

  // Derived correlation store — the multi-host picture, computed from collected evidence.
  correlation: (investigationId) => get(`/correlation/investigations/${investigationId}/`),
  campaignGraph: (id) => get(`/correlation/campaigns/${id}/graph/`),
  campaignTimeline: (id) => get(`/correlation/campaigns/${id}/timeline/`),
  sharedIndicators: () => get("/correlation/indicators/"),
  recorrelate: (investigationId) =>
    post("/correlation/recompute/", investigationId ? { investigation_id: investigationId } : {}),
};
