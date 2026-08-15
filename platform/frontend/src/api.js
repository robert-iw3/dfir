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

// One sign-in redirect per page load, however many calls get 401 at once. The app shell fires
// several API calls in parallel on load.
let signingIn = false;

function toSignIn() {
  if (signingIn) return;
  signingIn = true;
  const rd = window.location.pathname + window.location.search;
  window.location.assign(`/oauth2/start?rd=${encodeURIComponent(rd)}`);
}

// The STATUS travels with the error. Without it every failure looks alike, and a gate
// answering 502 because the backend is restarting is indistinguishable from a session that
// expired — which is how a kiosk ends up showing a password form nobody there can use.
function apiError(status, message) {
  const e = new Error(message);
  e.status = status;
  return e;
}

async function req(method, path, body) {
  let r;
  try {
    r = await fetch(`${BASE}${path}`, {
      method,
      headers: headers(),
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch (netErr) {
    // DNS gone, tunnel down, connection refused: unreachable, not unauthorized.
    throw apiError(0, `platform unreachable: ${netErr.message || netErr}`);
  }
  if (r.status === 401) {
    // A token-authenticated caller (the UAT harness, a script) gets the error and decides for
    // itself; only a browser session is sent to sign in, because only it can complete one.
    if (!getToken()) toSignIn();
    throw apiError(401, "unauthorized");
  }
  if (!r.ok) throw apiError(r.status, `${r.status} ${r.statusText}`);
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
  // Records the sign-out before the gate clears the cookie; the browser still goes to the
  // gate afterwards to end the cookie and the Keycloak session.
  logout: () => post("/auth/logout/", {}),
  ssoSessions: (limit = 100) => get(`/auth/sessions/?limit=${limit}`),
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
  hostOverview: (id) => get(`/hosts/${id}/overview/`),
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
  campaignTradecraft: (id) => get(`/correlation/campaigns/${id}/tradecraft/`),
  correlationLinks: (runId) => get(`/correlation/runs/${runId}/links/`),
  sharedIndicators: () => get("/correlation/indicators/"),
  correlationHistory: (invId) => get(`/correlation/investigations/${invId}/history/`),
  recorrelate: (investigationId) =>
    post("/correlation/recompute/", investigationId ? { investigation_id: investigationId } : {}),

  // Server-side aggregates. A chart that sums a page of rows draws that page, not the case.
  investigationStats: (id) => get(`/investigations/${id}/stats/`),
  investigationCoverage: (id) => get(`/investigations/${id}/coverage/`),
  stalledInvestigations: (days) => get(`/investigations/stalled/?days=${days ?? 30}`),
  archiveDue: () => get("/investigations/archive-due/"),
  caseTree: (id) => get(`/investigations/${id}/tree/`),
  caseTags: (id) => get(`/investigations/${id}/tags/`),
  applyCaseTag: (id, tag, remove = false) =>
    post(`/investigations/${id}/tags/`, { tag, remove }),
  tagVocabulary: () => get("/tags/"),
  createTag: (body) => post("/tags/", body),
  caseTasks: (id) => get(`/investigations/${id}/tasks/`),
  saveCaseTask: (id, body) => post(`/investigations/${id}/tasks/`, body),
  reportTemplates: () => get("/report-templates/"),
  caseReports: (id) => get(`/investigations/${id}/reports/`),
  generateReport: (id, body) => post(`/investigations/${id}/reports/`, body),
  // Reading a report in place is an analyst right; the download below is export.
  reportMarkdown: async (id) => (await get(`/reports/${id}/`)).text,
  reportDownloadUrl: (id) => `/api/reports/${id}/download/`,
  // Fetched as a blob rather than followed as a link: a top-level navigation to the API
  // is what the kiosk's policy blocks, and it turns a refused export into a browser error
  // page instead of a message the analyst can act on.
  downloadBlob: async (url, filename) => {
    const r = await fetch(url, {
      headers: getToken() ? { Authorization: `Token ${getToken()}` } : {},
    });
    if (!r.ok) {
      const detail = r.status === 403
        ? "export requires the export right; reading a report does not imply it"
        : `${r.status} ${r.statusText}`;
      throw new Error(detail);
    }
    const blob = await r.blob();
    const href = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = href;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(href);
  },
  task: (taskId) => get(`/tasks/${taskId}/`),
  addTaskNote: (taskId, body) => post(`/tasks/${taskId}/notes/`, { body }),
  attachEvidence: (taskId, body) => post(`/tasks/${taskId}/attachments/`, body),
  // Multipart, so it bypasses the JSON wrapper: the browser sets the boundary itself
  // and a Content-Type we chose would truncate the body at the first part.
  uploadTaskDocument: async (taskId, file, label) => {
    const form = new FormData();
    form.append("file", file);
    if (label) form.append("label", label);
    const r = await fetch(`/api/tasks/${taskId}/attachments/`, {
      method: "POST",
      headers: getToken() ? { Authorization: `Token ${getToken()}` } : {},
      body: form,
    });
    if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
    return r.json();
  },
  detachTaskAttachment: (taskId, id) => del(`/tasks/${taskId}/attachments/?id=${id}`),
  taskAttachmentUrl: (taskId, id) => `/api/tasks/${taskId}/attachments/${id}/`,
  taskBoard: (assignee) =>
    get(`/tasks/board/${assignee ? `?assignee=${encodeURIComponent(assignee)}` : ""}`),
  restoreInvestigation: (id) => post(`/investigations/${id}/restore/`),
  transitionInvestigation: (id, status) =>
    post(`/investigations/${id}/transition/`, { status }),
  runTimeline: (id) => get(`/runs/${id}/timeline/`),
  runCustody: (id) => get(`/runs/${id}/custody/`),
  iocSpread: (type, value) =>
    get(`/iocs/${encodeURIComponent(type)}/${encodeURIComponent(value)}/spread/`),
  queueDepth: () => get("/admin/queue-depth/"),
  storageAllocation: () => get("/admin/storage-allocation/"),
  investigationsActivity: (days = 30) => get(`/investigations/activity/?days=${days}`),
  findingsFunnel: (invId) => get(`/findings/funnel/${invId ? `?investigation=${invId}` : ""}`),
  findingsBacklog: (days = 30) => get(`/findings/backlog/?days=${days}`),
  findingsMatrix: (invId) => get(`/findings/matrix/${invId ? `?investigation=${invId}` : ""}`),

  // Operational telemetry. `reportClientError` deliberately uses fetch directly and swallows
  // everything: it runs from an error boundary, and a reporter that can throw would replace
  // one broken view with two.
  reportClientError: (body) => {
    try {
      return fetch(`${BASE}/opslog/client-errors/`, {
        method: "POST",
        headers: headers(),
        body: JSON.stringify(body || {}),
      }).catch(() => {});
    } catch {
      return Promise.resolve();
    }
  },
  // Working alongside other people. Every one of these is advisory: nothing here can stop
  // a write, so a failed call degrades to working alone rather than to being blocked.
  deleteUser: (username) => del(`/users/?username=${encodeURIComponent(username)}`),
  heartbeat: (investigation, location) =>
    post("/presence/", { investigation: investigation || null, location: location || "" }),
  presence: (investigation) =>
    get(`/presence/${investigation ? `?investigation=${investigation}` : ""}`),
  claimLock: (investigation, refType, refId) =>
    post("/locks/", { investigation, ref_type: refType, ref_id: refId }),
  releaseLock: (refType, refId) =>
    del(`/locks/?ref_type=${encodeURIComponent(refType)}&ref_id=${refId}`),
  locks: (investigation) =>
    get(`/locks/${investigation ? `?investigation=${investigation}` : ""}`),
  notifications: (unreadOnly) => get(`/notifications/${unreadOnly ? "?unread=1" : ""}`),
  markNotificationsRead: (ids) => post("/notifications/", { ids: ids || [] }),
  hereNow: () => get("/me/here/"),
  caseActivity: (id, limit) => get(`/investigations/${id}/activity/?limit=${limit ?? 100}`),
  search: (q) => get(`/search/?q=${encodeURIComponent(q)}`),
  handover: (since) =>
    get(`/handover/${since ? `?since=${encodeURIComponent(since)}` : ""}`),

  requestLog: (params) =>
    get(`/opslog/requests/?${new URLSearchParams(params || {}).toString()}`),
  clientErrors: (limit) => get(`/opslog/client-errors/list/?limit=${limit ?? 50}`),
  logSources: () => get("/opslog/logs/sources/"),
  logObjects: (source) => get(`/opslog/logs/objects/?source=${encodeURIComponent(source)}`),
  logObject: (key) => get(`/opslog/logs/objects/?key=${encodeURIComponent(key)}`),
  logDownloadUrl: (key) => `/api/opslog/logs/download/?key=${encodeURIComponent(key)}`,
};
