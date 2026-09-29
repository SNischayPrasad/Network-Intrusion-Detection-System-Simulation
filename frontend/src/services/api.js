// Thin API client. The analyst's API key lives in sessionStorage only
// (cleared when the tab closes) and is sent in the X-API-Key header.

const KEY_STORAGE = "ids_api_key";

export function getApiKey() {
  try {
    return sessionStorage.getItem(KEY_STORAGE);
  } catch {
    return null;
  }
}

export function setApiKey(key) {
  try {
    if (key) sessionStorage.setItem(KEY_STORAGE, key);
    else sessionStorage.removeItem(KEY_STORAGE);
  } catch {
    /* storage unavailable (private mode) — key lives only in memory */
  }
}

export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function describe(detail) {
  if (!detail) return "Request failed";
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) return detail.map((d) => `${(d.loc || []).slice(1).join(".")}: ${d.msg}`).join("; ");
  if (detail.errors) return `${detail.message}: ${detail.errors.join("; ")}`;
  return JSON.stringify(detail);
}

async function request(method, path, body, { raw = false, key } = {}) {
  const resp = await fetch(path, {
    method,
    headers: { "Content-Type": "application/json", "X-API-Key": key || getApiKey() || "" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (resp.status === 401 && !key) {
    setApiKey(null);
    window.dispatchEvent(new Event("ids-logout"));
  }
  if (!resp.ok) {
    let detail;
    try {
      detail = (await resp.json()).detail;
    } catch {
      detail = resp.statusText;
    }
    throw new ApiError(resp.status, describe(detail));
  }
  return raw ? resp.text() : resp.json();
}

function qs(params) {
  const clean = Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== "");
  return clean.length ? "?" + new URLSearchParams(clean).toString() : "";
}

export const api = {
  whoami: (key) => request("GET", "/api/auth/whoami", undefined, { key }),
  stats: (range) => request("GET", `/api/dashboard/stats${qs({ range })}`),
  traffic: (range) => request("GET", `/api/dashboard/traffic${qs({ range })}`),
  alertAnalytics: (range) => request("GET", `/api/dashboard/alerts${qs({ range })}`),
  alerts: (params) => request("GET", `/api/alerts${qs(params)}`),
  alert: (id) => request("GET", `/api/alerts/${encodeURIComponent(id)}`),
  updateStatus: (id, status, note) =>
    request("PUT", `/api/alerts/${encodeURIComponent(id)}/status`, { status, note: note || undefined }),
  addNote: (id, note) => request("POST", `/api/alerts/${encodeURIComponent(id)}/notes`, { note }),
  report: (id) => request("GET", `/api/alerts/${encodeURIComponent(id)}/report`, undefined, { raw: true }),
  incidents: (range) => request("GET", `/api/incidents${qs({ range, limit: 200 })}`),
  incident: (id) => request("GET", `/api/incidents/${encodeURIComponent(id)}`),
  rules: () => request("GET", "/api/rules"),
  updateRule: (id, body) => request("PUT", `/api/rules/${encodeURIComponent(id)}`, body),
};
