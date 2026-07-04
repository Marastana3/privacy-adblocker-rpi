// Thin fetch client for the FastAPI backend.
const BASE = import.meta.env.VITE_API_BASE ?? "";

let apiKey = "";
export function setApiKey(key) {
  apiKey = key || "";
}

function headers() {
  const h = { "Content-Type": "application/json" };
  if (apiKey) h["X-API-Key"] = apiKey;
  return h;
}

async function req(path, opts = {}) {
  const res = await fetch(BASE + path, { ...opts, headers: headers() });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`${res.status} ${res.statusText}${text ? ` - ${text}` : ""}`);
  }
  if (res.status === 204) return null;
  return res.json();
}

export const api = {
  health: () => req("/health"),
  stats: () => req("/stats"),
  topBlocked: (limit = 10) => req(`/stats/top-blocked?limit=${limit}`),
  privacy: () => req("/privacy"),

  categories: () => req("/categories"),
  setCategory: (name, enabled) =>
    req(`/categories/${encodeURIComponent(name)}`, {
      method: "POST",
      body: JSON.stringify({ enabled }),
    }),

  whitelist: () => req("/lists/whitelist"),
  addAllow: (domain) =>
    req("/lists/whitelist", { method: "POST", body: JSON.stringify({ domain }) }),
  removeAllow: (domain) =>
    req(`/lists/whitelist/${encodeURIComponent(domain)}`, { method: "DELETE" }),

  blocklist: () => req("/lists/block"),
  addBlock: (domain, category = "custom") =>
    req("/lists/block", {
      method: "POST",
      body: JSON.stringify({ domain, category }),
    }),
  removeBlock: (domain) =>
    req(`/lists/block/${encodeURIComponent(domain)}`, { method: "DELETE" }),
};
