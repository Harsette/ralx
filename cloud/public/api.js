// Talks to the Worker (API-CONTRACT.md). Falls back to the in-memory mock with ?mock=1,
// or on localhost when /api/me can't be reached.

const params = new URLSearchParams(location.search);
const local = ["localhost", "127.0.0.1", "[::1]"].includes(location.hostname);
export let mockMode = params.has("mock");
let mockModule;

export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

async function real(method, path, body) {
  const res = await fetch(path, {
    method,
    credentials: "same-origin",
    headers: body !== undefined || method !== "GET" ? { "content-type": "application/json", accept: "application/json" } : { accept: "application/json" },
    body: body !== undefined ? JSON.stringify(body) : method !== "GET" ? "{}" : undefined,
  });
  let data = null;
  try {
    data = await res.json();
  } catch {}
  return { ok: res.ok, status: res.status, data };
}

export async function api(method, path, body) {
  let r;
  if (mockMode) {
    mockModule ??= await import("./mock.js");
    r = await mockModule.mock(method, path, body);
  } else {
    try {
      r = await real(method, path, body);
    } catch (e) {
      throw new ApiError(0, "offline");
    }
  }
  if (!r.ok) throw new ApiError(r.status, r.data?.error || `HTTP ${r.status}`);
  return r.data;
}

// Raw file upload (password exports). The bytes go straight from this browser to the Worker.
export async function apiBytes(path, bytes) {
  let r;
  if (mockMode) {
    mockModule ??= await import("./mock.js");
    r = await mockModule.mock("POST", path, bytes);
  } else {
    try {
      const res = await fetch(path, { method: "POST", credentials: "same-origin", headers: { "content-type": "application/octet-stream", accept: "application/json" }, body: bytes });
      let data = null;
      try {
        data = await res.json();
      } catch {}
      r = { ok: res.ok, status: res.status, data };
    } catch {
      throw new ApiError(0, "offline");
    }
  }
  if (!r.ok) throw new ApiError(r.status, r.data?.error || `HTTP ${r.status}`);
  return r.data;
}

// First call decides the mode: a dead or missing API on localhost means design work, so use the mock.
export async function me() {
  if (!mockMode && local) {
    try {
      const r = await real("GET", "/api/me");
      if (r.status === 401) return null;
      if (r.ok && r.data?.user) return r.data;
      mockMode = true;
    } catch {
      mockMode = true;
    }
  }
  try {
    return await api("GET", "/api/me");
  } catch (e) {
    if (e.status === 401) return null;
    throw e;
  }
}

export async function enrollSoon() {
  if (mockMode) (mockModule ??= await import("./mock.js")).mockEnrollSoon();
}
