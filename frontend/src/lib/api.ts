const BASE = "/api/v1";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const resp = await fetch(`${BASE}${path}`, {
    credentials: "include",
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options?.headers,
    },
  });
  if (resp.status === 401) {
    throw new Error("Not authenticated");
  }
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({}));
    throw new Error(body.detail || `HTTP ${resp.status}`);
  }
  return resp.json();
}

export const api = {
  login: (email: string) =>
    request("/auth/login", { method: "POST", body: JSON.stringify({ email }) }),
  verifyOtp: (email: string, code: string) =>
    request("/auth/verify-otp", { method: "POST", body: JSON.stringify({ email, code }) }),
  getMe: () =>
    request("/auth/me"),
  logout: () =>
    request("/auth/logout", { method: "POST" }),
  getOverviewStats: (period = "24h") =>
    request(`/overview/stats?period=${period}`),
  getTimeline: (period = "24h") =>
    request(`/overview/timeline?period=${period}`),
  getAlerts: (params: Record<string, string> = {}) => {
    const qs = new URLSearchParams({ period: "24h", ...params }).toString();
    return request(`/alerts?${qs}`);
  },
  getAlert: (id: string) =>
    request(`/alerts/${id}`),
  getTopRules: (period = "24h") =>
    request(`/overview/top-rules?period=${period}`),
  getCompliance: () =>
    request("/compliance"),
  getDevelopers: (period = "24h") =>
    request(`/developers?period=${period}`),
  getAudit: (params: Record<string, string> = {}) => {
    const qs = new URLSearchParams({ period: "24h", ...params }).toString();
    return request(`/audit?${qs}`);
  },
  getAuditExportUrl: (format: "csv" | "json", period = "24h") =>
    `${BASE}/audit?format=${format}&period=${period}`,
  getRule: (id: string) =>
    request(`/rules/${id}`),
  getRules: (params: Record<string, string> = {}) => {
    const qs = new URLSearchParams(params).toString();
    return request(`/rules${qs ? `?${qs}` : ""}`);
  },
  createRule: (body: Record<string, unknown>) =>
    request("/rules", { method: "POST", body: JSON.stringify(body) }),
  updateRule: (id: string, body: Record<string, unknown>) =>
    request(`/rules/${id}`, { method: "PUT", body: JSON.stringify(body) }),
  deleteRule: (id: string) =>
    request(`/rules/${id}`, { method: "DELETE" }),
  cloneRule: (id: string) =>
    request(`/rules/${id}/clone`, { method: "POST" }),
  getApiKeys: () =>
    request("/auth/api-keys"),
  createApiKey: (label: string) =>
    request("/auth/api-keys", { method: "POST", body: JSON.stringify({ label }) }),
  revokeApiKey: (id: string) =>
    request(`/auth/api-keys/${id}`, { method: "DELETE" }),
  getUsers: () =>
    request("/users"),
  inviteUser: (body: { email: string; name: string; role: string }) =>
    request("/users/invite", { method: "POST", body: JSON.stringify(body) }),
  updateUser: (id: string, body: { role?: string; active?: boolean }) =>
    request(`/users/${id}`, { method: "PUT", body: JSON.stringify(body) }),
  deactivateUser: (id: string) =>
    request(`/users/${id}`, { method: "DELETE" }),
  acceptInvite: (token: string) =>
    request(`/auth/accept-invite?token=${token}`),
};
