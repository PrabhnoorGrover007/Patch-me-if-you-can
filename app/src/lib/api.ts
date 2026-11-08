/**
 * Small fetch wrapper shared by server components, server actions and the few
 * client views that page through the large 72,670-row dataset.
 *
 * On the server we call FastAPI directly. In the browser we use the relative
 * `/api` path, which next.config.ts rewrites to the same FastAPI service.
 */
const SERVER_BASE = process.env.API_BASE || "http://127.0.0.1:8000";

export async function apiFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const base = typeof window === "undefined" ? SERVER_BASE : "";
  const headers = new Headers(init.headers);
  if (init.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const response = await fetch(`${base}${path}`, {
    cache: "no-store",
    ...init,
    headers,
  });

  if (!response.ok) {
    const detail = (await response.text()).slice(0, 300);
    throw new Error(`API ${response.status} for ${path}: ${detail || response.statusText}`);
  }
  return (await response.json()) as T;
}
