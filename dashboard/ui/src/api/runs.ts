import { apiFetch } from "./client";
import type { RunMeta, RunDetail } from "./types";

export function getRuns() {
  return apiFetch<RunMeta[]>("/api/runs");
}

export function getRun(id: string, since = 0, includeConfig = false) {
  const params = new URLSearchParams({ since: String(since) });
  if (includeConfig) params.set("includeConfig", "1");
  return apiFetch<RunDetail>(`/api/run/${id}?${params}`);
}

export function renameRun(id: string, name: string) {
  return apiFetch<{ runId: string; name: string | null }>(`/api/run/${id}`, {
    method: "PATCH",
    body: JSON.stringify({ name }),
  });
}

export function createRun(config: Record<string, unknown>) {
  return apiFetch<{ runId: string; status: string; estimatedTotal?: number }>(
    "/api/run",
    { method: "POST", body: JSON.stringify(config) },
  );
}

export function deleteRun(id: string, purge = false) {
  const params = purge ? "?purge=1" : "";
  return apiFetch<void>(`/api/run/${id}${params}`, { method: "DELETE" });
}
