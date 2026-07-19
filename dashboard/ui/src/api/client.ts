import { useAuthStore } from "@/stores/authStore";

export async function apiFetch<T>(
  url: string,
  options: RequestInit = {},
): Promise<T> {
  const token = useAuthStore.getState().token;
  const headers = new Headers(options.headers);

  if (token && url.startsWith("/api") && !url.startsWith("/api/auth-config")) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  if (
    options.body &&
    typeof options.body === "string" &&
    !headers.has("Content-Type")
  ) {
    headers.set("Content-Type", "application/json");
  }

  const res = await fetch(url, { ...options, headers, credentials: "include" });

  if (res.status === 401 || res.status === 403) {
    const { logout } = useAuthStore.getState();
    logout();
    throw new Error("Unauthorized");
  }

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`API error ${res.status}: ${formatApiErrorBody(text)}`);
  }

  const contentType = res.headers.get("Content-Type") || "";
  if (contentType.includes("application/json")) {
    return res.json() as Promise<T>;
  }

  return res.text() as unknown as T;
}

/**
 * API errors arrive as JSON like { error, detail, hint, ... }. Flatten the
 * human-readable fields into one line instead of showing the raw JSON blob.
 */
function formatApiErrorBody(text: string): string {
  try {
    const body = JSON.parse(text) as Record<string, unknown>;
    const parts = ["error", "detail", "hint"]
      .map((k) => body[k])
      .filter((v): v is string => typeof v === "string" && v.length > 0);
    if (parts.length > 0) return parts.join(" — ");
  } catch {
    // not JSON; fall through to the raw text
  }
  return text;
}

export function apiStream(
  url: string,
  options: RequestInit = {},
): Promise<Response> {
  const token = useAuthStore.getState().token;
  const headers = new Headers(options.headers);

  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  if (
    options.body &&
    typeof options.body === "string" &&
    !headers.has("Content-Type")
  ) {
    headers.set("Content-Type", "application/json");
  }

  return fetch(url, { ...options, headers, credentials: "include" });
}
