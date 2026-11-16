import { apiFetch } from "./client";
import type { AuthConfig, AuthUser } from "./types";

export function getAuthConfig() {
  return apiFetch<AuthConfig>("/api/auth-config");
}

export function login(username: string, password: string, captchaToken?: string) {
  return apiFetch<{ user: AuthUser }>("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password, captchaToken }),
  });
}

export function signup(email: string, name: string, captchaToken?: string) {
  return apiFetch<{ ok: true }>("/api/auth/signup", {
    method: "POST",
    body: JSON.stringify({ email, name: name || undefined, captchaToken }),
  });
}

export function forgotPassword(email: string, captchaToken?: string) {
  return apiFetch<{ ok: true }>("/api/auth/forgot-password", {
    method: "POST",
    body: JSON.stringify({ email, captchaToken }),
  });
}

export function setPassword(token: string, password: string) {
  return apiFetch<{ user: AuthUser }>("/api/auth/set-password", {
    method: "POST",
    body: JSON.stringify({ token, password }),
  });
}

export function logout() {
  return apiFetch<void>("/api/auth/logout", { method: "POST" });
}

export function getMe() {
  return apiFetch<{ user: AuthUser }>("/api/auth/me");
}
