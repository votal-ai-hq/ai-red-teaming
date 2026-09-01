import { isDbConfigured } from "./db.js";

export type AuthMode = "none" | "simple" | "dev" | "oidc";

function nodeEnv(): string {
  return (process.env.NODE_ENV || "").trim().toLowerCase();
}

function rawAuthMode(): string {
  return (process.env.AUTH_MODE || "").trim().toLowerCase();
}

export function isProductionNodeEnv(): boolean {
  return nodeEnv() === "production";
}

/** True when AUTH_MODE=none is set in the environment (not merely the default). */
export function isExplicitAuthNone(): boolean {
  return rawAuthMode() === "none";
}

/**
 * Effective auth mode for the dashboard.
 * Unset AUTH_MODE + Postgres → oidc. Unset AUTH_MODE + no DB → none (local files).
 */
export function resolveAuthMode(): AuthMode {
  const raw = rawAuthMode();
  if (raw === "none" || raw === "simple" || raw === "dev" || raw === "oidc") {
    return raw;
  }
  return isDbConfigured() ? "oidc" : "none";
}

/**
 * Open (unauthenticated) dashboard access.
 * Never in production. Local file-mode only: explicit AUTH_MODE=none, or
 * AUTH_MODE unset with no DATABASE_URL.
 */
export function shouldBypassDashboardAuth(): boolean {
  if (isProductionNodeEnv()) return false;
  if (isExplicitAuthNone()) return true;
  if (!rawAuthMode() && !isDbConfigured()) return true;
  return false;
}

function isLoopbackBind(host: string): boolean {
  return (
    host === "127.0.0.1" ||
    host === "localhost" ||
    host === "::1"
  );
}

/**
 * Unauthenticated dashboards must not listen on all interfaces.
 * AUTH_MODE=simple / oidc / dev keep the previous 0.0.0.0 default (or DASHBOARD_BIND).
 */
export function resolveDashboardBindHost(): string {
  const requested = process.env.DASHBOARD_BIND?.trim();
  if (shouldBypassDashboardAuth()) {
    if (requested && !isLoopbackBind(requested)) {
      throw new Error(
        `AUTH_MODE=none cannot bind to ${requested}. Use 127.0.0.1 or enable AUTH_MODE=simple/oidc.`,
      );
    }
    return "127.0.0.1";
  }
  return requested || "0.0.0.0";
}

export function assertDashboardAuthSafeToServe(): void {
  if (isProductionNodeEnv() && isExplicitAuthNone()) {
    throw new Error(
      "AUTH_MODE=none is forbidden when NODE_ENV=production. Use AUTH_MODE=simple or OIDC.",
    );
  }
  if (isProductionNodeEnv() && shouldBypassDashboardAuth()) {
    throw new Error(
      "Unauthenticated dashboard access is forbidden when NODE_ENV=production.",
    );
  }
  resolveDashboardBindHost();
}
