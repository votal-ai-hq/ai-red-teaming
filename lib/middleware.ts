/**
 * HTTP request middleware pipeline.
 * Handles CORS, authentication, RBAC, and tenant scoping.
 * When DATABASE_URL is not set, passes ctx=null for backward compatibility.
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import { validateToken, type AuthContext } from "./auth.js";
import {
  assertDevAuthModeAllowed,
  resolveDevApiKey,
  validateDevToken,
} from "./auth-dev.js";
import { validateApiKey } from "./auth-apikey.js";
import { validateSimpleSession } from "./auth-simple.js";
import { checkPermission } from "./rbac.js";
import { isDbConfigured } from "./db.js";
import { resolveAuthMode, shouldBypassDashboardAuth } from "./auth-mode.js";
import type { Role } from "./rbac.js";

export interface RequestContext {
  tenantId: string;
  userId: string;
  role: Role;
  ip: string;
}

type Handler = (
  req: IncomingMessage,
  res: ServerResponse,
  ctx: RequestContext | null,
) => Promise<void>;

/**
 * Wrap the server handler with authentication and authorization.
 * When DATABASE_URL is not set, all requests pass through with ctx=null.
 */
export function withMiddleware(
  handler: Handler,
): (req: IncomingMessage, res: ServerResponse) => void {
  return (req, res) => {
    void handleRequest(req, res, handler);
  };
}

async function handleRequest(
  req: IncomingMessage,
  res: ServerResponse,
  handler: Handler,
): Promise<void> {
  try {
    // Block dangerous HTTP methods (TRACE, PUT, DELETE, PATCH, CONNECT)
    const allowedMethods = new Set(["GET", "POST", "OPTIONS", "HEAD", "DELETE"]);
    if (!allowedMethods.has(req.method || "")) {
      res.writeHead(405, {
        "Content-Type": "text/plain",
        Allow: "GET, POST, OPTIONS, HEAD",
      });
      res.end("Method Not Allowed");
      return;
    }

    // ── CORS (origin allowlist) ──
    const allowedOrigins = (process.env.CORS_ALLOWED_ORIGINS || "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    const origin = req.headers.origin;
    if (origin && allowedOrigins.length > 0) {
      // Only allow explicitly configured origins
      if (allowedOrigins.includes(origin)) {
        res.setHeader("Access-Control-Allow-Origin", origin);
        res.setHeader("Vary", "Origin");
      }
    } else if (origin && !process.env.CORS_ALLOWED_ORIGINS && !isDbConfigured()) {
      // Local dev only: allow localhost when no DB configured
      if (/^https?:\/\/localhost(:\d+)?$/.test(origin)) {
        res.setHeader("Access-Control-Allow-Origin", origin);
        res.setHeader("Vary", "Origin");
      }
    }
    // ── Security headers ──
    res.setHeader(
      "Strict-Transport-Security",
      "max-age=31536000; includeSubDomains; preload",
    );
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("X-XSS-Protection", "1; mode=block");
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    res.setHeader(
      "Permissions-Policy",
      "camera=(), microphone=(), geolocation=(), payment=()",
    );
    res.setHeader(
      "Content-Security-Policy",
      "default-src 'self'; script-src 'self' 'unsafe-inline' https://js.hcaptcha.com https://newassets.hcaptcha.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self' https://api.hcaptcha.com; frame-src https://newassets.hcaptcha.com; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
    );
    // Prevent caching of API responses (sensitive data)
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
    res.setHeader("Pragma", "no-cache");
    // Remove server fingerprinting
    res.removeHeader("X-Powered-By");

    if (req.method === "OPTIONS") {
      res.setHeader("Access-Control-Allow-Methods", "GET, POST, HEAD, DELETE");
      res.setHeader(
        "Access-Control-Allow-Headers",
        "Content-Type, Authorization",
      );
      res.writeHead(204);
      res.end();
      return;
    }

    const url = new URL(req.url ?? "/", `http://localhost`);

    // Static files and public API endpoints — no auth needed
    if (
      !url.pathname.startsWith("/api/") ||
      url.pathname === "/api/auth-config" ||
      url.pathname === "/api/reference" ||
      url.pathname === "/api/auth/login" ||
      url.pathname === "/api/auth/logout" ||
      url.pathname === "/api/auth/me"
    ) {
      return handler(req, res, null);
    }

    const authMode = resolveAuthMode();

    // Unauthenticated access is opt-in (AUTH_MODE=none) and never allowed
    // when NODE_ENV=production. Missing DATABASE_URL used to skip auth.
    if (shouldBypassDashboardAuth()) {
      return handler(req, res, null);
    }

    // Validate token — try multiple auth methods
    let authCtx: AuthContext;
    try {
      if (authMode === "dev") {
        assertDevAuthModeAllowed();
        const presented = req.headers.authorization;
        if (typeof presented === "string" && presented.trim()) {
          authCtx = await validateDevToken(presented);
        } else {
          // Dashboard "no login" UX: synthesize the configured key only after
          // production is rejected and DEV_API_KEY is a real secret.
          authCtx = await validateDevToken(`Bearer ${resolveDevApiKey()}`);
        }
      } else if (authMode === "simple") {
        authCtx = await validateSimpleSession(req.headers.cookie);
      } else if (req.headers["x-api-key"]) {
        // API key auth — for CI/CD, scripts, and programmatic access
        authCtx = await validateApiKey(req.headers["x-api-key"] as string);
      } else {
        // OIDC JWT auth — for browser/Clerk
        authCtx = await validateToken(req.headers.authorization);
      }
    } catch (err) {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          error: "Unauthorized",
          detail: err instanceof Error ? err.message : String(err),
        }),
      );
      return;
    }

    // RBAC check
    if (!checkPermission(req.method!, url.pathname, authCtx.role)) {
      res.writeHead(403, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Forbidden" }));
      return;
    }

    // Build context
    const ctx: RequestContext = {
      tenantId: authCtx.tenantId,
      userId: authCtx.userId,
      role: authCtx.role,
      ip: req.socket.remoteAddress ?? "",
    };

    return handler(req, res, ctx);
  } catch (err) {
    console.error("Middleware error:", err);
    if (!res.headersSent) {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Internal server error" }));
    }
  }
}
