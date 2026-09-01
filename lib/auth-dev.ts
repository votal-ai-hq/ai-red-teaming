/**
 * Development-mode authentication.
 * Uses a simple API key (DEV_API_KEY env var) instead of OIDC JWT.
 * Auto-creates a default tenant and admin user on first use.
 *
 * AUTH_MODE=dev is forbidden when NODE_ENV=production.
 * DEV_API_KEY must be set to a unique value (not the historical default "dev-key").
 */

import { timingSafeEqual } from "node:crypto";
import { query } from "./db.js";
import { generateTenantKey } from "./encryption.js";
import type { AuthContext } from "./auth.js";
import type { Role } from "./rbac.js";

let devTenantId: string | null = null;
let devUserId: string | null = null;

export function assertDevAuthModeAllowed(): void {
  const env = (process.env.NODE_ENV || "").trim().toLowerCase();
  if (env === "production") {
    throw new Error(
      "AUTH_MODE=dev is forbidden when NODE_ENV=production. Use OIDC or AUTH_MODE=simple.",
    );
  }
}

export function resolveDevApiKey(): string {
  const key = process.env.DEV_API_KEY?.trim() || "";
  if (!key || key === "dev-key") {
    throw new Error(
      "DEV_API_KEY must be set to a unique value (at least 16 characters, not 'dev-key') when AUTH_MODE=dev",
    );
  }
  if (key.length < 16) {
    throw new Error("DEV_API_KEY must be at least 16 characters");
  }
  return key;
}

function safeEqual(a: string, b: string): boolean {
  const aBuf = Buffer.from(a);
  const bBuf = Buffer.from(b);
  if (aBuf.length !== bBuf.length) return false;
  return timingSafeEqual(aBuf, bBuf);
}

/**
 * Validate a dev API key from the Authorization header.
 * Format: "Bearer <DEV_API_KEY>" or "ApiKey <DEV_API_KEY>"
 */
export async function validateDevToken(
  authHeader: string | undefined,
): Promise<AuthContext> {
  assertDevAuthModeAllowed();
  const devKey = resolveDevApiKey();

  if (!authHeader) {
    throw new Error("Missing Authorization header");
  }

  const token = authHeader.replace(/^(Bearer|ApiKey)\s+/i, "").trim();
  if (!token || !safeEqual(token, devKey)) {
    throw new Error("Invalid dev API key");
  }

  if (!devTenantId) {
    const existing = await query<{ id: string }>(
      "SELECT id FROM tenants WHERE name = $1",
      ["default"],
    );

    if (existing.rows.length > 0) {
      devTenantId = existing.rows[0].id;
    } else {
      const encKey = generateTenantKey();
      const result = await query<{ id: string }>(
        `INSERT INTO tenants (name, oidc_issuer, encryption_key_enc)
         VALUES ($1, $2, $3) RETURNING id`,
        ["default", "https://localhost/dev", encKey],
      );
      devTenantId = result.rows[0].id;
      console.log(`  Dev mode: created default tenant ${devTenantId}`);
    }
  }

  if (!devUserId) {
    const existing = await query<{ id: string; role?: string }>(
      "SELECT id FROM users WHERE tenant_id = $1 AND sub = $2",
      [devTenantId, "dev-admin"],
    );

    if (existing.rows.length > 0) {
      devUserId = existing.rows[0].id;
    } else {
      const result = await query<{ id: string }>(
        `INSERT INTO users (tenant_id, sub, email, role)
         VALUES ($1, $2, $3, $4) RETURNING id`,
        [devTenantId, "dev-admin", "admin@localhost", "admin"],
      );
      devUserId = result.rows[0].id;
      console.log(`  Dev mode: created admin user ${devUserId}`);
    }
  }

  return {
    sub: "dev-admin",
    email: "admin@localhost",
    tenantId: devTenantId,
    role: "admin" as Role,
    userId: devUserId,
  };
}
