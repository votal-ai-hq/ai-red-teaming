/**
 * OIDC JWT validation.
 * Validates tokens from external identity providers (Okta, Azure AD, Auth0).
 * The server validates but never issues tokens.
 */

import * as jose from "jose";
import { query } from "./db.js";
import type { Role } from "./rbac.js";

export interface AuthContext {
  sub: string;
  email?: string;
  tenantId: string;
  role: Role;
  userId: string;
  /** Account created through open email sign-up (lib/auth-signup.ts). */
  selfSignup?: boolean;
}

// Cached JWKS per issuer URL
const jwksCache = new Map<string, ReturnType<typeof jose.createRemoteJWKSet>>();

function getJwks(issuer: string): ReturnType<typeof jose.createRemoteJWKSet> {
  if (!jwksCache.has(issuer)) {
    const jwksUrl = new URL("/.well-known/jwks.json", issuer);
    jwksCache.set(issuer, jose.createRemoteJWKSet(jwksUrl));
  }
  return jwksCache.get(issuer)!;
}

/**
 * Validate an Authorization header and return the auth context.
 * Throws if the token is invalid, expired, or from an unknown tenant.
 */
export async function validateToken(
  authHeader: string | undefined,
): Promise<AuthContext> {
  if (!authHeader?.startsWith("Bearer ")) {
    throw new Error("Missing or invalid Authorization header");
  }

  const token = authHeader.slice(7);

  // Decode without verification to get issuer
  const decoded = jose.decodeJwt(token);
  const issuer = decoded.iss;
  if (!issuer) {
    throw new Error("JWT missing iss claim");
  }

  // Look up tenant by OIDC issuer
  const tenantResult = await query<{
    id: string;
    oidc_issuer: string;
  }>("SELECT id, oidc_issuer FROM tenants WHERE oidc_issuer = $1", [issuer]);

  if (tenantResult.rows.length === 0) {
    throw new Error(`Unknown OIDC issuer: ${issuer}`);
  }

  const tenant = tenantResult.rows[0];

  // Verify JWT signature using issuer's JWKS
  const jwks = getJwks(issuer);
  const { payload } = await jose.jwtVerify(token, jwks, {
    issuer,
    algorithms: ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
  });

  const sub = payload.sub;
  if (!sub) {
    throw new Error("JWT missing sub claim");
  }

  const email = typeof payload.email === "string" ? payload.email : undefined;

  // Extract role from JWT claim or default to viewer
  let role: Role = "viewer";
  const roleClaim = payload.red_team_role ?? payload.role;
  if (
    typeof roleClaim === "string" &&
    (roleClaim === "admin" || roleClaim === "viewer" || roleClaim === "auditor")
  ) {
    role = roleClaim;
  }

  // Upsert user
  const userResult = await query<{ id: string; role: string }>(
    `INSERT INTO users (tenant_id, sub, email, role)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (tenant_id, sub) DO UPDATE SET email = EXCLUDED.email
     RETURNING id, role`,
    [tenant.id, sub, email, role],
  );

  const user = userResult.rows[0];

  // If user already exists in DB, use their stored role (admin may have set it)
  // Only use JWT claim for initial creation
  const effectiveRole = (
    user.role === "admin" || user.role === "viewer" || user.role === "auditor"
      ? user.role
      : role
  ) as Role;

  return {
    sub,
    email,
    tenantId: tenant.id,
    role: effectiveRole,
    userId: user.id,
  };
}
