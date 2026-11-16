import { createHmac, timingSafeEqual, randomUUID } from "node:crypto";
import bcrypt from "bcryptjs";
import { queryWithRetry, isDbConfigured } from "./db.js";
import { generateTenantKey } from "./encryption.js";
import type { AuthContext } from "./auth.js";
import {
  getAccountById,
  verifyAccountLogin,
  type Account,
} from "./auth-signup.js";
import type { Role } from "./rbac.js";

interface SimpleAuthUser {
  username: string;
  password: string;
  role: Role;
  email?: string;
  name?: string;
}

interface SessionPayload {
  username: string;
  role: Role;
  sid: string;
  exp: number;
  iat: number;
  nbf: number;
  iss: string;
  aud: string;
  /** Set for self-signup accounts (lib/auth-signup.ts); absent for env-configured users. */
  kind?: "account";
  aid?: string;
  email?: string;
  name?: string;
  /** The account's password_changed_at (ms) when the session was issued. */
  pwv?: number;
}

export interface SimpleAuthUserInfo {
  username: string;
  role: Role;
  email?: string;
  name: string;
}

function getSessionCookieName(): string {
  // Use __Host- prefix when Secure flag is enabled (prevents subdomain attacks)
  return getCookieSecure() ? "__Host-rt_session" : "rt_session";
}

function getSessionSecret(): string {
  const secret =
    process.env.SIMPLE_AUTH_SESSION_SECRET || process.env.SESSION_SECRET;

  if (!secret) {
    if (process.env.AUTH_MODE === "simple") {
      throw new Error(
        "SIMPLE_AUTH_SESSION_SECRET must be set when AUTH_MODE=simple. " +
          'Generate one with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"',
      );
    }
    return "dev-only-simple-auth-secret";
  }

  if (secret.length < 32) {
    throw new Error(
      "SIMPLE_AUTH_SESSION_SECRET must be at least 32 characters. " +
        'Generate one with: node -e "console.log(require(\'crypto\').randomBytes(64).toString(\'hex\'))"',
    );
  }

  return secret;
}

function getSessionTtlSeconds(): number {
  const hours = parseInt(process.env.SIMPLE_AUTH_SESSION_TTL_HOURS || "12", 10);
  return Math.max(1, hours) * 60 * 60;
}

function getCookieSecure(): boolean {
  if (process.env.SIMPLE_AUTH_COOKIE_SECURE === "false") return false;
  return true;
}

function base64UrlEncode(input: string): string {
  return Buffer.from(input, "utf8").toString("base64url");
}

function base64UrlDecode(input: string): string {
  return Buffer.from(input, "base64url").toString("utf8");
}

function signPayload(payload: string): string {
  return createHmac("sha256", getSessionSecret())
    .update(payload)
    .digest("base64url");
}

function safeCompare(a: string, b: string): boolean {
  const aBuf = Buffer.from(a);
  const bBuf = Buffer.from(b);
  if (aBuf.length !== bBuf.length) return false;
  return timingSafeEqual(aBuf, bBuf);
}

function parseSimpleAuthUsers(): SimpleAuthUser[] {
  if (process.env.SIMPLE_AUTH_USERS) {
    const raw = JSON.parse(process.env.SIMPLE_AUTH_USERS) as unknown;
    if (!Array.isArray(raw)) {
      throw new Error("SIMPLE_AUTH_USERS must be a JSON array");
    }
    return raw.map((entry, index) => {
      if (!entry || typeof entry !== "object") {
        throw new Error(`SIMPLE_AUTH_USERS[${index}] must be an object`);
      }
      const user = entry as Record<string, unknown>;
      const username = String(user.username || "").trim();
      const password = String(user.password || "");
      const role = String(user.role || "viewer") as Role;
      if (!username || !password) {
        throw new Error(
          `SIMPLE_AUTH_USERS[${index}] must include username and password`,
        );
      }
      if (!["admin", "viewer", "auditor"].includes(role)) {
        throw new Error(
          `SIMPLE_AUTH_USERS[${index}].role must be admin, viewer, or auditor`,
        );
      }
      return {
        username,
        password,
        role,
        email: typeof user.email === "string" ? user.email : undefined,
        name: typeof user.name === "string" ? user.name : undefined,
      };
    });
  }

  const username = (process.env.SIMPLE_AUTH_USERNAME || "").trim();
  const password = process.env.SIMPLE_AUTH_PASSWORD || "";
  if (!username || !password) {
    throw new Error(
      "Simple auth requires SIMPLE_AUTH_USERS or SIMPLE_AUTH_USERNAME and SIMPLE_AUTH_PASSWORD",
    );
  }

  const role = (process.env.SIMPLE_AUTH_ROLE || "admin") as Role;
  if (!["admin", "viewer", "auditor"].includes(role)) {
    throw new Error("SIMPLE_AUTH_ROLE must be admin, viewer, or auditor");
  }

  return [
    {
      username,
      password,
      role,
      email: process.env.SIMPLE_AUTH_EMAIL || undefined,
      name: process.env.SIMPLE_AUTH_NAME || undefined,
    },
  ];
}

function hasEnvUsers(): boolean {
  return !!(
    process.env.SIMPLE_AUTH_USERS ||
    (process.env.SIMPLE_AUTH_USERNAME && process.env.SIMPLE_AUTH_PASSWORD)
  );
}

function findSimpleAuthUser(username: string): SimpleAuthUser | undefined {
  // With self-signup accounts in the DB, env-configured users are optional.
  if (!hasEnvUsers() && isDbConfigured()) return undefined;
  return parseSimpleAuthUsers().find((user) => user.username === username);
}

function parseCookies(
  cookieHeader: string | undefined,
): Record<string, string> {
  const cookies: Record<string, string> = {};
  if (!cookieHeader) return cookies;
  for (const part of cookieHeader.split(";")) {
    const [rawKey, ...rawValue] = part.trim().split("=");
    if (!rawKey) continue;
    cookies[rawKey] = decodeURIComponent(rawValue.join("="));
  }
  return cookies;
}

async function ensureSimpleAuthContext(
  user: SimpleAuthUser,
): Promise<AuthContext> {
  if (!isDbConfigured()) {
    return {
      sub: `simple:${user.username}`,
      email: user.email,
      tenantId: "local",
      role: user.role,
      userId: user.username,
    };
  }

  const tenantName = process.env.SIMPLE_AUTH_TENANT || "default";
  let tenantId: string;
  const existingTenant = await queryWithRetry<{ id: string }>(
    "SELECT id FROM tenants WHERE name = $1",
    [tenantName],
  );
  if (existingTenant.rows.length > 0) {
    tenantId = existingTenant.rows[0].id;
  } else {
    const encKey = generateTenantKey();
    const createdTenant = await queryWithRetry<{ id: string }>(
      `INSERT INTO tenants (name, oidc_issuer, encryption_key_enc)
       VALUES ($1, $2, $3)
       ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
       RETURNING id`,
      [tenantName, `simple-auth:${tenantName}`, encKey],
    );
    tenantId = createdTenant.rows[0].id;
  }

  const sub = `simple:${user.username}`;
  const email = user.email || `${user.username}@local`;
  const userResult = await queryWithRetry<{ id: string; role: string }>(
    `INSERT INTO users (tenant_id, sub, email, role)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (tenant_id, sub) DO UPDATE
       SET email = EXCLUDED.email,
           role = EXCLUDED.role
     RETURNING id, role`,
    [tenantId, sub, email, user.role],
  );

  return {
    sub,
    email,
    tenantId,
    role: userResult.rows[0].role as Role,
    userId: userResult.rows[0].id,
  };
}

const JWT_HEADER = base64UrlEncode(JSON.stringify({ alg: "HS256", typ: "JWT" }));

function serializeSession(payload: SessionPayload): string {
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const signingInput = `${JWT_HEADER}.${encodedPayload}`;
  const signature = signPayload(signingInput);
  return `${JWT_HEADER}.${encodedPayload}.${signature}`;
}

function deserializeSession(token: string): SessionPayload {
  const parts = token.split(".");
  // Support both legacy 2-part (payload.sig) and standard 3-part JWT (header.payload.sig)
  let encodedPayload: string;
  let signature: string;
  let signingInput: string;
  if (parts.length === 3) {
    // Standard JWT: header.payload.signature
    encodedPayload = parts[1];
    signature = parts[2];
    signingInput = `${parts[0]}.${parts[1]}`;
  } else if (parts.length === 2) {
    // Legacy format: payload.signature (backward compat for active sessions)
    encodedPayload = parts[0];
    signature = parts[1];
    signingInput = parts[0];
  } else {
    throw new Error("Invalid session token");
  }
  if (!encodedPayload || !signature) {
    throw new Error("Invalid session token");
  }
  const expected = signPayload(signingInput);
  if (!safeCompare(signature, expected)) {
    throw new Error("Invalid session signature");
  }
  const payload = JSON.parse(base64UrlDecode(encodedPayload)) as SessionPayload;
  if (
    !payload.username ||
    typeof payload.exp !== "number" ||
    !payload.role ||
    !payload.sid ||
    typeof payload.iat !== "number"
  ) {
    throw new Error("Invalid session payload — please log in again");
  }
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp < now) {
    throw new Error("Session expired");
  }
  // Validate not-before if present (new tokens always have it)
  if (typeof payload.nbf === "number" && payload.nbf > now + 30) {
    throw new Error("Token not yet valid");
  }
  // Validate issuer/audience if present (new tokens always have them)
  if (payload.iss && payload.iss !== "red-team-dashboard") {
    throw new Error("Invalid token issuer");
  }
  if (payload.aud && payload.aud !== "red-team-session") {
    throw new Error("Invalid token audience");
  }
  return payload;
}

export async function loginSimpleUser(
  username: string,
  password: string,
): Promise<{ auth: AuthContext; user: SimpleAuthUserInfo; token: string }> {
  const user = findSimpleAuthUser(username);
  if (!user) {
    if (isDbConfigured()) {
      // Self-signup accounts sign in with their email as the username.
      // verifyAccountLogin runs a full bcrypt compare even when no account matches.
      const account = await verifyAccountLogin(username, password);
      if (account) return issueAccountSession(account);
    } else {
      // Constant-time: always run a bcrypt compare even if user not found
      await bcrypt.compare(password, "$2a$10$invalidhashplaceholderXXXXXXXXXXXXXXXXXXXXXXX");
    }
    throw new Error("Invalid username or password");
  }

  // Support bcrypt hashes ($2a$, $2b$, $2y$) and plaintext (backward compat)
  const isBcrypt = /^\$2[aby]\$\d+\$/.test(user.password);
  const passwordValid = isBcrypt
    ? await bcrypt.compare(password, user.password)
    : user.password === password;
  if (!passwordValid) {
    throw new Error("Invalid username or password");
  }

  const auth = await ensureSimpleAuthContext(user);
  const now = Math.floor(Date.now() / 1000);
  const token = serializeSession({
    username: user.username,
    role: user.role,
    sid: randomUUID(),
    exp: now + getSessionTtlSeconds(),
    iat: now,
    nbf: now,
    iss: "red-team-dashboard",
    aud: "red-team-session",
  });

  return {
    auth,
    token,
    user: {
      username: user.username,
      role: auth.role,
      email: user.email,
      name: user.name || user.username,
    },
  };
}

function accountAuthContext(account: Account): AuthContext {
  return {
    sub: `account:${account.id}`,
    email: account.email,
    tenantId: account.tenantId,
    role: "admin",
    userId: account.userId,
    selfSignup: true,
  };
}

/** Issue a session for a self-signup account (after login or setting a password). */
export function issueAccountSession(account: Account): {
  auth: AuthContext;
  user: SimpleAuthUserInfo;
  token: string;
} {
  const now = Math.floor(Date.now() / 1000);
  const name = account.name || account.email;
  const token = serializeSession({
    username: account.email,
    role: "admin",
    sid: randomUUID(),
    exp: now + getSessionTtlSeconds(),
    iat: now,
    nbf: now,
    iss: "red-team-dashboard",
    aud: "red-team-session",
    kind: "account",
    aid: account.id,
    email: account.email,
    name,
    pwv: account.passwordChangedAt,
  });
  return {
    auth: accountAuthContext(account),
    token,
    user: { username: account.email, role: "admin", email: account.email, name },
  };
}

export async function validateSimpleSession(
  cookieHeader: string | undefined,
): Promise<AuthContext> {
  const cookies = parseCookies(cookieHeader);
  // Check current cookie name, fall back to legacy name for active sessions during migration
  const token = cookies[getSessionCookieName()] || cookies["rt_session"] || cookies["__Host-rt_session"];
  if (!token) {
    throw new Error("Missing session cookie");
  }

  const payload = deserializeSession(token);
  if (payload.kind === "account") {
    if (!payload.aid || !isDbConfigured()) throw new Error("Invalid session");
    const account = await getAccountById(payload.aid);
    if (!account) {
      throw new Error("User no longer exists");
    }
    if (account.passwordChangedAt !== payload.pwv) {
      throw new Error("Password changed — please log in again");
    }
    return accountAuthContext(account);
  }
  const user = findSimpleAuthUser(payload.username);
  if (!user) {
    throw new Error("User no longer exists");
  }
  if (user.role !== payload.role) {
    throw new Error("Session role mismatch — please log in again");
  }

  return ensureSimpleAuthContext(user);
}

/**
 * Resolve the signed-in user for /api/auth/me WITHOUT touching the database.
 *
 * The session token is a self-contained, HMAC-signed JWT: verifying its
 * signature and expiry fully proves the session is valid, and everything
 * /api/auth/me reports (username, role, email, name) comes from the token
 * payload + the env-configured user list. The DB was only ever consulted here to
 * resolve tenant/user rows, which this endpoint does not need.
 *
 * Coupling this hot path to Postgres was the root cause of the "logged out after
 * a refresh" bug: a transient DB hiccup made validateSimpleSession throw, the
 * handler swallowed it into a 401, and the frontend treated that 401 as a real
 * logout. Keeping validation DB-free means a momentary DB blip can never sign a
 * valid user out. (validateSimpleSession is still used by the API middleware,
 * where a real tenantId is genuinely required.)
 */
export async function getSimpleSessionUser(
  cookieHeader: string | undefined,
): Promise<SimpleAuthUserInfo> {
  const cookies = parseCookies(cookieHeader);
  const token =
    cookies[getSessionCookieName()] ||
    cookies["rt_session"] ||
    cookies["__Host-rt_session"];
  if (!token) {
    throw new Error("Missing session cookie");
  }

  const payload = deserializeSession(token); // verifies signature + expiry, no DB
  if (payload.kind === "account") {
    // Everything /me needs is in the signed token. Revocation (deleted account,
    // changed password) is enforced by validateSimpleSession on every API call.
    return {
      username: payload.username,
      role: "admin",
      email: payload.email,
      name: payload.name || payload.username,
    };
  }
  const user = findSimpleAuthUser(payload.username);
  if (!user) {
    throw new Error("User no longer exists");
  }
  if (user.role !== payload.role) {
    throw new Error("Session role mismatch — please log in again");
  }

  return {
    username: user.username,
    role: user.role,
    email: user.email,
    name: user.name || user.username,
  };
}

export function buildSimpleSessionCookie(token: string): string {
  const maxAge = getSessionTtlSeconds();
  const secure = getCookieSecure() ? "; Secure" : "";
  return `${getSessionCookieName()}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure}`;
}

export function buildSimpleLogoutCookie(): string {
  const secure = getCookieSecure() ? "; Secure" : "";
  return `${getSessionCookieName()}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure}`;
}
