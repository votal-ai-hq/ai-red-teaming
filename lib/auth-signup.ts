/**
 * Self-service sign-up for simple auth: any email address, corporate or personal.
 *
 * Flow:
 *  1. requestEmailLink(email, "signup") emails a one-time link to
 *     {APP_BASE_URL}/#/set-password?token=...
 *  2. setPasswordWithLink(token, password) proves the user owns the address,
 *     creates the account (its own tenant, as admin) or updates its password.
 *  3. Afterwards the user signs in through /api/auth/login with email + password.
 *
 * The password is chosen only after the email is proven, so nobody can
 * pre-register someone else's address with a password they know. Sign-up
 * behaves the same whether or not the account exists, so it can't be used to
 * probe for accounts.
 */

import { createHash, randomBytes, randomUUID } from "node:crypto";
import bcrypt from "bcryptjs";
import { getPool, isDbConfigured, queryWithRetry } from "./db.js";
import { generateTenantKey } from "./encryption.js";
import { sendEmail } from "./mailer.js";

export const LINK_TTL_MS = 24 * 60 * 60 * 1000;
export const LINK_COOLDOWN_SECONDS = 60;
export const MIN_PASSWORD_LENGTH = 8;
/** bcrypt ignores everything past 72 bytes, so longer passwords are rejected rather than silently truncated. */
export const MAX_PASSWORD_BYTES = 72;
const BCRYPT_ROUNDS = 12;

const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

export interface Account {
  id: string;
  email: string;
  name: string | null;
  tenantId: string;
  userId: string;
  /** ms since epoch; sessions carry this and are rejected once it changes. */
  passwordChangedAt: number;
}

interface AccountRow {
  id: string;
  email: string;
  name: string | null;
  password_hash: string | null;
  tenant_id: string;
  user_id: string;
  password_changed_at: Date;
}

/** Sign-up needs simple auth, Postgres (per-account tenants) and a base URL for links. */
export function isSignupEnabled(): boolean {
  return (
    process.env.AUTH_MODE === "simple" &&
    isDbConfigured() &&
    process.env.SIGNUP_ENABLED === "true" &&
    !!process.env.APP_BASE_URL
  );
}

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

export function isValidEmail(email: string): boolean {
  return email.length <= 254 && EMAIL_RE.test(email);
}

/** Returns a user-facing problem with the password, or null if it's acceptable. */
export function passwordProblem(password: string): string | null {
  if (password.length < MIN_PASSWORD_LENGTH) {
    return `Password must be at least ${MIN_PASSWORD_LENGTH} characters`;
  }
  if (Buffer.byteLength(password, "utf8") > MAX_PASSWORD_BYTES) {
    return `Password must be at most ${MAX_PASSWORD_BYTES} bytes`;
  }
  return null;
}

export function hashLinkToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

function toAccount(row: AccountRow): Account {
  return {
    id: row.id,
    email: row.email,
    name: row.name,
    tenantId: row.tenant_id,
    userId: row.user_id,
    passwordChangedAt: new Date(row.password_changed_at).getTime(),
  };
}

let dummyHash: string | null = null;
/** A real hash with the same cost, so failed logins take as long as real ones. */
function getDummyHash(): string {
  dummyHash ??= bcrypt.hashSync("not-a-real-password", BCRYPT_ROUNDS);
  return dummyHash;
}

function buildLink(token: string): string {
  const base = (process.env.APP_BASE_URL || "").replace(/\/+$/, "");
  // Hash route: the token stays in the fragment, so it never reaches server logs or Referer headers.
  return `${base}/#/set-password?token=${encodeURIComponent(token)}`;
}

/**
 * Email a one-time set-password link.
 * "signup": always sends (to existing accounts too, as a "set a new password" email).
 * "reset": only sends if the account exists.
 * At most one email per address per LINK_COOLDOWN_SECONDS.
 */
export async function requestEmailLink(
  rawEmail: string,
  mode: "signup" | "reset",
  name?: string,
): Promise<void> {
  const email = normalizeEmail(rawEmail);
  const existing = await queryWithRetry(
    "SELECT 1 FROM accounts WHERE email = $1",
    [email],
  );
  const exists = existing.rows.length > 0;
  if (mode === "reset" && !exists) return;

  const recent = await queryWithRetry(
    `SELECT 1 FROM email_links
     WHERE email = $1 AND created_at > now() - make_interval(secs => $2)`,
    [email, LINK_COOLDOWN_SECONDS],
  );
  if (recent.rows.length > 0) return;

  const token = randomBytes(32).toString("base64url");
  await queryWithRetry(
    `INSERT INTO email_links (token_hash, email, name, expires_at)
     VALUES ($1, $2, $3, $4)`,
    [
      hashLinkToken(token),
      email,
      name?.trim().slice(0, 200) || null,
      new Date(Date.now() + LINK_TTL_MS),
    ],
  );

  const link = buildLink(token);
  const [subject, intro] = exists
    ? [
        "Set your Red-Team AI password",
        "Someone asked to set a new password for your Red-Team AI account.",
      ]
    : [
        "Finish creating your Red-Team AI account",
        "Thanks for signing up for Red-Team AI.",
      ];
  // Not awaited: the response shouldn't wait on (or reveal) email delivery.
  void sendEmail(
    email,
    subject,
    `${intro}\n\nChoose your password here (the link works once and expires in 24 hours):\n${link}\n\nIf this wasn't you, you can ignore this email.`,
  );
}

/**
 * Use a link token to set the account's password, creating the account (and its
 * tenant) on first use. Returns null if the link is unknown, used or expired.
 */
export async function setPasswordWithLink(
  token: string,
  password: string,
): Promise<Account | null> {
  const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  const client = await getPool().connect();
  try {
    await client.query("BEGIN");
    const link = await client.query<{ email: string; name: string | null }>(
      `DELETE FROM email_links
       WHERE token_hash = $1 AND expires_at > now()
       RETURNING email, name`,
      [hashLinkToken(token)],
    );
    if (link.rows.length === 0) {
      await client.query("ROLLBACK");
      return null;
    }
    const { email, name } = link.rows[0];
    // Serialize concurrent links for the same address so only one account is created.
    await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", [email]);

    const existing = await client.query<AccountRow>(
      "SELECT * FROM accounts WHERE email = $1",
      [email],
    );
    let row: AccountRow;
    if (existing.rows.length > 0) {
      const updated = await client.query<AccountRow>(
        `UPDATE accounts
         SET password_hash = $1, password_changed_at = now(), last_login_at = now()
         WHERE id = $2 RETURNING *`,
        [passwordHash, existing.rows[0].id],
      );
      row = updated.rows[0];
    } else {
      const accountId = randomUUID();
      const tenant = await client.query<{ id: string }>(
        `INSERT INTO tenants (name, oidc_issuer, encryption_key_enc)
         VALUES ($1, 'self-signup', $2) RETURNING id`,
        [`signup:${accountId}`, generateTenantKey()],
      );
      const user = await client.query<{ id: string }>(
        `INSERT INTO users (tenant_id, sub, email, role)
         VALUES ($1, $2, $3, 'admin') RETURNING id`,
        [tenant.rows[0].id, `account:${accountId}`, email],
      );
      const created = await client.query<AccountRow>(
        `INSERT INTO accounts (id, email, name, password_hash, tenant_id, user_id, last_login_at)
         VALUES ($1, $2, $3, $4, $5, $6, now()) RETURNING *`,
        [accountId, email, name, passwordHash, tenant.rows[0].id, user.rows[0].id],
      );
      row = created.rows[0];
    }
    // Any other outstanding links for this address are void now.
    await client.query("DELETE FROM email_links WHERE email = $1", [email]);
    await client.query("COMMIT");
    return toAccount(row);
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

/** Check an email + password. Returns null on any mismatch, in constant-ish time. */
export async function verifyAccountLogin(
  rawEmail: string,
  password: string,
): Promise<Account | null> {
  const result = await queryWithRetry<AccountRow>(
    "SELECT * FROM accounts WHERE email = $1",
    [normalizeEmail(rawEmail)],
  );
  const row = result.rows[0];
  if (!row?.password_hash) {
    await bcrypt.compare(password, getDummyHash());
    return null;
  }
  if (!(await bcrypt.compare(password, row.password_hash))) return null;

  await queryWithRetry("UPDATE accounts SET last_login_at = now() WHERE id = $1", [
    row.id,
  ]);
  return toAccount(row);
}

export async function getAccountById(id: string): Promise<Account | null> {
  const result = await queryWithRetry<AccountRow>(
    "SELECT * FROM accounts WHERE id = $1",
    [id],
  );
  return result.rows[0] ? toAccount(result.rows[0]) : null;
}
