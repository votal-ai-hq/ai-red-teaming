import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const sentEmails: { to: string; subject: string; text: string }[] = [];
vi.mock("../lib/mailer.js", () => ({
  sendEmail: vi.fn(async (to: string, subject: string, text: string) => {
    sentEmails.push({ to, subject, text });
  }),
}));

import {
  isSignupEnabled,
  isValidEmail,
  normalizeEmail,
  passwordProblem,
  requestEmailLink,
  setPasswordWithLink,
  verifyAccountLogin,
} from "../lib/auth-signup.js";
import {
  buildSimpleSessionCookie,
  getSimpleSessionUser,
  issueAccountSession,
  loginSimpleUser,
  validateSimpleSession,
} from "../lib/auth-simple.js";
import { closePool, query, runMigrations } from "../lib/db.js";

const ENV_KEYS = [
  "AUTH_MODE",
  "SIGNUP_ENABLED",
  "APP_BASE_URL",
  "DATABASE_URL",
  "__DB_DISABLED",
  "SIMPLE_AUTH_SESSION_SECRET",
  "SIMPLE_AUTH_USERS",
  "SIMPLE_AUTH_USERNAME",
  "SIMPLE_AUTH_PASSWORD",
  "MASTER_ENCRYPTION_KEY",
];
const ORIGINAL_ENV = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));

function restoreEnv() {
  for (const [key, value] of Object.entries(ORIGINAL_ENV)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
}

describe("sign-up input rules", () => {
  it("accepts corporate and personal addresses, normalized", () => {
    expect(normalizeEmail("  Alice@Company.COM ")).toBe("alice@company.com");
    expect(isValidEmail("alice@company.com")).toBe(true);
    expect(isValidEmail("someone@gmail.com")).toBe(true);
    expect(isValidEmail("not-an-email")).toBe(false);
    expect(isValidEmail("a@b")).toBe(false);
  });

  it("enforces password length without silent bcrypt truncation", () => {
    expect(passwordProblem("short")).toMatch(/at least 8/);
    expect(passwordProblem("long enough")).toBeNull();
    expect(passwordProblem("x".repeat(72))).toBeNull();
    expect(passwordProblem("x".repeat(73))).toMatch(/at most 72 bytes/);
    expect(passwordProblem("é".repeat(37))).toMatch(/at most 72 bytes/); // 74 bytes
  });

  it("is only enabled with simple auth, a database, the flag and a base URL", () => {
    try {
      process.env.AUTH_MODE = "simple";
      process.env.DATABASE_URL = "postgres://unused";
      delete process.env.__DB_DISABLED;
      process.env.SIGNUP_ENABLED = "true";
      process.env.APP_BASE_URL = "https://cart.votal.ai";
      expect(isSignupEnabled()).toBe(true);

      for (const [key, value] of [
        ["AUTH_MODE", "oidc"],
        ["SIGNUP_ENABLED", "false"],
        ["APP_BASE_URL", ""],
        ["__DB_DISABLED", "1"],
      ] as const) {
        const before = process.env[key];
        process.env[key] = value;
        expect(isSignupEnabled()).toBe(false);
        if (before === undefined) delete process.env[key];
        else process.env[key] = before;
      }
    } finally {
      restoreEnv();
    }
  });
});

describe("account sessions", () => {
  afterEach(restoreEnv);

  it("carries account details in the token so /me needs no database", async () => {
    process.env.SIMPLE_AUTH_SESSION_SECRET = "test-secret-that-is-long-enough-for-32-chars";
    process.env.__DB_DISABLED = "1";
    const { token, auth } = issueAccountSession({
      id: "acct-1",
      email: "alice@company.com",
      name: "Alice",
      tenantId: "tenant-1",
      userId: "user-1",
      passwordChangedAt: 1000,
    });
    expect(auth).toMatchObject({ tenantId: "tenant-1", role: "admin", selfSignup: true });

    const cookie = buildSimpleSessionCookie(token).split(";")[0];
    await expect(getSimpleSessionUser(cookie)).resolves.toEqual({
      username: "alice@company.com",
      role: "admin",
      email: "alice@company.com",
      name: "Alice",
    });
    // API requests need the database to check the account still exists.
    await expect(validateSimpleSession(cookie)).rejects.toThrow();
  });
});

const TEST_DB = process.env.TEST_DATABASE_URL;

describe.skipIf(!TEST_DB)("email sign-up against Postgres (TEST_DATABASE_URL)", () => {
  beforeAll(async () => {
    process.env.DATABASE_URL = TEST_DB;
    delete process.env.__DB_DISABLED;
    process.env.MASTER_ENCRYPTION_KEY = "a".repeat(64);
    process.env.SIMPLE_AUTH_SESSION_SECRET = "test-secret-that-is-long-enough-for-32-chars";
    process.env.AUTH_MODE = "simple";
    process.env.SIGNUP_ENABLED = "true";
    process.env.APP_BASE_URL = "https://cart.votal.ai/";
    delete process.env.SIMPLE_AUTH_USERS;
    delete process.env.SIMPLE_AUTH_USERNAME;
    delete process.env.SIMPLE_AUTH_PASSWORD;
    await runMigrations();
  });

  beforeEach(async () => {
    sentEmails.length = 0;
    await query("DELETE FROM email_links");
    await query("DELETE FROM accounts");
  });

  afterAll(async () => {
    await closePool();
    restoreEnv();
  });

  function lastToken(): string {
    const match = /#\/set-password\?token=([\w-]+)/.exec(sentEmails.at(-1)!.text);
    return decodeURIComponent(match![1]);
  }

  /** Let the per-address cooldown pass. */
  async function expireCooldown() {
    await query("UPDATE email_links SET created_at = created_at - interval '2 minutes'");
  }

  async function signUp(email: string, password: string, name?: string) {
    await requestEmailLink(email, "signup", name);
    return setPasswordWithLink(lastToken(), password);
  }

  it("signs up with a link, then logs in with email + password", async () => {
    const account = await signUp("New@Company.com", "correct horse", "New User");
    expect(account).toMatchObject({ email: "new@company.com", name: "New User" });
    expect(sentEmails[0].to).toBe("new@company.com");
    expect(sentEmails[0].text).toContain("https://cart.votal.ai/#/set-password?token=");

    await expect(loginSimpleUser("new@company.com", "wrong password")).rejects.toThrow();
    const { auth, user } = await loginSimpleUser("NEW@company.com", "correct horse");
    expect(user).toMatchObject({ username: "new@company.com", role: "admin", name: "New User" });
    expect(auth).toMatchObject({ tenantId: account!.tenantId, selfSignup: true });
  });

  it("gives every account its own tenant, as admin", async () => {
    const a = await signUp("a@company.com", "password one");
    const b = await signUp("b@company.com", "password two");
    expect(a!.tenantId).not.toBe(b!.tenantId);
    const users = await query("SELECT role, tenant_id FROM users WHERE id = $1", [a!.userId]);
    expect(users.rows[0]).toMatchObject({ role: "admin", tenant_id: a!.tenantId });
  });

  it("creates no account until the link is used", async () => {
    await requestEmailLink("new@company.com", "signup");
    await expect(verifyAccountLogin("new@company.com", "")).resolves.toBeNull();
    await requestEmailLink("new@company.com", "reset");
    expect(sentEmails).toHaveLength(1); // reset sends nothing without an account
  });

  it("links are single-use, expire, and using one voids the others", async () => {
    await requestEmailLink("new@company.com", "signup");
    const first = lastToken();
    await expireCooldown();
    await requestEmailLink("new@company.com", "signup");
    const second = lastToken();

    expect(await setPasswordWithLink(second, "password one")).not.toBeNull();
    expect(await setPasswordWithLink(second, "password two")).toBeNull();
    expect(await setPasswordWithLink(first, "password two")).toBeNull();

    await expireCooldown();
    await requestEmailLink("other@company.com", "signup");
    await query("UPDATE email_links SET expires_at = now() - interval '1 second'");
    expect(await setPasswordWithLink(lastToken(), "password one")).toBeNull();
  });

  it("limits each address to one email per minute", async () => {
    await requestEmailLink("new@company.com", "signup");
    await requestEmailLink("new@company.com", "signup");
    expect(sentEmails).toHaveLength(1);
  });

  it("someone else signing up with your address can't change your password", async () => {
    await signUp("owner@company.com", "owner password");
    await expireCooldown();
    await requestEmailLink("owner@company.com", "signup");
    expect(sentEmails.at(-1)!.to).toBe("owner@company.com"); // the link goes to the owner
    expect(sentEmails.at(-1)!.subject).toMatch(/Set your/);
    await expect(loginSimpleUser("owner@company.com", "owner password")).resolves.toBeTruthy();
  });

  it("password reset works and ends sessions issued before it", async () => {
    await signUp("owner@company.com", "old password");
    const { token } = await loginSimpleUser("owner@company.com", "old password");
    const oldCookie = buildSimpleSessionCookie(token).split(";")[0];
    await expect(validateSimpleSession(oldCookie)).resolves.toMatchObject({ selfSignup: true });

    await expireCooldown();
    await new Promise((r) => setTimeout(r, 5)); // password_changed_at must move
    await requestEmailLink("owner@company.com", "reset");
    await setPasswordWithLink(lastToken(), "new password");

    await expect(validateSimpleSession(oldCookie)).rejects.toThrow(/Password changed/);
    await expect(loginSimpleUser("owner@company.com", "old password")).rejects.toThrow();
    await expect(loginSimpleUser("owner@company.com", "new password")).resolves.toBeTruthy();
  });

  it("rejects sessions for deleted accounts", async () => {
    await signUp("gone@company.com", "some password");
    const { token } = await loginSimpleUser("gone@company.com", "some password");
    await query("DELETE FROM accounts WHERE email = 'gone@company.com'");
    await expect(
      validateSimpleSession(buildSimpleSessionCookie(token).split(";")[0]),
    ).rejects.toThrow(/no longer exists/);
  });

  it("env-configured users keep working alongside accounts", async () => {
    process.env.SIMPLE_AUTH_USERNAME = "admin";
    process.env.SIMPLE_AUTH_PASSWORD = "env-secret";
    try {
      await signUp("new@company.com", "correct horse");
      await expect(loginSimpleUser("admin", "env-secret")).resolves.toMatchObject({
        user: { username: "admin" },
      });
      await expect(loginSimpleUser("new@company.com", "correct horse")).resolves.toBeTruthy();
    } finally {
      delete process.env.SIMPLE_AUTH_USERNAME;
      delete process.env.SIMPLE_AUTH_PASSWORD;
    }
  });
});
