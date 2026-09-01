import { afterEach, describe, expect, it } from "vitest";
import {
  assertDashboardAuthSafeToServe,
  resolveAuthMode,
  resolveDashboardBindHost,
  shouldBypassDashboardAuth,
} from "../lib/auth-mode.js";

const ORIGINAL = {
  AUTH_MODE: process.env.AUTH_MODE,
  NODE_ENV: process.env.NODE_ENV,
  DATABASE_URL: process.env.DATABASE_URL,
  __DB_DISABLED: process.env.__DB_DISABLED,
  DASHBOARD_BIND: process.env.DASHBOARD_BIND,
};

afterEach(() => {
  for (const [key, value] of Object.entries(ORIGINAL)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

describe("shouldBypassDashboardAuth (C-03)", () => {
  it("never bypasses in production even with no DATABASE_URL", () => {
    process.env.NODE_ENV = "production";
    delete process.env.AUTH_MODE;
    delete process.env.DATABASE_URL;
    process.env.__DB_DISABLED = "1";
    expect(shouldBypassDashboardAuth()).toBe(false);
  });

  it("never bypasses in production when AUTH_MODE=none", () => {
    process.env.NODE_ENV = "production";
    process.env.AUTH_MODE = "none";
    delete process.env.DATABASE_URL;
    process.env.__DB_DISABLED = "1";
    expect(shouldBypassDashboardAuth()).toBe(false);
  });

  it("bypasses only for explicit none outside production", () => {
    process.env.NODE_ENV = "development";
    process.env.AUTH_MODE = "none";
    delete process.env.DATABASE_URL;
    process.env.__DB_DISABLED = "1";
    expect(shouldBypassDashboardAuth()).toBe(true);
  });

  it("does not bypass AUTH_MODE=simple without a database", () => {
    process.env.NODE_ENV = "development";
    process.env.AUTH_MODE = "simple";
    delete process.env.DATABASE_URL;
    process.env.__DB_DISABLED = "1";
    expect(shouldBypassDashboardAuth()).toBe(false);
  });

  it("does not bypass AUTH_MODE=dev without a database", () => {
    process.env.NODE_ENV = "development";
    process.env.AUTH_MODE = "dev";
    delete process.env.DATABASE_URL;
    process.env.__DB_DISABLED = "1";
    expect(shouldBypassDashboardAuth()).toBe(false);
  });
});

describe("resolveDashboardBindHost", () => {
  it("forces loopback when auth is bypassed", () => {
    process.env.NODE_ENV = "development";
    process.env.AUTH_MODE = "none";
    delete process.env.DASHBOARD_BIND;
    expect(resolveDashboardBindHost()).toBe("127.0.0.1");
  });

  it("rejects a public bind when auth is bypassed", () => {
    process.env.NODE_ENV = "development";
    process.env.AUTH_MODE = "none";
    process.env.DASHBOARD_BIND = "0.0.0.0";
    expect(() => resolveDashboardBindHost()).toThrow(/cannot bind/);
  });

  it("allows 0.0.0.0 when simple auth is on", () => {
    process.env.NODE_ENV = "production";
    process.env.AUTH_MODE = "simple";
    delete process.env.DASHBOARD_BIND;
    expect(resolveDashboardBindHost()).toBe("0.0.0.0");
  });
});

describe("assertDashboardAuthSafeToServe", () => {
  it("refuses AUTH_MODE=none in production", () => {
    process.env.NODE_ENV = "production";
    process.env.AUTH_MODE = "none";
    expect(() => assertDashboardAuthSafeToServe()).toThrow(
      /AUTH_MODE=none is forbidden/,
    );
  });
});

describe("resolveAuthMode", () => {
  it("defaults to oidc when DATABASE_URL is set", () => {
    delete process.env.AUTH_MODE;
    process.env.DATABASE_URL = "postgres://x";
    delete process.env.__DB_DISABLED;
    expect(resolveAuthMode()).toBe("oidc");
  });
});
