import { afterEach, describe, expect, it } from "vitest";
import {
  assertDevAuthModeAllowed,
  resolveDevApiKey,
  validateDevToken,
} from "../lib/auth-dev.js";

const ORIGINAL = {
  NODE_ENV: process.env.NODE_ENV,
  DEV_API_KEY: process.env.DEV_API_KEY,
};

afterEach(() => {
  for (const [key, value] of Object.entries(ORIGINAL)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

describe("assertDevAuthModeAllowed", () => {
  it("rejects NODE_ENV=production", () => {
    process.env.NODE_ENV = "production";
    expect(() => assertDevAuthModeAllowed()).toThrow(/forbidden when NODE_ENV=production/);
  });

  it("allows development and unset", () => {
    process.env.NODE_ENV = "development";
    expect(() => assertDevAuthModeAllowed()).not.toThrow();
    delete process.env.NODE_ENV;
    expect(() => assertDevAuthModeAllowed()).not.toThrow();
  });
});

describe("resolveDevApiKey", () => {
  it("rejects missing and default keys", () => {
    delete process.env.DEV_API_KEY;
    expect(() => resolveDevApiKey()).toThrow(/DEV_API_KEY must be set/);
    process.env.DEV_API_KEY = "dev-key";
    expect(() => resolveDevApiKey()).toThrow(/DEV_API_KEY must be set/);
    process.env.DEV_API_KEY = "short";
    expect(() => resolveDevApiKey()).toThrow(/at least 16/);
  });

  it("accepts a unique key", () => {
    process.env.DEV_API_KEY = "local-dev-secret-1";
    expect(resolveDevApiKey()).toBe("local-dev-secret-1");
  });
});

describe("validateDevToken", () => {
  it("rejects a wrong presented bearer token", async () => {
    process.env.NODE_ENV = "development";
    process.env.DEV_API_KEY = "local-dev-secret-1";
    await expect(
      validateDevToken("Bearer totally-wrong-key"),
    ).rejects.toThrow(/Invalid dev API key/);
  });

  it("rejects missing header", async () => {
    process.env.NODE_ENV = "development";
    process.env.DEV_API_KEY = "local-dev-secret-1";
    await expect(validateDevToken(undefined)).rejects.toThrow(
      /Missing Authorization header/,
    );
  });
});
