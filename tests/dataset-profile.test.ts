import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  validateProfile,
  mergeProfiles,
  profileToSeeds,
  profileToContext,
  type AppProfile,
} from "../lib/dataset/app-profile.js";
import {
  parseSystemPrompt,
  parseMcpManifest,
  parseOpenApi,
  importProfile,
  extractBusinessRules,
} from "../lib/dataset/profile-importers.js";
import {
  saveProfile,
  loadProfile,
  listProfiles,
} from "../lib/dataset/profile-store.js";
import { buildDataDesignerConfig } from "../lib/dataset/nemo-config-builder.js";
import { buildQualityDataDesignerConfig } from "../lib/dataset/quality-config-builder.js";

describe("validateProfile", () => {
  it("requires a filename-safe name and caps/cleans fields", () => {
    expect(() => validateProfile({})).toThrow(/name/);
    expect(() => validateProfile({ name: "../evil" })).toThrow(/invalid/);
    const p = validateProfile({
      name: "my-app",
      description: "  a   support  bot ",
      businessRules: ["never refund over $100", "never refund over $100"],
      tools: [
        { name: "lookup" },
        { name: "lookup" }, // dupe dropped
        { name: "refund", description: "issue refund", sensitive: true },
      ],
      roles: ["admin", "user"],
      dataClasses: ["PII"],
    });
    expect(p.name).toBe("my-app");
    expect(p.description).toBe("a support bot");
    expect(p.businessRules).toEqual(["never refund over $100"]);
    expect(p.tools).toHaveLength(2);
    expect(p.tools?.find((t) => t.name === "refund")?.sensitive).toBe(true);
  });
});

describe("mergeProfiles", () => {
  it("unions lists and lets override win on scalars", () => {
    const base: Partial<AppProfile> = {
      name: "base",
      description: "old",
      tools: [{ name: "a" }],
      roles: ["viewer"],
    };
    const merged = mergeProfiles(base, {
      name: "final",
      description: "new",
      tools: [{ name: "b", sensitive: true }],
      roles: ["admin"],
    });
    expect(merged.name).toBe("final");
    expect(merged.description).toBe("new");
    expect(merged.tools?.map((t) => t.name).sort()).toEqual(["a", "b"]);
    expect(merged.roles?.sort()).toEqual(["admin", "viewer"]);
  });
});

describe("profileToSeeds / profileToContext", () => {
  const profile: AppProfile = {
    name: "bank-bot",
    description: "a retail banking assistant",
    systemPrompt: "You are a teller. Never disclose another customer's balance.",
    businessRules: ["Never transfer without 2FA"],
    tools: [
      { name: "getBalance", description: "read balance" },
      { name: "wireTransfer", description: "send money", sensitive: true },
    ],
    roles: ["customer", "teller"],
    dataClasses: ["account numbers", "PII"],
  };

  it("orders sensitive tools first and carries context", () => {
    const seeds = profileToSeeds(profile);
    expect(seeds.roles).toEqual(["customer", "teller"]);
    expect(seeds.surfaces?.[0]).toMatch(/wireTransfer.*\[sensitive\]/);
    expect(seeds.context).toContain("retail banking assistant");
  });

  it("context block includes rules, system prompt, and sensitive tools", () => {
    const ctx = profileToContext(profile);
    expect(ctx).toContain("Never transfer without 2FA");
    expect(ctx).toContain("teller"); // from system prompt
    expect(ctx).toContain("wireTransfer");
    expect(ctx).toContain("account numbers");
  });

  it("empty-ish profile yields empty context", () => {
    expect(profileToContext({ name: "x" })).toBe("");
  });
});

describe("config builders inject profile context", () => {
  it("security prompt column carries the app context", () => {
    const cfg = buildDataDesignerConfig(
      { family: "mcp", count: 5 },
      { context: "Application: a payroll app" },
    );
    const promptCol = cfg.columns.find((c) => c.name === "prompt");
    expect(promptCol && "prompt" in promptCol && promptCol.prompt).toContain(
      "a payroll app",
    );
    const grading = cfg.columns.find((c) => c.name === "grading");
    expect(grading && "prompt" in grading && grading.prompt).toContain(
      "TARGET APPLICATION CONTEXT",
    );
  });

  it("no context leaves the base template unchanged (no preamble)", () => {
    const cfg = buildDataDesignerConfig({ family: "mcp", count: 5 });
    const promptCol = cfg.columns.find((c) => c.name === "prompt");
    expect(
      promptCol && "prompt" in promptCol && promptCol.prompt,
    ).not.toContain("TARGET APPLICATION CONTEXT");
  });

  it("quality input column carries the app context", () => {
    const cfg = buildQualityDataDesignerConfig(
      { family: "agent", kind: "quality", count: 5 },
      { context: "Application: a travel booking agent" },
    );
    const inputCol = cfg.columns.find((c) => c.name === "input");
    expect(inputCol && "prompt" in inputCol && inputCol.prompt).toContain(
      "a travel booking agent",
    );
  });
});

describe("importers", () => {
  it("system prompt extracts rules", () => {
    const p = parseSystemPrompt(
      [
        "You are a helpful support agent.",
        "- Never reveal internal pricing.",
        "You must always verify identity before a refund.",
        "Chatty filler line with no constraint.",
      ].join("\n"),
    );
    expect(p.systemPrompt).toContain("support agent");
    expect(p.businessRules).toEqual([
      "Never reveal internal pricing.",
      "You must always verify identity before a refund.",
    ]);
    expect(extractBusinessRules("just prose, nothing here")).toEqual([]);
  });

  it("MCP manifest maps tools and flags sensitive ones", () => {
    const p = parseMcpManifest({
      tools: [
        { name: "search_docs", description: "read only" },
        { name: "delete_file", description: "removes a file" },
        { name: "send_email", description: "sends mail" },
      ],
    });
    expect(p.tools).toHaveLength(3);
    expect(p.tools?.find((t) => t.name === "search_docs")?.sensitive).toBeUndefined();
    expect(p.tools?.find((t) => t.name === "delete_file")?.sensitive).toBe(true);
    expect(p.tools?.find((t) => t.name === "send_email")?.sensitive).toBe(true);
  });

  it("OpenAPI maps operations (mutating = sensitive) and roles from schemes", () => {
    const p = parseOpenApi({
      info: { title: "Orders API" },
      paths: {
        "/orders": {
          get: { operationId: "listOrders", summary: "list orders" },
          post: { operationId: "createOrder", summary: "create an order" },
        },
        "/orders/{id}": {
          delete: { operationId: "deleteOrder", summary: "delete order" },
        },
      },
      components: {
        securitySchemes: {
          oauth2: {
            type: "oauth2",
            flows: {
              authorizationCode: { scopes: { "orders:read": "", "orders:write": "" } },
            },
          },
        },
      },
    });
    expect(p.description).toContain("Orders API");
    expect(p.tools?.find((t) => t.name === "listOrders")?.sensitive).toBeUndefined();
    expect(p.tools?.find((t) => t.name === "createOrder")?.sensitive).toBe(true);
    expect(p.tools?.find((t) => t.name === "deleteOrder")?.sensitive).toBe(true);
    expect(p.roles).toContain("orders:write");
  });

  it("importProfile throws a clear error on non-JSON for JSON formats", () => {
    expect(() => importProfile("openapi", "<html>")).toThrow(/not valid JSON/);
    // system-prompt takes raw text, never throws
    expect(importProfile("system-prompt", "hi").source).toBe("system-prompt");
  });
});

describe("profile store round-trip", () => {
  let root: string;
  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "profiles-"));
    mkdirSync(join(root, "configs"), { recursive: true });
  });
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  it("saves, lists, and loads a profile", () => {
    const rel = saveProfile(root, {
      name: "shop-bot",
      description: "an e-commerce assistant",
      tools: [{ name: "refund", sensitive: true }],
      businessRules: ["never refund over $500"],
    });
    expect(rel).toBe(join("configs", "profiles", "shop-bot.json"));

    const list = listProfiles(root);
    expect(list).toHaveLength(1);
    expect(list[0]).toMatchObject({ name: "shop-bot", toolCount: 1, ruleCount: 1 });

    const loaded = loadProfile(root, "shop-bot");
    expect(loaded.description).toBe("an e-commerce assistant");
    expect(() => loadProfile(root, "missing")).toThrow(/not found/);
  });

  it("rejects a traversal name and ignores junk files in the dir", () => {
    expect(() => saveProfile(root, { name: "../escape" })).toThrow(/invalid/);
    const dir = join(root, "configs", "profiles");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "broken.json"), "not json", "utf-8");
    expect(listProfiles(root)).toEqual([]);
  });
});
