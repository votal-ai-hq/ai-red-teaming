import { describe, it, expect, vi } from "vitest";
import { loadConfig } from "../lib/config-loader.js";
import { writeFileSync, mkdtempSync, rmSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";

function writeTestConfig(dir: string, config: Record<string, unknown>): string {
  const path = join(dir, "config.json");
  writeFileSync(path, JSON.stringify(config));
  return path;
}

function makeValidConfig(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    target: {
      baseUrl: "http://localhost:3000",
      agentEndpoint: "/api/agent",
      authEndpoint: "/api/login",
      applicationDetails:
        "Internal support assistant for order lookups and refunds.",
    },
    auth: {
      methods: ["jwt"],
      jwtSecret: "test-secret",
      credentials: [{ email: "a@b.com", password: "pass", role: "admin" }],
      apiKeys: {},
    },
    requestSchema: {
      messageField: "message",
      roleField: "role",
      apiKeyField: "api_key",
      guardrailModeField: "guardrail_mode",
    },
    responseSchema: {
      responsePath: "response",
      toolCallsPath: "tool_calls",
      userInfoPath: "user",
      guardrailsPath: "guardrails",
    },
    sensitivePatterns: ["sk-proj-"],
    ...overrides,
  };
}

describe("loadConfig", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "redteam-test-"));
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("loads a valid config file", () => {
    const path = writeTestConfig(tmpDir, makeValidConfig());
    const config = loadConfig(path);
    expect(config.target.type).toBe("http_agent");
    expect(config.target.baseUrl).toBe("http://localhost:3000");
    expect(config.target.agentEndpoint).toBe("/api/agent");
    expect(config.target.applicationDetails).toBe(
      "Internal support assistant for order lookups and refunds.",
    );
  });

  it("applies default attackConfig values", () => {
    const path = writeTestConfig(tmpDir, makeValidConfig());
    const config = loadConfig(path);
    expect(config.attackConfig.adaptiveRounds).toBe(3);
    expect(config.attackConfig.maxAttacksPerCategory).toBe(15);
    expect(config.attackConfig.concurrency).toBe(3);
    expect(config.attackConfig.delayBetweenRequestsMs).toBe(200);
    expect(config.attackConfig.llmModel).toBe("gpt-4o");
    expect(config.attackConfig.enableLlmGeneration).toBe(true);
    expect(config.attackConfig.includeSeedAttacks).toBe(true);
    expect(config.attackConfig.maxMultiTurnSteps).toBe(8);
  });

  it("allows overriding attackConfig defaults", () => {
    const path = writeTestConfig(
      tmpDir,
      makeValidConfig({
        attackConfig: {
          adaptiveRounds: 5,
          llmModel: "gpt-4o-mini",
          includeSeedAttacks: false,
          strategyCategoryAffinityFile: "data/strategy-category-affinity.csv",
        },
      }),
    );
    const config = loadConfig(path);
    expect(config.attackConfig.adaptiveRounds).toBe(5);
    expect(config.attackConfig.llmModel).toBe("gpt-4o-mini");
    expect(config.attackConfig.includeSeedAttacks).toBe(false);
    expect(config.attackConfig.strategyCategoryAffinityFile).toBe(
      "data/strategy-category-affinity.csv",
    );
    // Non-overridden fields get defaults
    expect(config.attackConfig.concurrency).toBe(3);
  });

  it("throws on duplicate enabled categories", () => {
    const path = writeTestConfig(
      tmpDir,
      makeValidConfig({
        attackConfig: {
          enabledCategories: ["prompt_injection", "prompt_injection"],
        },
      }),
    );
    expect(() => loadConfig(path)).toThrow("duplicate enabledCategories");
  });

  it("throws on duplicate enabled strategies", () => {
    const path = writeTestConfig(
      tmpDir,
      makeValidConfig({
        attackConfig: {
          enabledStrategies: [
            "life_or_death_emergency",
            "life_or_death_emergency",
          ],
        },
      }),
    );
    expect(() => loadConfig(path)).toThrow("duplicate enabledStrategies");
  });

  it("preserves target.applicationDetails when provided", () => {
    const path = writeTestConfig(
      tmpDir,
      makeValidConfig({
        target: {
          baseUrl: "http://localhost:3000",
          agentEndpoint: "/api/agent",
          authEndpoint: "/api/login",
          applicationDetails:
            "Customer support AI assistant for refunds and order lookups.",
        },
      }),
    );
    const config = loadConfig(path);
    expect(config.target.applicationDetails).toBe(
      "Customer support AI assistant for refunds and order lookups.",
    );
  });

  it("defaults target.applicationDetails to empty string when omitted", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const path = writeTestConfig(
      tmpDir,
      makeValidConfig({
        target: {
          baseUrl: "http://localhost:3000",
          agentEndpoint: "/api/agent",
          authEndpoint: "/api/login",
        },
      }),
    );
    const config = loadConfig(path);
    expect(config.target.applicationDetails).toBe("");
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining("target.applicationDetails"),
    );
    warn.mockRestore();
  });

  it("loads a valid MCP target config", () => {
    const path = writeTestConfig(
      tmpDir,
      makeValidConfig({
        target: {
          type: "mcp",
          applicationDetails: "MCP security test target",
          mcp: {
            transport: "stdio",
            command: "node",
            args: ["server.js"],
          },
        },
      }),
    );
    const config = loadConfig(path);
    expect(config.target.type).toBe("mcp");
    expect(config.target.mcp?.transport).toBe("stdio");
    expect(config.target.mcp?.command).toBe("node");
    expect(config.target.baseUrl).toBe("");
    expect(config.target.agentEndpoint).toBe("");
  });

  it("throws when MCP target is missing target.mcp", () => {
    const path = writeTestConfig(
      tmpDir,
      makeValidConfig({
        target: {
          type: "mcp",
          applicationDetails: "MCP security test target",
        },
      }),
    );
    expect(() => loadConfig(path)).toThrow("target.mcp is required");
  });

  it("throws when stdio MCP target is missing command", () => {
    const path = writeTestConfig(
      tmpDir,
      makeValidConfig({
        target: {
          type: "mcp",
          applicationDetails: "MCP security test target",
          mcp: {
            transport: "stdio",
          },
        },
      }),
    );
    expect(() => loadConfig(path)).toThrow("target.mcp.command is required");
  });

  it("throws on missing baseUrl", () => {
    const path = writeTestConfig(
      tmpDir,
      makeValidConfig({
        target: { agentEndpoint: "/api/agent", authEndpoint: "/api/login" },
      }),
    );
    expect(() => loadConfig(path)).toThrow("target.baseUrl is required");
  });

  it("throws on missing agentEndpoint", () => {
    const path = writeTestConfig(
      tmpDir,
      makeValidConfig({
        target: {
          baseUrl: "http://localhost:3000",
          authEndpoint: "/api/login",
        },
      }),
    );
    expect(() => loadConfig(path)).toThrow("target.agentEndpoint is required");
  });

  it("accepts a config with no auth (public/unauthenticated endpoint)", () => {
    const path = writeTestConfig(
      tmpDir,
      makeValidConfig({
        auth: {
          methods: [],
          jwtSecret: "s",
          credentials: [],
          apiKeys: undefined,
        },
      }),
    );
    const config = loadConfig(path);
    // No auth provided → normalized to a safe "no auth" shape, not an error.
    expect(config.auth.credentials).toEqual([]);
    expect(config.auth.apiKeys).toEqual({});
    expect(config.auth.methods).toEqual([]);
  });

  it("defaults request/response schema when omitted (e.g. a minimal MCP config)", () => {
    const cfg = makeValidConfig();
    delete cfg.requestSchema;
    delete cfg.responseSchema;
    const path = writeTestConfig(tmpDir, cfg);
    const config = loadConfig(path);
    // The response analyzer reads these on every result — they must exist.
    expect(config.responseSchema.toolCallsPath).toBe("tool_calls");
    expect(config.responseSchema.responsePath).toBe("response");
    expect(config.responseSchema.userInfoPath).toBe("user");
    expect(config.responseSchema.guardrailsPath).toBe("guardrails");
    expect(config.requestSchema.messageField).toBe("message");
  });

  it("throws on non-existent config file", () => {
    expect(() => loadConfig("/nonexistent/path/config.json")).toThrow();
  });
});
