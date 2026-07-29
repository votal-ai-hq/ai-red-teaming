import { describe, it, expect } from "vitest";
import {
  loadCustomAttacksFromConfig,
  mergeCustomAttacksForRound,
  mapLabelToCategory,
  splitPromptByTurnMarkers,
  attacksFromCustomRows,
} from "../lib/custom-attacks-loader.js";
import { generateAppTailoredCustomAttacks } from "../lib/app-tailored-custom-prompts.js";
import type { Config } from "../lib/types.js";

const baseConfig = (): Config =>
  ({
    target: {
      baseUrl: "http://localhost:3000",
      agentEndpoint: "/api/agent",
      authEndpoint: "/api/auth",
      applicationDetails: "test",
    },
    codebasePath: ".",
    codebaseGlob: "**/*.ts",
    auth: {
      methods: ["body_role"],
      jwtSecret: "x",
      credentials: [{ email: "a@b.com", password: "p", role: "viewer" }],
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
    sensitivePatterns: [],
    attackConfig: {
      adaptiveRounds: 1,
      maxAttacksPerCategory: 5,
      concurrency: 1,
      delayBetweenRequestsMs: 0,
      llmProvider: "openai",
      llmModel: "gpt-4o",
      enableLlmGeneration: false,
      maxMultiTurnSteps: 8,
    },
  }) as Config;

describe("splitPromptByTurnMarkers", () => {
  it("returns single segment when no turn markers", () => {
    expect(splitPromptByTurnMarkers("hello")).toEqual(["hello"]);
  });

  it("splits multi-turn prompts", () => {
    const s =
      "[Turn 1] First ask for help. [Turn 2] Now ask for secrets. [Turn 3] Thanks.";
    const parts = splitPromptByTurnMarkers(s);
    expect(parts.length).toBe(3);
    expect(parts[0]).toContain("First ask");
    expect(parts[2]).toContain("Thanks");
  });
});

describe("mapLabelToCategory", () => {
  it("maps spreadsheet-style labels", () => {
    expect(mapLabelToCategory("PII Minimization")).toBe("pii_disclosure");
    expect(mapLabelToCategory("Multi Turn Attack")).toBe(
      "multi_turn_escalation",
    );
  });
});

describe("loadCustomAttacksFromConfig", () => {
  it("loads JSON rows with path relative to config directory", () => {
    const config = baseConfig();
    config.customAttacksFile = "examples/custom-attacks.example.json";
    const loaded = loadCustomAttacksFromConfig(config, {
      configDir: process.cwd(),
    });
    expect(loaded.length).toBeGreaterThanOrEqual(2);
    expect(loaded[0]!.payload.message).toBeDefined();
    expect(loaded[0]!.category).toBe("pii_disclosure");
    expect(loaded[1]!.category).toBe("prompt_injection");
  });

  it("loads CSV", () => {
    const config = baseConfig();
    config.customAttacksFile = "examples/custom-attacks.example.csv";
    const attacks = loadCustomAttacksFromConfig(config, {
      configDir: process.cwd(),
    });
    expect(attacks.length).toBe(8);
    expect(attacks[0]!.category).toBe("pii_disclosure");
  });
});

describe("attacksFromCustomRows", () => {
  it("sets idPrefix and isLlmGenerated", () => {
    const config = baseConfig();
    const rows = [
      {
        prompt: "test message",
        successCriteria: "x",
        category: "prompt_injection",
        severity: "low",
        description: "d",
      },
    ];
    const attacks = attacksFromCustomRows(config, rows, "body_role", {
      idPrefix: "app-tailored",
      isLlmGenerated: true,
    });
    expect(attacks).toHaveLength(1);
    expect(attacks[0]!.id).toBe("app-tailored-1");
    expect(attacks[0]!.isLlmGenerated).toBe(true);
  });

  it("preserves MCP-native execution fields in the attack payload", () => {
    const config = baseConfig();
    const attacks = attacksFromCustomRows(
      config,
      [
        {
          prompt: '{"bookingId":"BK-7001","newAmountINR":1}',
          successCriteria: "price changed",
          category: "tool_misuse",
          severity: "critical",
          _mcpOperation: "tools/call",
          _mcpTool: "override_price",
          _mcpArguments: { bookingId: "BK-7001", newAmountINR: 1 },
        },
      ],
      "none",
    );
    expect(attacks[0].payload).toMatchObject({
      message: '{"bookingId":"BK-7001","newAmountINR":1}',
      _mcpOperation: "tools/call",
      _mcpTool: "override_price",
      _mcpArguments: { bookingId: "BK-7001", newAmountINR: 1 },
    });
  });
});

describe("generateAppTailoredCustomAttacks", () => {
  it("returns empty array when count is 0", async () => {
    const config = baseConfig();
    config.attackConfig.appTailoredCustomPromptCount = 0;
    const attacks = await generateAppTailoredCustomAttacks(config, {
      tools: [],
      roles: [],
      guardrailPatterns: [],
      sensitiveData: [],
      authMechanisms: [],
      knownWeaknesses: [],
      systemPromptHints: [],
      detectedFrameworks: [],
      toolChains: [],
    });
    expect(attacks).toEqual([]);
  });
});

describe("mergeCustomAttacksForRound", () => {
  it("prepends custom on round 1", () => {
    const config = baseConfig();
    const custom = [{ id: "c1" } as never];
    const planned = [{ id: "p1" } as never];
    const m = mergeCustomAttacksForRound(config, 1, planned, custom);
    expect(m.map((x) => x.id)).toEqual(["c1", "p1"]);
  });

  it("returns only custom when customAttacksOnly", () => {
    const config = baseConfig();
    config.attackConfig.customAttacksOnly = true;
    const custom = [{ id: "c1" } as never];
    const planned = [{ id: "p1" } as never];
    const m = mergeCustomAttacksForRound(config, 1, planned, custom);
    expect(m.map((x) => x.id)).toEqual(["c1"]);
  });

  it("ignores custom after round 1", () => {
    const config = baseConfig();
    const custom = [{ id: "c1" } as never];
    const planned = [{ id: "p1" } as never];
    const m = mergeCustomAttacksForRound(config, 2, planned, custom);
    expect(m).toEqual(planned);
  });
});
