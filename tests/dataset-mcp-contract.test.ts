import { describe, expect, it } from "vitest";
import { defaultCategoryPool } from "../lib/dataset/category-set.js";
import {
  hasOpenStringInput,
  mcpContractFromSurfaces,
  mcpToolContract,
  mergeMcpContracts,
  resolveDirectMcpCategories,
  resolveMcpDatasetContract,
} from "../lib/dataset/mcp-contract.js";
import {
  decodeQualityPair,
  encodeQualityPair,
  resolveMcpQualityPairs,
} from "../lib/dataset/quality-set.js";
import { recordToQualityRow } from "../lib/dataset/map-records.js";
import {
  mergeDatasets,
  validateQualityRows,
  validateRows,
} from "../lib/dataset/validate.js";
import type {
  DatasetRow,
  McpDatasetContract,
  QualityRow,
} from "../lib/dataset/types.js";

const bookingSchema = {
  type: "object",
  additionalProperties: false,
  properties: {
    bookingId: { type: "string", minLength: 1 },
    email: { type: "string", format: "email" },
    amount: { type: "number", minimum: 0 },
  },
  required: ["bookingId", "email"],
} as const;

const contract: McpDatasetContract = {
  tools: [
    { name: "book_trip", inputSchema: bookingSchema },
    {
      name: "numeric_lookup",
      inputSchema: {
        type: "object",
        properties: { id: { type: "integer" } },
        required: ["id"],
        additionalProperties: false,
      },
    },
  ],
  prompts: ["admin_report"],
  resources: ["booking://record/{id}"],
  roles: ["traveler", "admin"],
};

function securityRow(overrides: Partial<DatasetRow> = {}): DatasetRow {
  return {
    category: "tool_misuse",
    name: "booking misuse",
    prompt: '{"bookingId":"BK-1","email":"user@example.com"}',
    role: "traveler",
    severity: "high",
    successCriteria: "the unauthorized operation succeeds",
    _mcpOperation: "tools/call",
    _mcpTool: "book_trip",
    _mcpArguments: {
      bookingId: "BK-1",
      email: "user@example.com",
    },
    ...overrides,
  };
}

function qualityRow(overrides: Partial<QualityRow> = {}): QualityRow {
  return {
    task: "tool_selection",
    name: "select booking tool",
    input: "Book the saved itinerary for BK-1",
    expectedTools: ["book_trip"],
    metric: "tool_call_accuracy",
    ...overrides,
  };
}

describe("MCP contract construction", () => {
  it("parses JSON schema text without weakening it", () => {
    const tool = mcpToolContract(" book_trip ", JSON.stringify(bookingSchema));
    expect(tool.name).toBe("book_trip");
    expect(tool.inputSchema).toEqual(bookingSchema);
    expect(tool.schemaError).toBeUndefined();
  });

  it("records malformed discovery schema text as a contract error", () => {
    const tool = mcpToolContract("broken", '{"type":"object"');
    expect(tool.inputSchema).toBeUndefined();
    expect(tool.schemaError).toMatch(/not valid JSON/);
  });

  it("recovers tools, prompts, resources, and roles from legacy seeds", () => {
    const resolved = mcpContractFromSurfaces(
      [
        `tool "book_trip" - schema=${JSON.stringify(bookingSchema)}`,
        'MCP prompt "admin_report"',
        'MCP resource "booking://record/{id}"',
        "tool chain lookup -> book_trip (high)",
      ],
      ["traveler", "traveler", "admin"],
    );
    expect(resolved?.tools.map((tool) => tool.name)).toEqual(["book_trip"]);
    expect(resolved?.prompts).toEqual(["admin_report"]);
    expect(resolved?.resources).toEqual(["booking://record/{id}"]);
    expect(resolved?.roles).toEqual(["traveler", "admin"]);
  });

  it("prefers a structured seed contract over truncated surface text", () => {
    const resolved = resolveMcpDatasetContract({
      surfaces: ['tool "book_trip" schema={"type":"obj'],
      mcpContract: contract,
    });
    expect(resolved).toBe(contract);
  });

  it("merges duplicate tools with primary values and a secondary schema fallback", () => {
    const merged = mergeMcpContracts(
      {
        tools: [{ name: "book_trip" }, { name: "primary", inputSchema: {} }],
        prompts: ["one"],
        resources: [],
        roles: ["traveler"],
      },
      {
        tools: [
          { name: "book_trip", inputSchema: bookingSchema },
          { name: "primary", inputSchema: { type: "null" } },
        ],
        prompts: ["one", "two"],
        resources: ["booking://record/{id}"],
        roles: ["admin"],
      },
    );
    expect(merged?.tools[0].inputSchema).toEqual(bookingSchema);
    expect(merged?.tools[1].inputSchema).toEqual({});
    expect(merged?.prompts).toEqual(["one", "two"]);
    expect(merged?.roles).toEqual(["traveler", "admin"]);
  });
});

describe("MCP direct security category support", () => {
  it("removes categories the one-operation runner cannot observe by default", () => {
    const resolved = resolveDirectMcpCategories(defaultCategoryPool("mcp"), false);
    expect(resolved).toContain("tool_misuse");
    expect(resolved).toContain("shell_injection");
    expect(resolved).not.toContain("tool_chain_hijack");
    expect(resolved).not.toContain("cross_tenant_access");
    expect(resolved).not.toContain("sdk_dependency_attack");
  });

  it("rejects an explicitly requested unsupported category", () => {
    expect(() =>
      resolveDirectMcpCategories(["tool_misuse", "cross_tenant_access"], true),
    ).toThrow(/cross_tenant_access.*authenticated tenant identities/);
  });

  it("also rejects an unsupported category if it reaches row validation", () => {
    const result = validateRows(
      [securityRow({ category: "tool_chain_hijack" })],
      { family: "mcp", mcpContract: contract },
    );
    expect(result.valid).toHaveLength(0);
    expect(result.errors[0]).toMatch(/multiple ordered MCP operations/);
  });
});

describe("MCP security row contract validation", () => {
  it("accepts an exact tool name with schema-valid arguments", () => {
    const result = validateRows([securityRow()], {
      family: "mcp",
      mcpContract: contract,
    });
    expect(result.errors).toEqual([]);
    expect(result.valid).toHaveLength(1);
  });

  it("rejects a hallucinated tool name", () => {
    const result = validateRows(
      [securityRow({ _mcpTool: "travel:write" })],
      { family: "mcp", mcpContract: contract },
    );
    expect(result.errors[0]).toMatch(/tool "travel:write" is not declared/);
  });

  it("rejects missing required arguments", () => {
    const result = validateRows(
      [securityRow({ _mcpArguments: { bookingId: "BK-1" } })],
      { family: "mcp", mcpContract: contract },
    );
    expect(result.errors[0]).toMatch(/required property 'email'/);
  });

  it("rejects invalid formats and unexpected arguments", () => {
    const result = validateRows(
      [
        securityRow({
          _mcpArguments: {
            bookingId: "BK-1",
            email: "not-an-email",
            invented: true,
          },
        }),
      ],
      { family: "mcp", mcpContract: contract },
    );
    expect(result.errors[0]).toMatch(/additional properties/);
    expect(result.errors[0]).toMatch(/format "email"/);
  });

  it("fails closed when a used tool has no usable schema", () => {
    const noSchema: McpDatasetContract = {
      ...contract,
      tools: [{ name: "book_trip" }],
    };
    const result = validateRows([securityRow()], {
      family: "mcp",
      mcpContract: noSchema,
    });
    expect(result.errors[0]).toMatch(/has no input schema/);
  });

  it("supports JSON Schema 2020-12 declarations", () => {
    const modern: McpDatasetContract = {
      ...contract,
      tools: [{
        name: "book_trip",
        inputSchema: {
          $schema: "https://json-schema.org/draft/2020-12/schema",
          type: "object",
          properties: { bookingId: { type: "string" } },
          required: ["bookingId"],
          unevaluatedProperties: false,
        },
      }],
    };
    const result = validateRows(
      [securityRow({ _mcpArguments: { bookingId: "BK-1" } })],
      { family: "mcp", mcpContract: modern },
    );
    expect(result.errors).toEqual([]);
  });

  it("rejects a generated role outside the declared contract", () => {
    const result = validateRows(
      [securityRow({ role: "super-admin" })],
      { family: "mcp", mcpContract: contract },
    );
    expect(result.errors[0]).toMatch(/role "super-admin" is not declared/);
  });

  it("accepts declared prompt and templated resource targets", () => {
    const prompt = securityRow({
      prompt: "prompt target",
      category: "debug_access",
      _mcpOperation: "prompts/get",
      _mcpPrompt: "admin_report",
      _mcpTool: undefined,
      _mcpArguments: {},
    });
    const resource = securityRow({
      prompt: "resource target",
      category: "debug_access",
      _mcpOperation: "resources/read",
      _mcpResourceUri: "booking://record/BK-21",
      _mcpTool: undefined,
      _mcpArguments: undefined,
    });
    const result = validateRows([prompt, resource], {
      family: "mcp",
      mcpContract: contract,
    });
    expect(result.errors).toEqual([]);
    expect(result.valid).toHaveLength(2);
  });

  it("rejects prompt and resource targets absent from discovery", () => {
    const promptResult = validateRows(
      [securityRow({
        _mcpOperation: "prompts/get",
        _mcpPrompt: "unknown",
        _mcpTool: undefined,
        _mcpArguments: {},
      })],
      { family: "mcp", mcpContract: contract },
    );
    const resourceResult = validateRows(
      [securityRow({
        _mcpOperation: "resources/read",
        _mcpResourceUri: "secret://other",
        _mcpTool: undefined,
        _mcpArguments: undefined,
      })],
      { family: "mcp", mcpContract: contract },
    );
    expect(promptResult.errors[0]).toMatch(/prompt "unknown" is not declared/);
    expect(resourceResult.errors[0]).toMatch(/resource "secret:\/\/other" is not declared/);
  });
});

describe("injection carrier validation", () => {
  it("finds nested and local-reference string inputs", () => {
    expect(hasOpenStringInput({
      type: "object",
      properties: { payload: { $ref: "#/$defs/text" } },
      $defs: { text: { type: "string" } },
    })).toBe(true);
    expect(hasOpenStringInput({
      type: "object",
      properties: { id: { type: "integer" } },
    })).toBe(false);
  });

  it("rejects injection rows against tools with numeric-only inputs", () => {
    const result = validateRows(
      [securityRow({
        category: "sql_injection",
        _mcpTool: "numeric_lookup",
        _mcpArguments: { id: 7 },
      })],
      { family: "mcp", mcpContract: contract },
    );
    expect(result.errors[0]).toMatch(/needs an unconstrained string input/);
  });

  it("rejects injection categories placed on prompt or resource reads", () => {
    const result = validateRows(
      [securityRow({
        category: "prompt_template_injection",
        _mcpOperation: "prompts/get",
        _mcpPrompt: "admin_report",
        _mcpTool: undefined,
        _mcpArguments: {},
      })],
      { family: "mcp", mcpContract: contract },
    );
    expect(result.errors[0]).toMatch(/requires a tool call/);
  });
});

describe("MCP quality contract and scorer compatibility", () => {
  it("accepts a measurable task with discovered expected tools", () => {
    const result = validateQualityRows([qualityRow()], { mcpContract: contract });
    expect(result.errors).toEqual([]);
    expect(result.valid).toHaveLength(1);
  });

  it("rejects expected tool names not present in discovery", () => {
    const result = validateQualityRows(
      [qualityRow({ expectedTools: ["travel:write"] })],
      { mcpContract: contract },
    );
    expect(result.errors[0]).toMatch(/travel:write/);
  });

  it("rejects a metric that does not measure the selected task", () => {
    const result = validateQualityRows(
      [qualityRow({ metric: "goal_accuracy", reference: "Booking created" })],
      { mcpContract: contract },
    );
    expect(result.errors[0]).toMatch(/does not measure MCP task "tool_selection"/);
  });

  it("rejects argument tasks until expected argument capture exists", () => {
    const result = validateQualityRows(
      [qualityRow({ task: "tool_argument_accuracy" })],
      { mcpContract: contract },
    );
    expect(result.errors[0]).toMatch(/records tool names but not arguments/);
  });

  it("requires the grading artifact consumed by each metric", () => {
    const missingTools = validateQualityRows([
      qualityRow({ expectedTools: undefined }),
    ]);
    const missingReference = validateQualityRows([
      qualityRow({
        task: "goal_completion",
        metric: "goal_accuracy",
        expectedTools: ["book_trip"],
      }),
    ]);
    expect(missingTools.errors[0]).toMatch(/requires expectedTools/);
    expect(missingReference.errors[0]).toMatch(/requires a reference/);
  });

  it("applies the same contract when appending generated quality rows", () => {
    const result = mergeDatasets(
      "quality",
      [qualityRow()],
      [qualityRow({ input: "Use the write scope", expectedTools: ["travel:write"] })],
      { family: "mcp", mcpContract: contract },
    );
    expect(result.valid).toHaveLength(1);
    expect(result.added).toBe(0);
    expect(result.errors[0]).toMatch(/travel:write/);
  });
});

describe("atomic MCP quality task/metric sampling", () => {
  const tasks = [
    "tool_selection",
    "tool_argument_accuracy",
    "multi_step_task",
    "goal_completion",
    "parameter_extraction",
  ];

  it("returns only combinations the current scorer can observe", () => {
    const pairs = resolveMcpQualityPairs(
      tasks,
      ["tool_call_accuracy", "goal_accuracy", "topic_adherence"],
      false,
    );
    expect(pairs.map(encodeQualityPair)).toEqual([
      "tool_selection::tool_call_accuracy",
      "multi_step_task::tool_call_accuracy",
      "multi_step_task::goal_accuracy",
      "goal_completion::goal_accuracy",
    ]);
  });

  it("fails early for an explicitly requested unmeasurable task", () => {
    expect(() =>
      resolveMcpQualityPairs(
        ["tool_argument_accuracy"],
        ["tool_call_accuracy"],
        true,
      ),
    ).toThrow(/does not capture expected arguments|not arguments/);
  });

  it("fails when requested metrics leave a task with no compatible scorer", () => {
    expect(() =>
      resolveMcpQualityPairs(["tool_selection"], ["goal_accuracy"], true),
    ).toThrow(/no compatible requested metric/);
  });

  it("round-trips the pair through a generated record", () => {
    const pair = decodeQualityPair("tool_selection::tool_call_accuracy");
    expect(pair).toEqual({
      task: "tool_selection",
      metric: "tool_call_accuracy",
    });
    const row = recordToQualityRow({
      taskMetric: "tool_selection::tool_call_accuracy",
      input: "Book BK-1",
      grading: { expectedTools: ["book_trip"] },
    });
    expect(row).toMatchObject({
      task: "tool_selection",
      metric: "tool_call_accuracy",
      expectedTools: ["book_trip"],
    });
  });
});
