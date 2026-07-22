import { describe, it, expect, vi } from "vitest";
import type { Config } from "../lib/types.js";
import type { QualityRow } from "../lib/dataset/types.js";

// Prove the scorer dispatches correctly per target type:
//   - MCP        → the agent loop (runQualityMcpAgent)
//   - WebSocket  → executeAttack → executeWebSocketAttack
//   - HTTP       → executeAttack → fetch (covered in quality-scorer.test.ts)
// Both transports feed the same downstream scoring, so a passing score here
// means the row actually reached the target and was graded on its response.

vi.mock("../lib/quality/mcp-agent.js", () => ({
  runQualityMcpAgent: vi.fn(async () => ({
    response: "the answer from the mcp agent",
    toolCalls: ["read_secret"],
    steps: 1,
    statusCode: 200,
    responseTimeMs: 4,
  })),
}));

vi.mock("../lib/websocket-attack-executor.js", () => ({
  executeWebSocketAttack: vi.fn(async () => ({
    statusCode: 200,
    body: { answer: "ws replied", tools: [{ name: "lookup" }] },
    timeMs: 7,
  })),
}));

const { scoreQualityRow } = await import("../lib/quality/scorer.js");
const { runQualityMcpAgent } = await import("../lib/quality/mcp-agent.js");
const { executeWebSocketAttack } = await import("../lib/websocket-attack-executor.js");

const baseResponseSchema = { responsePath: "answer", toolCallsPath: "tools" };
const baseAuth = { methods: ["none"], credentials: [{ role: "viewer" }] };
const baseRow: QualityRow = {
  task: "tool_selection",
  name: "t",
  input: "do the task",
  expectedTools: ["read_secret"],
  metric: "tool_call_accuracy",
};

describe("scoreQualityRow target-type dispatch", () => {
  it("MCP target routes through the agent loop and scores its tool calls", async () => {
    const config = {
      target: { type: "mcp", mcp: { transport: "stdio", command: "node", args: [] } },
      requestSchema: { messageField: "message", roleField: "role" },
      responseSchema: baseResponseSchema,
      auth: baseAuth,
      customAttacksDefaults: { authMethod: "none" },
      attackConfig: { concurrency: 1, llmProvider: "openai", llmModel: "gpt-4o-mini" },
    } as unknown as Config;

    const r = await scoreQualityRow(config, baseRow, 0, 0.7);
    expect(runQualityMcpAgent).toHaveBeenCalledOnce();
    expect(r.error).toBeUndefined();
    expect(r.statusCode).toBe(200);
    expect(r.actualTools).toEqual(["read_secret"]);
    expect(r.response).toBe("the answer from the mcp agent");
    expect(r.score).toBe(1);
    expect(r.pass).toBe(true);
  });

  it("WebSocket target routes through executeAttack and scores its response", async () => {
    const config = {
      target: {
        type: "websocket_agent",
        baseUrl: "wss://x",
        websocket: { path: "/ws" },
      },
      requestSchema: { messageField: "message", roleField: "role" },
      responseSchema: baseResponseSchema,
      auth: baseAuth,
      customAttacksDefaults: { authMethod: "none" },
      attackConfig: { concurrency: 1 },
    } as unknown as Config;

    const row: QualityRow = { ...baseRow, expectedTools: ["lookup"] };
    const r = await scoreQualityRow(config, row, 0, 0.7);
    expect(executeWebSocketAttack).toHaveBeenCalledOnce();
    expect(r.error).toBeUndefined();
    expect(r.statusCode).toBe(200);
    expect(r.actualTools).toEqual(["lookup"]);
    expect(r.score).toBe(1);
    expect(r.pass).toBe(true);
  });
});
