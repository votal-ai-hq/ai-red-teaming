import { describe, it, expect } from "vitest";
import {
  exactMatch,
  f1,
  rougeL,
  toolCallAccuracy,
  scoreDeterministic,
  DETERMINISTIC_METRICS,
} from "../lib/quality/metrics.js";
import { extractToolNames, scoreQualityRow } from "../lib/quality/scorer.js";
import { isJudgeMetric } from "../lib/quality/judge.js";
import type { Config } from "../lib/types.js";
import type { QualityRow } from "../lib/dataset/types.js";

describe("deterministic metrics", () => {
  it("exactMatch normalizes punctuation/case/space", () => {
    expect(exactMatch("A $30 fee.", "a 30 fee")).toBe(1);
    expect(exactMatch("thirty dollars", "a 30 fee")).toBe(0);
  });
  it("f1 rewards token overlap", () => {
    expect(f1("the fee is 30", "the fee is 30")).toBe(1);
    expect(f1("nothing alike here", "completely different text")).toBe(0);
    expect(f1("the fee is 30 dollars", "the fee is 30")).toBeGreaterThan(0.6);
  });
  it("rougeL rewards in-order overlap", () => {
    expect(rougeL("a b c d", "a b c d")).toBe(1);
    expect(rougeL("a b c d", "a c")).toBeGreaterThan(0);
    expect(rougeL("x y z", "a b c")).toBe(0);
  });
  it("toolCallAccuracy is order-insensitive F1 over names", () => {
    expect(toolCallAccuracy(["refund", "lookup"], ["lookup", "refund"])).toBe(1);
    expect(toolCallAccuracy([], [])).toBe(1);
    expect(toolCallAccuracy(["lookup"], ["lookup", "refund"])).toBeCloseTo(0.667, 2);
    expect(toolCallAccuracy(["wrong"], ["lookup"])).toBe(0);
  });
  it("scoreDeterministic dispatches by metric", () => {
    expect(
      scoreDeterministic("tool_call_accuracy", {
        response: "",
        actualTools: ["a"],
        expectedTools: ["a"],
      }),
    ).toBe(1);
    expect(DETERMINISTIC_METRICS.has("f1")).toBe(true);
    expect(isJudgeMetric("faithfulness")).toBe(true);
    expect(isJudgeMetric("f1")).toBe(false);
  });
});

describe("extractToolNames", () => {
  const body = {
    choices: [
      { message: { tool_calls: [{ function: { name: "lookup" } }, { function: { name: "refund" } }] } },
    ],
  };
  it("pulls names from OpenAI-shaped tool_calls", () => {
    expect(extractToolNames(body, "choices.0.message.tool_calls")).toEqual(["lookup", "refund"]);
  });
  it("returns [] when path missing", () => {
    expect(extractToolNames(body, "nope.path")).toEqual([]);
  });
});

describe("scoreQualityRow (deterministic, mocked target)", () => {
  // Config whose target is a plain HTTP echo we intercept via fetch mock.
  const config = {
    target: { type: "http_agent", baseUrl: "http://x", agentEndpoint: "/a" },
    requestSchema: { messageField: "message", roleField: "role" },
    responseSchema: { responsePath: "answer", toolCallsPath: "tools" },
    auth: { methods: ["none"], credentials: [{ role: "viewer" }] },
    customAttacksDefaults: { authMethod: "none" },
    attackConfig: { concurrency: 1 },
  } as unknown as Config;

  it("scores tool_call_accuracy from the target's tool calls", async () => {
    const origFetch = globalThis.fetch;
    // The http adapter posts to the target; return a body our paths can read.
    globalThis.fetch = (async () =>
      new Response(
        JSON.stringify({ answer: "done", tools: [{ name: "lookup" }, { name: "refund" }] }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      )) as unknown as typeof fetch;
    try {
      const row: QualityRow = {
        task: "tool_selection",
        name: "t",
        input: "refund order 91",
        expectedTools: ["lookup", "refund"],
        metric: "tool_call_accuracy",
      };
      const r = await scoreQualityRow(config, row, 0, 0.7);
      expect(r.error).toBeUndefined();
      expect(r.scorer).toBe("deterministic");
      expect(r.score).toBe(1);
      expect(r.pass).toBe(true);
      expect(r.actualTools).toEqual(["lookup", "refund"]);
    } finally {
      globalThis.fetch = origFetch;
    }
  });
});
