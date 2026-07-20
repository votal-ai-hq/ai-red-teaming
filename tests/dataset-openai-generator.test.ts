import { describe, it, expect } from "vitest";
import { generateWithOpenAI, type ChatFn } from "../lib/dataset/openai-generator.js";
import { buildDataDesignerConfig } from "../lib/dataset/nemo-config-builder.js";
import { buildQualityDataDesignerConfig } from "../lib/dataset/quality-config-builder.js";
import { recordsToRows } from "../lib/dataset/map-records.js";
import { validateRows } from "../lib/dataset/validate.js";

/** A deterministic stub chat that records the prompts it was asked. */
function stubChat(): { chat: ChatFn; prompts: string[] } {
  const prompts: string[] = [];
  const chat: ChatFn = async ({ user, json }) => {
    prompts.push(user);
    if (json) {
      return JSON.stringify({
        successCriteria: "the tool was misused",
        expectation: "the agent should have refused",
        reference: "the correct answer",
        expectedTools: ["lookup"],
      });
    }
    return "a concrete synthetic attacker message";
  };
  return { chat, prompts };
}

describe("generateWithOpenAI", () => {
  it("produces Data-Designer-shaped records that pass validation", async () => {
    const { chat } = stubChat();
    const config = buildDataDesignerConfig({ family: "mcp", count: 6 });
    const records = await generateWithOpenAI(config, 6, { chat });

    expect(records).toHaveLength(6);
    const rec = records[0] as Record<string, unknown>;
    // sampler fields present at top level
    for (const k of ["category", "severity", "strategy", "role", "surface"]) {
      expect(typeof rec[k]).toBe("string");
    }
    // text column + nested structured column
    expect(typeof rec.prompt).toBe("string");
    expect(rec.grading).toMatchObject({ successCriteria: expect.any(String) });

    // round-trips through the real mapper + validator
    const { valid, errors } = validateRows(recordsToRows(records, "mcp"));
    expect(errors).toEqual([]);
    expect(valid.length).toBeGreaterThan(0);
  });

  it("round-robins the category axis for even coverage", async () => {
    const { chat } = stubChat();
    const config = buildDataDesignerConfig({
      family: "mcp",
      categories: ["tool_misuse", "debug_access"],
      count: 4,
    });
    const records = await generateWithOpenAI(config, 4, { chat });
    const cats = records.map((r) => (r as Record<string, string>).category);
    // 4 rows over 2 categories, round-robined → 2 each
    expect(cats.filter((c) => c === "tool_misuse")).toHaveLength(2);
    expect(cats.filter((c) => c === "debug_access")).toHaveLength(2);
  });

  it("renders {{turns}} into the text prompt for multi-turn configs", async () => {
    const { chat, prompts } = stubChat();
    const config = buildDataDesignerConfig({
      family: "mcp",
      count: 1,
      turnMode: "multi",
      maxTurns: 3,
    });
    await generateWithOpenAI(config, 1, { chat });
    // the first (text) prompt should carry a concrete turn count, not "{{turns}}"
    expect(prompts[0]).not.toContain("{{turns}}");
    expect(prompts[0]).toMatch(/[23]-message attacker/);
  });

  it("works for quality configs too (task/metric/input/grading)", async () => {
    const { chat } = stubChat();
    const config = buildQualityDataDesignerConfig({
      family: "agent",
      kind: "quality",
      count: 2,
    });
    const records = await generateWithOpenAI(config, 2, { chat });
    const rec = records[0] as Record<string, unknown>;
    expect(typeof rec.task).toBe("string");
    expect(typeof rec.metric).toBe("string");
    expect(typeof rec.input).toBe("string");
    expect(rec.grading).toMatchObject({ reference: expect.any(String) });
  });

  it("throws without an API key and without an injected chat", async () => {
    const prev = process.env.OPENAI_API_KEY;
    delete process.env.OPENAI_API_KEY;
    const config = buildDataDesignerConfig({ family: "mcp", count: 1 });
    await expect(generateWithOpenAI(config, 1)).rejects.toThrow(/OPENAI_API_KEY/);
    if (prev !== undefined) process.env.OPENAI_API_KEY = prev;
  });

  it("salvages a JSON object wrapped in prose", async () => {
    const chat: ChatFn = async ({ json }) =>
      json
        ? 'Sure! Here you go:\n{"successCriteria":"x","expectation":"y"}\nHope that helps'
        : "msg";
    const config = buildDataDesignerConfig({ family: "mcp", count: 1 });
    const records = await generateWithOpenAI(config, 1, { chat });
    expect((records[0] as Record<string, unknown>).grading).toEqual({
      successCriteria: "x",
      expectation: "y",
    });
  });
});
