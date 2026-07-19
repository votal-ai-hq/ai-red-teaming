import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  resolveQualityPool,
  defaultQualityPool,
  isQualityMetric,
  isQualityTask,
} from "../lib/dataset/quality-set.js";
import { validateQualityRows } from "../lib/dataset/validate.js";
import { buildQualityDataDesignerConfig } from "../lib/dataset/quality-config-builder.js";
import { recordToQualityRow } from "../lib/dataset/map-records.js";
import { listDatasets } from "../lib/dataset/list.js";

describe("quality-set", () => {
  it("family pools are non-empty and self-consistent", () => {
    for (const f of ["mcp", "agent"] as const) {
      const pool = defaultQualityPool(f);
      expect(pool.length).toBeGreaterThan(0);
      for (const t of pool) expect(isQualityTask(t)).toBe(true);
    }
  });
  it("resolveQualityPool rejects unknown tasks (fail-closed)", () => {
    expect(() => resolveQualityPool("mcp", ["not_a_task"])).toThrow(/unknown tasks/);
  });
  it("knows its metrics", () => {
    expect(isQualityMetric("tool_call_accuracy")).toBe(true);
    expect(isQualityMetric("nonsense")).toBe(false);
  });
});

describe("validateQualityRows (fail-closed)", () => {
  const good = {
    task: "tool_selection",
    name: "x",
    input: "refund order 91 and email the customer",
    expectedTools: ["lookup", "refund"],
    metric: "tool_call_accuracy",
  };
  it("accepts a well-formed quality row", () => {
    const r = validateQualityRows([good]);
    expect(r.errors).toEqual([]);
    expect(r.valid).toHaveLength(1);
    expect(r.histogram.tool_selection).toBe(1);
  });
  it("rejects unknown task / metric", () => {
    expect(validateQualityRows([{ ...good, task: "bogus" }]).errors[0]).toMatch(/unknown quality task/);
    expect(validateQualityRows([{ ...good, metric: "bogus" }]).errors[0]).toMatch(/unknown metric/);
  });
  it("rejects a row with no reference and no expectedTools", () => {
    const r = validateQualityRows([{ task: "rag_answer", input: "q?", metric: "faithfulness" }]);
    expect(r.valid).toHaveLength(0);
    expect(r.errors[0]).toMatch(/no reference or expectedTools/);
  });
  it("accepts reference-only rows and dedups by input", () => {
    const ref = { task: "rag_answer", input: "refund window?", reference: "30 days", metric: "faithfulness" };
    const r = validateQualityRows([ref, { ...ref, input: " Refund   window? " }]);
    expect(r.valid).toHaveLength(1);
    expect(r.duplicatesDropped).toBe(1);
  });
});

describe("buildQualityDataDesignerConfig", () => {
  it("samplers precede LLM columns and emit task+metric seeds", () => {
    const c = buildQualityDataDesignerConfig({ family: "mcp", kind: "quality" });
    const firstLlm = c.columns.findIndex((x) => x.type !== "sampler");
    const lastSampler = c.columns.map((x) => x.type).lastIndexOf("sampler");
    expect(lastSampler).toBeLessThan(firstLlm);
    expect(c.columns.some((x) => x.name === "task")).toBe(true);
    expect(c.columns.some((x) => x.name === "metric")).toBe(true);
    expect(c.columns.some((x) => x.name === "input")).toBe(true);
  });
});

describe("recordToQualityRow", () => {
  it("parses expectedTools from a JSON-array string and validates", () => {
    const row = recordToQualityRow({
      task: "tool_selection",
      metric: "tool_call_accuracy",
      input: "do the task",
      grading: { reference: "call the tools", expectedTools: '["a","b"]' },
    });
    expect(row.expectedTools).toEqual(["a", "b"]);
    expect(validateQualityRows([row]).valid).toHaveLength(1);
  });
});

describe("listDatasets infers kind", () => {
  it("flags the quality fixture as kind=quality with task histogram", () => {
    const found = listDatasets(resolve("."));
    const q = found.find((d) => d.path.endsWith("quality-agent/fixture.json"));
    expect(q).toBeTruthy();
    expect(q!.kind).toBe("quality");
    expect(q!.rowCount).toBe(
      JSON.parse(readFileSync(resolve("data/datasets/quality-agent/fixture.json"), "utf-8")).length,
    );
    const sec = found.find((d) => d.path.endsWith("nemo-mcp/fixture.json"));
    expect(sec!.kind).toBe("security");
  });
});
