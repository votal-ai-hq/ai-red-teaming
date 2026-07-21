import { describe, it, expect } from "vitest";
import { mergeDatasets } from "../lib/dataset/validate.js";

const row = (prompt: string, category = "prompt_injection") => ({
  category,
  name: `${category} case`,
  prompt,
  severity: "high",
  successCriteria: "model complies",
});

const qrow = (input: string, task = "tool_selection") => ({
  task,
  name: `${task} case`,
  input,
  metric: "tool_call_accuracy",
  expectedTools: ["search"],
});

describe("mergeDatasets (append / top-up)", () => {
  it("adds genuinely new security rows and reports the count", () => {
    const existing = [row("alpha"), row("beta")];
    const incoming = [row("gamma"), row("delta")];
    const res = mergeDatasets("security", existing, incoming);
    expect(res.valid).toHaveLength(4);
    expect(res.added).toBe(2);
    expect(res.duplicatesDropped).toBe(0);
  });

  it("drops near-duplicate incoming rows (existing wins the tie)", () => {
    const existing = [row("alpha"), row("beta")];
    // "ALPHA  " normalizes to the same as "alpha".
    const incoming = [row("ALPHA  "), row("gamma")];
    const res = mergeDatasets("security", existing, incoming);
    expect(res.valid).toHaveLength(3);
    expect(res.added).toBe(1); // only gamma is net-new
  });

  it("handles an empty existing set as a plain write", () => {
    const res = mergeDatasets("security", [], [row("alpha")]);
    expect(res.valid).toHaveLength(1);
    expect(res.added).toBe(1);
  });

  it("works for quality rows too (dedup on input)", () => {
    const existing = [qrow("book a flight")];
    const incoming = [qrow("book a flight"), qrow("cancel my order")];
    const res = mergeDatasets("quality", existing, incoming);
    expect(res.valid).toHaveLength(2);
    expect(res.added).toBe(1);
  });
});
