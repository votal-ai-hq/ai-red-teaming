import { describe, it, expect } from "vitest";
import { estimateCost } from "../lib/dataset/cost-estimate.js";

describe("estimateCost", () => {
  it("prices a known OpenAI model and scales with count", () => {
    const a = estimateCost({ backend: "openai", model: "gpt-4o-mini", count: 100 });
    const b = estimateCost({ backend: "openai", model: "gpt-4o-mini", count: 200 });
    expect(a.priced).toBe(true);
    expect(a.usd).toBeGreaterThan(0);
    expect(a.calls).toBe(200); // 2 calls per row
    // Doubling the row count roughly doubles the cost.
    expect(b.usd).toBeCloseTo(a.usd * 2, 6);
  });

  it("matches the longest model substring (gpt-4o-mini over gpt-4o)", () => {
    const mini = estimateCost({ backend: "openai", model: "gpt-4o-mini", count: 100 });
    const full = estimateCost({ backend: "openai", model: "gpt-4o", count: 100 });
    // gpt-4o is priced much higher than gpt-4o-mini.
    expect(full.usd).toBeGreaterThan(mini.usd * 5);
  });

  it("treats Ollama as free (local)", () => {
    const c = estimateCost({ backend: "ollama", model: "llama3", count: 300 });
    expect(c.usd).toBe(0);
    expect(c.priced).toBe(true);
    expect(c.note).toMatch(/local/i);
  });

  it("returns an unpriced estimate for data-designer", () => {
    const c = estimateCost({ backend: "data-designer", count: 100 });
    expect(c.priced).toBe(false);
  });

  it("falls back to the engine default price for an unknown model", () => {
    const c = estimateCost({ backend: "anthropic", model: "some-future-model", count: 50 });
    expect(c.priced).toBe(true);
    expect(c.usd).toBeGreaterThan(0);
  });

  it("multi-turn costs more output than single-turn", () => {
    const single = estimateCost({
      backend: "openai",
      model: "gpt-4o-mini",
      count: 100,
      turnMode: "single",
    });
    const multi = estimateCost({
      backend: "openai",
      model: "gpt-4o-mini",
      count: 100,
      turnMode: "multi",
      maxTurns: 5,
    });
    expect(multi.outputTokens).toBeGreaterThan(single.outputTokens);
    expect(multi.usd).toBeGreaterThan(single.usd);
  });

  it("a zero count is free with zero calls", () => {
    const c = estimateCost({ backend: "openai", model: "gpt-4o-mini", count: 0 });
    expect(c.calls).toBe(0);
    expect(c.usd).toBe(0);
  });
});
