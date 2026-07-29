import { describe, it, expect } from "vitest";
import {
  priceFor,
  computeCostUsd,
  normalizeModel,
  claudeSonnet5Price,
} from "../lib/llm-pricing.js";
import {
  UsageCollector,
  withUsageContext,
  recordLlmUsage,
  activeUsageCollector,
  classifyLlmError,
} from "../lib/llm-usage.js";

describe("llm-pricing: normalization", () => {
  it("strips provider prefix, date, and version dashes", () => {
    expect(normalizeModel("anthropic/claude-sonnet-4.5")).toBe("claude-sonnet-4.5");
    expect(normalizeModel("claude-sonnet-4-20250514")).toBe("claude-sonnet-4");
    expect(normalizeModel("claude-sonnet-4-5-20250929")).toBe("claude-sonnet-4.5");
    expect(normalizeModel("gpt-4o-2024-08-06")).toBe("gpt-4o");
    expect(normalizeModel("claude-haiku-4-5")).toBe("claude-haiku-4.5");
    expect(normalizeModel("z-ai/glm-5.1:thinking")).toBe("glm-5.1");
  });
});

describe("llm-pricing: priceFor", () => {
  it("prices the models used in a real scan config", () => {
    // generation model
    expect(priceFor("anthropic", "claude-sonnet-4-20250514")).toEqual({ inputPer1M: 3, outputPer1M: 15 });
    // judge model
    expect(priceFor("openai", "gpt-5.1")).toEqual({ inputPer1M: 1.25, outputPer1M: 10 });
  });

  it("prices all five families", () => {
    expect(priceFor("openai", "gpt-4o")).toEqual({ inputPer1M: 2.5, outputPer1M: 10 });
    expect(priceFor("anthropic", "claude-opus-4.8")).toEqual({ inputPer1M: 5, outputPer1M: 25 });
    expect(priceFor("alibaba", "qwen-plus")).toEqual({ inputPer1M: 0.4, outputPer1M: 1.2 });
    expect(priceFor("zhipu", "glm-5.1")).toEqual({ inputPer1M: 1.4, outputPer1M: 4.4 });
    expect(priceFor("together", "llama-3.3-70b-instruct")).toEqual({ inputPer1M: 1.04, outputPer1M: 1.04 });
  });

  it("returns null for an unknown model (never guesses)", () => {
    expect(priceFor("custom", "some-internal-model-x")).toBeNull();
  });

  it("honors a per-run override by model or provider/model", () => {
    const overrides = { "glm-5.1": { inputPer1M: 0.9, outputPer1M: 3 } };
    expect(priceFor("zhipu", "glm-5.1", overrides)).toEqual({ inputPer1M: 0.9, outputPer1M: 3 });
    const provScoped = { "openai/gpt-4o": { inputPer1M: 1, outputPer1M: 2 } };
    expect(priceFor("openai", "gpt-4o", provScoped)).toEqual({ inputPer1M: 1, outputPer1M: 2 });
  });

  it("switches Claude Sonnet 5 from intro to standard on 2026-09-01", () => {
    expect(claudeSonnet5Price(new Date("2026-08-15T00:00:00Z"))).toEqual({ inputPer1M: 2, outputPer1M: 10 });
    expect(claudeSonnet5Price(new Date("2026-09-01T00:00:00Z"))).toEqual({ inputPer1M: 3, outputPer1M: 15 });
    expect(priceFor("anthropic", "claude-sonnet-5", undefined, new Date("2026-08-15T00:00:00Z")))
      .toEqual({ inputPer1M: 2, outputPer1M: 10 });
  });
});

describe("llm-pricing: computeCostUsd", () => {
  it("computes cost from tokens × price", () => {
    // gpt-4o: 1M in @ $2.5 + 0.5M out @ $10 = 2.5 + 5 = 7.5
    expect(computeCostUsd("openai", "gpt-4o", 1_000_000, 500_000)).toBeCloseTo(7.5, 6);
  });
  it("returns null for unpriced models", () => {
    expect(computeCostUsd("custom", "mystery-model", 1000, 1000)).toBeNull();
  });
});

describe("UsageCollector.summarize", () => {
  it("aggregates totals, byModel, byPhase, and errors", () => {
    const c = new UsageCollector();
    c.record({ provider: "anthropic", model: "claude-sonnet-4", phase: "generation", inputTokens: 1_000_000, outputTokens: 200_000, latencyMs: 1000, ok: true, tokensReported: true });
    c.record({ provider: "openai", model: "gpt-5.1", phase: "judging", inputTokens: 500_000, outputTokens: 100_000, latencyMs: 800, ok: true, tokensReported: true });
    c.record({ provider: "openai", model: "gpt-5.1", phase: "judging", inputTokens: 0, outputTokens: 0, latencyMs: 200, ok: false, errorKind: "rate_limit", tokensReported: false });

    const s = c.summarize();
    expect(s.totalCalls).toBe(3);
    expect(s.failedCalls).toBe(1);
    expect(s.errorsByKind.rate_limit).toBe(1);
    expect(s.inputTokens).toBe(1_500_000);
    expect(s.outputTokens).toBe(300_000);
    expect(s.totalTokens).toBe(1_800_000);
    expect(s.llmLatencyMsTotal).toBe(2000);
    // cost: sonnet-4 (3/15): 3 + 3 = 6 ; gpt-5.1 (1.25/10): 0.625 + 1 = 1.625 ; total 7.625
    expect(s.costUsd).toBeCloseTo(7.625, 4);
    expect(s.costComplete).toBe(true);
    expect(s.byModel).toHaveLength(2);
    expect(s.byPhase.map((p) => p.phase).sort()).toEqual(["generation", "judging"]);
    const gpt = s.byModel.find((m) => m.model === "gpt-5.1")!;
    expect(gpt.calls).toBe(2);
    expect(gpt.priced).toBe(true);
  });

  it("marks cost partial and lists unpriced models, keeping tokens honest", () => {
    const c = new UsageCollector();
    c.record({ provider: "custom", model: "mystery-x", phase: "generation", inputTokens: 100_000, outputTokens: 50_000, latencyMs: 500, ok: true, tokensReported: true });
    const s = c.summarize();
    expect(s.costComplete).toBe(false);
    expect(s.unpricedModels).toContain("custom/mystery-x");
    expect(s.inputTokens).toBe(100_000); // tokens still counted
    expect(s.costUsd).toBeNull(); // nothing priceable
  });

  it("flags incomplete tokens when a provider does not report usage", () => {
    const c = new UsageCollector();
    c.record({ provider: "nim", model: "llama-3.1-8b-instruct", phase: "generation", inputTokens: 0, outputTokens: 0, latencyMs: 300, ok: true, tokensReported: false });
    expect(c.summarize().tokensComplete).toBe(false);
  });
});

describe("recordLlmUsage + async context", () => {
  it("is a no-op outside a run context", () => {
    expect(activeUsageCollector()).toBeUndefined();
    expect(() => recordLlmUsage({ provider: "openai", model: "gpt-4o", latencyMs: 1, ok: true, tokensReported: false })).not.toThrow();
  });

  it("isolates concurrent runs — no cross-contamination", async () => {
    const runScan = (provider: string, model: string, n: number) =>
      withUsageContext(new UsageCollector(), async () => {
        const c = activeUsageCollector()!;
        for (let i = 0; i < n; i++) {
          await Promise.resolve();
          recordLlmUsage({ provider, model, phase: "generation", inputTokens: 100, outputTokens: 50, latencyMs: 10, ok: true, tokensReported: true });
        }
        return c.summarize();
      });

    // Launch two scans concurrently in the same tick (the dashboard's pattern).
    const [a, b] = await Promise.all([
      runScan("anthropic", "claude-sonnet-4", 3),
      runScan("openai", "gpt-5.1", 5),
    ]);

    expect(a.totalCalls).toBe(3);
    expect(a.byModel).toHaveLength(1);
    expect(a.byModel[0].model).toBe("claude-sonnet-4");
    expect(b.totalCalls).toBe(5);
    expect(b.byModel).toHaveLength(1);
    expect(b.byModel[0].model).toBe("gpt-5.1");
  });
});

describe("classifyLlmError", () => {
  it("classifies rate limit, timeout, and other", () => {
    expect(classifyLlmError({ status: 429 })).toBe("rate_limit");
    expect(classifyLlmError(new Error("Request timed out"))).toBe("timeout");
    expect(classifyLlmError(new Error("boom"))).toBe("other");
  });
});
