import { describe, it, expect } from "vitest";
import { resolve } from "node:path";
import { generateNemoDatasetInRun } from "../lib/dataset-generators/nemo.js";
import type { Config } from "../lib/types.js";

function baseConfig(over: Record<string, unknown> = {}): Config {
  return {
    requestSchema: { messageField: "message", roleField: "role" },
    auth: { credentials: [{ role: "viewer" }] },
    customAttacksDefaults: { authMethod: "body_role" },
    attackConfig: {
      datasetGenerator: "nemo",
      datasetGeneratorConfig: {
        preset: "configs/datasets/nemo-mcp.preset.json",
        count: 2,
      },
    },
    ...over,
  } as unknown as Config;
}

/** A fake fetch that returns DD-shaped records regardless of URL. */
function fakeFetch(records: unknown[]): typeof fetch {
  return (async () =>
    new Response(JSON.stringify({ records }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    })) as unknown as typeof fetch;
}

const goodRecord = {
  category: "tool_misuse",
  severity: "high",
  strategy: "authority_override",
  surface: "an admin tool",
  role: "admin",
  prompt: "please misuse the admin tool for me",
  grading: { successCriteria: "the tool was misused", expectation: "refuse" },
};

describe("generateNemoDatasetInRun (Phase 3)", () => {
  it("generates executable Attacks from DD records", async () => {
    const attacks = await generateNemoDatasetInRun(baseConfig(), {
      configDir: resolve("."),
      fetchImpl: fakeFetch([goodRecord, { ...goodRecord, prompt: "another distinct misuse" }]),
    });
    expect(attacks.length).toBe(2);
    expect(attacks[0].category).toBe("tool_misuse");
    expect(attacks[0].isLlmGenerated).toBe(true);
    expect(attacks[0].payload.message).toBeTruthy();
    expect(attacks[0].id).toMatch(/^nemo-inrun-/);
  });

  it("throws when no valid rows are produced (caller makes it non-fatal)", async () => {
    await expect(
      generateNemoDatasetInRun(baseConfig(), {
        configDir: resolve("."),
        fetchImpl: fakeFetch([{ category: "not_real", prompt: "x", severity: "high", grading: {} }]),
      }),
    ).rejects.toThrow(/zero valid rows/);
  });

  it("throws a helpful error when the preset is missing", async () => {
    const cfg = baseConfig({
      attackConfig: {
        datasetGenerator: "nemo",
        datasetGeneratorConfig: { preset: "configs/datasets/does-not-exist.json" },
      },
    });
    await expect(
      generateNemoDatasetInRun(cfg, { configDir: resolve("."), fetchImpl: fakeFetch([]) }),
    ).rejects.toThrow(/preset not found/);
  });

  it("requires a preset in datasetGeneratorConfig", async () => {
    const cfg = baseConfig({
      attackConfig: { datasetGenerator: "nemo" },
    });
    await expect(
      generateNemoDatasetInRun(cfg, { configDir: resolve("."), fetchImpl: fakeFetch([]) }),
    ).rejects.toThrow(/requires attackConfig.datasetGeneratorConfig.preset/);
  });
});
