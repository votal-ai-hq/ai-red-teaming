import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import {
  defaultCategoryPool,
  resolveCategoryPool,
  allStrategySlugs,
  isAttackCategory,
} from "../lib/dataset/category-set.js";
import {
  validateRows,
  formatHistogram,
  underFloor,
} from "../lib/dataset/validate.js";
import { buildDataDesignerConfig } from "../lib/dataset/nemo-config-builder.js";
import { recordToRow } from "../lib/dataset/map-records.js";
import {
  extractRecords,
  NemoDataDesignerClient,
} from "../lib/dataset/nemo-client.js";
import { applyGenerationOverrides } from "../lib/dataset/provider-options.js";
import { loadCustomAttacksFromConfig } from "../lib/custom-attacks-loader.js";
import { listDatasets } from "../lib/dataset/list.js";
import type { Config } from "../lib/types.js";

describe("category-set", () => {
  it("every default family pool entry is a real AttackCategory", () => {
    for (const family of ["mcp", "agent"] as const) {
      const pool = defaultCategoryPool(family);
      expect(pool.length).toBeGreaterThan(0);
      for (const c of pool) expect(isAttackCategory(c)).toBe(true);
    }
  });

  it("resolveCategoryPool rejects labels outside the union (fail-closed)", () => {
    expect(() => resolveCategoryPool("mcp", ["not_a_real_category"])).toThrow(
      /outside AttackCategory/,
    );
  });

  it("resolveCategoryPool passes through a valid subset", () => {
    const pool = resolveCategoryPool("mcp", ["tool_misuse", "debug_access"]);
    expect(pool).toEqual(["tool_misuse", "debug_access"]);
  });

  it("exposes strategy slugs as seed data", () => {
    expect(allStrategySlugs().length).toBeGreaterThan(5);
  });
});

describe("validateRows (fail-closed)", () => {
  const good = {
    category: "tool_misuse",
    name: "x",
    prompt: "do the bad thing",
    severity: "high",
    successCriteria: "the tool was misused",
  };

  it("accepts a well-formed row", () => {
    const r = validateRows([good]);
    expect(r.errors).toEqual([]);
    expect(r.valid).toHaveLength(1);
    expect(r.histogram.tool_misuse).toBe(1);
  });

  it("rejects an unknown category instead of defaulting", () => {
    const r = validateRows([{ ...good, category: "totally_made_up" }]);
    expect(r.valid).toHaveLength(0);
    expect(r.errors[0]).toMatch(/invalid category/);
  });

  it("rejects empty prompt, bad severity, empty successCriteria", () => {
    expect(validateRows([{ ...good, prompt: "" }]).errors[0]).toMatch(/empty prompt/);
    expect(validateRows([{ ...good, severity: "sev1" }]).errors[0]).toMatch(/invalid severity/);
    expect(validateRows([{ ...good, successCriteria: "" }]).errors[0]).toMatch(/empty successCriteria/);
  });

  it("drops near-duplicate prompts", () => {
    const r = validateRows([good, { ...good, prompt: "  DO the bad   thing " }]);
    expect(r.valid).toHaveLength(1);
    expect(r.duplicatesDropped).toBe(1);
  });

  it("underFloor flags categories below the balance floor", () => {
    const r = validateRows([good]);
    const short = underFloor(r.histogram, ["tool_misuse", "debug_access"], 2);
    expect(short.map((s) => s.category)).toContain("debug_access");
    expect(formatHistogram(r.histogram)).toMatch(/tool_misuse/);
  });
});

describe("buildDataDesignerConfig", () => {
  it("emits all sampler columns before any LLM column (DD requirement)", () => {
    const config = buildDataDesignerConfig({ family: "mcp", count: 10 });
    const firstLlm = config.columns.findIndex((c) => c.type !== "sampler");
    const lastSampler = config.columns
      .map((c) => c.type)
      .lastIndexOf("sampler");
    expect(lastSampler).toBeLessThan(firstLlm);
    expect(config.columns.some((c) => c.name === "prompt")).toBe(true);
    expect(config.columns.some((c) => c.name === "grading")).toBe(true);
  });

  it("seeds the category sampler from the resolved pool", () => {
    const config = buildDataDesignerConfig({
      family: "mcp",
      categories: ["tool_misuse"],
    });
    const cat = config.columns.find((c) => c.name === "category");
    expect(cat && "values" in cat && cat.values).toEqual(["tool_misuse"]);
  });

  it("single-turn (default) emits no turns sampler and the single-message template", () => {
    const config = buildDataDesignerConfig({ family: "mcp", count: 5 });
    expect(config.columns.some((c) => c.name === "turns")).toBe(false);
    const promptCol = config.columns.find((c) => c.name === "prompt");
    const text = promptCol && "prompt" in promptCol ? promptCol.prompt : "";
    expect(text).toContain("Write ONE realistic attacker message");
    expect(text).not.toContain("[Turn 1]");
  });

  it("multi-turn adds a turns sampler (2..maxTurns) and the transcript template", () => {
    const config = buildDataDesignerConfig({
      family: "mcp",
      count: 5,
      turnMode: "multi",
      maxTurns: 4,
    });
    const turns = config.columns.find((c) => c.name === "turns");
    expect(turns && "values" in turns && turns.values).toEqual(["2", "3", "4"]);
    // turns sampler must precede the LLM prompt column (DD seed-before-LLM rule)
    const turnsIdx = config.columns.findIndex((c) => c.name === "turns");
    const promptIdx = config.columns.findIndex((c) => c.name === "prompt");
    expect(turnsIdx).toBeLessThan(promptIdx);
    const promptCol = config.columns[promptIdx];
    const text = "prompt" in promptCol ? promptCol.prompt : "";
    expect(text).toContain("{{turns}}-message attacker");
    expect(text).toContain("[Turn 1]");
  });

  it("clamps maxTurns into 2..8", () => {
    const lo = buildDataDesignerConfig({ family: "mcp", turnMode: "multi", maxTurns: 1 });
    const loTurns = lo.columns.find((c) => c.name === "turns");
    expect(loTurns && "values" in loTurns && loTurns.values).toEqual(["2"]);
    const hi = buildDataDesignerConfig({ family: "mcp", turnMode: "multi", maxTurns: 99 });
    const hiTurns = hi.columns.find((c) => c.name === "turns");
    expect(hiTurns && "values" in hiTurns && (hiTurns.values as string[]).length).toBe(7);
  });

  it("defaults to the nim provider", () => {
    const config = buildDataDesignerConfig({ family: "mcp" });
    expect(config.modelProvider).toBe("nim");
    expect(config.modelConfigs[0].provider).toBe("nim");
  });

  it("propagates an OpenAI provider + model from the preset", () => {
    const config = buildDataDesignerConfig({
      family: "mcp",
      provider: "openai",
      generationModel: "gpt-4o-mini",
    });
    expect(config.modelProvider).toBe("openai");
    expect(config.modelConfigs).toEqual([
      { alias: "generator", model: "gpt-4o-mini", provider: "openai" },
    ]);
  });
});

describe("recordToRow", () => {
  it("flattens a DD record (incl. nested grading) into a row", () => {
    const row = recordToRow(
      {
        category: "tool_misuse",
        severity: "High",
        strategy: "authority_override",
        surface: "an admin tool",
        role: "admin",
        prompt: "  do it  ",
        grading: { successCriteria: "misused", expectation: "refuse" },
      },
      "mcp",
    );
    expect(row.category).toBe("tool_misuse");
    expect(row.severity).toBe("high");
    expect(row.prompt).toBe("do it");
    expect(row.successCriteria).toBe("misused");
    expect(String(row.description)).toMatch(/family=mcp/);
    // The mapped row passes strict validation.
    expect(validateRows([row]).valid).toHaveLength(1);
  });
});

describe("applyGenerationOverrides", () => {
  const base = () => ({ family: "mcp", provider: "nim" }) as never;

  it("accepts a known provider and applies its default model", () => {
    const preset = base() as { provider?: string; generationModel?: string };
    expect(applyGenerationOverrides(preset as never, { provider: "openai" })).toBeNull();
    expect(preset.provider).toBe("openai");
    expect(preset.generationModel).toBe("gpt-4o-mini");
  });

  it("an explicit model wins over the provider default", () => {
    const preset = base() as { provider?: string; generationModel?: string };
    expect(
      applyGenerationOverrides(preset as never, {
        provider: "openai",
        generationModel: "gpt-4o",
      }),
    ).toBeNull();
    expect(preset.generationModel).toBe("gpt-4o");
  });

  it("rejects unknown providers and malformed model ids (fail-closed)", () => {
    expect(
      applyGenerationOverrides(base(), { provider: "closedai" }),
    ).toMatch(/unknown provider/);
    expect(
      applyGenerationOverrides(base(), { generationModel: "bad model !!" }),
    ).toMatch(/invalid generationModel/);
    expect(
      applyGenerationOverrides(base(), { generationModel: 42 }),
    ).toMatch(/must be a string/);
  });

  it("leaves the preset untouched when no overrides are given", () => {
    const preset = base() as { provider?: string; generationModel?: string };
    expect(applyGenerationOverrides(preset as never, {})).toBeNull();
    expect(preset.provider).toBe("nim");
    expect(preset.generationModel).toBeUndefined();
  });
});

describe("NemoDataDesignerClient error handling", () => {
  const config = { columns: [] } as never;

  const clientWith = (fetchImpl: typeof fetch) =>
    new NemoDataDesignerClient({
      baseUrl: "http://dd.example:8080",
      fetchImpl,
    });

  it("returns records on a well-formed JSON response", async () => {
    const client = clientWith(async () =>
      new Response(JSON.stringify({ records: [{ a: 1 }] }), { status: 200 }),
    );
    await expect(client.generate(config, 1)).resolves.toEqual([{ a: 1 }]);
  });

  it("explains an HTML 200 response instead of throwing a JSON.parse error", async () => {
    const client = clientWith(async () =>
      new Response("<!doctype html><html><body>a web app</body></html>", {
        status: 200,
        headers: { "Content-Type": "text/html" },
      }),
    );
    await expect(client.generate(config, 1)).rejects.toThrow(
      /non-JSON body.*<!doctype html.*NEMO_DATA_DESIGNER_URL/s,
    );
    // The old failure mode must not resurface.
    await expect(client.generate(config, 1)).rejects.not.toThrow(
      /Unexpected token/,
    );
  });

  it("explains a connection failure with the resolved base url", async () => {
    const client = clientWith(async () => {
      throw Object.assign(new TypeError("fetch failed"), {
        cause: { code: "ECONNREFUSED" },
      });
    });
    await expect(client.generate(config, 1)).rejects.toThrow(
      /unreachable at http:\/\/dd\.example:8080 \(ECONNREFUSED\)/,
    );
  });

  it("still reports HTTP error statuses with the body snippet", async () => {
    const client = clientWith(async () =>
      new Response("upstream exploded", { status: 500 }),
    );
    await expect(client.generate(config, 1)).rejects.toThrow(
      /HTTP 500: upstream exploded/,
    );
  });

  it("exposes the resolved base url for diagnostics", () => {
    const client = clientWith(fetch);
    expect(client.url).toBe("http://dd.example:8080");
  });
});

describe("extractRecords", () => {
  it("handles array and enveloped payloads", () => {
    expect(extractRecords([{ a: 1 }])).toHaveLength(1);
    expect(extractRecords({ records: [{ a: 1 }, { b: 2 }] })).toHaveLength(2);
    expect(extractRecords({ nothing: true })).toEqual([]);
  });
});

describe("fixture dataset round-trips through the real loader", () => {
  it("loads every fixture row as an executable Attack", () => {
    const config = {
      requestSchema: { messageField: "message", roleField: "role" },
      auth: { credentials: [{ role: "viewer" }] },
      customAttacksFile: "data/datasets/nemo-mcp/fixture.json",
    } as unknown as Config;

    const attacks = loadCustomAttacksFromConfig(config, {
      configDir: resolve("."),
    });
    const fixture = JSON.parse(
      readFileSync(resolve("data/datasets/nemo-mcp/fixture.json"), "utf-8"),
    );
    expect(attacks.length).toBe(fixture.length);
    for (const a of attacks) {
      expect(isAttackCategory(a.category)).toBe(true);
      expect(a.payload.message).toBeTruthy();
    }
  });
});

describe("listDatasets", () => {
  it("summarizes committed datasets with counts + histogram + family", () => {
    const found = listDatasets(resolve("."));
    const fixture = found.find((d) => d.path.endsWith("nemo-mcp/fixture.json"));
    expect(fixture).toBeTruthy();
    expect(fixture!.family).toBe("mcp");
    expect(fixture!.rowCount).toBeGreaterThan(0);
    expect(Object.keys(fixture!.histogram).length).toBeGreaterThan(0);
  });

  it("returns [] when the datasets dir is absent", () => {
    expect(listDatasets(resolve("./lib"))).toEqual([]);
  });
});
