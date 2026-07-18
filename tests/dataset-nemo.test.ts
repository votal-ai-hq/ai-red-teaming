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
import { extractRecords } from "../lib/dataset/nemo-client.js";
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
