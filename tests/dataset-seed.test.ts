import { describe, it, expect } from "vitest";
import {
  seedsFromAnalysis,
  mergeSeeds,
} from "../lib/dataset/seed-from-analysis.js";
import { buildDataDesignerConfig } from "../lib/dataset/nemo-config-builder.js";
import type { CodebaseAnalysis } from "../lib/types.js";

function analysis(over: Partial<CodebaseAnalysis> = {}): CodebaseAnalysis {
  return {
    tools: [],
    roles: [],
    guardrailPatterns: [],
    sensitiveData: [],
    authMechanisms: [],
    knownWeaknesses: [],
    systemPromptHints: [],
    detectedFrameworks: [],
    toolChains: [],
    ...over,
  };
}

describe("seedsFromAnalysis", () => {
  it("derives roles and surfaces from the tool graph + MCP surface", () => {
    const a = analysis({
      tools: [
        { name: "read_file", description: "reads a file from disk", parameters: "path" },
        { name: "send_email", description: "sends email", parameters: "to,body" },
      ],
      roles: [
        { name: "admin", permissions: ["*"] },
        { name: "viewer", permissions: ["read"] },
      ],
      toolChains: [
        { source: "read_file", sink: "send_email", risk: "critical", description: "exfil" },
      ],
      mcpSurface: {
        capabilities: ["tools"],
        prompts: ["summarize"],
        resources: ["db://customers"],
      },
    });
    const seeds = seedsFromAnalysis(a);
    expect(seeds.roles).toEqual(["admin", "viewer"]);
    expect(seeds.surfaces?.some((s) => s.includes("read_file"))).toBe(true);
    expect(seeds.surfaces?.some((s) => s.includes("read_file → send_email"))).toBe(true);
    expect(seeds.surfaces?.some((s) => s.includes("MCP prompt"))).toBe(true);
    expect(seeds.surfaces?.some((s) => s.includes("db://customers"))).toBe(true);
  });

  it("returns empty seeds for an empty analysis (falls back to defaults)", () => {
    const seeds = seedsFromAnalysis(analysis());
    expect(seeds.roles).toBeUndefined();
    expect(seeds.surfaces).toBeUndefined();
  });

  it("dedups repeated tool names", () => {
    const a = analysis({
      tools: [
        { name: "lookup", description: "", parameters: "" },
        { name: "lookup", description: "", parameters: "" },
      ],
    });
    const surfaces = seedsFromAnalysis(a).surfaces ?? [];
    expect(surfaces.filter((s) => s.startsWith('tool "lookup"')).length).toBe(1);
  });
});

describe("mergeSeeds", () => {
  it("unions two seed sets, primary first, deduped", () => {
    const merged = mergeSeeds(
      { roles: ["admin"], surfaces: ["a"] },
      { roles: ["admin", "viewer"], surfaces: ["b"] },
    );
    expect(merged?.roles).toEqual(["admin", "viewer"]);
    expect(merged?.surfaces).toEqual(["a", "b"]);
  });

  it("returns the other side when one is undefined", () => {
    expect(mergeSeeds(undefined, { roles: ["x"] })?.roles).toEqual(["x"]);
    expect(mergeSeeds({ roles: ["y"] }, undefined)?.roles).toEqual(["y"]);
  });
});

describe("analysis seeds flow into the DD config", () => {
  it("populates the surface sampler from derived seeds", () => {
    const seeds = seedsFromAnalysis(
      analysis({
        tools: [{ name: "charge_card", description: "bills a customer", parameters: "amt" }],
        roles: [{ name: "cashier", permissions: ["charge"] }],
      }),
    );
    const config = buildDataDesignerConfig({ family: "mcp" }, seeds);
    const surface = config.columns.find((c) => c.name === "surface");
    const role = config.columns.find((c) => c.name === "role");
    expect(surface && "values" in surface && surface.values.some((v) => v.includes("charge_card"))).toBe(true);
    expect(role && "values" in role && role.values).toEqual(["cashier"]);
  });
});
