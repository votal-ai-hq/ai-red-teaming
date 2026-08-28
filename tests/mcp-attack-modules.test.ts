import { describe, it, expect } from "vitest";
import type { AttackModule, CodebaseAnalysis } from "../lib/types.js";
import { mcpToolMisuseModule } from "../attacks-mcp/mcp-tool-misuse.js";
import { mcpDataExfiltrationModule } from "../attacks-mcp/mcp-data-exfiltration.js";
import { mcpIndirectPromptInjectionModule } from "../attacks-mcp/mcp-indirect-prompt-injection.js";
import { mcpPathTraversalModule } from "../attacks-mcp/mcp-path-traversal.js";
import { mcpSsrfModule } from "../attacks-mcp/mcp-ssrf.js";
import { mcpCrossTenantAccessModule } from "../attacks-mcp/mcp-cross-tenant-access.js";
import { mcpDebugAccessModule } from "../attacks-mcp/mcp-debug-access.js";
import { mcpToolPoisoningModule } from "../attacks-mcp/mcp-tool-poisoning.js";
import { mcpPromptPoisoningModule } from "../attacks-mcp/mcp-prompt-poisoning.js";

const MCP_MODULES: AttackModule[] = [
  mcpToolMisuseModule,
  mcpDataExfiltrationModule,
  mcpIndirectPromptInjectionModule,
  mcpPathTraversalModule,
  mcpSsrfModule,
  mcpCrossTenantAccessModule,
  mcpDebugAccessModule,
  mcpToolPoisoningModule,
  mcpPromptPoisoningModule,
];

const mockAnalysis: CodebaseAnalysis = {
  tools: [
    {
      name: "read_secret",
      description: "Read a fake secret",
      parameters: "path: string",
    },
  ],
  roles: [],
  guardrailPatterns: [],
  sensitiveData: [
    {
      type: "secret",
      location: "memory://secrets/demo",
      example: "demo-secret",
    },
  ],
  authMechanisms: ["mcp"],
  knownWeaknesses: ["MCP prompts exposed: security-review"],
  systemPromptHints: [],
  detectedFrameworks: [],
  toolChains: [],
  mcpSurface: {
    capabilities: ["tools", "prompts", "resources"],
    prompts: ["security-review", "debug-mode"],
    resources: ["memory://secrets/demo", "debug://status"],
  },
};

describe("MCP attack modules", () => {
  for (const mod of MCP_MODULES) {
    it(`${mod.category} returns valid seed attacks`, () => {
      const seeds = mod.getSeedAttacks();
      expect(seeds.length).toBeGreaterThan(0);
      for (const attack of seeds) {
        expect(attack.category).toBe(mod.category);
        expect(attack.payload.message).toBeTruthy();
        expect(typeof attack.payload._mcpOperation).toBe("string");
      }
    });

    it(`${mod.category} returns a generation prompt`, () => {
      const prompt = mod.getGenerationPrompt(mockAnalysis);
      expect(prompt.length).toBeGreaterThan(50);
      expect(prompt.toLowerCase()).toContain("mcp");
    });
  }

  it("builds MCP seed attacks from discovered tool, prompt, and resource names", () => {
    const toolSeeds = mcpToolMisuseModule.getSeedAttacks(mockAnalysis);
    const exfilSeeds = mcpDataExfiltrationModule.getSeedAttacks(mockAnalysis);
    const promptSeeds =
      mcpIndirectPromptInjectionModule.getSeedAttacks(mockAnalysis);
    const debugSeeds = mcpDebugAccessModule.getSeedAttacks(mockAnalysis);

    expect(
      toolSeeds.some((attack) => attack.payload._mcpTool === "read_secret"),
    ).toBe(true);
    expect(
      exfilSeeds.some(
        (attack) => attack.payload._mcpResourceUri === "memory://secrets/demo",
      ),
    ).toBe(true);
    expect(
      promptSeeds.some(
        (attack) => attack.payload._mcpPrompt === "security-review",
      ),
    ).toBe(true);
    expect(
      debugSeeds.some(
        (attack) => attack.payload._mcpResourceUri === "debug://status",
      ),
    ).toBe(true);
  });
});
