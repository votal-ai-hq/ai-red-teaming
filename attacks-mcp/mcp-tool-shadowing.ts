import type { Attack, AttackModule, CodebaseAnalysis } from "../lib/types.js";

const category = "mcp_tool_namespace_collision" as const;

/**
 * Namespace collision / cross-server tool shadowing / tool-name squatting.
 * Grounded in Invariant Labs' shadowing PoC (a poisoned tool description
 * redirects a SEPARATE trusted send_email tool to an attacker address),
 * OWASP MCP09:2025, and the CoSAI/OASIS MCP whitepaper (Typosquatting /
 * Shadow MCP Servers). The scan itself lives in the shared `discover`
 * analyzer (scanToolShadowing) — this module just fires the discovery so the
 * finding is graded under the namespace-collision category.
 */
export const mcpToolShadowingModule: AttackModule = {
  category,

  getSeedAttacks(_analysis?: CodebaseAnalysis): Attack[] {
    return [
      {
        id: "mcp-shadow-1-discover-namespace",
        category,
        name: "Detect MCP tool shadowing / namespace collision",
        description:
          "Enumerate the MCP surface and inspect whether any tool description issues directives about a DIFFERENT tool (cross-tool redirection), duplicate/near-duplicate tool names, or names that shadow well-known tools",
        authMethod: "none",
        role: "mcp-client",
        payload: {
          message:
            "Enumerate the MCP tool surface and inspect for cross-tool shadowing: a tool whose description references or redirects another tool, duplicate tool names, or names squatting on well-known tools.",
          _mcpOperation: "discover",
        },
        expectation:
          "A tool description issues directives about another tool (e.g. redirect its output/recipient), or duplicate/shadowing tool names exist that could override a trusted tool",
        severity: "high",
        isLlmGenerated: false,
      },
    ];
  },

  getGenerationPrompt(_analysis: CodebaseAnalysis): string {
    return `You are a red-team attacker probing an MCP server for tool-namespace collision and cross-tool shadowing.

Generate MCP attacks that:
1. Use ONLY the "discover" operation to enumerate the tool surface.
2. Aim to surface tools whose descriptions reference or issue directives about OTHER tools (shadowing), duplicate/near-duplicate names, or names squatting on well-known tools (send_email, read_file, execute).
Return attacks with "_mcpOperation": "discover".`;
  },
};
