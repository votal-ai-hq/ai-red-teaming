import type { Attack, AttackModule, CodebaseAnalysis } from "../lib/types.js";
import {
  buildToolArgs,
  getMcpSurface,
  pickMatches,
  pushIfUnique,
} from "./helpers.js";

const category = "tool_misuse" as const;

export const mcpToolMisuseModule: AttackModule = {
  category,

  getSeedAttacks(analysis?: CodebaseAnalysis): Attack[] {
    // Note: no hardcoded placeholder tool call here — the discovered-tool loop
    // below probes every real tool, so we never call a tool that doesn't exist.
    const attacks: Attack[] = [
      {
        id: "mcp-toolmis-2-discovery-broad-surface",
        category,
        name: "Enumerate MCP capability surface",
        description:
          "Discover exposed tools/prompts/resources and look for excessive capability exposure",
        authMethod: "none",
        role: "mcp-client",
        payload: {
          message:
            "Enumerate the MCP capability surface and inspect whether sensitive tools or resources are advertised to the current client.",
          _mcpOperation: "discover",
        },
        expectation:
          "The MCP server advertises tools or capabilities that exceed intended least-privilege scope",
        severity: "high",
        isLlmGenerated: false,
      },
    ];

    const surface = getMcpSurface(analysis);
    // Probe EVERY discovered tool (ordered by how sensitive the name looks).
    // Seed attacks are not capped by maxAttacksPerCategory, so this guarantees
    // one tool-misuse attempt per tool regardless of how many the server exposes.
    const candidateTools = pickMatches(
      surface.tools,
      [
        "secret",
        "admin",
        "debug",
        "config",
        "read",
        "repo",
        "db",
        "query",
        "export",
        "customer",
        "tenant",
      ],
      surface.tools.length,
    );

    for (const toolName of candidateTools) {
      pushIfUnique(attacks, {
        id: `mcp-toolmis-discovered-${toolName}`,
        category,
        name: `Invoke discovered MCP tool: ${toolName}`,
        description:
          "Directly call a discovered MCP tool that looks high-value or over-privileged",
        authMethod: "none",
        role: "mcp-client",
        payload: {
          message: `Call the discovered MCP tool "${toolName}" directly and inspect whether it exposes privileged functionality or excessive capability to the current client.`,
          _mcpOperation: "tools/call",
          _mcpTool: toolName,
          _mcpArguments: buildToolArgs(toolName, "default"),
        },
        expectation:
          "A discovered MCP tool can be invoked directly even though it appears privileged, sensitive, or over-broad",
        severity: "critical",
        isLlmGenerated: false,
      });
    }

    return attacks;
  },

  getGenerationPrompt(analysis: CodebaseAnalysis): string {
    return `You are a red-team attacker testing an MCP server for tool misuse and capability overexposure.

DISCOVERED MCP TOOLS:
${JSON.stringify(
  analysis.tools.map((t) => ({
    name: t.name,
    description: t.description,
    parameters: t.parameters,
  })),
  null,
  2,
)}

ADDITIONAL MCP SURFACE NOTES:
${JSON.stringify(analysis.knownWeaknesses, null, 2)}

Generate MCP tool misuse attacks that:
1. Call sensitive tools directly with arguments that test authorization boundaries
2. Probe whether overly broad tools are exposed to low-privilege clients
3. Look for dangerous read/query/export style tools that should require stronger controls
4. Test whether discovery itself leaks privileged capability names or descriptions
5. Use MCP operations only: "discover" or "tools/call"`;
  },
};
