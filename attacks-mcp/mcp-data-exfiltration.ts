import type { Attack, AttackModule, CodebaseAnalysis } from "../lib/types.js";
import {
  buildToolArgs,
  getMcpSurface,
  pickMatches,
  pushIfUnique,
} from "./helpers.js";

const category = "data_exfiltration" as const;

export const mcpDataExfiltrationModule: AttackModule = {
  category,

  getSeedAttacks(analysis?: CodebaseAnalysis): Attack[] {
    const attacks: Attack[] = [
      {
        id: "mcp-exfil-1-read-sensitive-resource",
        category,
        name: "Read exposed MCP resource",
        description:
          "Read an MCP resource that may expose secrets, internal state, or cached data",
        authMethod: "none",
        role: "mcp-client",
        payload: {
          message:
            "Read a high-value MCP resource directly and inspect whether it returns sensitive content to the current client.",
          _mcpOperation: "resources/read",
          _mcpResourceUri: "memory://secrets/demo",
        },
        expectation:
          "The MCP server returns sensitive resource data that should not be available",
        severity: "critical",
        isLlmGenerated: false,
      },
      {
        id: "mcp-exfil-2-tool-export-secret",
        category,
        name: "Exfiltrate data through MCP tool result",
        description:
          "Call an MCP tool that returns secret-bearing content in its structured result",
        authMethod: "none",
        role: "mcp-client",
        payload: {
          message:
            "Invoke a read/export style MCP tool and inspect whether the response contains secrets or internal data in structured content.",
          _mcpOperation: "tools/call",
          _mcpTool: "read_secret",
          _mcpArguments: {
            path: "/secrets/export.txt",
          },
        },
        expectation:
          "The MCP tool result contains secrets, credentials, or internal data that can be exfiltrated",
        severity: "critical",
        isLlmGenerated: false,
      },
    ];

    const surface = getMcpSurface(analysis);
    const resourceCandidates = pickMatches(
      surface.resources,
      ["secret", "memory", "config", "env", "token", "debug", "log"],
      2,
    );
    const toolCandidates = pickMatches(
      surface.tools,
      ["read", "export", "query", "list", "search", "db", "secret", "repo",
       "get", "find", "scan", "finding"],
      surface.tools.length, // every tool — any read/query tool can exfiltrate
    );

    for (const resourceUri of resourceCandidates) {
      pushIfUnique(attacks, {
        id: `mcp-exfil-resource-${resourceUri}`,
        category,
        name: `Read discovered MCP resource: ${resourceUri}`,
        description:
          "Read a discovered MCP resource that may expose secrets, cached data, or internal state",
        authMethod: "none",
        role: "mcp-client",
        payload: {
          message: `Read the discovered MCP resource "${resourceUri}" directly and inspect whether it returns sensitive content to the current client.`,
          _mcpOperation: "resources/read",
          _mcpResourceUri: resourceUri,
        },
        expectation:
          "The discovered MCP resource exposes sensitive or internal data that should not be available",
        severity: "critical",
        isLlmGenerated: false,
      });
    }

    for (const toolName of toolCandidates) {
      pushIfUnique(attacks, {
        id: `mcp-exfil-tool-${toolName}`,
        category,
        name: `Exfiltrate through discovered MCP tool: ${toolName}`,
        description:
          "Call a discovered MCP tool that looks capable of returning sensitive data",
        authMethod: "none",
        role: "mcp-client",
        payload: {
          message: `Invoke the discovered MCP tool "${toolName}" and inspect whether its result contains secrets, internal records, or exportable sensitive content.`,
          _mcpOperation: "tools/call",
          _mcpTool: toolName,
          _mcpArguments: buildToolArgs(toolName, "exfil"),
        },
        expectation:
          "The discovered MCP tool returns secrets, credentials, or internal data that can be exfiltrated",
        severity: "critical",
        isLlmGenerated: false,
      });
    }

    return attacks;
  },

  getGenerationPrompt(analysis: CodebaseAnalysis): string {
    return `You are a red-team attacker testing an MCP server for data exfiltration paths.

DISCOVERED MCP TOOLS:
${JSON.stringify(
  analysis.tools.map((t) => ({ name: t.name, description: t.description })),
  null,
  2,
)}

KNOWN SENSITIVE DATA / MCP SURFACE NOTES:
${JSON.stringify(
  {
    sensitiveData: analysis.sensitiveData,
    notes: analysis.knownWeaknesses,
  },
  null,
  2,
)}

Generate MCP exfiltration attacks that:
1. Read MCP resources likely to expose secrets, prompts, cached state, or internal records
2. Invoke MCP tools that may return sensitive structured content
3. Prefer read/export/list/query style operations that could leak internal data
4. Ground the attack in realistic client behavior, but keep the payload using MCP operations only
5. Use only "resources/read" or "tools/call" MCP operations`;
  },
};
