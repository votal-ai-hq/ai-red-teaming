import type { NemoRecord } from "./nemo-client.js";

export type McpDatasetOperation =
  | "tools/call"
  | "resources/read"
  | "prompts/get";

export interface McpDatasetExecution {
  _mcpOperation: McpDatasetOperation;
  _mcpTool?: string;
  _mcpResourceUri?: string;
  _mcpPrompt?: string;
  _mcpArguments?: Record<string, unknown>;
}

/**
 * Resolve an executable MCP target from a generated surface sampler.
 *
 * Analysis/profile seeds use one of these forms:
 * - tool "name" / MCP tool name
 * - MCP prompt "name"
 * - MCP resource "uri"
 */
export function executionForMcpSurface(
  surface: string,
): Omit<McpDatasetExecution, "_mcpArguments"> | null {
  const resource = surface.match(/\bMCP\s+resource\s+"([^"]+)"/i);
  if (resource?.[1]) {
    return {
      _mcpOperation: "resources/read",
      _mcpResourceUri: resource[1].trim(),
    };
  }

  const prompt = surface.match(/\bMCP\s+prompt\s+"([^"]+)"/i);
  if (prompt?.[1]) {
    return {
      _mcpOperation: "prompts/get",
      _mcpPrompt: prompt[1].trim(),
    };
  }

  const quotedTool = surface.match(/\b(?:MCP\s+)?tool\s+"([^"]+)"/i);
  const unquotedTool = surface.match(
    /\bMCP\s+tool\s+([A-Za-z0-9][A-Za-z0-9_.:/-]*)/i,
  );
  const tool = quotedTool?.[1] ?? unquotedTool?.[1];
  if (tool && tool.toLowerCase() !== "chain") {
    return {
      _mcpOperation: "tools/call",
      _mcpTool: tool.trim(),
    };
  }

  return null;
}

/** Return every balanced JSON object embedded in text, including HTTP examples. */
function jsonObjects(text: string): Record<string, unknown>[] {
  const found: Record<string, unknown>[] = [];
  for (let start = 0; start < text.length; start++) {
    if (text[start] !== "{") continue;
    let depth = 0;
    let quoted = false;
    let escaped = false;
    for (let end = start; end < text.length; end++) {
      const ch = text[end];
      if (quoted) {
        if (escaped) escaped = false;
        else if (ch === "\\") escaped = true;
        else if (ch === '"') quoted = false;
        continue;
      }
      if (ch === '"') quoted = true;
      else if (ch === "{") depth++;
      else if (ch === "}") {
        depth--;
        if (depth === 0) {
          try {
            const parsed = JSON.parse(text.slice(start, end + 1));
            if (
              parsed &&
              typeof parsed === "object" &&
              !Array.isArray(parsed)
            ) {
              found.push(parsed as Record<string, unknown>);
            }
          } catch {
            // The model may include a malformed example before a valid object.
          }
          start = end;
          break;
        }
      }
    }
  }
  return found;
}

/**
 * Convert one Data Designer record into the MCP-native fields consumed by the
 * target adapter. Tool/prompt/resource identity is derived from the sampled
 * discovered surface, never invented by the model.
 */
export function executionFromMcpRecord(
  rec: NemoRecord,
): McpDatasetExecution | null {
  const target = executionForMcpSurface(String(rec.surface ?? ""));
  if (!target) return null;

  if (
    target._mcpOperation === "tools/call" ||
    target._mcpOperation === "prompts/get"
  ) {
    const explicit = rec._mcpArguments;
    const args =
      explicit && typeof explicit === "object" && !Array.isArray(explicit)
        ? (explicit as Record<string, unknown>)
        : (jsonObjects(String(rec.prompt ?? "")).at(-1) ?? {});
    return { ...target, _mcpArguments: args };
  }

  return target;
}
