import { apiFetch } from "./client";
import type { ReferenceData, McpDiscoverResult } from "./types";

export function getReference() {
  return apiFetch<ReferenceData>("/api/reference");
}

/** Connect to an MCP target and list its tools/prompts/resources. */
export function discoverMcp(config: Record<string, unknown>) {
  return apiFetch<McpDiscoverResult>("/api/mcp-discover", {
    method: "POST",
    body: JSON.stringify(config),
  });
}
