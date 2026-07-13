import type { Config } from "../types.js";
import { McpSession } from "./session.js";
import type { McpDiscoveryResult } from "./types.js";

function extractCapabilityNames(
  capabilities: Record<string, unknown> | undefined,
): string[] {
  if (!capabilities) return [];
  return Object.entries(capabilities)
    .filter(([, value]) => value != null)
    .map(([key]) => key)
    .sort();
}

export async function discoverMcpSurface(
  config: Config,
): Promise<McpDiscoveryResult> {
  const session = new McpSession(config);
  try {
    const init = await session.initialize();
    const [tools, prompts, resources] = await Promise.all([
      session.listTools().catch(() => []),
      session.listPrompts().catch(() => []),
      session.listResources().catch(() => []),
    ]);

    return {
      transport: config.target.mcp!.transport,
      serverInfo: init.serverInfo,
      protocolVersion: init.protocolVersion,
      capabilities: extractCapabilityNames(init.capabilities),
      tools,
      prompts,
      resources,
      instructions: init.instructions,
    };
  } finally {
    await session.close();
  }
}
