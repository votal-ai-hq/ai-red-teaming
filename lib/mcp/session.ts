import type { Config, McpExecutionTrace } from "../types.js";
import { createMcpTransport, type McpTransport } from "./transport.js";
import type {
  McpInitializeResult,
  McpPromptDescriptor,
  McpResourceDescriptor,
  McpResourceTemplateDescriptor,
  McpToolDescriptor,
} from "./types.js";

const DEFAULT_PROTOCOL_VERSION = "2024-11-05";

export class McpSession {
  private readonly transport: McpTransport;
  private initialized?: McpInitializeResult;

  constructor(private readonly config: Config) {
    this.transport = createMcpTransport(config);
  }

  async connect(): Promise<void> {
    await this.transport.connect(this.config);
  }

  async initialize(): Promise<McpInitializeResult> {
    if (this.initialized) return this.initialized;

    await this.connect();
    const result = await this.transport.request<McpInitializeResult>(
      "initialize",
      {
        protocolVersion: DEFAULT_PROTOCOL_VERSION,
        capabilities: {},
        clientInfo: {
          name: "wb-red-team",
          version: "phase-2",
        },
      },
      { timeoutMs: this.config.target.mcp?.startupTimeoutMs ?? 10_000 },
    );

    this.initialized = result;

    try {
      await this.transport.notify("notifications/initialized");
    } catch {
      // Best-effort only. Some servers may not care about this notification.
    }

    return result;
  }

  async listTools(): Promise<McpToolDescriptor[]> {
    await this.initialize();
    const result = await this.transport.request<{
      tools?: McpToolDescriptor[];
    }>(
      "tools/list",
      {},
      { timeoutMs: this.config.target.mcp?.sessionTimeoutMs ?? 10_000 },
    );
    return result.tools ?? [];
  }

  async callTool(
    name: string,
    args: Record<string, unknown> = {},
  ): Promise<unknown> {
    await this.initialize();
    return this.transport.request(
      "tools/call",
      { name, arguments: args },
      { timeoutMs: this.config.target.mcp?.sessionTimeoutMs ?? 10_000 },
    );
  }

  async listPrompts(): Promise<McpPromptDescriptor[]> {
    await this.initialize();
    const result = await this.transport.request<{
      prompts?: McpPromptDescriptor[];
    }>(
      "prompts/list",
      {},
      { timeoutMs: this.config.target.mcp?.sessionTimeoutMs ?? 10_000 },
    );
    return result.prompts ?? [];
  }

  async getPrompt(
    name: string,
    args: Record<string, unknown> = {},
  ): Promise<unknown> {
    await this.initialize();
    return this.transport.request(
      "prompts/get",
      { name, arguments: args },
      { timeoutMs: this.config.target.mcp?.sessionTimeoutMs ?? 10_000 },
    );
  }

  async listResources(): Promise<McpResourceDescriptor[]> {
    await this.initialize();
    const result = await this.transport.request<{
      resources?: McpResourceDescriptor[];
    }>(
      "resources/list",
      {},
      { timeoutMs: this.config.target.mcp?.sessionTimeoutMs ?? 10_000 },
    );
    return result.resources ?? [];
  }

  async listResourceTemplates(): Promise<McpResourceTemplateDescriptor[]> {
    await this.initialize();
    const result = await this.transport.request<{
      resourceTemplates?: McpResourceTemplateDescriptor[];
    }>(
      "resources/templates/list",
      {},
      { timeoutMs: this.config.target.mcp?.sessionTimeoutMs ?? 10_000 },
    );
    return result.resourceTemplates ?? [];
  }

  async readResource(uri: string): Promise<unknown> {
    await this.initialize();
    return this.transport.request(
      "resources/read",
      { uri },
      { timeoutMs: this.config.target.mcp?.sessionTimeoutMs ?? 10_000 },
    );
  }

  async close(): Promise<void> {
    await this.transport.close();
  }

  getRecentStderr(): string {
    return this.transport.getRecentStderr();
  }

  getExecutionTrace(operation?: string): McpExecutionTrace {
    return {
      transport: this.config.target.mcp!.transport,
      operation,
      serverName: this.initialized?.serverInfo?.name,
      protocolVersion: this.initialized?.protocolVersion,
      transcript: this.transport.getTranscript(),
      stderr: this.transport.getRecentStderr() || undefined,
    };
  }
}
