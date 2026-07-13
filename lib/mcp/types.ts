import type { McpTargetConfig } from "../types.js";
import type { McpTraceEvent } from "../types.js";

export interface JsonRpcRequest {
  jsonrpc: "2.0";
  id: number;
  method: string;
  params?: unknown;
}

export interface JsonRpcError {
  code: number;
  message: string;
  data?: unknown;
}

export interface JsonRpcResponse<T = unknown> {
  jsonrpc: "2.0";
  id?: number | string | null;
  result?: T;
  error?: JsonRpcError;
  method?: string;
  params?: unknown;
}

export interface McpServerInfo {
  name: string;
  version?: string;
}

export interface McpInitializeResult {
  protocolVersion?: string;
  capabilities?: Record<string, unknown>;
  serverInfo?: McpServerInfo;
  instructions?: string;
}

export interface McpToolDescriptor {
  name: string;
  description?: string;
  inputSchema?: unknown;
}

export interface McpPromptDescriptor {
  name: string;
  description?: string;
  arguments?: unknown;
}

export interface McpResourceDescriptor {
  uri: string;
  name?: string;
  description?: string;
  mimeType?: string;
}

export interface McpDiscoveryResult {
  transport: McpTargetConfig["transport"];
  serverInfo?: McpServerInfo;
  protocolVersion?: string;
  capabilities: string[];
  tools: McpToolDescriptor[];
  prompts: McpPromptDescriptor[];
  resources: McpResourceDescriptor[];
  /**
   * Server-provided instructions from the initialize result. Part of the MCP
   * metadata surface, so it is scanned for tool-poisoning / injection content
   * alongside tool and resource descriptions.
   */
  instructions?: string;
}

export interface McpRequestOptions {
  timeoutMs?: number;
}

export interface TranscriptSnapshot {
  events: McpTraceEvent[];
}
