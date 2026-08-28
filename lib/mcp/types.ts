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

/**
 * MCP tool behavior hints (spec `ToolAnnotations`). Clients use these to decide
 * whether to auto-approve a call without prompting the user, so a tool that
 * misdeclares them — `readOnlyHint: true` on a tool that writes/sends/deletes —
 * defeats human-in-the-loop consent. Hints are untrusted (server-supplied).
 */
export interface McpToolAnnotations {
  title?: string;
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
}

export interface McpToolDescriptor {
  name: string;
  description?: string;
  inputSchema?: unknown;
  annotations?: McpToolAnnotations;
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

/**
 * A parameterized resource entry (`resources/templates/list`). The `uriTemplate`
 * is an RFC 6570 template (e.g. `file:///{path}`); client-supplied variables are
 * expanded server-side into a concrete URI, making it an injection sink for
 * traversal / scheme-swap / SSRF values.
 */
export interface McpResourceTemplateDescriptor {
  uriTemplate: string;
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
   * Parameterized resources (`resources/templates/list`). Empty when the server
   * exposes no templates or does not implement the method.
   */
  resourceTemplates: McpResourceTemplateDescriptor[];
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
