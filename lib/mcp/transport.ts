import { createInterface } from "node:readline";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import type { Config } from "../types.js";
import type { McpTraceEvent } from "../types.js";
import type {
  JsonRpcRequest,
  JsonRpcResponse,
  McpRequestOptions,
} from "./types.js";

interface PendingRequest {
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
  timeout?: NodeJS.Timeout;
}

export interface McpTransport {
  connect(config: Config): Promise<void>;
  request<T = unknown>(
    method: string,
    params?: unknown,
    options?: McpRequestOptions,
  ): Promise<T>;
  notify(method: string, params?: unknown): Promise<void>;
  close(): Promise<void>;
  getRecentStderr(): string;
  getTranscript(): McpTraceEvent[];
  /** Server-assigned session id (streamable_http). Undefined for stdio. */
  getSessionId(): string | undefined;
}

export function createMcpTransport(config: Config): McpTransport {
  const transport = config.target.mcp?.transport;
  switch (transport) {
    case "stdio":
      return new McpStdioTransport();
    case "streamable_http":
      return new McpStreamableHttpTransport();
    default:
      throw new Error(
        `MCP transport "${transport ?? "unknown"}" is not implemented yet`,
      );
  }
}

export class McpStdioTransport implements McpTransport {
  private child?: ChildProcessWithoutNullStreams;
  private nextId = 1;
  private pending = new Map<number, PendingRequest>();
  private stderrBuffer: string[] = [];
  private transcript: McpTraceEvent[] = [];

  async connect(config: Config): Promise<void> {
    const mcp = config.target.mcp;
    if (!mcp || mcp.transport !== "stdio" || !mcp.command) {
      throw new Error("MCP stdio transport requires target.mcp.command");
    }
    if (this.child) return;

    this.child = spawn(mcp.command, mcp.args ?? [], {
      env: { ...process.env, ...(mcp.env ?? {}) },
      stdio: "pipe",
    });

    this.child.stderr.on("data", (chunk) => {
      this.stderrBuffer.push(chunk.toString());
      if (this.stderrBuffer.length > 20) {
        this.stderrBuffer.shift();
      }
    });

    this.child.on("error", (error) => {
      this.failAllPending(
        new Error(`MCP stdio process error: ${(error as Error).message}`),
      );
    });

    this.child.on("exit", (code, signal) => {
      this.failAllPending(
        new Error(
          `MCP stdio process exited before response (code=${code ?? "null"}, signal=${signal ?? "null"})`,
        ),
      );
      this.child = undefined;
    });

    const rl = createInterface({ input: this.child.stdout });
    rl.on("line", (line) => {
      this.handleLine(line);
    });
  }

  async request<T = unknown>(
    method: string,
    params?: unknown,
    options: McpRequestOptions = {},
  ): Promise<T> {
    if (!this.child) {
      throw new Error("MCP transport is not connected");
    }

    const id = this.nextId++;
    const timeoutMs = options.timeoutMs ?? 10_000;
    const request: JsonRpcRequest = {
      jsonrpc: "2.0",
      id,
      method,
      ...(params === undefined ? {} : { params }),
    };

    const payload = JSON.stringify(request);
    this.transcript.push({
      direction: "client->server",
      method,
      payload: request,
    });

    return new Promise<T>((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pending.delete(id);
        reject(
          new Error(
            `MCP request timed out for method "${method}" after ${timeoutMs}ms`,
          ),
        );
      }, timeoutMs);

      this.pending.set(id, {
        resolve: (value) => resolve(value as T),
        reject,
        timeout,
      });

      this.child!.stdin.write(`${payload}\n`, (error) => {
        if (!error) return;
        clearTimeout(timeout);
        this.pending.delete(id);
        reject(
          new Error(
            `Failed to write MCP request "${method}": ${(error as Error).message}`,
          ),
        );
      });
    });
  }

  async notify(method: string, params?: unknown): Promise<void> {
    if (!this.child) {
      throw new Error("MCP transport is not connected");
    }
    const payload = JSON.stringify({
      jsonrpc: "2.0",
      method,
      ...(params === undefined ? {} : { params }),
    });
    this.transcript.push({
      direction: "client->server",
      method,
      payload: JSON.parse(payload),
    });
    await new Promise<void>((resolve, reject) => {
      this.child!.stdin.write(`${payload}\n`, (error) => {
        if (error) {
          reject(
            new Error(
              `Failed to write MCP notification "${method}": ${(error as Error).message}`,
            ),
          );
          return;
        }
        resolve();
      });
    });
  }

  async close(): Promise<void> {
    if (!this.child) return;

    const child = this.child;
    this.child = undefined;
    this.failAllPending(new Error("MCP transport closed"));

    child.stdin.end();
    if (!child.killed) {
      child.kill();
    }
  }

  getRecentStderr(): string {
    return this.stderrBuffer.join("");
  }

  getSessionId(): string | undefined {
    return undefined;
  }

  getTranscript(): McpTraceEvent[] {
    return this.transcript.map((event) => ({
      ...event,
      payload: structuredClone(event.payload),
    }));
  }

  private handleLine(line: string): void {
    const trimmed = line.trim();
    if (!trimmed) return;

    let message: JsonRpcResponse;
    try {
      message = JSON.parse(trimmed) as JsonRpcResponse;
    } catch {
      return;
    }

    this.transcript.push({
      direction:
        typeof message.id === "number"
          ? "server->client"
          : "server->client-notify",
      method: message.method,
      payload: message,
    });

    if (typeof message.id !== "number") {
      return;
    }

    const pending = this.pending.get(message.id);
    if (!pending) {
      // A numeric id with a `method` and no pending entry is a server→client
      // REQUEST (e.g. sampling/createMessage). We record it above as evidence
      // and reply with a canned refusal so the server does not hang — we never
      // actually run the requested LLM sampling / elicitation.
      if (typeof message.method === "string") {
        this.respondToServerRequest(message.id);
      }
      return;
    }
    this.pending.delete(message.id);
    if (pending.timeout) {
      clearTimeout(pending.timeout);
    }

    if (message.error) {
      pending.reject(
        new Error(`MCP error ${message.error.code}: ${message.error.message}`),
      );
      return;
    }

    pending.resolve(message.result);
  }

  private failAllPending(error: Error): void {
    for (const [id, pending] of this.pending) {
      if (pending.timeout) {
        clearTimeout(pending.timeout);
      }
      pending.reject(error);
      this.pending.delete(id);
    }
  }

  /** Refuse a server→client request (e.g. sampling/createMessage) without
   *  running it, so the server proceeds while we record the attempt. */
  private respondToServerRequest(id: number): void {
    if (!this.child) return;
    const payload = JSON.stringify({
      jsonrpc: "2.0",
      id,
      error: { code: -32601, message: "client does not fulfill server-initiated requests" },
    });
    this.transcript.push({
      direction: "client->server",
      method: "response",
      payload: JSON.parse(payload),
    });
    this.child.stdin.write(`${payload}\n`, () => {});
  }
}

export class McpStreamableHttpTransport implements McpTransport {
  private nextId = 1;
  private transcript: McpTraceEvent[] = [];
  private config?: Config;
  private sessionId?: string;
  private connected = false;

  async connect(config: Config): Promise<void> {
    const mcp = config.target.mcp;
    if (
      !mcp ||
      mcp.transport !== "streamable_http" ||
      typeof mcp.url !== "string" ||
      !mcp.url
    ) {
      throw new Error("MCP streamable_http transport requires target.mcp.url");
    }

    this.config = config;
    this.connected = true;
  }

  async request<T = unknown>(
    method: string,
    params?: unknown,
    options: McpRequestOptions = {},
  ): Promise<T> {
    this.ensureConnected();

    const id = this.nextId++;
    const request: JsonRpcRequest = {
      jsonrpc: "2.0",
      id,
      method,
      ...(params === undefined ? {} : { params }),
    };

    this.transcript.push({
      direction: "client->server",
      method,
      payload: request,
    });

    const response = await this.sendHttpRequest(
      "POST",
      request,
      method,
      options.timeoutMs ?? 10_000,
    );
    const messages = await this.readResponseMessages(response, method);
    const matching = messages.find((message) => message.id === id);

    if (!matching) {
      throw new Error(
        `MCP streamable_http response for "${method}" did not include matching id ${id}`,
      );
    }

    if (matching.error) {
      throw new Error(
        `MCP error ${matching.error.code}: ${matching.error.message}`,
      );
    }

    return matching.result as T;
  }

  async notify(method: string, params?: unknown): Promise<void> {
    this.ensureConnected();

    const notification = {
      jsonrpc: "2.0" as const,
      method,
      ...(params === undefined ? {} : { params }),
    };

    this.transcript.push({
      direction: "client->server",
      method,
      payload: notification,
    });

    const response = await this.sendHttpRequest(
      "POST",
      notification,
      method,
      this.config?.target.mcp?.sessionTimeoutMs ?? 10_000,
    );
    await this.readResponseMessages(response, method);
  }

  async close(): Promise<void> {
    if (!this.connected) return;

    const url = this.config?.target.mcp?.url;
    if (url && this.sessionId) {
      const headers = this.buildHeaders({ includeContentType: false });
      try {
        await fetch(url, {
          method: "DELETE",
          headers,
        });
      } catch {
        // Best-effort only.
      }
    }

    this.connected = false;
    this.sessionId = undefined;
  }

  getRecentStderr(): string {
    return "";
  }

  getSessionId(): string | undefined {
    return this.sessionId;
  }

  getTranscript(): McpTraceEvent[] {
    return this.transcript.map((event) => ({
      ...event,
      payload: structuredClone(event.payload),
    }));
  }

  private ensureConnected(): void {
    if (!this.connected || !this.config?.target.mcp?.url) {
      throw new Error("MCP transport is not connected");
    }
  }

  private buildHeaders(options: { includeContentType: boolean }): Headers {
    const headers = new Headers(this.config?.target.mcp?.headers ?? {});
    headers.set("Accept", "application/json, text/event-stream");
    if (options.includeContentType) {
      headers.set("Content-Type", "application/json");
    }
    if (this.sessionId) {
      headers.set("Mcp-Session-Id", this.sessionId);
    }
    return headers;
  }

  private async sendHttpRequest(
    method: "POST" | "DELETE",
    payload: unknown,
    operation: string,
    timeoutMs: number,
  ): Promise<Response> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);

    try {
      return await fetch(this.config!.target.mcp!.url!, {
        method,
        headers: this.buildHeaders({ includeContentType: method === "POST" }),
        body: method === "POST" ? JSON.stringify(payload) : undefined,
        signal: controller.signal,
      });
    } catch (error) {
      const message =
        error instanceof Error && error.name === "AbortError"
          ? `MCP request timed out for method "${operation}" after ${timeoutMs}ms`
          : `Failed MCP ${this.config!.target.mcp!.transport} request "${operation}": ${(error as Error).message}`;
      throw new Error(message);
    } finally {
      clearTimeout(timeout);
    }
  }

  private async readResponseMessages(
    response: Response,
    operation: string,
  ): Promise<JsonRpcResponse[]> {
    const sessionId = response.headers.get("Mcp-Session-Id");
    if (sessionId) {
      this.sessionId = sessionId;
    }

    const responseText = await response.text();
    if (!response.ok) {
      throw new Error(
        `MCP HTTP ${response.status} for "${operation}": ${truncateResponseBody(responseText)}`,
      );
    }

    if (!responseText.trim()) {
      return [];
    }

    const contentType = response.headers.get("content-type") ?? "";
    const messages = contentType.includes("text/event-stream")
      ? this.parseSseMessages(responseText)
      : this.parseJsonMessages(responseText, operation);

    for (const message of messages) {
      this.recordServerMessage(message);
    }

    return messages;
  }

  private parseJsonMessages(
    responseText: string,
    operation: string,
  ): JsonRpcResponse[] {
    let parsed: unknown;
    try {
      parsed = JSON.parse(responseText);
    } catch {
      throw new Error(
        `MCP ${this.config!.target.mcp!.transport} response for "${operation}" was not valid JSON`,
      );
    }

    if (Array.isArray(parsed)) {
      return parsed as JsonRpcResponse[];
    }
    return [parsed as JsonRpcResponse];
  }

  private parseSseMessages(responseText: string): JsonRpcResponse[] {
    const messages: JsonRpcResponse[] = [];
    const lines = responseText.split(/\r?\n/);
    let eventData: string[] = [];

    const flush = (): void => {
      if (!eventData.length) return;
      const data = eventData.join("\n").trim();
      eventData = [];
      if (!data) return;

      let parsed: unknown;
      try {
        parsed = JSON.parse(data);
      } catch {
        throw new Error("MCP streamable_http SSE event did not contain JSON");
      }
      messages.push(parsed as JsonRpcResponse);
    };

    for (const line of lines) {
      if (!line.trim()) {
        flush();
        continue;
      }
      if (line.startsWith(":")) {
        continue;
      }
      if (line.startsWith("data:")) {
        eventData.push(line.slice(5).trimStart());
      }
    }

    flush();
    return messages;
  }

  private recordServerMessage(message: JsonRpcResponse): void {
    this.transcript.push({
      direction:
        typeof message.id === "number"
          ? "server->client"
          : "server->client-notify",
      method: message.method,
      payload: message,
    });
  }
}

function truncateResponseBody(body: string): string {
  const trimmed = body.trim();
  if (!trimmed) {
    return "<empty response>";
  }
  return trimmed.length > 400 ? `${trimmed.slice(0, 397)}...` : trimmed;
}
