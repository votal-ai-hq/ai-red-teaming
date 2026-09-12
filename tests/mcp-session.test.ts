import { describe, it, expect, vi, afterEach } from "vitest";
import { fileURLToPath } from "node:url";
import type { Attack, Config } from "../lib/types.js";
import { McpSession } from "../lib/mcp/session.js";
import { discoverMcpSurface } from "../lib/mcp/discovery.js";
import { describeTarget, getTargetAdapter } from "../lib/target-adapter.js";

const FIXTURE_PATH = fileURLToPath(
  new URL("./fixtures/mock-mcp-server.js", import.meta.url),
);

function makeMcpConfig(): Config {
  return {
    target: {
      type: "mcp",
      applicationDetails: "Mock MCP server for testing",
      mcp: {
        transport: "stdio",
        command: "node",
        args: [FIXTURE_PATH],
      },
      baseUrl: "",
      agentEndpoint: "",
      authEndpoint: "",
    },
    codebasePath: ".",
    codebaseGlob: "**/*.ts",
    auth: {
      methods: ["jwt"],
      jwtSecret: "secret",
      credentials: [{ email: "a@b.com", password: "pass", role: "admin" }],
      apiKeys: {},
    },
    requestSchema: {
      messageField: "message",
      roleField: "role",
      apiKeyField: "api_key",
      guardrailModeField: "guardrail_mode",
    },
    responseSchema: {
      responsePath: "response",
      toolCallsPath: "tool_calls",
      userInfoPath: "user",
      guardrailsPath: "guardrails",
    },
    sensitivePatterns: ["demo-secret"],
    attackConfig: {
      adaptiveRounds: 1,
      maxAttacksPerCategory: 10,
      concurrency: 1,
      delayBetweenRequestsMs: 0,
      llmProvider: "openai",
      llmModel: "gpt-4o-mini",
      enableLlmGeneration: true,
      maxMultiTurnSteps: 3,
    },
  };
}

const MOCK_STREAMABLE_HTTP_URL = "https://example.test/mcp";

function makeStreamableHttpConfig(url = MOCK_STREAMABLE_HTTP_URL): Config {
  return {
    target: {
      type: "mcp",
      applicationDetails: "Mock MCP streamable HTTP server for testing",
      mcp: {
        transport: "streamable_http",
        url,
        headers: {
          "x-api-key": "test-key",
        },
      },
      baseUrl: "",
      agentEndpoint: "",
      authEndpoint: "",
    },
    codebasePath: ".",
    codebaseGlob: "**/*.ts",
    auth: {
      methods: ["none"],
      jwtSecret: "secret",
      credentials: [],
      apiKeys: {},
    },
    requestSchema: {
      messageField: "message",
      roleField: "role",
      apiKeyField: "api_key",
      guardrailModeField: "guardrail_mode",
    },
    responseSchema: {
      responsePath: "response",
      toolCallsPath: "tool_calls",
      userInfoPath: "user",
      guardrailsPath: "guardrails",
    },
    sensitivePatterns: ["demo-secret"],
    attackConfig: {
      adaptiveRounds: 1,
      maxAttacksPerCategory: 10,
      concurrency: 1,
      delayBetweenRequestsMs: 0,
      llmProvider: "openai",
      llmModel: "gpt-4o-mini",
      enableLlmGeneration: true,
      maxMultiTurnSteps: 3,
    },
  };
}

function mockStreamableHttpFetch(): void {
  const sessionId = "session-123";

  vi.spyOn(globalThis, "fetch").mockImplementation(
    async (input: string | URL | Request, init?: RequestInit) => {
      const url =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.toString()
            : input.url;

      expect(url).toBe(MOCK_STREAMABLE_HTTP_URL);

      const method = init?.method ?? "GET";
      const headers = new Headers(init?.headers ?? {});

      if (method === "DELETE") {
        expect(headers.get("Mcp-Session-Id")).toBe(sessionId);
        return new Response(null, { status: 204 });
      }

      expect(method).toBe("POST");

      const rawBody =
        typeof init?.body === "string"
          ? init.body
          : init?.body instanceof Uint8Array
            ? Buffer.from(init.body).toString("utf-8")
            : "";
      const message = JSON.parse(rawBody) as {
        id?: number;
        method?: string;
        params?: Record<string, unknown>;
      };

      if (
        message.method !== "initialize" &&
        headers.get("Mcp-Session-Id") !== sessionId
      ) {
        return new Response(
          JSON.stringify({
            jsonrpc: "2.0",
            id: message.id ?? null,
            error: { code: -32000, message: "missing session id" },
          }),
          {
            status: 400,
            headers: {
              "Content-Type": "application/json",
              "Mcp-Session-Id": sessionId,
            },
          },
        );
      }

      const responseHeaders = {
        "Mcp-Session-Id": sessionId,
      };

      switch (message.method) {
        case "initialize":
          return new Response(
            JSON.stringify({
              jsonrpc: "2.0",
              id: message.id,
              result: {
                protocolVersion: "2024-11-05",
                capabilities: {
                  tools: {},
                  prompts: {},
                  resources: {},
                },
                serverInfo: {
                  name: "mock-http-mcp-server",
                  version: "1.0.0",
                },
              },
            }),
            {
              status: 200,
              headers: {
                ...responseHeaders,
                "Content-Type": "application/json",
              },
            },
          );
        case "notifications/initialized":
          return new Response(null, {
            status: 202,
            headers: responseHeaders,
          });
        case "tools/list":
          return new Response(
            JSON.stringify({
              jsonrpc: "2.0",
              id: message.id,
              result: {
                tools: [
                  {
                    name: "read_secret",
                    description: "Reads a fake secret",
                  },
                ],
              },
            }),
            {
              status: 200,
              headers: {
                ...responseHeaders,
                "Content-Type": "application/json",
              },
            },
          );
        case "prompts/list":
          return new Response(
            JSON.stringify({
              jsonrpc: "2.0",
              id: message.id,
              result: {
                prompts: [
                  {
                    name: "security-review",
                    description: "Review a pull request",
                  },
                ],
              },
            }),
            {
              status: 200,
              headers: {
                ...responseHeaders,
                "Content-Type": "application/json",
              },
            },
          );
        case "resources/list":
          return new Response(
            JSON.stringify({
              jsonrpc: "2.0",
              id: message.id,
              result: {
                resources: [
                  {
                    uri: "memory://secrets/demo",
                    name: "Demo secret",
                  },
                ],
              },
            }),
            {
              status: 200,
              headers: {
                ...responseHeaders,
                "Content-Type": "application/json",
              },
            },
          );
        case "tools/call":
          return new Response(
            [
              "event: message",
              'data: {"jsonrpc":"2.0","method":"notifications/log","params":{"message":"tool call observed"}}',
              "",
              `data: ${JSON.stringify({
                jsonrpc: "2.0",
                id: message.id,
                result: {
                  structuredContent: {
                    secret:
                      (
                        message.params?.arguments as
                          | Record<string, unknown>
                          | undefined
                      )?.path === "/tmp/http-demo.txt"
                        ? "demo-secret"
                        : "unexpected",
                  },
                },
              })}`,
              "",
            ].join("\n"),
            {
              status: 200,
              headers: {
                ...responseHeaders,
                "Content-Type": "text/event-stream",
              },
            },
          );
        default:
          return new Response(
            JSON.stringify({
              jsonrpc: "2.0",
              id: message.id ?? null,
              error: { code: -32601, message: "method not found" },
            }),
            {
              status: 404,
              headers: {
                ...responseHeaders,
                "Content-Type": "application/json",
              },
            },
          );
      }
    },
  );
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("MCP session", () => {
  it("initializes a stdio MCP session and lists capabilities", async () => {
    const session = new McpSession(makeMcpConfig());
    try {
      const init = await session.initialize();
      expect(init.serverInfo?.name).toBe("mock-mcp-server");

      const tools = await session.listTools();
      const prompts = await session.listPrompts();
      const resources = await session.listResources();

      expect(tools.map((tool) => tool.name)).toContain("read_secret");
      expect(prompts.map((prompt) => prompt.name)).toContain("security-review");
      expect(resources.map((resource) => resource.uri)).toContain(
        "memory://secrets/demo",
      );
    } finally {
      await session.close();
    }
  });

  it("discovers MCP surface through the discovery helper", async () => {
    const surface = await discoverMcpSurface(makeMcpConfig());
    expect(surface.serverInfo?.name).toBe("mock-mcp-server");
    expect(surface.capabilities).toEqual(["prompts", "resources", "tools"]);
    expect(surface.tools).toHaveLength(1);
    expect(surface.prompts).toHaveLength(1);
    expect(surface.resources).toHaveLength(1);
  });

  it("retains tool schemas in the adapter surface summary", async () => {
    const adapter = getTargetAdapter(makeMcpConfig());
    const surface = await adapter?.discoverSurface?.(makeMcpConfig());
    expect(surface?.tools).toEqual(["read_secret"]);
    expect(surface?.toolDescriptors?.[0]).toMatchObject({
      name: "read_secret",
      inputSchema: {
        type: "object",
        properties: { path: { type: "string" } },
      },
    });
  });

  it("executes generic MCP tool calls via the adapter", async () => {
    const config = makeMcpConfig();
    const adapter = getTargetAdapter(config);
    expect(adapter?.type).toBe("mcp");

    const attack: Attack = {
      id: "mcp-tool-call",
      category: "tool_misuse",
      name: "Call read_secret",
      description: "Invoke an MCP tool directly",
      authMethod: "none",
      role: "admin",
      payload: {
        _mcpOperation: "tools/call",
        _mcpTool: "read_secret",
        _mcpArguments: { path: "/tmp/demo.txt" },
      },
      expectation: "Tool call succeeds",
      severity: "medium",
      isLlmGenerated: false,
    };

    const result = await adapter!.executeAttack(config, attack);
    expect(result.statusCode).toBe(200);
    expect(
      (
        result.body as {
          result: {
            structuredContent?: { secret?: string };
          };
        }
      ).result.structuredContent?.secret,
    ).toBe("demo-secret");
    expect(result.executionTrace?.transport).toBe("stdio");
    expect(result.executionTrace?.serverName).toBe("mock-mcp-server");
    expect(result.executionTrace?.operation).toBe("tools/call");
    expect(result.executionTrace?.transcript.length).toBeGreaterThan(0);
  });

  it("formats MCP targets for display", () => {
    const label = describeTarget(makeMcpConfig());
    expect(label).toContain("mcp+stdio://node");
  });
});

describe("MCP streamable_http session", () => {
  it("initializes a streamable HTTP MCP session and lists capabilities", async () => {
    mockStreamableHttpFetch();
    const session = new McpSession(makeStreamableHttpConfig());
    try {
      const init = await session.initialize();
      expect(init.serverInfo?.name).toBe("mock-http-mcp-server");

      const tools = await session.listTools();
      const prompts = await session.listPrompts();
      const resources = await session.listResources();

      expect(tools.map((tool) => tool.name)).toContain("read_secret");
      expect(prompts.map((prompt) => prompt.name)).toContain("security-review");
      expect(resources.map((resource) => resource.uri)).toContain(
        "memory://secrets/demo",
      );
    } finally {
      await session.close();
    }
  });

  it("executes streamable HTTP MCP tool calls via the adapter and captures trace events", async () => {
    mockStreamableHttpFetch();
    const config = makeStreamableHttpConfig();
    const adapter = getTargetAdapter(config);

    const attack: Attack = {
      id: "mcp-http-tool-call",
      category: "tool_misuse",
      name: "Call read_secret over HTTP MCP",
      description: "Invoke an MCP tool directly over streamable_http",
      authMethod: "none",
      role: "admin",
      payload: {
        _mcpOperation: "tools/call",
        _mcpTool: "read_secret",
        _mcpArguments: { path: "/tmp/http-demo.txt" },
      },
      expectation: "Tool call succeeds",
      severity: "medium",
      isLlmGenerated: false,
    };

    const result = await adapter!.executeAttack(config, attack);
    expect(result.statusCode).toBe(200);
    expect(
      (
        result.body as {
          result: {
            structuredContent?: { secret?: string };
          };
        }
      ).result.structuredContent?.secret,
    ).toBe("demo-secret");
    expect(result.executionTrace?.transport).toBe("streamable_http");
    expect(result.executionTrace?.serverName).toBe("mock-http-mcp-server");
    expect(
      result.executionTrace?.transcript.some(
        (event) => event.direction === "server->client-notify",
      ),
    ).toBe(true);
  });

  it("formats streamable HTTP MCP targets for display", () => {
    const label = describeTarget(makeStreamableHttpConfig());
    expect(label).toBe(`mcp+streamable_http:${MOCK_STREAMABLE_HTTP_URL}`);
  });
});
