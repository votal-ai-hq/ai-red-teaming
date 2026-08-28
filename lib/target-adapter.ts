import type { Attack, Config, Credential, McpExecutionTrace } from "./types.js";
import { discoverMcpSurface } from "./mcp/discovery.js";
import { McpSession } from "./mcp/session.js";
import { getLlmProvider } from "./llm-provider.js";
import {
  runMcpAgentLoop,
  type AgentLoopScenario,
} from "./mcp/agent-loop.js";
import {
  tamperHeaders,
  parseHttpStatus,
  type AuthVariant,
  type AuthProbeResult,
} from "./mcp/auth-probe.js";
import { type ProtocolProbeResult } from "./mcp/protocol-probe.js";
import { runSessionProbe } from "./mcp/session-probe.js";
import {
  scanServerInitiatedRequests,
  summarizeCapabilityProbe,
} from "./mcp/capability-probe.js";
import { diffMcpMetadata } from "./mcp/metadata-poisoning.js";

/**
 * When an MCP tools/call fails schema validation (JSON-RPC -32602 "Invalid
 * arguments"), ask the LLM to produce corrected arguments that satisfy the
 * tool's inputSchema while preserving the adversarial intent, so the attack
 * actually exercises the tool instead of erroring out. Returns null if repair
 * isn't possible (no schema, no LLM key, unparseable output).
 */
async function repairMcpToolArgs(
  config: Config,
  session: McpSession,
  toolName: string,
  attemptedArgs: Record<string, unknown>,
  errorMessage: string,
  attack: Attack,
): Promise<Record<string, unknown> | null> {
  let schema: unknown;
  try {
    const tools = await session.listTools();
    schema = tools.find((t) => t.name === toolName)?.inputSchema;
  } catch {
    return null;
  }
  if (!schema) return null;

  let llm;
  try {
    llm = getLlmProvider(config);
  } catch {
    return null; // no LLM configured — can't repair
  }

  const prompt = `An MCP tools/call failed schema validation. Produce a corrected JSON "arguments" object that (a) satisfies the tool's inputSchema and (b) preserves the security-test intent.

TOOL: ${toolName}
INPUT SCHEMA (JSON Schema):
${JSON.stringify(schema)}
ATTEMPTED ARGUMENTS:
${JSON.stringify(attemptedArgs)}
VALIDATION ERROR:
${errorMessage}
ATTACK INTENT: ${attack.name} — ${attack.description ?? ""}

Rules:
- Output ONLY a JSON object of arguments (no prose, no markdown).
- Satisfy every required field and correct type from the schema.
- Preserve adversarial values where they still fit the schema (e.g. other-tenant / other-org IDs, path traversal strings, oversized inputs). If the schema wants an array of IDs, include plausible/guessed IDs (including other-org-style IDs) to probe IDOR.`;

  try {
    const text = await llm.chat({ phase: "generation",
      model: config.attackConfig.llmModel,
      messages: [{ role: "user", content: prompt }],
      temperature: 0,
      maxTokens: 600,
      responseFormat: "json_object",
    });
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) return null;
    const parsed = JSON.parse(jsonMatch[0]);
    return parsed && typeof parsed === "object" ? parsed : null;
  } catch {
    return null;
  }
}

export interface AttackExecutionResult {
  statusCode: number;
  body: unknown;
  timeMs: number;
  executionTrace?: McpExecutionTrace;
}

export interface TargetSurfaceSummary {
  transport: Config["target"]["type"];
  serverName?: string;
  protocolVersion?: string;
  capabilities?: string[];
  tools?: string[];
  prompts?: string[];
  resources?: string[];
  resourceTemplates?: string[];
}

export interface TargetAdapter {
  readonly type: NonNullable<Config["target"]["type"]>;
  preAuthenticate(config: Config): Promise<void>;
  loginForToken?(config: Config, cred: Credential): Promise<string>;
  executeAttack(config: Config, attack: Attack): Promise<AttackExecutionResult>;
  discoverSurface?(config: Config): Promise<TargetSurfaceSummary>;
}

class McpTargetAdapter implements TargetAdapter {
  readonly type = "mcp" as const;

  async preAuthenticate(config: Config): Promise<void> {
    const session = new McpSession(config);
    try {
      await session.initialize();
    } finally {
      await session.close();
    }
  }

  async executeAttack(
    config: Config,
    attack: Attack,
  ): Promise<AttackExecutionResult> {
    const operation = attack.payload._mcpOperation;
    const start = Date.now();

    if (typeof operation !== "string") {
      return {
        statusCode: 400,
        body: {
          error:
            'MCP attack payload requires "_mcpOperation" (supported: "discover", "tools/call", "resources/read", "prompts/get", "agent_loop", "auth_probe", "rug_pull_probe", "protocol_probe", "session_probe", "capability_probe")',
        },
        timeMs: Date.now() - start,
      };
    }

    let session: McpSession | undefined;
    try {
      let result: unknown;
      switch (operation) {
        case "discover": {
          result = await discoverMcpSurface(config);
          break;
        }
        case "tools/call": {
          session = new McpSession(config);
          const toolName = attack.payload._mcpTool;
          if (typeof toolName !== "string" || !toolName) {
            return {
              statusCode: 400,
              body: {
                error:
                  'MCP tools/call requires payload field "_mcpTool" to be a non-empty string',
              },
              timeMs: Date.now() - start,
            };
          }
          let toolArgs =
            typeof attack.payload._mcpArguments === "object" &&
            attack.payload._mcpArguments !== null
              ? (attack.payload._mcpArguments as Record<string, unknown>)
              : {};
          try {
            result = await session.callTool(toolName, toolArgs);
          } catch (callErr) {
            const msg = (callErr as Error)?.message ?? "";
            // On a schema/arg validation error, repair the args with the LLM and
            // retry once so the attack actually reaches the tool.
            if (/-32602/.test(msg) && /invalid arguments/i.test(msg)) {
              const repaired = await repairMcpToolArgs(
                config,
                session,
                toolName,
                toolArgs,
                msg,
                attack,
              );
              if (repaired) {
                toolArgs = repaired;
                // Reflect the args actually sent in the report's request panel.
                attack.payload._mcpArguments = repaired;
                (attack.payload as Record<string, unknown>)._mcpArgsRepaired = true;
                result = await session.callTool(toolName, toolArgs);
              } else {
                throw callErr;
              }
            } else {
              throw callErr;
            }
          }
          break;
        }
        case "resources/read": {
          session = new McpSession(config);
          const uri = attack.payload._mcpResourceUri;
          if (typeof uri !== "string" || !uri) {
            return {
              statusCode: 400,
              body: {
                error:
                  'MCP resources/read requires payload field "_mcpResourceUri" to be a non-empty string',
              },
              timeMs: Date.now() - start,
            };
          }
          result = await session.readResource(uri);
          break;
        }
        case "prompts/get": {
          session = new McpSession(config);
          const promptName = attack.payload._mcpPrompt;
          if (typeof promptName !== "string" || !promptName) {
            return {
              statusCode: 400,
              body: {
                error:
                  'MCP prompts/get requires payload field "_mcpPrompt" to be a non-empty string',
              },
              timeMs: Date.now() - start,
            };
          }
          const promptArgs =
            typeof attack.payload._mcpArguments === "object" &&
            attack.payload._mcpArguments !== null
              ? (attack.payload._mcpArguments as Record<string, unknown>)
              : {};
          result = await session.getPrompt(promptName, promptArgs);
          break;
        }
        case "rug_pull_probe": {
          // Diff tool metadata across two successive tools/list loads to detect
          // rug-pull / sleeper mutation (MCP has no re-approval on drift).
          const first = await discoverMcpSurface(config);
          const second = await discoverMcpSurface(config);
          result = diffMcpMetadata(first, second);
          break;
        }
        case "auth_probe": {
          // Present a credential the server MUST reject (absent / invalid /
          // wrong-audience) and observe whether it is accepted. Runs its own
          // short-lived session with tampered headers; never touches the outer
          // `session`.
          const variant = (attack.payload._authVariant as AuthVariant) ?? "invalid";
          const mcp = config.target.mcp;
          if (!mcp || mcp.transport === "stdio") {
            result = {
              variant,
              accepted: false,
              statusCode: 0,
              detail: "auth_probe is not applicable to this transport",
            } satisfies AuthProbeResult;
            break;
          }
          const probeConfig: Config = {
            ...config,
            target: {
              ...config.target,
              mcp: { ...mcp, headers: tamperHeaders(mcp.headers ?? {}, variant) },
            },
          };
          const probeSession = new McpSession(probeConfig);
          try {
            await probeSession.initialize();
            result = {
              variant,
              accepted: true,
              statusCode: 200,
              detail: `server accepted a ${variant} credential`,
            } satisfies AuthProbeResult;
          } catch (probeErr) {
            const msg = (probeErr as Error)?.message ?? "";
            result = {
              variant,
              accepted: false,
              statusCode: parseHttpStatus(msg),
              detail: msg.slice(0, 200),
            } satisfies AuthProbeResult;
          } finally {
            await probeSession.close();
          }
          break;
        }
        case "protocol_probe": {
          // Advertise an unsupported / garbage protocolVersion at initialize in
          // a short-lived session and observe whether the server rejects it,
          // negotiates away from it, or echoes it back verbatim (downgrade).
          const requested =
            (attack.payload._protocolVersion as string | undefined) ??
            "not-a-version";
          const mcp = config.target.mcp;
          if (!mcp) {
            return {
              statusCode: 400,
              body: { error: "protocol_probe requires an MCP target" },
              timeMs: Date.now() - start,
            };
          }
          const probeConfig: Config = {
            ...config,
            target: {
              ...config.target,
              mcp: { ...mcp, protocolVersion: requested },
            },
          };
          const probeSession = new McpSession(probeConfig);
          try {
            const init = await probeSession.initialize();
            const negotiated = init.protocolVersion;
            result = {
              variant: String(
                (attack.payload._protocolVariant as string | undefined) ??
                  "custom",
              ),
              requested,
              negotiated,
              accepted: true,
              echoedUnsupported: negotiated === requested,
              statusCode: 200,
              detail: `server accepted initialize; negotiated protocolVersion="${negotiated ?? "<none>"}"`,
            } satisfies ProtocolProbeResult;
          } catch (probeErr) {
            const msg = (probeErr as Error)?.message ?? "";
            result = {
              variant: String(
                (attack.payload._protocolVariant as string | undefined) ??
                  "custom",
              ),
              requested,
              accepted: false,
              echoedUnsupported: false,
              statusCode: parseHttpStatus(msg),
              detail: msg.slice(0, 200),
            } satisfies ProtocolProbeResult;
          } finally {
            await probeSession.close();
          }
          break;
        }
        case "session_probe": {
          // Streamable-HTTP session-id handling: forged-id acceptance, borrowed
          // session without auth, unauthenticated DELETE, low entropy. Runs its
          // own raw HTTP calls; never touches the outer `session`.
          result = await runSessionProbe(config);
          break;
        }
        case "capability_probe": {
          // Advertise `sampling` + `roots` at initialize, then give the server a
          // chance to issue a server→client request (sampling/createMessage,
          // elicitation/create, roots/list). The transport records — and refuses
          // — any such request; we scan the transcript for evidence. We never run
          // the requested sampling.
          const mcp = config.target.mcp;
          if (!mcp) {
            return {
              statusCode: 400,
              body: { error: "capability_probe requires an MCP target" },
              timeMs: Date.now() - start,
            };
          }
          const probeConfig: Config = {
            ...config,
            target: {
              ...config.target,
              mcp: {
                ...mcp,
                clientCapabilities: {
                  ...(mcp.clientCapabilities ?? {}),
                  sampling: {},
                  roots: { listChanged: true },
                },
              },
            },
          };
          session = new McpSession(probeConfig);
          await session.initialize();
          // Provoke server activity: enumerate, then best-effort call the first
          // tool — a common trigger for a server that wants to sample.
          const provoke = await session.listTools().catch(() => []);
          if (provoke[0]?.name) {
            await session.callTool(provoke[0].name, {}).catch(() => undefined);
          }
          const transcript = session.getExecutionTrace("capability_probe").transcript;
          const requests = scanServerInitiatedRequests(transcript);
          result = summarizeCapabilityProbe(true, requests);
          break;
        }
        case "agent_loop": {
          const scenario = attack.payload._agentScenario as
            | AgentLoopScenario
            | undefined;
          if (
            !scenario ||
            typeof scenario !== "object" ||
            typeof scenario.poisonedTool !== "string"
          ) {
            return {
              statusCode: 400,
              body: {
                error:
                  'MCP agent_loop requires payload field "_agentScenario" with a "poisonedTool"',
              },
              timeMs: Date.now() - start,
            };
          }
          let provider;
          try {
            provider = getLlmProvider(config);
          } catch {
            return {
              statusCode: 400,
              body: {
                error:
                  "MCP agent_loop requires a configured LLM provider (no API key)",
              },
              timeMs: Date.now() - start,
            };
          }
          session = new McpSession(config);
          const tools = await session.listTools();
          result = await runMcpAgentLoop(
            config,
            provider,
            session,
            tools,
            scenario,
          );
          break;
        }
        default:
          return {
            statusCode: 400,
            body: {
              error: `Unsupported MCP operation "${operation}"`,
            },
            timeMs: Date.now() - start,
          };
      }

      const executionTrace = session?.getExecutionTrace(operation);
      return {
        statusCode: 200,
        body: {
          operation,
          result,
        },
        timeMs: Date.now() - start,
        executionTrace,
      };
    } catch (error) {
      const executionTrace = session?.getExecutionTrace(operation);
      return {
        statusCode: 0,
        body: { error: (error as Error).message },
        timeMs: Date.now() - start,
        executionTrace,
      };
    } finally {
      await session?.close();
    }
  }

  async discoverSurface(config: Config): Promise<TargetSurfaceSummary> {
    const result = await discoverMcpSurface(config);
    return {
      transport: config.target.type ?? "mcp",
      serverName: result.serverInfo?.name,
      protocolVersion: result.protocolVersion,
      capabilities: result.capabilities,
      tools: (result.tools || []).map((tool) => tool.name),
      prompts: (result.prompts || []).map((prompt) => prompt.name),
      resources: (result.resources || []).map((resource) => resource.uri),
      resourceTemplates: (result.resourceTemplates || []).map(
        (template) => template.uriTemplate,
      ),
    };
  }
}

let mcpTargetAdapter: TargetAdapter | undefined;

export function getTargetAdapter(config: Config): TargetAdapter | undefined {
  const targetType = config.target.type ?? "http_agent";
  if (targetType === "mcp") {
    mcpTargetAdapter ??= new McpTargetAdapter();
    return mcpTargetAdapter;
  }
  return undefined;
}

export function describeTarget(config: Config): string {
  if ((config.target.type ?? "http_agent") === "websocket_agent") {
    const p = config.target.websocket?.path ?? "/ws/chat";
    return `${config.target.baseUrl ?? ""} (WebSocket ${p})`;
  }
  if ((config.target.type ?? "http_agent") === "mcp") {
    const mcp = config.target.mcp;
    if (!mcp) return "mcp://unknown";
    if (mcp.transport === "stdio") {
      const args = (mcp.args ?? []).join(" ");
      return `mcp+stdio://${mcp.command ?? "unknown"}${args ? ` ${args}` : ""}`;
    }
    return `mcp+${mcp.transport}:${mcp.url ?? "unknown"}`;
  }

  return `${config.target.baseUrl ?? ""}${config.target.agentEndpoint ?? ""}`;
}
