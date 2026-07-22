/**
 * Drive a functional-quality task through an MCP agent loop.
 *
 * The quality scorer normally POSTs `input` as an HTTP body. That doesn't work
 * for an MCP (JSON-RPC) target: the server needs an explicit tool call, so a
 * plain body is rejected. This module instead lets an LLM that *holds* the
 * server's tools decide which tool(s) to call, executes them over a live MCP
 * session, and returns the tool-call trace + final answer so the scorer can
 * grade tool-call accuracy (vs expectedTools) and answer/goal quality (vs the
 * reference).
 *
 * It reuses the red-team loop's ReAct protocol (`buildAgentSystemPrompt` +
 * `parseAgentAction`) but carries NONE of its poisoning/compromise grading —
 * this drives a *legitimate* task. The core is dependency-injected so it can be
 * unit-tested without a live model or server.
 */
import { getLlmProvider } from "../llm-provider.js";
import { McpSession } from "../mcp/session.js";
import { buildAgentSystemPrompt, parseAgentAction } from "../mcp/agent-loop.js";
import type { ChatMessage } from "../llm-provider.js";
import type { Config } from "../types.js";
import type { McpToolDescriptor } from "../mcp/types.js";

const DEFAULT_MAX_STEPS = 6;

export interface QualityAgentResult {
  /** The agent's final answer (or the last tool observation if it never gave one). */
  response: string;
  /** Tool names the agent actually called, in order. */
  toolCalls: string[];
  /** Number of agent turns taken. */
  steps: number;
}

export interface QualityAgentDeps {
  chat(messages: ChatMessage[]): Promise<string>;
  executeTool(tool: string, args: Record<string, unknown>): Promise<unknown>;
  tools: McpToolDescriptor[];
}

/** Join MCP tool-result content blocks into text (or JSON-stringify). */
export function mcpResultToText(raw: unknown): string {
  if (typeof raw === "string") return raw;
  if (raw && typeof raw === "object") {
    const content = (raw as Record<string, unknown>).content;
    if (Array.isArray(content)) {
      const text = content
        .map((c) =>
          c && typeof c === "object"
            ? String((c as Record<string, unknown>).text ?? "")
            : "",
        )
        .filter(Boolean)
        .join("\n");
      if (text) return text;
    }
  }
  return JSON.stringify(raw ?? "");
}

/**
 * Core agent loop. Injectable deps keep it testable. Records every tool the
 * agent calls and returns its final answer — no grading here; that's the
 * scorer's job.
 */
export async function runQualityAgent(
  deps: QualityAgentDeps,
  input: string,
  maxSteps = DEFAULT_MAX_STEPS,
): Promise<QualityAgentResult> {
  const messages: ChatMessage[] = [
    { role: "system", content: buildAgentSystemPrompt(deps.tools, input) },
    { role: "user", content: input },
  ];
  const toolCalls: string[] = [];
  let finalAnswer: string | undefined;
  let lastObservation = "";
  let malformed = 0;
  let steps = 0;

  for (let step = 1; step <= maxSteps; step++) {
    steps = step;
    const text = await deps.chat(messages);
    messages.push({ role: "assistant", content: text });
    const action = parseAgentAction(text);

    if (action.type === "error") {
      if (++malformed >= 2) break;
      messages.push({
        role: "user",
        content:
          'Reply with exactly one JSON object using the "call_tool" or "final" format.',
      });
      continue;
    }
    malformed = 0;

    if (action.type === "final") {
      finalAnswer = action.answer;
      break;
    }

    // action.type === "call_tool"
    toolCalls.push(action.tool);
    let observation: string;
    try {
      const raw = await deps.executeTool(action.tool, action.arguments);
      observation = mcpResultToText(raw);
    } catch (err) {
      observation = `ERROR: ${(err as Error).message}`;
    }
    lastObservation = observation;
    messages.push({
      role: "user",
      content: `OBSERVATION from ${action.tool}:\n${observation.slice(0, 4000)}`,
    });
  }

  return { response: finalAnswer ?? lastObservation, toolCalls, steps };
}

/**
 * Adapter: run the quality agent against a real LLM provider + live MCP session.
 * Opens a session, discovers tools, drives the loop, and always closes the
 * session. Honors the engagement's allow/deny tool scope. Returns transport
 * metadata (statusCode / timing / error) alongside the agent result so the
 * scorer can report it like the HTTP path.
 */
export async function runQualityMcpAgent(
  config: Config,
  input: string,
  maxSteps = DEFAULT_MAX_STEPS,
): Promise<QualityAgentResult & { statusCode: number; responseTimeMs: number; error?: string }> {
  const start = Date.now();
  let session: McpSession | undefined;
  try {
    const provider = getLlmProvider(config);
    const model = config.attackConfig.llmModel;
    session = new McpSession(config);
    const tools = await session.listTools();

    const deny = new Set(config.target.mcp?.denylistedTools ?? []);
    const allow = new Set(config.target.mcp?.allowlistedTools ?? []);
    const outOfScope = (tool: string) =>
      deny.has(tool) || (allow.size > 0 && !allow.has(tool));

    const result = await runQualityAgent(
      {
        tools,
        chat: (messages) =>
          provider.chat({ model, messages, responseFormat: "json_object" }),
        executeTool: (tool, args) =>
          outOfScope(tool)
            ? Promise.resolve(
                `ERROR: tool "${tool}" is out of scope for this engagement and was not executed`,
              )
            : session!.callTool(tool, args),
      },
      input,
      maxSteps,
    );
    return { ...result, statusCode: 200, responseTimeMs: Date.now() - start };
  } catch (e) {
    return {
      response: "",
      toolCalls: [],
      steps: 0,
      statusCode: 0,
      responseTimeMs: Date.now() - start,
      error: (e as Error).message,
    };
  } finally {
    if (session) {
      try {
        await session.close();
      } catch {
        /* ignore close errors */
      }
    }
  }
}
