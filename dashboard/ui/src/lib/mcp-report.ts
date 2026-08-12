/**
 * Structured, human-readable views over the MCP / agent traffic captured in a
 * report result.
 *
 * A result stores the same exchange in several shapes:
 *   • `attack.payload`  — what the scanner sent (`_mcpOperation`, `_mcpTool`,
 *                         `_mcpArguments`, `message`, …)
 *   • `responseBody`    — `{ operation, result }` for MCP targets, where the
 *                         `result` shape depends on the operation
 *   • `conversation[]`  — one `{ payload, responseBody }` per turn (multi-turn)
 *   • `executionTrace`  — the JSON-RPC wire transcript (client ↔ server)
 *
 * The report UI used to `JSON.stringify` those blobs. This module turns them
 * into labelled fields, plain text and an ordered interaction flow — every
 * summary keeps its `raw` object so the UI can still offer a raw-JSON view.
 */

/* ─── shared primitives ─── */

export interface KeyValue {
  label: string;
  value: string;
}

/** Who sent / received a step of the interaction. */
export type FlowParty = "user" | "model" | "server" | "system";

const PARTY_LABELS: Record<FlowParty, string> = {
  user: "User",
  model: "Model",
  server: "MCP server",
  system: "System",
};

/** Display name for a party. Non-MCP targets are plain agents, not servers. */
export function partyLabel(party: FlowParty, isMcp = true): string {
  if (party === "server" && !isMcp) return "Agent";
  return PARTY_LABELS[party];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Render one value for a label/value row: strings as-is, objects as JSON. */
export function formatValue(value: unknown): string {
  if (value == null) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

const TRUNCATION_MARK = "... [truncated]";

/**
 * Reports store large bodies as JSON *strings* (the generator stringifies
 * anything over its size cap and appends a truncation marker). Parse those back
 * into objects so they can be rendered structurally; leave real text alone.
 */
export function parseJsonish(value: unknown): {
  value: unknown;
  truncated: boolean;
} {
  if (typeof value !== "string") return { value, truncated: false };
  const trimmed = value.trim();
  const truncated = trimmed.endsWith(TRUNCATION_MARK);
  if (!/^[[{]/.test(trimmed)) return { value, truncated };
  const candidate = truncated
    ? trimmed.slice(0, -TRUNCATION_MARK.length)
    : trimmed;
  try {
    return { value: JSON.parse(candidate), truncated };
  } catch {
    // Truncated mid-object, or not JSON after all — show it as text.
    return { value, truncated };
  }
}

/* ─── request side ─── */

export interface AgentScenarioSummary {
  userTask?: string;
  poisonedTool?: string;
  poisonedContent?: string;
  canary?: string;
  writeTools?: string[];
}

export interface RequestSummary {
  /** MCP operation, e.g. "tools/call". Absent for plain HTTP agent payloads. */
  operation?: string;
  tool?: string;
  resourceUri?: string;
  promptName?: string;
  authVariant?: string;
  /** Tool / prompt arguments as label-value rows. */
  args: KeyValue[];
  /** The natural-language message sent to the target, when there is one. */
  message?: string;
  /** Role the attack authenticated as. */
  role?: string;
  /** Any other caller-supplied payload fields. */
  extras: KeyValue[];
  /** The scanner's LLM repaired the arguments after a schema rejection. */
  argsRepaired: boolean;
  /** Agent-in-the-loop scenario (`_agentScenario`). */
  agentScenario?: AgentScenarioSummary;
  /** Nothing structured could be derived — the UI should fall back to raw. */
  isEmpty: boolean;
  truncated: boolean;
  raw: unknown;
}

/** Payload keys the summary renders explicitly (everything else is an extra). */
const KNOWN_PAYLOAD_KEYS = new Set([
  "message",
  "role",
  "_mcpOperation",
  "_mcpTool",
  "_mcpArguments",
  "_mcpResourceUri",
  "_mcpPrompt",
  "_authVariant",
  "_agentScenario",
  "_mcpArgsRepaired",
]);

function asString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value : undefined;
}

function describeScenario(value: unknown): AgentScenarioSummary | undefined {
  if (!isRecord(value)) return undefined;
  return {
    userTask: asString(value.userTask),
    poisonedTool: asString(value.poisonedTool),
    poisonedContent: asString(value.poisonedContent),
    canary: asString(value.canary),
    writeTools: Array.isArray(value.writeTools)
      ? value.writeTools.filter((t): t is string => typeof t === "string")
      : undefined,
  };
}

/**
 * Describe one request payload.
 *
 * `inherit` supplies MCP context for follow-up turns: adaptive multi-turn only
 * records `{ message }` per turn, while the operation and tool live on the
 * attack payload — without inheriting them a follow-up step would look like a
 * bare message with no idea which tool it hit.
 */
export function describeRequest(
  payload: unknown,
  inherit?: unknown,
): RequestSummary {
  const parsed = parseJsonish(payload);
  const source: Record<string, unknown> = isRecord(parsed.value)
    ? { ...parsed.value }
    : {};
  const inherited = parseJsonish(inherit).value;
  if (isRecord(inherited)) {
    for (const [key, value] of Object.entries(inherited)) {
      // Only scanner-internal (`_`-prefixed) context is inherited — never the
      // message or role, which must reflect this turn.
      if (!key.startsWith("_")) continue;
      if (source[key] !== undefined) continue;
      source[key] = value;
    }
  }

  const argsValue = source._mcpArguments;
  const args = isRecord(argsValue)
    ? Object.entries(argsValue).map(([label, value]) => ({
        label,
        value: formatValue(value),
      }))
    : [];

  let message = asString(source.message) ?? asString(parsed.value);
  // Some generators put the tool arguments in `message` as a JSON blob too.
  // Showing both duplicates the argument table for no gain.
  if (message && args.length > 0) {
    const inner = parseJsonish(message).value;
    if (isRecord(inner) && isRecord(argsValue)) {
      const same =
        JSON.stringify(Object.entries(inner).sort()) ===
        JSON.stringify(Object.entries(argsValue).sort());
      if (same) message = undefined;
    }
  }

  const extras = Object.entries(source)
    .filter(([key]) => !KNOWN_PAYLOAD_KEYS.has(key) && !key.startsWith("_"))
    .map(([label, value]) => ({ label, value: formatValue(value) }));

  const operation = asString(source._mcpOperation);
  const tool = asString(source._mcpTool);
  const resourceUri = asString(source._mcpResourceUri);
  const promptName = asString(source._mcpPrompt);
  const authVariant = asString(source._authVariant);
  const agentScenario = describeScenario(source._agentScenario);

  return {
    operation,
    tool,
    resourceUri,
    promptName,
    authVariant,
    args,
    message,
    role: asString(source.role),
    extras,
    argsRepaired: source._mcpArgsRepaired === true,
    agentScenario,
    isEmpty:
      !operation &&
      !tool &&
      !resourceUri &&
      !promptName &&
      !authVariant &&
      !message &&
      !agentScenario &&
      args.length === 0 &&
      extras.length === 0,
    truncated: parsed.truncated,
    raw: payload,
  };
}

/** One-line title for a request, e.g. `tools/call · search_flights`. */
export function requestTitle(request: RequestSummary): string {
  const subject =
    request.tool ??
    request.promptName ??
    request.resourceUri ??
    (request.authVariant ? `${request.authVariant} credential` : undefined);
  if (request.operation && subject) return `${request.operation} · ${subject}`;
  if (request.operation) return request.operation;
  if (subject) return subject;
  return "Request";
}

/* ─── response side ─── */

export type ResponseKind =
  | "tool-result"
  | "tools-list"
  | "resource"
  | "prompt"
  | "auth-probe"
  | "rug-pull"
  | "agent-loop"
  | "discovery"
  | "adapter-error"
  | "text"
  | "json"
  | "empty";

export interface AgentToolCallSummary {
  step: number;
  tool: string;
  args: KeyValue[];
  risk: string;
  afterPoisonedRead: boolean;
  canaryInArgs: boolean;
  taintedArgs: string[];
}

export interface AgentLoopSummary {
  steps: number;
  compromised: boolean;
  finalAnswer?: string;
  toolCalls: AgentToolCallSummary[];
  transcript: { role: string; content: string }[];
  findings: string[];
}

export interface ResponseSummary {
  /** MCP operation echoed by the adapter. */
  operation?: string;
  kind: ResponseKind;
  /** The server (or adapter) reported a failure. */
  isError: boolean;
  /** JSON-RPC error code parsed out of an MCP error string. */
  errorCode?: number;
  /** One-line outcome, e.g. "MCP protocol error -32602". */
  headline?: string;
  /** The response text, unescaped and ready to print. */
  text?: string;
  fields: KeyValue[];
  agentLoop?: AgentLoopSummary;
  truncated: boolean;
  isEmpty: boolean;
  raw: unknown;
}

const MCP_ERROR_RE = /^MCP error (-?\d+):\s*([\s\S]*)$/;

/** Flatten an MCP `content` array into text plus non-text part descriptions. */
function contentToText(content: unknown): { text: string; fields: KeyValue[] } {
  if (typeof content === "string") return { text: content, fields: [] };
  if (!Array.isArray(content)) return { text: "", fields: [] };
  const texts: string[] = [];
  const fields: KeyValue[] = [];
  for (const part of content) {
    if (typeof part === "string") {
      texts.push(part);
      continue;
    }
    if (!isRecord(part)) continue;
    if (typeof part.text === "string") {
      texts.push(part.text);
      continue;
    }
    if (isRecord(part.resource)) {
      const resource = part.resource;
      if (typeof resource.text === "string") {
        texts.push(resource.text);
        continue;
      }
      fields.push({
        label: "embedded resource",
        value: formatValue(resource.uri ?? resource),
      });
      continue;
    }
    const type = asString(part.type) ?? "content";
    fields.push({
      label: type,
      value: formatValue(part.mimeType ?? part.uri ?? part.data ?? part),
    });
  }
  return { text: texts.join("\n\n"), fields };
}

function describeAgentLoop(result: Record<string, unknown>): AgentLoopSummary {
  const rawCalls = Array.isArray(result.toolCalls) ? result.toolCalls : [];
  const toolCalls: AgentToolCallSummary[] = rawCalls
    .filter(isRecord)
    .map((call, i) => ({
      step: typeof call.step === "number" ? call.step : i + 1,
      tool: asString(call.tool) ?? "(unnamed tool)",
      args: isRecord(call.arguments)
        ? Object.entries(call.arguments).map(([label, value]) => ({
            label,
            value: formatValue(value),
          }))
        : [],
      risk: asString(call.risk) ?? "read",
      afterPoisonedRead: call.afterPoisonedRead === true,
      canaryInArgs: call.canaryInArgs === true,
      taintedArgs: Array.isArray(call.taintedArgs)
        ? call.taintedArgs.filter((k): k is string => typeof k === "string")
        : [],
    }));
  const transcript = (Array.isArray(result.transcript) ? result.transcript : [])
    .filter(isRecord)
    .map((m) => ({
      role: asString(m.role) ?? "assistant",
      content: typeof m.content === "string" ? m.content : formatValue(m.content),
    }));
  return {
    steps: typeof result.steps === "number" ? result.steps : transcript.length,
    compromised: result.compromised === true,
    finalAnswer: asString(result.finalAnswer),
    toolCalls,
    transcript,
    findings: Array.isArray(result.findings)
      ? result.findings.filter((f): f is string => typeof f === "string")
      : [],
  };
}

/** Text keys a plain (non-MCP) agent uses for its answer. */
const AGENT_TEXT_KEYS = [
  "response",
  "content",
  "text",
  "message",
  "answer",
  "output",
  "reply",
];

export function describeResponse(body: unknown): ResponseSummary {
  const parsed = parseJsonish(body);
  const base = {
    fields: [] as KeyValue[],
    isError: false,
    truncated: parsed.truncated,
    raw: body,
  };

  if (parsed.value == null || parsed.value === "") {
    return { ...base, kind: "empty", isEmpty: true };
  }
  if (typeof parsed.value === "string") {
    return { ...base, kind: "text", text: parsed.value, isEmpty: false };
  }
  if (!isRecord(parsed.value)) {
    return {
      ...base,
      kind: "json",
      text: formatValue(parsed.value),
      isEmpty: false,
    };
  }

  const envelope = parsed.value;
  const operation = asString(envelope.operation);
  const hasEnvelope = operation !== undefined && "result" in envelope;
  const result = hasEnvelope ? envelope.result : envelope;

  // Adapter-level failure (bad payload, unreachable server, thrown error).
  const errorText =
    asString(envelope.error) ??
    (isRecord(result) ? asString(result.error) : undefined);
  if (errorText) {
    const match = MCP_ERROR_RE.exec(errorText);
    return {
      ...base,
      operation,
      kind: "adapter-error",
      isError: true,
      errorCode: match ? Number(match[1]) : undefined,
      headline: match ? `MCP protocol error ${match[1]}` : "Request failed",
      text: match ? match[2] : errorText,
      isEmpty: false,
    };
  }

  if (isRecord(result)) {
    // agent-in-the-loop
    if (Array.isArray(result.toolCalls) && Array.isArray(result.transcript)) {
      const agentLoop = describeAgentLoop(result);
      return {
        ...base,
        operation,
        kind: "agent-loop",
        isError: false,
        headline: agentLoop.compromised
          ? "Injection landed — the agent took an unauthorized action"
          : "Agent completed the task without an unauthorized action",
        text: agentLoop.finalAnswer,
        fields: [
          { label: "agent steps", value: String(agentLoop.steps) },
          { label: "tool calls", value: String(agentLoop.toolCalls.length) },
        ],
        agentLoop,
        isEmpty: false,
      };
    }

    // tools/call result
    if ("content" in result || result.isError !== undefined) {
      const { text, fields } = contentToText(result.content);
      const match = MCP_ERROR_RE.exec(text.trim());
      const isError = result.isError === true || Boolean(match);
      if (isRecord(result.structuredContent)) {
        fields.push({
          label: "structuredContent",
          value: formatValue(result.structuredContent),
        });
      }
      return {
        ...base,
        operation,
        kind: "tool-result",
        isError,
        errorCode: match ? Number(match[1]) : undefined,
        headline: match
          ? `MCP protocol error ${match[1]}`
          : isError
            ? "Tool reported an error"
            : "Tool executed successfully",
        text: match ? match[2] : text,
        fields,
        isEmpty: !text && fields.length === 0,
      };
    }

    // tools/list (also the `discover` surface summary)
    const tools = Array.isArray(result.tools) ? result.tools : undefined;
    if (tools) {
      const names = tools.filter(isRecord).map((t) => {
        const name = asString(t.name) ?? "(unnamed)";
        const description = asString(t.description);
        return description ? `• ${name} — ${description}` : `• ${name}`;
      });
      const fields: KeyValue[] = [{ label: "tools", value: String(tools.length) }];
      for (const key of ["prompts", "resources"] as const) {
        if (Array.isArray(result[key])) {
          fields.push({ label: key, value: String((result[key] as unknown[]).length) });
        }
      }
      if (asString(result.instructions)) {
        fields.push({ label: "instructions", value: String(result.instructions) });
      }
      return {
        ...base,
        operation,
        kind: operation === "discover" ? "discovery" : "tools-list",
        isError: false,
        headline: `${tools.length} tool${tools.length === 1 ? "" : "s"} exposed`,
        text: names.join("\n"),
        fields,
        isEmpty: false,
      };
    }

    // resources/read
    if (Array.isArray(result.contents)) {
      const texts: string[] = [];
      const fields: KeyValue[] = [];
      for (const entry of result.contents) {
        if (!isRecord(entry)) continue;
        const uri = asString(entry.uri);
        if (typeof entry.text === "string") {
          texts.push(uri ? `${uri}\n${entry.text}` : entry.text);
        } else {
          fields.push({
            label: uri ?? "content",
            value: formatValue(entry.mimeType ?? entry.blob ?? entry),
          });
        }
      }
      return {
        ...base,
        operation,
        kind: "resource",
        isError: false,
        headline: `${result.contents.length} resource content block${result.contents.length === 1 ? "" : "s"}`,
        text: texts.join("\n\n"),
        fields,
        isEmpty: texts.length === 0 && fields.length === 0,
      };
    }

    // prompts/get
    if (Array.isArray(result.messages)) {
      const lines = result.messages.filter(isRecord).map((m) => {
        const role = asString(m.role) ?? "message";
        const { text } = contentToText(
          isRecord(m.content) ? [m.content] : m.content,
        );
        return `${role}: ${text || formatValue(m.content)}`;
      });
      return {
        ...base,
        operation,
        kind: "prompt",
        isError: false,
        headline: `${result.messages.length} prompt message${result.messages.length === 1 ? "" : "s"}`,
        text: lines.join("\n\n"),
        isEmpty: lines.length === 0,
      };
    }

    // auth_probe
    if (result.accepted !== undefined && asString(result.variant)) {
      const accepted = result.accepted === true;
      return {
        ...base,
        operation,
        kind: "auth-probe",
        isError: false,
        headline: accepted
          ? `Server ACCEPTED a ${String(result.variant)} credential`
          : `Server rejected the ${String(result.variant)} credential`,
        text: asString(result.detail),
        fields: [
          { label: "variant", value: String(result.variant) },
          { label: "accepted", value: String(accepted) },
          { label: "status", value: String(result.statusCode ?? "-") },
        ],
        isEmpty: false,
      };
    }

    // rug_pull_probe metadata diff
    if (Array.isArray(result.changed) && Array.isArray(result.addedTools)) {
      const changed = result.changed.filter(isRecord);
      const newSignals = Array.isArray(result.newPoisonSignals)
        ? result.newPoisonSignals.filter(isRecord)
        : [];
      const lines = changed.map(
        (c) =>
          `${asString(c.tool) ?? "?"} · ${asString(c.field) ?? "?"}\n  before: ${formatValue(c.before)}\n  after:  ${formatValue(c.after)}`,
      );
      return {
        ...base,
        operation,
        kind: "rug-pull",
        isError: false,
        headline:
          changed.length + newSignals.length === 0
            ? "Tool metadata was stable across two loads"
            : "Tool metadata changed between two loads",
        text: lines.join("\n\n"),
        fields: [
          { label: "changed fields", value: String(changed.length) },
          { label: "added tools", value: formatValue(result.addedTools) || "0" },
          { label: "removed tools", value: formatValue(result.removedTools) || "0" },
          { label: "new poisoning signals", value: String(newSignals.length) },
        ],
        isEmpty: false,
      };
    }

    // Plain agent body: { response, tool_calls, ... }
    for (const key of AGENT_TEXT_KEYS) {
      const text = asString(result[key]);
      if (!text) continue;
      const fields: KeyValue[] = [];
      for (const [label, value] of Object.entries(result)) {
        if (label === key) continue;
        fields.push({ label, value: formatValue(value) });
      }
      return {
        ...base,
        operation,
        kind: "text",
        isError: false,
        text,
        fields,
        isEmpty: false,
      };
    }
  }

  // Anything else — keep every field visible rather than dumping a blob.
  const fields = isRecord(result)
    ? Object.entries(result).map(([label, value]) => ({
        label,
        value: formatValue(value),
      }))
    : [];
  const text = fields.length === 0 ? formatValue(result) : undefined;
  return {
    ...base,
    operation,
    kind: "json",
    isError: false,
    text,
    fields,
    isEmpty: fields.length === 0 && !text,
  };
}

/* ─── interaction flow ─── */

export interface ConversationLike {
  stepIndex?: number;
  payload?: unknown;
  statusCode?: number;
  responseBody?: unknown;
  responseTimeMs?: number;
  /** Legacy chat-transcript shape. */
  role?: string;
  content?: string;
}

export interface TraceLike {
  transport?: string;
  operation?: string;
  serverName?: string;
  protocolVersion?: string;
  transcript?: unknown;
  stderr?: string;
}

export interface FlowSource {
  /** `attack.payload` — the request the scanner built. */
  attackPayload?: unknown;
  /** Result-level response body. */
  responseBody?: unknown;
  statusCode?: number;
  responseTimeMs?: number;
  conversation?: ConversationLike[];
  executionTrace?: TraceLike;
}

export type FlowTone = "request" | "response" | "error" | "model" | "note";

export interface FlowStep {
  /** 1-based position in the rendered sequence. */
  index: number;
  from: FlowParty;
  to: FlowParty;
  /** Short headline, e.g. `Tool call · send_email`. */
  title: string;
  /** Turn number for multi-turn conversations (1-based). */
  turn?: number;
  request?: RequestSummary;
  response?: ResponseSummary;
  /** Free text when neither summary applies (model thought, system prompt). */
  note?: string;
  tags: string[];
  tone: FlowTone;
  statusCode?: number;
  timeMs?: number;
  raw?: unknown;
}

const OBSERVATION_RE = /^OBSERVATION from ([^\n:]+):\n?([\s\S]*)$/;

/** Extract the first balanced JSON object from text (agent actions are JSON). */
function firstJsonObject(text: string): Record<string, unknown> | undefined {
  const start = text.indexOf("{");
  if (start === -1) return undefined;
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let i = start; i < text.length; i++) {
    const ch = text[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') inString = true;
    else if (ch === "{") depth++;
    else if (ch === "}") {
      depth--;
      if (depth === 0) {
        try {
          const parsed: unknown = JSON.parse(text.slice(start, i + 1));
          return isRecord(parsed) ? parsed : undefined;
        } catch {
          return undefined;
        }
      }
    }
  }
  return undefined;
}

function toolCallTags(call: AgentToolCallSummary | undefined): string[] {
  if (!call) return [];
  const tags: string[] = [];
  if (call.risk === "write") tags.push("write tool");
  if (call.afterPoisonedRead) tags.push("after poisoned read");
  if (call.canaryInArgs) tags.push("canary in arguments");
  if (call.taintedArgs.length > 0) {
    tags.push(`tainted args: ${call.taintedArgs.join(", ")}`);
  }
  return tags;
}

/**
 * The agent-in-the-loop flow: the model holds the MCP tools, so the sequence is
 * User → Model → MCP server → Model → … → User. Built from the recorded chat
 * transcript, enriched with the graded tool-call metadata.
 */
function agentLoopFlow(
  loop: AgentLoopSummary,
  scenario: AgentScenarioSummary | undefined,
  push: (step: Omit<FlowStep, "index">) => void,
): void {
  let callCursor = 0;
  let sawUserTask = false;

  for (const message of loop.transcript) {
    if (message.role === "system") {
      push({
        from: "system",
        to: "model",
        title: "System prompt · tool manifest",
        note: message.content,
        tags: [],
        tone: "note",
      });
      continue;
    }

    if (message.role === "user") {
      const observation = OBSERVATION_RE.exec(message.content);
      if (observation) {
        const tool = observation[1].trim();
        const poisoned = tool === scenario?.poisonedTool;
        push({
          from: "server",
          to: "model",
          title: `Tool result · ${tool}`,
          note: observation[2],
          tags: poisoned ? ["attacker-controlled content"] : [],
          tone: poisoned ? "error" : "response",
        });
        continue;
      }
      if (!sawUserTask) {
        sawUserTask = true;
        push({
          from: "user",
          to: "model",
          title: "User task",
          note: message.content,
          tags: [],
          tone: "request",
        });
        continue;
      }
      push({
        from: "system",
        to: "model",
        title: "Harness correction",
        note: message.content,
        tags: [],
        tone: "note",
      });
      continue;
    }

    // assistant
    const action = firstJsonObject(message.content);
    const tool = action ? asString(action.tool) : undefined;
    const thought = action ? asString(action.thought) : undefined;
    if (tool) {
      const call = loop.toolCalls[callCursor++];
      const callArgs = action?.arguments;
      push({
        from: "model",
        to: "server",
        title: `Tool call · ${tool}`,
        request: {
          operation: "tools/call",
          tool,
          args: isRecord(callArgs)
            ? Object.entries(callArgs).map(([label, value]) => ({
                label,
                value: formatValue(value),
              }))
            : (call?.args ?? []),
          extras: [],
          argsRepaired: false,
          isEmpty: false,
          truncated: false,
          message: thought,
          raw: action,
        },
        tags: toolCallTags(call),
        tone: "model",
      });
      continue;
    }
    const answer = action ? asString(action.answer) : undefined;
    if (answer) {
      push({
        from: "model",
        to: "user",
        title: "Final answer",
        note: answer,
        tags: [],
        tone: "response",
      });
      continue;
    }
    push({
      from: "model",
      to: "system",
      title: "Model output",
      note: message.content,
      tags: [],
      tone: "note",
    });
  }

  if (loop.transcript.length === 0 && loop.finalAnswer) {
    push({
      from: "model",
      to: "user",
      title: "Final answer",
      note: loop.finalAnswer,
      tags: [],
      tone: "response",
    });
  }
}

/**
 * Build the ordered interaction flow for one result: every request the scanner
 * sent and every response it got back, in order, with the model's own turns
 * expanded when the target was driven agent-in-the-loop.
 */
export function buildInteractionFlow(src: FlowSource): FlowStep[] {
  const steps: FlowStep[] = [];
  const push = (step: Omit<FlowStep, "index">) => {
    steps.push({ ...step, index: steps.length + 1 });
  };

  const attackRequest = describeRequest(src.attackPayload);
  const resultResponse = describeResponse(src.responseBody);

  if (resultResponse.agentLoop) {
    agentLoopFlow(
      resultResponse.agentLoop,
      attackRequest.agentScenario,
      push,
    );
    return steps;
  }

  const turns = (src.conversation ?? []).filter(
    (t) => t && (t.payload !== undefined || t.responseBody !== undefined || t.content),
  );

  if (turns.length === 0) {
    if (!attackRequest.isEmpty) {
      push({
        from: "user",
        to: "server",
        title: requestTitle(attackRequest),
        request: attackRequest,
        tags: [],
        tone: "request",
      });
    }
    if (!resultResponse.isEmpty) {
      push({
        from: "server",
        to: "user",
        title: "Response",
        response: resultResponse,
        tags: resultResponse.isError ? ["error"] : [],
        tone: resultResponse.isError ? "error" : "response",
        statusCode: src.statusCode,
        timeMs: src.responseTimeMs,
      });
    }
    return steps;
  }

  turns.forEach((turn, i) => {
    const turnNumber = (turn.stepIndex ?? i) + 1;

    // Legacy `{ role, content }` transcript entries.
    if (turn.payload === undefined && typeof turn.content === "string") {
      const fromUser = turn.role === "user";
      push({
        from: fromUser ? "user" : "server",
        to: fromUser ? "server" : "user",
        title: fromUser ? "User message" : `${turn.role ?? "agent"} message`,
        note: turn.content,
        turn: turnNumber,
        tags: [],
        tone: fromUser ? "request" : "response",
        statusCode: turn.statusCode,
      });
      return;
    }

    const request = describeRequest(turn.payload, src.attackPayload);
    if (!request.isEmpty) {
      push({
        from: "user",
        to: "server",
        title: requestTitle(request),
        request,
        turn: turnNumber,
        tags: [],
        tone: "request",
      });
    }
    const response = describeResponse(turn.responseBody);
    if (!response.isEmpty) {
      push({
        from: "server",
        to: "user",
        title: "Response",
        response,
        turn: turnNumber,
        tags: response.isError ? ["error"] : [],
        tone: response.isError ? "error" : "response",
        statusCode: turn.statusCode,
        timeMs: turn.responseTimeMs,
      });
    }
  });

  return steps;
}

/* ─── JSON-RPC protocol trace ─── */

export interface ProtocolEvent {
  index: number;
  from: FlowParty;
  to: FlowParty;
  /** JSON-RPC method, or the method this message answers. */
  method?: string;
  /** e.g. `request #2 · tools/call` */
  label: string;
  /** One-line human summary of the payload. */
  summary?: string;
  isError: boolean;
  isNotification: boolean;
  raw: unknown;
}

function jsonRpcId(payload: unknown): string | undefined {
  if (!isRecord(payload)) return undefined;
  const id = payload.id;
  if (typeof id === "string" || typeof id === "number") return String(id);
  return undefined;
}

/** Short human summary of a JSON-RPC message. */
function protocolSummary(payload: unknown, method?: string): string | undefined {
  if (!isRecord(payload)) return undefined;
  if (isRecord(payload.error)) {
    return `error ${formatValue(payload.error.code)}: ${formatValue(payload.error.message)}`;
  }
  if ("result" in payload) {
    const result = payload.result;
    if (isRecord(result)) {
      if (Array.isArray(result.content)) {
        const { text } = contentToText(result.content);
        const prefix = result.isError === true ? "isError · " : "";
        return prefix + text.replace(/\s+/g, " ").slice(0, 200);
      }
      if (Array.isArray(result.tools)) return `${result.tools.length} tools`;
      if (isRecord(result.serverInfo)) {
        return `${formatValue(result.serverInfo.name)} · protocol ${formatValue(result.protocolVersion)}`;
      }
    }
    return formatValue(result).replace(/\s+/g, " ").slice(0, 200);
  }
  const params = isRecord(payload.params) ? payload.params : undefined;
  if (!params) return undefined;
  if (method === "tools/call") {
    const args = isRecord(params.arguments) ? Object.keys(params.arguments) : [];
    return `${formatValue(params.name)}(${args.join(", ")})`;
  }
  if (method === "initialize") {
    return `protocol ${formatValue(params.protocolVersion)}`;
  }
  const keys = Object.keys(params);
  return keys.length > 0 ? keys.join(", ") : undefined;
}

/** Turn the wire transcript into labelled, ordered protocol events. */
export function buildProtocolTrace(trace?: TraceLike): ProtocolEvent[] {
  const raw = Array.isArray(trace?.transcript) ? trace!.transcript : [];
  const events = raw.filter(isRecord);
  // JSON-RPC responses carry only an id, so remember which method each id asked.
  const methodById = new Map<string, string>();
  for (const event of events) {
    const method = asString(event.method);
    const id = jsonRpcId(event.payload);
    if (method && id) methodById.set(id, method);
  }

  return events.map((event, i) => {
    const direction = asString(event.direction) ?? "client->server";
    const fromClient = direction.startsWith("client");
    const id = jsonRpcId(event.payload);
    const method =
      asString(event.method) ?? (id ? methodById.get(id) : undefined);
    const payload = event.payload;
    const isNotification = !fromClient
      ? direction.endsWith("notify")
      : Boolean(method?.startsWith("notifications/")) || (!id && Boolean(method));
    const label = fromClient
      ? `${isNotification ? "notify" : "request"}${id ? ` #${id}` : ""}${method ? ` · ${method}` : ""}`
      : `response${id ? ` #${id}` : ""}${method ? ` · ${method}` : ""}`;
    const isError =
      isRecord(payload) &&
      (isRecord(payload.error) ||
        (isRecord(payload.result) && payload.result.isError === true));
    return {
      index: i + 1,
      from: fromClient ? "user" : "server",
      to: fromClient ? "server" : "user",
      method,
      label,
      summary: protocolSummary(payload, method),
      isError,
      isNotification,
      raw: payload,
    };
  });
}

/** True when this result came from an MCP target (vs an HTTP agent). */
export function isMcpResult(src: {
  attackPayload?: unknown;
  responseBody?: unknown;
  executionTrace?: TraceLike;
}): boolean {
  if (src.executionTrace) return true;
  const payload = parseJsonish(src.attackPayload).value;
  if (isRecord(payload) && typeof payload._mcpOperation === "string") return true;
  const body = parseJsonish(src.responseBody).value;
  return isRecord(body) && typeof body.operation === "string" && "result" in body;
}
