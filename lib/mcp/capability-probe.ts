import type { McpTraceEvent } from "../types.js";

/**
 * MCP capability-manipulation detection.
 *
 * A client advertises capabilities at initialize (sampling, roots,
 * elicitation). If it advertises `sampling`, a malicious/over-reaching server
 * can issue a server→client `sampling/createMessage` — driving the client's LLM,
 * at the client's cost, with attacker-chosen prompts, and reading the
 * completion. `roots/list` and `elicitation/create` are analogous server→client
 * requests. The client normally advertises `{}`, so this is never exercised;
 * the probe advertises the capabilities and scans the transcript for any
 * UNSOLICITED server-initiated request. Pure so it is unit-testable.
 */

/** Server→client request methods that indicate the server is driving the client. */
const SERVER_INITIATED_METHODS = new Set([
  "sampling/createmessage",
  "elicitation/create",
  "roots/list",
]);

export interface ServerInitiatedRequest {
  method: string;
  /** Snippet of the request params (e.g. the sampling prompt) for evidence. */
  snippet: string;
}

export interface CapabilityProbeResult {
  applicable: boolean;
  samplingRequested: boolean;
  elicitationRequested: boolean;
  rootsRequested: boolean;
  requests: ServerInitiatedRequest[];
  detail: string;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object";
}

/**
 * Find server→client REQUESTS (a `method` plus an `id`, not a notification) in a
 * transcript — the server asking the client to do something it was never asked
 * to offer beyond advertising the capability.
 */
export function scanServerInitiatedRequests(
  transcript: McpTraceEvent[],
): ServerInitiatedRequest[] {
  const found: ServerInitiatedRequest[] = [];
  for (const ev of transcript) {
    if (!ev.direction.startsWith("server->client")) continue;
    const payload = ev.payload;
    if (!isRecord(payload)) continue;
    const method = payload.method;
    // A request (has method + id); a plain response has no method.
    if (typeof method !== "string" || payload.id == null) continue;
    if (!SERVER_INITIATED_METHODS.has(method.toLowerCase())) continue;
    const params = payload.params;
    const snippet = JSON.stringify(params ?? {}).slice(0, 200);
    found.push({ method, snippet });
  }
  return found;
}

export function summarizeCapabilityProbe(
  applicable: boolean,
  requests: ServerInitiatedRequest[],
): CapabilityProbeResult {
  const has = (m: string) =>
    requests.some((r) => r.method.toLowerCase() === m);
  return {
    applicable,
    samplingRequested: has("sampling/createmessage"),
    elicitationRequested: has("elicitation/create"),
    rootsRequested: has("roots/list"),
    requests,
    detail: applicable
      ? `${requests.length} server-initiated request(s): ${requests.map((r) => r.method).join(", ") || "none"}`
      : "capability_probe requires a configured LLM/MCP surface",
  };
}
