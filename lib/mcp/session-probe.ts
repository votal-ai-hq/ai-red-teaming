import type { Config } from "../types.js";
import { McpSession } from "./session.js";
import { tamperHeaders } from "./auth-probe.js";
import type { JsonRpcResponse } from "./types.js";

/**
 * MCP session-handling probes (streamable_http only).
 *
 * Spec requirements (2025-03-26 / 2025-06-18): the `Mcp-Session-Id` MUST be
 * cryptographically secure, the server MUST NOT treat it as authentication, and
 * a request bearing an unknown/terminated session id SHOULD get HTTP 404. These
 * probes test three failure modes with credentials STRIPPED:
 *   - forged session id accepted on a non-initialize request (weak validation)
 *   - a captured session id honored without the owner's credentials (session
 *     used as auth — hijack)
 *   - an unauthenticated DELETE terminating a known session (hijack / DoS)
 * plus a low-entropy / predictable session-id signal.
 */

export interface SessionProbeResult {
  applicable: boolean;
  capturedSessionId?: string;
  /** Auth headers were present to strip (so "without-auth acceptance" is meaningful). */
  authPresent: boolean;
  lowEntropy: boolean;
  forgedAccepted: boolean;
  borrowedWithoutAuthAccepted: boolean;
  unauthenticatedDeleteAccepted: boolean;
  detail: string;
}

const AUTH_HEADER =
  /^(authorization|x-api-key|api-key|x-auth-token|x-access-token|x-api-token)$/i;

function hasAuthHeader(headers: Record<string, string> | undefined): boolean {
  if (!headers) return false;
  return Object.keys(headers).some((k) => AUTH_HEADER.test(k));
}

/** A session id is weak if short or looks numeric / sequential / guessable. */
export function isLowEntropySessionId(id: string | undefined): boolean {
  if (!id) return false;
  if (id.length < 16) return true;
  if (/^\d+$/.test(id)) return true;
  if (/^(sess(ion)?|id|mcp)[-_]?\d+$/i.test(id)) return true;
  return false;
}

function buildProbeHeaders(
  baseHeaders: Record<string, string> | undefined,
  sessionId: string,
): Headers {
  const stripped = tamperHeaders(baseHeaders ?? {}, "absent");
  const headers = new Headers(stripped);
  headers.set("Accept", "application/json, text/event-stream");
  headers.set("Content-Type", "application/json");
  headers.set("Mcp-Session-Id", sessionId);
  return headers;
}

/** A POST is "accepted" if it returned 2xx with a JSON-RPC result (not an error/rejection). */
async function postAccepted(
  url: string,
  headers: Headers,
  timeoutMs: number,
): Promise<boolean> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
      signal: controller.signal,
    });
    if (!res.ok) return false; // 401/403/404/… → rejected
    const text = await res.text();
    if (!text.trim()) return false;
    // Parse either JSON or SSE data frames; accepted iff a result (not error) came back.
    const payloads = parsePayloads(text);
    return payloads.some((p) => p.result !== undefined && p.error === undefined);
  } catch {
    return false;
  } finally {
    clearTimeout(timeout);
  }
}

function parsePayloads(text: string): JsonRpcResponse[] {
  const trimmed = text.trim();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      const parsed = JSON.parse(trimmed);
      return Array.isArray(parsed) ? parsed : [parsed];
    } catch {
      return [];
    }
  }
  // SSE: collect `data:` lines.
  const out: JsonRpcResponse[] = [];
  for (const line of trimmed.split(/\r?\n/)) {
    if (line.startsWith("data:")) {
      try {
        out.push(JSON.parse(line.slice(5).trim()));
      } catch {
        /* ignore */
      }
    }
  }
  return out;
}

async function deleteAccepted(
  url: string,
  headers: Headers,
  timeoutMs: number,
): Promise<boolean> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { method: "DELETE", headers, signal: controller.signal });
    return res.ok; // 2xx = the server terminated the session for an unauthenticated caller
  } catch {
    return false;
  } finally {
    clearTimeout(timeout);
  }
}

export async function runSessionProbe(config: Config): Promise<SessionProbeResult> {
  const mcp = config.target.mcp;
  if (!mcp || mcp.transport !== "streamable_http" || !mcp.url) {
    return {
      applicable: false,
      authPresent: false,
      lowEntropy: false,
      forgedAccepted: false,
      borrowedWithoutAuthAccepted: false,
      unauthenticatedDeleteAccepted: false,
      detail: "session_probe is only applicable to streamable_http targets",
    };
  }

  const url = mcp.url;
  const timeoutMs = mcp.sessionTimeoutMs ?? 10_000;
  const authPresent = hasAuthHeader(mcp.headers);

  // 1. Establish a legitimate session and capture its id.
  const session = new McpSession(config);
  let capturedSessionId: string | undefined;
  try {
    await session.initialize();
    capturedSessionId = session.getSessionId();
  } catch {
    /* fall through — we can still run the forged-id probe */
  } finally {
    await session.close();
  }

  // 2. Forged session id on a non-initialize request (no auth).
  const forgedId = "rt-forged-0000000000000001";
  const forgedAccepted = await postAccepted(
    url,
    buildProbeHeaders(mcp.headers, forgedId),
    timeoutMs,
  );

  // 3 & 4. Borrowed real session id without auth, and unauthenticated DELETE.
  let borrowedWithoutAuthAccepted = false;
  let unauthenticatedDeleteAccepted = false;
  if (capturedSessionId) {
    borrowedWithoutAuthAccepted = await postAccepted(
      url,
      buildProbeHeaders(mcp.headers, capturedSessionId),
      timeoutMs,
    );
    unauthenticatedDeleteAccepted = await deleteAccepted(
      url,
      buildProbeHeaders(mcp.headers, capturedSessionId),
      timeoutMs,
    );
  }

  const lowEntropy = isLowEntropySessionId(capturedSessionId);

  return {
    applicable: true,
    capturedSessionId,
    authPresent,
    lowEntropy,
    forgedAccepted,
    borrowedWithoutAuthAccepted,
    unauthenticatedDeleteAccepted,
    detail: `captured=${capturedSessionId ? "yes" : "no"}, forgedAccepted=${forgedAccepted}, borrowedWithoutAuth=${borrowedWithoutAuthAccepted}, unauthDelete=${unauthenticatedDeleteAccepted}, lowEntropy=${lowEntropy}`,
  };
}
