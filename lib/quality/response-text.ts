/**
 * Pull the assistant's text out of an arbitrary target response.
 *
 * A target can answer in any shape: a bare string, `{message}`, `{data:{content}}`,
 * an OpenAI-style `{choices:[{message:{content}}]}`, MCP content blocks, or a
 * streamed SSE body. The scorer previously did
 * `String(extractPath(body, responsePath) ?? "")`, which yields "[object Object]"
 * for structured values and "" whenever the configured path doesn't match — so a
 * perfectly good answer got scored as empty.
 *
 * Strategy: honor the configured `responsePath` first (explicit config wins),
 * then try the common envelopes, and finally fall back to the whole body as
 * JSON. Anything is better than "" — an operator can see what came back and fix
 * their responsePath, instead of debugging a blank.
 */
import { extractPath } from "../response-analyzer.js";
import { toText } from "../dataset/to-text.js";

/** Common places a response text hides, tried in order. */
const FALLBACK_PATHS = [
  "response",
  "message",
  "content",
  "text",
  "answer",
  "output",
  "result",
  "reply",
  "data.message",
  "data.content",
  "data.text",
  "data.response",
  "choices.0.message.content",
  "choices.0.text",
  "candidates.0.content.parts.0.text",
];

/**
 * Join a streamed SSE body into one string. Handles OpenAI-style
 * `data: {"choices":[{"delta":{"content":"…"}}]}` frames and plain
 * `data: <text>` lines. Returns "" when the body isn't SSE.
 */
export function parseSseText(raw: string): string {
  if (!/(^|\n)\s*data:/.test(raw)) return "";
  const out: string[] = [];
  for (const line of raw.split(/\r?\n/)) {
    const m = /^\s*data:\s?(.*)$/.exec(line);
    if (!m) continue;
    const payload = m[1].trim();
    if (!payload || payload === "[DONE]") continue;
    if (payload.startsWith("{") || payload.startsWith("[")) {
      try {
        const obj = JSON.parse(payload) as Record<string, unknown>;
        // streamed delta, then non-streamed shapes, then any text-bearing field
        const delta =
          extractPath(obj, "choices.0.delta.content") ??
          extractPath(obj, "choices.0.message.content") ??
          extractPath(obj, "delta.text") ??
          extractPath(obj, "content") ??
          extractPath(obj, "text");
        const t = toText(delta);
        if (t) out.push(t);
        continue;
      } catch {
        /* not JSON — fall through and take it literally */
      }
    }
    out.push(payload);
  }
  return out.join("");
}

/**
 * Extract response text from an arbitrary body.
 * @param responsePath the operator-configured path (wins when it resolves)
 */
export function extractResponseText(body: unknown, responsePath?: string): string {
  // A raw streamed body arrives as text.
  if (typeof body === "string") {
    const sse = parseSseText(body);
    if (sse.trim()) return sse;
    if (body.trim()) return body;
  }

  if (responsePath) {
    const t = toText(extractPath(body, responsePath));
    if (t.trim()) return t;
  }

  for (const p of FALLBACK_PATHS) {
    const t = toText(extractPath(body, p));
    if (t.trim()) return t;
  }

  // Nothing matched — show the whole body rather than a blank.
  return toText(body);
}
