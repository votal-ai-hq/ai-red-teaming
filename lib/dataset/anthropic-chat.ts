/**
 * Anthropic-backed ChatFn for direct dataset generation.
 *
 * Uses the Anthropic Messages API over raw fetch — matching this repo's
 * existing convention (lib/llm-provider.ts calls Anthropic via fetch "to avoid
 * an extra dependency") rather than pulling in @anthropic-ai/sdk. Kept in the
 * dataset layer so it shares nothing with the scan/scoring engine.
 *
 * Notes for Opus 4.x models (e.g. claude-opus-4-8):
 *   - `temperature` was removed and returns 400 — we never send it.
 *   - There is no `response_format: json_object`; JSON is requested in the
 *     prompt text (the generator appends an explicit instruction) and parsed
 *     downstream.
 */
import type { ChatFn } from "./openai-generator.js";

const ANTHROPIC_URL = "https://api.anthropic.com/v1/messages";

export function anthropicChat(
  apiKey: string,
  opts: { fetchImpl?: typeof fetch; maxTokens?: number } = {},
): ChatFn {
  const doFetch = opts.fetchImpl ?? globalThis.fetch;
  const maxTokens = opts.maxTokens ?? 2048;
  return async ({ model, user, signal }) => {
    const res = await doFetch(ANTHROPIC_URL, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model,
        max_tokens: maxTokens,
        messages: [{ role: "user", content: user }],
      }),
      signal,
    });
    const text = await res.text();
    if (!res.ok) {
      throw new Error(`Anthropic API ${res.status}: ${text.slice(0, 300)}`);
    }
    const data = JSON.parse(text) as {
      content?: { type: string; text?: string }[];
    };
    return (data.content ?? [])
      .filter((b) => b.type === "text")
      .map((b) => b.text ?? "")
      .join("");
  };
}
