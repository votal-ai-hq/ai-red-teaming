import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  GENERATION_ENGINES,
  getEngine,
  isEngineId,
  engineKeyConfigured,
} from "../lib/dataset/generation-engines.js";
import { anthropicChat } from "../lib/dataset/anthropic-chat.js";

describe("generation engines registry", () => {
  it("includes the four direct engines with sane defaults", () => {
    const ids = GENERATION_ENGINES.map((e) => e.id).sort();
    expect(ids).toEqual(["anthropic", "ollama", "openai", "openrouter"]);
    expect(getEngine("anthropic")?.defaultModel).toBe("claude-opus-4-8");
    expect(getEngine("openrouter")?.defaultBaseUrl).toContain("openrouter.ai");
    expect(getEngine("ollama")?.apiKeyEnv).toBeUndefined(); // keyless
    expect(isEngineId("anthropic")).toBe(true);
    expect(isEngineId("data-designer")).toBe(false);
  });

  it("engineKeyConfigured: keyless engine is always ready; keyed depends on env", () => {
    const prev = process.env.OPENAI_API_KEY;
    delete process.env.OPENAI_API_KEY;
    delete process.env.NEMO_API_KEY;
    expect(engineKeyConfigured(getEngine("ollama")!)).toBe(true);
    expect(engineKeyConfigured(getEngine("openai")!)).toBe(false);
    process.env.OPENAI_API_KEY = "sk-test";
    expect(engineKeyConfigured(getEngine("openai")!)).toBe(true);
    if (prev === undefined) delete process.env.OPENAI_API_KEY;
    else process.env.OPENAI_API_KEY = prev;
  });
});

describe("anthropicChat", () => {
  it("posts to the Messages API (no temperature) and returns joined text", async () => {
    let seen: { url: string; body: Record<string, unknown>; headers: Record<string, string> } | undefined;
    const fetchImpl = (async (url: string, init: RequestInit) => {
      seen = {
        url,
        body: JSON.parse(init.body as string),
        headers: init.headers as Record<string, string>,
      };
      return new Response(
        JSON.stringify({ content: [{ type: "text", text: "hello world" }] }),
        { status: 200 },
      );
    }) as unknown as typeof fetch;

    const chat = anthropicChat("key-123", { fetchImpl });
    const out = await chat({ model: "claude-opus-4-8", user: "hi" });

    expect(out).toBe("hello world");
    expect(seen?.url).toContain("api.anthropic.com/v1/messages");
    expect(seen?.headers["x-api-key"]).toBe("key-123");
    expect(seen?.headers["anthropic-version"]).toBe("2023-06-01");
    expect(seen?.body.model).toBe("claude-opus-4-8");
    // Opus 4.8 rejects temperature — it must not be sent.
    expect(seen?.body).not.toHaveProperty("temperature");
    expect(seen?.body.messages).toEqual([{ role: "user", content: "hi" }]);
  });

  it("throws a clear error on an HTTP error", async () => {
    const fetchImpl = (async () =>
      new Response("bad key", { status: 401 })) as unknown as typeof fetch;
    const chat = anthropicChat("bad", { fetchImpl });
    await expect(chat({ model: "claude-opus-4-8", user: "x" })).rejects.toThrow(
      /Anthropic API 401: bad key/,
    );
  });
});

describe("generateWithOpenAI works with an Anthropic-shaped chat", () => {
  // The Anthropic engine flows through the same generator via an injected chat.
  beforeEach(() => void 0);
  afterEach(() => void 0);

  it("produces valid rows using anthropicChat over a stub fetch", async () => {
    const { generateWithOpenAI } = await import("../lib/dataset/openai-generator.js");
    const { buildDataDesignerConfig } = await import("../lib/dataset/nemo-config-builder.js");
    const { recordsToRows } = await import("../lib/dataset/map-records.js");
    const { validateRows } = await import("../lib/dataset/validate.js");

    // Stub Anthropic: return a distinct attacker message per call (so rows
    // aren't dedup'd), then JSON grading.
    let n = 0;
    const fetchImpl = (async (_url: string, init: RequestInit) => {
      const body = JSON.parse(init.body as string) as { messages: { content: string }[] };
      const isGrading = /successCriteria/.test(body.messages[0].content);
      const text = isGrading
        ? '{"successCriteria":"the tool was misused","expectation":"refuse"}'
        : `{"bookingId":"BK-${n++}"}`;
      return new Response(JSON.stringify({ content: [{ type: "text", text }] }), { status: 200 });
    }) as unknown as typeof fetch;

    const config = buildDataDesignerConfig(
      { family: "mcp", generationModel: "claude-opus-4-8", count: 3 },
      { surfaces: ['tool "get_booking"'] },
    );
    const records = await generateWithOpenAI(config, 3, { chat: anthropicChat("k", { fetchImpl }) });
    const { valid, errors } = validateRows(recordsToRows(records, "mcp"), {
      family: "mcp",
    });
    expect(errors).toEqual([]);
    expect(valid).toHaveLength(3);
  });
});
