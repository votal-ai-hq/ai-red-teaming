/**
 * Direct-OpenAI dataset generator — a drop-in alternative to the NeMo Data
 * Designer service. It consumes the SAME `DataDesignerConfig` produced by the
 * config builders and returns records in the SAME shape Data Designer would,
 * so everything downstream (map-records → validate → write) and everything
 * upstream (presets, app profiles, policies, multi-turn) works unchanged — the
 * only difference is generation calls OpenAI directly instead of a self-hosted
 * microservice. No GPU, no NGC, no Data Designer stack.
 *
 * Self-contained on purpose (uses the `openai` SDK directly, not
 * lib/llm-provider.ts) so it shares no surface with the scan/scoring engine.
 *
 * For each row it: samples one value per sampler column, calls OpenAI to
 * produce the llm-text column (the attack `prompt` / task `input`, incl.
 * multi-turn [Turn N] transcripts), then calls OpenAI again for the
 * llm-structured column (grading `{successCriteria,expectation}` or
 * `{reference,expectedTools}`).
 */
import OpenAI from "openai";
import type {
  DataDesignerConfig,
  SamplerColumn,
  LlmTextColumn,
  LlmStructuredColumn,
} from "./nemo-config-builder.js";
import type { NemoRecord } from "./nemo-client.js";

/**
 * The single seam this module needs from an LLM: given a prompt, return text.
 * Injectable so tests can run without the network or an API key.
 */
export type ChatFn = (args: {
  model: string;
  user: string;
  json?: boolean;
  signal?: AbortSignal;
}) => Promise<string>;

export interface OpenAiGeneratorOptions {
  apiKey?: string;
  /** OpenAI-compatible base URL (Azure OpenAI, local endpoints, …). */
  baseURL?: string;
  /** Max concurrent OpenAI calls. Default 6. */
  concurrency?: number;
  /** Inject a chat implementation (tests / alternate providers). */
  chat?: ChatFn;
  /** Called as each row completes (out of order) — for live streaming. */
  onRow?: (record: NemoRecord, index: number, total: number) => void;
  signal?: AbortSignal;
}

/** Chat impl backed by the OpenAI SDK (also serves OpenAI-compatible endpoints
 *  like OpenRouter and Ollama via a custom baseURL). */
export function openAiChat(apiKey: string, baseURL?: string): ChatFn {
  const client = new OpenAI({ apiKey, baseURL });
  return async ({ model, user, json, signal }) => {
    const res = await client.chat.completions.create(
      {
        model,
        messages: [{ role: "user", content: user }],
        temperature: 0.9,
        ...(json ? { response_format: { type: "json_object" } } : {}),
      },
      { signal },
    );
    return res.choices[0]?.message?.content ?? "";
  };
}

/** Fill {{placeholder}} tokens from a sampled row. Unknown tokens → "". */
function render(template: string, values: Record<string, string>): string {
  return template.replace(/\{\{(\w+)\}\}/g, (_m, k: string) => values[k] ?? "");
}

/** Append an explicit JSON instruction so response_format=json_object is honored. */
function jsonInstruction(fields: { name: string; description: string }[]): string {
  const keys = fields.map((f) => `"${f.name}" (${f.description})`).join(", ");
  return `\n\nReturn ONLY a valid JSON object with these keys: ${keys}.`;
}

function parseJsonObject(text: string): Record<string, unknown> {
  try {
    const v = JSON.parse(text);
    return v && typeof v === "object" ? (v as Record<string, unknown>) : {};
  } catch {
    // Salvage the first {...} block if the model wrapped it in prose.
    const m = text.match(/\{[\s\S]*\}/);
    if (m) {
      try {
        return JSON.parse(m[0]) as Record<string, unknown>;
      } catch {
        /* fall through */
      }
    }
    return {};
  }
}

/** Bounded-concurrency map. */
async function pool<T, R>(
  items: T[],
  limit: number,
  fn: (item: T, i: number) => Promise<R>,
): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  const workers = Array.from(
    { length: Math.max(1, Math.min(limit, items.length)) },
    async () => {
      while (true) {
        const i = next++;
        if (i >= items.length) break;
        out[i] = await fn(items[i], i);
      }
    },
  );
  await Promise.all(workers);
  return out;
}

/**
 * Generate `count` records from a DataDesignerConfig using OpenAI directly.
 * Returns Data-Designer-shaped records (samplers at top level, the text column,
 * and the structured column as a nested object).
 */
export async function generateWithOpenAI(
  config: DataDesignerConfig,
  count: number,
  opts: OpenAiGeneratorOptions = {},
): Promise<NemoRecord[]> {
  const apiKey = opts.apiKey ?? process.env.OPENAI_API_KEY ?? "";
  if (!opts.chat && !apiKey) {
    throw new Error(
      "OPENAI_API_KEY is required for direct OpenAI generation (set it on the server).",
    );
  }
  const chat = opts.chat ?? openAiChat(apiKey, opts.baseURL);

  const samplers = config.columns.filter(
    (c): c is SamplerColumn => c.type === "sampler",
  );
  const textCol = config.columns.find(
    (c): c is LlmTextColumn => c.type === "llm-text",
  );
  const structCol = config.columns.find(
    (c): c is LlmStructuredColumn => c.type === "llm-structured",
  );
  if (!textCol || !structCol) {
    throw new Error(
      "config must have one llm-text and one llm-structured column",
    );
  }

  const model = config.model;
  const rows = Array.from({ length: Math.max(0, count) }, (_, i) => i);

  return pool(rows, opts.concurrency ?? 6, async (i) => {
    // Sample one value per sampler. The category/task axis is round-robined so
    // coverage is even (matches the balance-floor intent); the rest are random.
    const sample: Record<string, string> = {};
    for (const s of samplers) {
      if (s.values.length === 0) continue;
      const pick =
        s.name === "category" || s.name === "task"
          ? s.values[i % s.values.length]
          : s.values[Math.floor(Math.random() * s.values.length)];
      sample[s.name] = pick;
    }

    // 1) the text column (attacker message / task input, possibly multi-turn)
    const text = await chat({
      model,
      user: render(textCol.prompt, sample),
      signal: opts.signal,
    });
    sample[textCol.name] = text.trim();

    // 2) the structured grading column
    const structRaw = await chat({
      model,
      user: render(structCol.prompt, sample) + jsonInstruction(structCol.outputFields),
      json: true,
      signal: opts.signal,
    });
    const grading = parseJsonObject(structRaw);

    const record = { ...sample, [structCol.name]: grading } as NemoRecord;
    opts.onRow?.(record, i, rows.length);
    return record;
  });
}
