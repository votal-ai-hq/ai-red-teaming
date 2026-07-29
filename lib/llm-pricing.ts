// LLM pricing → used ONLY to turn real (provider-reported) token counts into an
// estimated USD cost for the per-scan usage panel. Tokens/latency/calls are always
// real; this file is the one place with a "price" constant, so cost is labelled an
// estimate everywhere it surfaces.
//
// Prices are USD per 1M tokens (input, output). Verified 2026-07-29 against the
// sources noted per family. For open/multi-hosted models (Qwen, GLM, Llama) the
// same model costs different amounts per host, so the bundled numbers are the
// first-party list price (or a supported host) — override with your real rate.
//
// Overrides (highest precedence first):
//   1. per-run overrides passed from config (config.attackConfig.modelPricing)
//   2. env LLM_PRICING_JSON — a JSON map { "<model>" | "<provider>/<model>": {inputPer1M, outputPer1M} }
//   3. this bundled table
// Unknown model → priceFor returns null → cost omitted for that call (never faked).

export interface ModelPrice {
  inputPer1M: number;
  outputPer1M: number;
}

export type PriceOverrides = Record<string, ModelPrice>;

// ── Bundled table (verified 2026-07-29) ──────────────────────────────────────
// Keyed by NORMALIZED model id (see normalizeModel): lowercased, provider prefix
// stripped, date/`:suffix` stripped, version dashes → dots (claude-sonnet-4-5 →
// claude-sonnet-4.5).
const PRICES: Record<string, ModelPrice> = {
  // OpenAI — first-party (platform.openai.com/docs/pricing)
  "gpt-4o": { inputPer1M: 2.5, outputPer1M: 10 },
  "gpt-4o-mini": { inputPer1M: 0.15, outputPer1M: 0.6 },
  "gpt-4.1": { inputPer1M: 2, outputPer1M: 8 },
  "gpt-4.1-mini": { inputPer1M: 0.4, outputPer1M: 1.6 },
  "gpt-4.1-nano": { inputPer1M: 0.1, outputPer1M: 0.4 },
  "gpt-5": { inputPer1M: 1.25, outputPer1M: 10 },
  "gpt-5-mini": { inputPer1M: 0.25, outputPer1M: 2 },
  "gpt-5-nano": { inputPer1M: 0.05, outputPer1M: 0.4 },
  "gpt-5.1": { inputPer1M: 1.25, outputPer1M: 10 },
  "gpt-5.2": { inputPer1M: 1.75, outputPer1M: 14 },
  "gpt-4-turbo": { inputPer1M: 10, outputPer1M: 30 },
  "gpt-4": { inputPer1M: 30, outputPer1M: 60 },
  "gpt-3.5-turbo": { inputPer1M: 0.5, outputPer1M: 1.5 },

  // Anthropic — first-party (Claude docs pricing table). Opus 4.5→5 tier is $5/$25;
  // older Opus 4/4.1 was $15/$75. claude-sonnet-5 handled dynamically below.
  "claude-opus-4": { inputPer1M: 15, outputPer1M: 75 },
  "claude-opus-4.1": { inputPer1M: 15, outputPer1M: 75 },
  "claude-opus-4.5": { inputPer1M: 5, outputPer1M: 25 },
  "claude-opus-4.6": { inputPer1M: 5, outputPer1M: 25 },
  "claude-opus-4.7": { inputPer1M: 5, outputPer1M: 25 },
  "claude-opus-4.8": { inputPer1M: 5, outputPer1M: 25 },
  "claude-opus-5": { inputPer1M: 5, outputPer1M: 25 },
  "claude-sonnet-4": { inputPer1M: 3, outputPer1M: 15 },
  "claude-sonnet-4.5": { inputPer1M: 3, outputPer1M: 15 },
  "claude-sonnet-4.6": { inputPer1M: 3, outputPer1M: 15 },
  "claude-haiku-4.5": { inputPer1M: 1, outputPer1M: 5 },
  "claude-3.5-haiku": { inputPer1M: 0.8, outputPer1M: 4 },
  "claude-3-haiku": { inputPer1M: 0.25, outputPer1M: 1.25 },
  "claude-fable-5": { inputPer1M: 10, outputPer1M: 50 },

  // Qwen — Alibaba Cloud Model Studio International (USD, base context tier)
  "qwen-plus": { inputPer1M: 0.4, outputPer1M: 1.2 },
  "qwen-max": { inputPer1M: 1.2, outputPer1M: 6 },
  "qwen3-max": { inputPer1M: 1.2, outputPer1M: 6 },
  "qwen-turbo": { inputPer1M: 0.05, outputPer1M: 0.2 },
  "qwen2.5-72b-instruct": { inputPer1M: 0.36, outputPer1M: 0.4 }, // host: DeepInfra

  // GLM — Z.ai first-party list (docs.z.ai/guides/overview/pricing)
  "glm-4.5": { inputPer1M: 0.6, outputPer1M: 2.2 },
  "glm-4.5-air": { inputPer1M: 0.13, outputPer1M: 0.85 },
  "glm-4.6": { inputPer1M: 0.6, outputPer1M: 2.2 },
  "glm-5.1": { inputPer1M: 1.4, outputPer1M: 4.4 },

  // Meta Llama — open-weight, HOST-DEPENDENT. Defaults from a supported host
  // (Together AI / Groq); override for your host.
  "llama-3.3-70b-instruct": { inputPer1M: 1.04, outputPer1M: 1.04 }, // Together
  "llama-3.1-8b-instruct": { inputPer1M: 0.05, outputPer1M: 0.08 }, // Groq
  "llama-3.1-70b-instruct": { inputPer1M: 0.88, outputPer1M: 0.88 }, // Together
  "llama-4-maverick": { inputPer1M: 0.27, outputPer1M: 0.85 }, // Together
  "llama-4-scout": { inputPer1M: 0.18, outputPer1M: 0.59 }, // Together
};

/** Normalize a raw model id to the table's canonical key. */
export function normalizeModel(model: string): string {
  let m = (model || "").trim().toLowerCase();
  if (m.includes("/")) m = m.slice(m.lastIndexOf("/") + 1); // drop "anthropic/…" style prefix
  m = m.replace(/:.*$/, ""); // drop ":batch" / ":thinking" style suffixes
  m = m.replace(/-\d{4}-\d{2}-\d{2}$/, ""); // drop -2025-05-14
  m = m.replace(/-\d{6,8}$/, ""); // drop -20250514
  m = m.replace(/(\d)-(\d)/g, "$1.$2"); // claude-sonnet-4-5 → claude-sonnet-4.5
  return m;
}

let envOverrides: PriceOverrides | null = null;
function getEnvOverrides(): PriceOverrides {
  if (envOverrides) return envOverrides;
  envOverrides = {};
  const raw = process.env.LLM_PRICING_JSON;
  if (raw) {
    try {
      const parsed = JSON.parse(raw) as Record<string, { inputPer1M?: number; outputPer1M?: number }>;
      for (const [k, v] of Object.entries(parsed)) {
        if (v && typeof v.inputPer1M === "number" && typeof v.outputPer1M === "number") {
          envOverrides[k.toLowerCase()] = { inputPer1M: v.inputPer1M, outputPer1M: v.outputPer1M };
        }
      }
    } catch {
      // ignore malformed override JSON — fall back to bundled table
    }
  }
  return envOverrides;
}

// Test seam: exported so tests can pin "now" for the Sonnet-5 intro-price switch.
export function claudeSonnet5Price(now: Date = new Date()): ModelPrice {
  // Introductory $2/$10 through 2026-08-31; standard $3/$15 from 2026-09-01.
  const cutoff = Date.UTC(2026, 8, 1); // month is 0-indexed → 8 = September
  return now.getTime() >= cutoff
    ? { inputPer1M: 3, outputPer1M: 15 }
    : { inputPer1M: 2, outputPer1M: 10 };
}

/**
 * Resolve the price for a (provider, model). Checks per-run overrides, then env
 * overrides, then the bundled table (with normalization). Returns null when the
 * model is unknown — callers must treat that as "cost unavailable", never zero.
 */
export function priceFor(
  provider: string,
  model: string,
  overrides?: PriceOverrides,
  now?: Date,
): ModelPrice | null {
  const prov = (provider || "").toLowerCase();
  const raw = (model || "").toLowerCase();
  const norm = normalizeModel(model);
  const keys = [`${prov}/${raw}`, raw, `${prov}/${norm}`, norm];

  const lc = (o?: PriceOverrides): PriceOverrides =>
    o ? Object.fromEntries(Object.entries(o).map(([k, v]) => [k.toLowerCase(), v])) : {};

  const runOv = lc(overrides);
  for (const k of keys) if (runOv[k]) return runOv[k];

  const envOv = getEnvOverrides();
  for (const k of keys) if (envOv[k]) return envOv[k];

  if (norm === "claude-sonnet-5") return claudeSonnet5Price(now);

  return PRICES[norm] ?? PRICES[raw] ?? null;
}

/**
 * Estimated cost in USD for a call, or null if the model has no known price.
 * cost = inputTokens/1e6 × inputPer1M + outputTokens/1e6 × outputPer1M.
 */
export function computeCostUsd(
  provider: string,
  model: string,
  inputTokens: number,
  outputTokens: number,
  overrides?: PriceOverrides,
  now?: Date,
): number | null {
  const p = priceFor(provider, model, overrides, now);
  if (!p) return null;
  return (inputTokens / 1e6) * p.inputPer1M + (outputTokens / 1e6) * p.outputPer1M;
}
