/**
 * Rough pre-generation cost estimate for direct-engine dataset generation.
 *
 * Pure (no I/O) so it can be unit-tested and called from both the server and a
 * thin API endpoint. The numbers are deliberately approximate — the goal is an
 * order-of-magnitude "this run costs about $X" so an operator isn't surprised
 * by a large batch, not billing-grade accounting.
 *
 * Model: each generated row costs TWO LLM calls in the direct path — one for
 * the prompt/input column and one for the structured grading column (see
 * openai-generator.ts / the config builders). Multi-turn inflates the prompt
 * call's output roughly linearly in the turn count.
 */

export interface CostEstimate {
  /** Estimated USD for the whole batch. 0 for local engines. */
  usd: number;
  /** Total LLM calls (2 per row). */
  calls: number;
  /** Estimated prompt (input) tokens across all calls. */
  inputTokens: number;
  /** Estimated completion (output) tokens across all calls. */
  outputTokens: number;
  /** True when a real per-token price backed the estimate (vs. a fallback). */
  priced: boolean;
  /** Human-readable note about assumptions / local engines. */
  note: string;
}

/** Per-1M-token USD pricing (input, output). Cached list; approximate. */
interface Price {
  in: number;
  out: number;
}

/** Matched by longest substring against the model id (case-insensitive). */
const MODEL_PRICES: { match: string; price: Price }[] = [
  { match: "gpt-4o-mini", price: { in: 0.15, out: 0.6 } },
  { match: "gpt-4.1-mini", price: { in: 0.4, out: 1.6 } },
  { match: "gpt-4.1-nano", price: { in: 0.1, out: 0.4 } },
  { match: "gpt-4.1", price: { in: 2.0, out: 8.0 } },
  { match: "gpt-4o", price: { in: 2.5, out: 10.0 } },
  { match: "o4-mini", price: { in: 1.1, out: 4.4 } },
  { match: "claude-opus-4", price: { in: 5.0, out: 25.0 } },
  { match: "claude-sonnet", price: { in: 3.0, out: 15.0 } },
  { match: "claude-haiku", price: { in: 1.0, out: 5.0 } },
  { match: "llama-3.3-70b", price: { in: 0.9, out: 0.9 } },
  { match: "llama-3.1-8b", price: { in: 0.2, out: 0.2 } },
];

/** Fallback price per engine when the model id doesn't match the table. */
const ENGINE_FALLBACK: Record<string, Price | null> = {
  openai: { in: 0.15, out: 0.6 }, // ~gpt-4o-mini, the default
  anthropic: { in: 5.0, out: 25.0 }, // ~opus, the default
  openrouter: { in: 1.0, out: 3.0 }, // mixed marketplace midpoint
  ollama: null, // local — no API cost
};

function priceFor(backend: string, model?: string): Price | null {
  const id = (model ?? "").toLowerCase();
  if (id) {
    let best: { match: string; price: Price } | undefined;
    for (const row of MODEL_PRICES) {
      if (id.includes(row.match)) {
        if (!best || row.match.length > best.match.length) best = row;
      }
    }
    if (best) return best.price;
  }
  return backend in ENGINE_FALLBACK ? ENGINE_FALLBACK[backend] : { in: 1.0, out: 3.0 };
}

export interface CostEstimateInput {
  backend: string;
  model?: string;
  count: number;
  turnMode?: "single" | "multi";
  maxTurns?: number;
}

/**
 * Estimate the cost of a direct-engine generation run. `data-designer` returns
 * an unpriced estimate (cost depends on the external service's own provider).
 */
export function estimateCost(input: CostEstimateInput): CostEstimate {
  const count = Math.max(0, Math.floor(input.count || 0));
  const calls = count * 2;

  // Local engine: no API spend.
  if (input.backend === "ollama") {
    return {
      usd: 0,
      calls,
      inputTokens: 0,
      outputTokens: 0,
      priced: true,
      note: "Local engine (Ollama) — no API cost, only your own compute.",
    };
  }
  if (input.backend === "data-designer") {
    return {
      usd: 0,
      calls,
      inputTokens: 0,
      outputTokens: 0,
      priced: false,
      note: "Cost depends on the Data Designer service's own model provider.",
    };
  }

  // Per-call token assumptions (rough averages).
  const INPUT_PER_CALL = 260; // template + samplers + context
  const OUT_GRADING = 120; // structured grading call
  const turns =
    input.turnMode === "multi" ? Math.min(8, Math.max(2, input.maxTurns ?? 3)) : 1;
  const OUT_PROMPT = input.turnMode === "multi" ? 70 * turns : 110;

  const inputTokens = calls * INPUT_PER_CALL;
  const outputTokens = count * (OUT_PROMPT + OUT_GRADING);

  const price = priceFor(input.backend, input.model);
  if (!price) {
    return {
      usd: 0,
      calls,
      inputTokens,
      outputTokens,
      priced: false,
      note: "No price available for this engine.",
    };
  }

  const usd =
    (inputTokens / 1_000_000) * price.in + (outputTokens / 1_000_000) * price.out;

  return {
    usd,
    calls,
    inputTokens,
    outputTokens,
    priced: true,
    note: `Estimate for ${count} rows (2 calls each${input.turnMode === "multi" ? `, ${turns}-turn` : ""}). Actual cost varies with prompt/output length.`,
  };
}
