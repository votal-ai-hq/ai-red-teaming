// Per-scan LLM usage tracking.
//
// A red-team scan fans out many LLM calls (attack generation, judging, analysis,
// ideal-response synthesis). This module captures real, measured metrics for each
// of those calls — token counts (from the provider's own `usage`), wall-clock
// latency, and errors — and rolls them up per scan.
//
// Concurrency: the dashboard runs scans concurrently (MAX_CONCURRENT_RUNS), and
// provider instances are shared/cached across runs. So the collector lives in an
// AsyncLocalStorage keyed to each run's async context — `runRedTeam` sets it once
// via `enterUsageContext`, and every downstream LLM call records into *its own*
// run's collector with no cross-contamination and no threading through call sites.

import { AsyncLocalStorage } from "node:async_hooks";
import { computeCostUsd } from "./llm-pricing.js";

export type UsageErrorKind = "rate_limit" | "timeout" | "other";

/** One recorded LLM call. */
export interface UsageRecord {
  provider: string;
  model: string;
  /** Coarse phase label (generation, judging, analysis, …); "uncategorized" if unset. */
  phase: string;
  inputTokens: number;
  outputTokens: number;
  latencyMs: number;
  ok: boolean;
  errorKind?: UsageErrorKind;
  /** Whether the provider actually returned token usage (some endpoints don't). */
  tokensReported: boolean;
}

interface Bucket {
  calls: number;
  inputTokens: number;
  outputTokens: number;
  latencyMs: number;
  costUsd: number;
  /** True once every priced call in the bucket had a known price. */
  fullyPriced: boolean;
}

export interface UsageByPhase {
  phase: string;
  calls: number;
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
  latencyMs: number;
  costUsd: number | null;
}

export interface UsageByModel {
  provider: string;
  model: string;
  calls: number;
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
  latencyMs: number;
  costUsd: number | null;
  /** False when this model has no known price (cost omitted, tokens still real). */
  priced: boolean;
}

/** The per-scan usage summary attached to a report as `report.usage`. */
export interface UsageSummary {
  totalCalls: number;
  failedCalls: number;
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
  /** True if every successful call reported token usage. */
  tokensComplete: boolean;
  /** Sum of estimated cost across priced calls; null if nothing could be priced. */
  costUsd: number | null;
  /** False when at least one model used had no known price. */
  costComplete: boolean;
  /** Distinct "provider/model" pairs with no known price (cost omitted for them). */
  unpricedModels: string[];
  /** Total wall-clock time spent inside LLM calls (ms). */
  llmLatencyMsTotal: number;
  errorsByKind: Record<UsageErrorKind, number>;
  byPhase: UsageByPhase[];
  byModel: UsageByModel[];
}

/** Accumulates LLM usage records for a single scan. */
export class UsageCollector {
  private records: UsageRecord[] = [];

  record(r: UsageRecord): void {
    this.records.push(r);
  }

  get count(): number {
    return this.records.length;
  }

  summarize(): UsageSummary {
    const errorsByKind: Record<UsageErrorKind, number> = {
      rate_limit: 0,
      timeout: 0,
      other: 0,
    };
    const byPhase = new Map<string, Bucket>();
    // Keyed by provider|model so the same model on two providers stays distinct.
    const byModel = new Map<string, Bucket & { provider: string; model: string; priced: boolean }>();
    const unpriced = new Set<string>();

    let totalCalls = 0;
    let failedCalls = 0;
    let inputTokens = 0;
    let outputTokens = 0;
    let llmLatencyMsTotal = 0;
    let tokensComplete = true;

    for (const r of this.records) {
      totalCalls += 1;
      inputTokens += r.inputTokens;
      outputTokens += r.outputTokens;
      llmLatencyMsTotal += r.latencyMs;
      if (!r.ok) {
        failedCalls += 1;
        errorsByKind[r.errorKind ?? "other"] += 1;
      } else if (!r.tokensReported) {
        // A successful call that returned no usage → totals are an undercount.
        tokensComplete = false;
      }

      const cost = computeCostUsd(r.provider, r.model, r.inputTokens, r.outputTokens);
      const priced = cost != null;
      const modelKey = `${r.provider}/${r.model}`;
      if (!priced && (r.inputTokens > 0 || r.outputTokens > 0)) {
        unpriced.add(modelKey);
      }

      // Phase bucket
      const pb = byPhase.get(r.phase) ?? {
        calls: 0, inputTokens: 0, outputTokens: 0, latencyMs: 0, costUsd: 0, fullyPriced: true,
      };
      pb.calls += 1;
      pb.inputTokens += r.inputTokens;
      pb.outputTokens += r.outputTokens;
      pb.latencyMs += r.latencyMs;
      pb.costUsd += cost ?? 0;
      if (!priced && (r.inputTokens > 0 || r.outputTokens > 0)) pb.fullyPriced = false;
      byPhase.set(r.phase, pb);

      // Model bucket
      const mb = byModel.get(modelKey) ?? {
        provider: r.provider, model: r.model, priced: true,
        calls: 0, inputTokens: 0, outputTokens: 0, latencyMs: 0, costUsd: 0, fullyPriced: true,
      };
      mb.calls += 1;
      mb.inputTokens += r.inputTokens;
      mb.outputTokens += r.outputTokens;
      mb.latencyMs += r.latencyMs;
      mb.costUsd += cost ?? 0;
      if (!priced && (r.inputTokens > 0 || r.outputTokens > 0)) mb.priced = false;
      byModel.set(modelKey, mb);
    }

    const anyPriced = [...byModel.values()].some((m) => m.costUsd > 0 || m.priced);
    const costComplete = unpriced.size === 0;

    const round2 = (n: number) => Math.round(n * 1e6) / 1e6;

    return {
      totalCalls,
      failedCalls,
      inputTokens,
      outputTokens,
      totalTokens: inputTokens + outputTokens,
      tokensComplete,
      costUsd: anyPriced ? round2([...byModel.values()].reduce((s, m) => s + m.costUsd, 0)) : null,
      costComplete,
      unpricedModels: [...unpriced].sort(),
      llmLatencyMsTotal,
      errorsByKind,
      byPhase: [...byPhase.entries()]
        .map(([phase, b]) => ({
          phase,
          calls: b.calls,
          inputTokens: b.inputTokens,
          outputTokens: b.outputTokens,
          totalTokens: b.inputTokens + b.outputTokens,
          latencyMs: b.latencyMs,
          costUsd: b.fullyPriced ? round2(b.costUsd) : (b.costUsd > 0 ? round2(b.costUsd) : null),
        }))
        .sort((a, b) => b.totalTokens - a.totalTokens),
      byModel: [...byModel.values()]
        .map((m) => ({
          provider: m.provider,
          model: m.model,
          calls: m.calls,
          inputTokens: m.inputTokens,
          outputTokens: m.outputTokens,
          totalTokens: m.inputTokens + m.outputTokens,
          latencyMs: m.latencyMs,
          costUsd: m.priced ? round2(m.costUsd) : (m.costUsd > 0 ? round2(m.costUsd) : null),
          priced: m.priced,
        }))
        .sort((a, b) => b.totalTokens - a.totalTokens),
    };
  }
}

// ── Per-run context ──────────────────────────────────────────────────────────

const usageContext = new AsyncLocalStorage<UsageCollector>();

/**
 * Run `fn` with `collector` bound as the active usage context for the whole
 * async call tree it spawns. Uses AsyncLocalStorage.run (not enterWith) so that
 * concurrent scans — which the dashboard launches without awaiting, in the same
 * tick — each get a cleanly-scoped, isolated collector with zero cross-talk.
 */
export function withUsageContext<T>(
  collector: UsageCollector,
  fn: () => Promise<T>,
): Promise<T> {
  return usageContext.run(collector, fn);
}

/**
 * Bind a fresh collector to the current async context and return it. For the CLI
 * entrypoint, which is a single-process, single-run flow (no concurrent scans),
 * so `enterWith` is safe. The dashboard uses `withUsageContext` instead because
 * it launches scans concurrently.
 */
export function enterUsageContext(): UsageCollector {
  const collector = new UsageCollector();
  usageContext.enterWith(collector);
  return collector;
}

/** The collector for the current run, if one is active (else undefined). */
export function activeUsageCollector(): UsageCollector | undefined {
  return usageContext.getStore();
}

/** Classify an LLM error into a coarse kind for the failure breakdown. */
export function classifyLlmError(err: unknown): UsageErrorKind {
  const msg = (err instanceof Error ? err.message : String(err ?? "")).toLowerCase();
  const status = (err as { status?: number } | undefined)?.status;
  if (status === 429 || msg.includes("rate limit") || msg.includes("429") || msg.includes("too many requests")) {
    return "rate_limit";
  }
  if (msg.includes("timeout") || msg.includes("timed out") || msg.includes("etimedout") || msg.includes("abort")) {
    return "timeout";
  }
  return "other";
}

/**
 * Record one LLM call into the active run's collector. No-op when called outside
 * a run context (e.g. on-demand dashboard analysis endpoints), so it's always
 * safe to call from the provider layer.
 */
export function recordLlmUsage(input: {
  provider: string;
  model: string;
  phase?: string;
  inputTokens?: number;
  outputTokens?: number;
  latencyMs: number;
  ok: boolean;
  errorKind?: UsageErrorKind;
  tokensReported: boolean;
}): void {
  const collector = usageContext.getStore();
  if (!collector) return;
  collector.record({
    provider: (input.provider || "unknown").toLowerCase(),
    model: input.model || "unknown",
    phase: input.phase || "uncategorized",
    inputTokens: input.inputTokens ?? 0,
    outputTokens: input.outputTokens ?? 0,
    latencyMs: Math.max(0, Math.round(input.latencyMs)),
    ok: input.ok,
    errorKind: input.errorKind,
    tokensReported: input.tokensReported,
  });
}

// ── Formatting (CLI summary) ──────────────────────────────────────────────────

export function formatUsd(n: number | null): string {
  if (n == null) return "n/a";
  if (n < 0.01) return `$${n.toFixed(4)}`;
  return `$${n.toFixed(2)}`;
}

export function formatTokens(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(2)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}

export function formatDurationMs(ms: number): string {
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const rem = s % 60;
  return `${m}m ${String(rem).padStart(2, "0")}s`;
}

/** Render the per-scan usage summary as plain-text lines for the CLI. */
export function formatUsageSummary(u: UsageSummary): string[] {
  const lines: string[] = [];
  lines.push("");
  lines.push("  LLM USAGE");
  const costStr = u.costUsd == null
    ? "cost n/a (no priced models)"
    : `${formatUsd(u.costUsd)}${u.costComplete ? "" : "+"} est.`;
  lines.push(
    `  ${costStr} · ${formatTokens(u.totalTokens)} tokens ` +
    `(${formatTokens(u.inputTokens)} in / ${formatTokens(u.outputTokens)} out) · ` +
    `${formatDurationMs(u.llmLatencyMsTotal)} LLM time`,
  );
  const failStr = u.failedCalls > 0
    ? ` · ${u.failedCalls} failed (${u.errorsByKind.rate_limit} rate-limit, ${u.errorsByKind.timeout} timeout, ${u.errorsByKind.other} other)`
    : "";
  lines.push(`  ${u.totalCalls} calls${failStr}`);
  if (!u.tokensComplete) {
    lines.push("  (some calls did not report token usage — totals are a lower bound)");
  }
  if (!u.costComplete && u.unpricedModels.length > 0) {
    lines.push(`  (cost partial — no price for: ${u.unpricedModels.join(", ")})`);
  }
  if (u.byModel.length > 0) {
    lines.push("  By model:");
    for (const m of u.byModel) {
      lines.push(
        `    ${m.provider}/${m.model}`.padEnd(42) +
        ` ${String(m.calls).padStart(4)} calls  ${formatTokens(m.totalTokens).padStart(7)}  ` +
        (m.costUsd == null ? "cost n/a" : formatUsd(m.costUsd)),
      );
    }
  }
  return lines;
}
