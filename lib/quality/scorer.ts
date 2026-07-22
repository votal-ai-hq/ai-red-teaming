/**
 * Native functional-quality scorer.
 *
 * For each quality row: send `input` to the target (same transport the security
 * engine uses), extract the response + tool calls, and score correctness
 * against the reference — deterministically (exact/f1/rouge/tool-call) or via
 * the LLM judge (goal_accuracy/faithfulness/…). Aggregates into a QualityReport.
 *
 * This is the quality-axis analogue of attack-runner + report-generator; it
 * shares the target adapter, LLM provider, and path extraction, but grades
 * "was it correct?" instead of "was it compromised?".
 *
 * See docs/specs/nemo-data-designer-datasets.md — quality scorer.
 */
import { executeAttack } from "../attack-runner.js";
import { extractPath } from "../response-analyzer.js";
import { describeTarget } from "../target-adapter.js";
import { runQualityMcpAgent } from "./mcp-agent.js";
import { extractResponseText } from "./response-text.js";
import { DETERMINISTIC_METRICS, scoreDeterministic } from "./metrics.js";
import { judgeQuality, isJudgeMetric } from "./judge.js";
import type { Attack, Config } from "../types.js";
import type { QualityRow } from "../dataset/types.js";
import type { QualityEvalResult, QualityReport } from "./types.js";

const DEFAULT_THRESHOLD = 0.7;

/** Build a minimal valid Attack that carries the quality task's input. */
function rowToRequest(config: Config, row: QualityRow, index: number): Attack {
  const messageField = config.requestSchema.messageField || "message";
  const roleField = config.requestSchema.roleField || "role";
  const role = config.auth.credentials[0]?.role ?? "viewer";
  const payload: Record<string, unknown> = {
    [messageField]: row.input,
    // validateAttackOrThrow requires a literal `message` key.
    message: row.input,
    [roleField]: role,
  };
  return {
    id: `quality-${index + 1}`,
    category: "off_topic",
    name: row.name || `quality ${index + 1}`,
    description: "functional-quality eval case",
    authMethod: config.customAttacksDefaults?.authMethod ?? "body_role",
    role,
    payload,
    expectation: "",
    severity: "low",
    isLlmGenerated: false,
  };
}

/** Best-effort extraction of tool-call names from the target's response body. */
export function extractToolNames(body: unknown, toolCallsPath: string): string[] {
  const raw = toolCallsPath ? extractPath(body, toolCallsPath) : undefined;
  if (!Array.isArray(raw)) return [];
  return raw
    .map((tc) => {
      if (typeof tc === "string") return tc;
      if (tc && typeof tc === "object") {
        const o = tc as Record<string, unknown>;
        const fn = o.function as Record<string, unknown> | undefined;
        return String(fn?.name ?? o.name ?? o.tool ?? o.type ?? "").trim();
      }
      return "";
    })
    .filter(Boolean);
}

/** Score a single quality row against the target. Never throws. */
export async function scoreQualityRow(
  config: Config,
  row: QualityRow,
  index: number,
  passThreshold = DEFAULT_THRESHOLD,
): Promise<QualityEvalResult> {
  try {
    // MCP targets are JSON-RPC: a plain HTTP body is rejected, so drive the
    // task through an MCP agent loop (an LLM holding the server's tools) and
    // grade on the tools it called + its final answer. HTTP/WS targets keep
    // the direct request path below unchanged.
    let statusCode: number;
    let timeMs: number;
    let responseText: string;
    let actualTools: string[];
    if ((config.target.type ?? "http_agent") === "mcp") {
      const agent = await runQualityMcpAgent(config, row.input);
      if (agent.error) throw new Error(agent.error);
      statusCode = agent.statusCode;
      timeMs = agent.responseTimeMs;
      responseText = agent.response;
      actualTools = agent.toolCalls;
    } else {
      const attack = rowToRequest(config, row, index);
      const res = await executeAttack(config, attack);
      statusCode = res.statusCode;
      timeMs = res.timeMs;
      // Targets answer in arbitrary shapes (and may stream) — resolve the
      // configured path first, then common envelopes, never "[object Object]".
      responseText = extractResponseText(
        res.body,
        config.responseSchema.responsePath,
      );
      actualTools = extractToolNames(
        res.body,
        config.responseSchema.toolCallsPath ?? "",
      );
    }

    let score: number;
    let scorer: "deterministic" | "judge";
    let reasoning: string | undefined;

    if (DETERMINISTIC_METRICS.has(row.metric)) {
      scorer = "deterministic";
      score = scoreDeterministic(row.metric, {
        response: responseText,
        reference: row.reference,
        actualTools,
        expectedTools: row.expectedTools ?? [],
      });
    } else if (isJudgeMetric(row.metric)) {
      scorer = "judge";
      const v = await judgeQuality(config, {
        metric: row.metric,
        input: row.input,
        reference: row.reference,
        response: responseText,
      });
      score = v.score;
      reasoning = v.reasoning;
    } else {
      return {
        row,
        score: 0,
        pass: false,
        metric: row.metric,
        scorer: "deterministic",
        response: responseText.slice(0, 1000),
        actualTools,
        statusCode,
        responseTimeMs: timeMs,
        error: `unknown metric "${row.metric}"`,
      };
    }

    return {
      row,
      score,
      pass: score >= passThreshold,
      metric: row.metric,
      scorer,
      response: responseText.slice(0, 1000),
      actualTools,
      statusCode,
      responseTimeMs: timeMs,
      reasoning,
    };
  } catch (e) {
    return {
      row,
      score: 0,
      pass: false,
      metric: row.metric,
      scorer: "deterministic",
      response: "",
      statusCode: 0,
      responseTimeMs: 0,
      error: (e as Error).message,
    };
  }
}

/** Run a bounded-concurrency map over items. */
async function pool<T, R>(
  items: T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, async () => {
    while (true) {
      const i = next++;
      if (i >= items.length) break;
      results[i] = await fn(items[i], i);
    }
  });
  await Promise.all(workers);
  return results;
}

export interface RunQualityEvalOptions {
  passThreshold?: number;
  concurrency?: number;
  dataset?: string;
  onProgress?: (done: number, total: number, last: QualityEvalResult) => void;
}

/** Aggregate helper for a metric/task bucket. */
function bucketize(
  results: QualityEvalResult[],
  key: (r: QualityEvalResult) => string,
): Record<string, { count: number; mean: number; passed: number }> {
  const out: Record<string, { count: number; sum: number; passed: number }> = {};
  for (const r of results) {
    if (r.error) continue;
    const k = key(r);
    out[k] ??= { count: 0, sum: 0, passed: 0 };
    out[k].count++;
    out[k].sum += r.score;
    if (r.pass) out[k].passed++;
  }
  const rounded: Record<string, { count: number; mean: number; passed: number }> = {};
  for (const [k, v] of Object.entries(out)) {
    rounded[k] = {
      count: v.count,
      mean: Math.round((v.sum / v.count) * 100) / 100,
      passed: v.passed,
    };
  }
  return rounded;
}

/** Run a full quality eval and produce a QualityReport. */
export async function runQualityEval(
  config: Config,
  rows: QualityRow[],
  opts: RunQualityEvalOptions = {},
): Promise<QualityReport> {
  const passThreshold = opts.passThreshold ?? DEFAULT_THRESHOLD;
  const concurrency = opts.concurrency ?? config.attackConfig.concurrency ?? 2;

  let done = 0;
  const results = await pool(rows, concurrency, async (row, i) => {
    const r = await scoreQualityRow(config, row, i, passThreshold);
    done++;
    opts.onProgress?.(done, rows.length, r);
    return r;
  });

  const scored = results.filter((r) => !r.error);
  const errors = results.length - scored.length;
  const meanScore =
    scored.length > 0
      ? Math.round((scored.reduce((s, r) => s + r.score, 0) / scored.length) * 100)
      : 0;

  return {
    timestamp: new Date().toISOString(),
    targetUrl: describeTarget(config),
    dataset: opts.dataset,
    passThreshold,
    summary: {
      total: results.length,
      scored: scored.length,
      errors,
      score: meanScore,
      passed: scored.filter((r) => r.pass).length,
      byMetric: bucketize(results, (r) => r.metric),
      byTask: bucketize(results, (r) => r.row.task),
    },
    results,
  };
}
