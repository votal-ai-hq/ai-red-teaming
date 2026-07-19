/**
 * Deterministic correctness metrics for functional-quality evaluation.
 * Pure + I/O-free — every function returns a score in [0, 1].
 *
 * These cover the metrics that don't need an LLM judge: exact_match, f1, rouge
 * (text vs reference) and tool_call_accuracy (actual vs expected tool calls).
 * Judge-based metrics (goal_accuracy, faithfulness, …) live in judge.ts.
 *
 * See docs/specs/nemo-data-designer-datasets.md — quality scorer.
 */

function normalize(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\s]/gu, " ")
    .replace(/\s+/g, " ")
    .trim();
}

export function tokenize(s: string): string[] {
  const n = normalize(s);
  return n ? n.split(" ") : [];
}

/** 1 if normalized strings match exactly, else 0. */
export function exactMatch(prediction: string, reference: string): number {
  return normalize(prediction) === normalize(reference) ? 1 : 0;
}

/** Token-overlap F1 (SQuAD-style) in [0,1]. */
export function f1(prediction: string, reference: string): number {
  const pred = tokenize(prediction);
  const ref = tokenize(reference);
  if (pred.length === 0 && ref.length === 0) return 1;
  if (pred.length === 0 || ref.length === 0) return 0;

  const refCounts = new Map<string, number>();
  for (const t of ref) refCounts.set(t, (refCounts.get(t) ?? 0) + 1);

  let overlap = 0;
  for (const t of pred) {
    const c = refCounts.get(t) ?? 0;
    if (c > 0) {
      overlap++;
      refCounts.set(t, c - 1);
    }
  }
  if (overlap === 0) return 0;
  const precision = overlap / pred.length;
  const recall = overlap / ref.length;
  return (2 * precision * recall) / (precision + recall);
}

/** Longest-common-subsequence length (token level). */
function lcsLength(a: string[], b: string[]): number {
  const dp = Array.from({ length: a.length + 1 }, () =>
    new Array<number>(b.length + 1).fill(0),
  );
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] =
        a[i - 1] === b[j - 1]
          ? dp[i - 1][j - 1] + 1
          : Math.max(dp[i - 1][j], dp[i][j - 1]);
    }
  }
  return dp[a.length][b.length];
}

/** ROUGE-L F-measure in [0,1]. */
export function rougeL(prediction: string, reference: string): number {
  const pred = tokenize(prediction);
  const ref = tokenize(reference);
  if (pred.length === 0 && ref.length === 0) return 1;
  if (pred.length === 0 || ref.length === 0) return 0;
  const lcs = lcsLength(pred, ref);
  if (lcs === 0) return 0;
  const precision = lcs / pred.length;
  const recall = lcs / ref.length;
  return (2 * precision * recall) / (precision + recall);
}

/**
 * Tool-call accuracy: how well the actual tool calls match the expected set.
 * Order-insensitive F1 over tool names (case-insensitive), which rewards
 * calling the right tools without over-penalizing order. Returns 1 when both
 * are empty (a task that correctly needed no tools).
 */
export function toolCallAccuracy(
  actual: string[],
  expected: string[],
): number {
  const norm = (xs: string[]) =>
    xs.map((x) => x.trim().toLowerCase()).filter(Boolean);
  const a = norm(actual);
  const e = norm(expected);
  if (a.length === 0 && e.length === 0) return 1;
  if (a.length === 0 || e.length === 0) return 0;

  const expCounts = new Map<string, number>();
  for (const t of e) expCounts.set(t, (expCounts.get(t) ?? 0) + 1);
  let overlap = 0;
  for (const t of a) {
    const c = expCounts.get(t) ?? 0;
    if (c > 0) {
      overlap++;
      expCounts.set(t, c - 1);
    }
  }
  if (overlap === 0) return 0;
  const precision = overlap / a.length;
  const recall = overlap / e.length;
  return (2 * precision * recall) / (precision + recall);
}

export const DETERMINISTIC_METRICS = new Set([
  "exact_match",
  "f1",
  "rouge",
  "tool_call_accuracy",
]);

/** Score a deterministic metric. Throws if the metric isn't deterministic. */
export function scoreDeterministic(
  metric: string,
  opts: { response: string; reference?: string; actualTools: string[]; expectedTools: string[] },
): number {
  switch (metric) {
    case "exact_match":
      return exactMatch(opts.response, opts.reference ?? "");
    case "f1":
      return f1(opts.response, opts.reference ?? "");
    case "rouge":
      return rougeL(opts.response, opts.reference ?? "");
    case "tool_call_accuracy":
      return toolCallAccuracy(opts.actualTools, opts.expectedTools);
    default:
      throw new Error(`not a deterministic metric: ${metric}`);
  }
}
