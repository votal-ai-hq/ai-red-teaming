/**
 * Taxonomy for FUNCTIONAL-QUALITY datasets (the "is it good?" axis).
 *
 * Unlike security datasets — whose `category` must be a member of the
 * `AttackCategory` union and whose grading asks "was the target compromised?"
 * — quality datasets ask "was the output correct?" against a reference. They
 * use their own task-type + metric taxonomy defined here, and a different row
 * schema (input + reference/expectedTools + metric). See
 * docs/specs/nemo-data-designer-datasets.md — quality datasets.
 */
import type { DatasetFamily } from "./category-set.js";

/** Quality metrics a row can be graded on (maps to NeMo Evaluator metrics). */
export const QUALITY_METRICS = [
  "tool_call_accuracy",
  "goal_accuracy",
  "topic_adherence",
  "faithfulness",
  "answer_relevancy",
  "context_recall",
  "exact_match",
  "f1",
  "rouge",
] as const;
export type QualityMetric = (typeof QUALITY_METRICS)[number];

const QUALITY_METRIC_SET = new Set<string>(QUALITY_METRICS);
export function isQualityMetric(s: string): s is QualityMetric {
  return QUALITY_METRIC_SET.has(s);
}

/**
 * Task types (the quality analogue of a security category). Keyed per family:
 * MCP/agent targets get tool-use & multi-step tasks; the agent family also
 * covers RAG/answer quality.
 */
const MCP_QUALITY_POOL = [
  "tool_selection",
  "tool_argument_accuracy",
  "multi_step_task",
  "goal_completion",
  "parameter_extraction",
] as const;

const AGENT_QUALITY_POOL = [
  "tool_selection",
  "multi_step_task",
  "goal_completion",
  "rag_answer",
  "summarization",
  "classification",
  "extraction",
  "instruction_following",
] as const;

export const ALL_QUALITY_TASKS = [
  ...new Set([...MCP_QUALITY_POOL, ...AGENT_QUALITY_POOL]),
] as const;
export type QualityTask = (typeof ALL_QUALITY_TASKS)[number];

const QUALITY_TASK_SET = new Set<string>(ALL_QUALITY_TASKS);
export function isQualityTask(s: string): s is QualityTask {
  return QUALITY_TASK_SET.has(s);
}

const FAMILY_QUALITY_POOLS: Record<DatasetFamily, readonly string[]> = {
  mcp: MCP_QUALITY_POOL,
  agent: AGENT_QUALITY_POOL,
};

/** Default quality task pool for a family. */
export function defaultQualityPool(family: DatasetFamily): string[] {
  return [...FAMILY_QUALITY_POOLS[family]];
}

/**
 * Normalize a user-supplied custom task label to a safe slug (lowercase,
 * underscore-separated, ≤40 chars), or null if it reduces to nothing. Custom
 * tasks are allowed for QUALITY datasets only — a quality row's `task` is a
 * report label the scorer buckets by; grading keys off `metric`, so a custom
 * task can't misroute or mis-grade. (Security `category` is different: the
 * red-team engine routes on it, so those stay fixed to the taxonomy.)
 */
export function sanitizeCustomTask(s: string): string | null {
  const slug = String(s ?? "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 40)
    .replace(/_+$/g, "");
  return slug || null;
}

/**
 * Resolve a preset's quality task list. Fail-closed on unknown tasks by default
 * (mirrors the security `resolveCategoryPool` contract). With `allowCustom`,
 * unknown tasks are kept as sanitized slugs instead of throwing — this is how
 * user-defined focus tasks (for non-security agent evals) flow through.
 */
export function resolveQualityPool(
  family: DatasetFamily,
  requested: string[] | undefined,
  opts?: { allowCustom?: boolean },
): string[] {
  if (!requested || requested.length === 0) return defaultQualityPool(family);
  if (opts?.allowCustom) {
    const out: string[] = [];
    for (const t of requested) {
      if (isQualityTask(t)) out.push(t);
      else {
        const slug = sanitizeCustomTask(t);
        if (slug) out.push(slug);
      }
    }
    return out.length ? [...new Set(out)] : defaultQualityPool(family);
  }
  const unknown = requested.filter((t) => !isQualityTask(t));
  if (unknown.length > 0) {
    throw new Error(
      `preset quality task pool has unknown tasks: ${unknown.join(", ")}`,
    );
  }
  return requested;
}

/** Default metrics offered for a family (a sensible starting mix). */
export function defaultMetrics(family: DatasetFamily): QualityMetric[] {
  return family === "mcp"
    ? ["tool_call_accuracy", "goal_accuracy", "topic_adherence"]
    : ["goal_accuracy", "faithfulness", "answer_relevancy", "exact_match"];
}

const MCP_TASK_METRICS: Partial<Record<string, readonly QualityMetric[]>> = {
  goal_completion: ["goal_accuracy"],
  multi_step_task: ["goal_accuracy", "tool_call_accuracy"],
  tool_selection: ["tool_call_accuracy"],
};

const MCP_UNMEASURABLE_TASKS: Record<string, string> = {
  parameter_extraction:
    "the current result model does not capture expected arguments",
  tool_argument_accuracy:
    "the current result model records tool names but not arguments",
};

export const QUALITY_PAIR_SEPARATOR = "::";

export interface QualityTaskMetricPair {
  task: string;
  metric: QualityMetric;
}

export function mcpQualityTaskIssue(task: string): string | undefined {
  return MCP_UNMEASURABLE_TASKS[task];
}

export function isMcpTaskMetricCompatible(
  task: string,
  metric: string,
): boolean {
  const allowed = MCP_TASK_METRICS[task];
  return !allowed || allowed.includes(metric as QualityMetric);
}

/**
 * Build only task/metric pairs the native MCP scorer can observe. Independent
 * task and metric samplers create invalid cross-products, so MCP generation
 * samples these pairs as one atomic value.
 */
export function resolveMcpQualityPairs(
  tasks: string[],
  metrics: string[],
  explicitTasks: boolean,
): QualityTaskMetricPair[] {
  const unknownMetrics = metrics.filter((metric) => !isQualityMetric(metric));
  if (unknownMetrics.length > 0) {
    throw new Error(`quality metric pool has unknown metrics: ${unknownMetrics.join(", ")}`);
  }

  const unmeasurable = tasks.filter((task) => mcpQualityTaskIssue(task));
  if (explicitTasks && unmeasurable.length > 0) {
    const details = unmeasurable
      .map((task) => `${task} (${mcpQualityTaskIssue(task)})`)
      .join(", ");
    throw new Error(`MCP quality generation cannot score: ${details}`);
  }

  const pairs: QualityTaskMetricPair[] = [];
  const tasksWithoutMetric: string[] = [];
  for (const task of tasks.filter((candidate) => !mcpQualityTaskIssue(candidate))) {
    const compatible = metrics.filter((metric) =>
      isMcpTaskMetricCompatible(task, metric),
    ) as QualityMetric[];
    if (compatible.length === 0) {
      tasksWithoutMetric.push(task);
      continue;
    }
    for (const metric of compatible) pairs.push({ task, metric });
  }
  if (tasksWithoutMetric.length > 0) {
    throw new Error(
      `MCP quality tasks have no compatible requested metric: ${tasksWithoutMetric.join(", ")}`,
    );
  }
  if (pairs.length === 0) {
    throw new Error("MCP quality generation has no measurable task/metric pairs");
  }
  return pairs;
}

export function encodeQualityPair(pair: QualityTaskMetricPair): string {
  return `${pair.task}${QUALITY_PAIR_SEPARATOR}${pair.metric}`;
}

export function decodeQualityPair(
  value: unknown,
): QualityTaskMetricPair | undefined {
  if (typeof value !== "string") return undefined;
  const [task, metric, extra] = value.split(QUALITY_PAIR_SEPARATOR);
  if (extra !== undefined || !task || !isQualityMetric(metric ?? "")) {
    return undefined;
  }
  return { task, metric: metric as QualityMetric };
}
