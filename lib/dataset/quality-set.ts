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
 * Resolve a preset's quality task list, fail-closed on unknown tasks (mirrors
 * the security `resolveCategoryPool` contract).
 */
export function resolveQualityPool(
  family: DatasetFamily,
  requested: string[] | undefined,
): string[] {
  if (!requested || requested.length === 0) return defaultQualityPool(family);
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
