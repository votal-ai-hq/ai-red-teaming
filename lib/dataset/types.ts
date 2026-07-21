/**
 * Types for the NeMo Data Designer dataset-generation layer.
 * See docs/specs/nemo-data-designer-datasets.md.
 */
import type { DatasetFamily } from "./category-set.js";

export type Severity = "critical" | "high" | "medium" | "low";

/**
 * A generated dataset row. This is the exact shape consumed by
 * `lib/custom-attacks-loader.ts` (row-object path) — no schema extension.
 */
export interface DatasetRow {
  category: string;
  name: string;
  prompt: string;
  role?: string;
  severity: Severity;
  successCriteria: string;
  description?: string;
  note?: string;
}

/**
 * A functional-QUALITY row. Grades "was the output correct?" against a
 * reference — the opposite direction from a security `DatasetRow`. Consumed by
 * a quality scorer (native correctness judge or NeMo Evaluator), NOT by the
 * security attack-runner.
 */
export interface QualityRow {
  /** Task type (see quality-set.ts), e.g. "tool_selection", "rag_answer". */
  task: string;
  name: string;
  /** The legitimate task/question posed to the target. */
  input: string;
  /** Expected free-text answer (for answer/rag/summarization tasks). */
  reference?: string;
  /** Expected tool call(s) (for tool-use tasks), e.g. ["lookup", "refund"]. */
  expectedTools?: string[];
  /** Metric this row is graded on (see QUALITY_METRICS). */
  metric: string;
  note?: string;
}

/**
 * A generation preset — the tuning knobs. Lives as JSON under
 * `configs/datasets/*.preset.json`.
 */
export interface DatasetPreset {
  family: DatasetFamily;
  /**
   * What the dataset evaluates. "security" (default) generates adversarial
   * attacks graded on compromise; "quality" generates legitimate tasks graded
   * on correctness against a reference.
   */
  kind?: "security" | "quality";
  /** (quality) Task-type pool override (validated fail-closed). */
  tasks?: string[];
  /** (quality) Metrics to sample rows across. */
  metrics?: string[];
  /** Optional override of the family's default category pool (validated fail-closed). */
  categories?: string[];
  /** Severity distribution to sample from. */
  severities?: Severity[];
  /** Target roles to sample from. */
  roles?: string[];
  /** MCP surface elements (tool/prompt/resource names). Optional; falls back to seeds. */
  surfaces?: string[];
  /**
   * Conversation shape of generated attacks. "single" (default) produces a
   * one-message attack; "multi" produces a [Turn N] escalation transcript the
   * runtime replays turn-by-turn (see lib/custom-attacks-loader.ts). Multi-turn
   * applies to security datasets only.
   */
  turnMode?: "single" | "multi";
  /** Max conversation turns when turnMode="multi" (clamped to 2..8). Default 3. */
  maxTurns?: number;
  /**
   * Operator-supplied custom instructions injected into the generation prompt —
   * the lever for iterating on a dataset's style/content without editing rows.
   * Refines how each case is written; the output-format contract is preserved.
   */
  customInstructions?: string;
  /**
   * Few-shot style examples — sample prompts/inputs the generator should match
   * in shape, tone, and difficulty (without copying verbatim). The strongest
   * lever for "make the dataset look like MY app's traffic". Capped in the
   * config builder so a large paste can't dominate the prompt.
   */
  examples?: string[];
  /** Total rows to generate. */
  count?: number;
  /** Minimum rows per category (balance floor). */
  perCategoryFloor?: number;
  /** Model id used for LLM columns (e.g. "meta/llama-3.3-70b-instruct", "gpt-4o-mini"). */
  generationModel?: string;
  /** Model alias registered with Data Designer for the generation model. */
  modelAlias?: string;
  /**
   * Data Designer model provider backing the generation model. Data Designer
   * is not NVIDIA-locked — it also supports OpenAI and other providers.
   * Common values: "nim" (default), "openai". Default: "nim".
   */
  provider?: string;
}

/** Optional seed inputs (Phase 2: derived from CodebaseAnalysis or an AppProfile). */
export interface DatasetSeeds {
  roles?: string[];
  surfaces?: string[];
  /**
   * App-context preamble injected into the generation prompt so generated
   * attacks/grading reference the target's real domain, rules, and data.
   * Populated from an AppProfile (see lib/dataset/app-profile.ts).
   */
  context?: string;
}

/** Result of validating a batch of rows. */
export interface ValidationResult {
  valid: DatasetRow[];
  errors: string[];
  histogram: Record<string, number>;
  duplicatesDropped: number;
}
