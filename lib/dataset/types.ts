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
 * A generation preset — the tuning knobs. Lives as JSON under
 * `configs/datasets/*.preset.json`.
 */
export interface DatasetPreset {
  family: DatasetFamily;
  /** Optional override of the family's default category pool (validated fail-closed). */
  categories?: string[];
  /** Severity distribution to sample from. */
  severities?: Severity[];
  /** Target roles to sample from. */
  roles?: string[];
  /** MCP surface elements (tool/prompt/resource names). Optional; falls back to seeds. */
  surfaces?: string[];
  /** Total rows to generate. */
  count?: number;
  /** Minimum rows per category (balance floor). */
  perCategoryFloor?: number;
  /** NIM model id used for LLM columns. */
  generationModel?: string;
  /** Model alias registered with Data Designer for the generation model. */
  modelAlias?: string;
}

/** Optional seed inputs (Phase 2: derived from CodebaseAnalysis). */
export interface DatasetSeeds {
  roles?: string[];
  surfaces?: string[];
}

/** Result of validating a batch of rows. */
export interface ValidationResult {
  valid: DatasetRow[];
  errors: string[];
  histogram: Record<string, number>;
  duplicatesDropped: number;
}
