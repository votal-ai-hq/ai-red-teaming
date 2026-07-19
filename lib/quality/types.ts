/**
 * Types for the native functional-quality scorer.
 * See docs/specs/nemo-data-designer-datasets.md — quality scorer.
 */
import type { QualityRow } from "../dataset/types.js";

export interface QualityEvalResult {
  row: QualityRow;
  /** Correctness score in [0,1] for this row's metric. */
  score: number;
  /** true when score >= the pass threshold. */
  pass: boolean;
  metric: string;
  /** How the score was produced: a deterministic metric or the LLM judge. */
  scorer: "deterministic" | "judge";
  /** The target's response text (truncated for the report). */
  response: string;
  /** Tool calls the target made (for tool-call metrics). */
  actualTools?: string[];
  statusCode: number;
  responseTimeMs: number;
  /** Judge reasoning (judge-scored rows only). */
  reasoning?: string;
  /** Set when the row could not be executed/scored. */
  error?: string;
}

export interface QualityReport {
  timestamp: string;
  targetUrl: string;
  dataset?: string;
  passThreshold: number;
  summary: {
    total: number;
    scored: number;
    errors: number;
    /** Mean score across scored rows, 0–100. */
    score: number;
    passed: number;
    byMetric: Record<string, { count: number; mean: number; passed: number }>;
    byTask: Record<string, { count: number; mean: number; passed: number }>;
  };
  results: QualityEvalResult[];
}
