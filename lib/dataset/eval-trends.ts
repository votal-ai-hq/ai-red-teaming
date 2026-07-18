/**
 * Group eval runs by dataset to track score over time (regression tracking).
 * Pure + testable. Feeds the dashboard's per-dataset trend view.
 *
 * An "eval run" is a report whose attack set came from a dataset
 * (`report.dataset.file`). Reports without dataset provenance are ignored here —
 * they are ordinary scans, not dataset evals.
 *
 * See docs/specs/nemo-data-designer-datasets.md — regression tracking.
 */

export interface EvalRunPoint {
  filename: string;
  timestamp: string;
  score: number;
  targetUrl: string;
  only: boolean;
  /** Score delta vs the previous run of the same dataset (undefined for the first). */
  delta?: number;
}

export interface EvalTrend {
  /** Dataset file path — the grouping key. */
  dataset: string;
  runs: EvalRunPoint[];
  latestScore: number;
  /** latest - first, across the series. */
  totalDelta: number;
  /** min / max score across the series. */
  minScore: number;
  maxScore: number;
}

export interface ReportLike {
  filename: string;
  timestamp: string;
  score: number;
  targetUrl?: string;
  dataset?: { file: string; only: boolean };
}

/**
 * Group reports by `dataset.file`, order each group oldest→newest, and annotate
 * per-run deltas. Reports without a dataset are dropped. Groups are returned
 * sorted by most-recent activity first.
 */
export function groupEvalRuns(reports: ReportLike[]): EvalTrend[] {
  const byDataset = new Map<string, ReportLike[]>();
  for (const r of reports) {
    const file = r.dataset?.file;
    if (!file) continue;
    const arr = byDataset.get(file) ?? [];
    arr.push(r);
    byDataset.set(file, arr);
  }

  const trends: EvalTrend[] = [];
  for (const [dataset, group] of byDataset) {
    const ordered = [...group].sort((a, b) =>
      a.timestamp.localeCompare(b.timestamp),
    );
    const runs: EvalRunPoint[] = ordered.map((r, i) => {
      const prev = ordered[i - 1];
      return {
        filename: r.filename,
        timestamp: r.timestamp,
        score: r.score,
        targetUrl: r.targetUrl ?? "",
        only: r.dataset?.only ?? false,
        delta: prev ? r.score - prev.score : undefined,
      };
    });
    const scores = runs.map((r) => r.score);
    trends.push({
      dataset,
      runs,
      latestScore: scores[scores.length - 1] ?? 0,
      totalDelta: scores.length > 1 ? scores[scores.length - 1] - scores[0] : 0,
      minScore: scores.length ? Math.min(...scores) : 0,
      maxScore: scores.length ? Math.max(...scores) : 0,
    });
  }

  // Most recently active dataset first.
  trends.sort((a, b) => {
    const at = a.runs[a.runs.length - 1]?.timestamp ?? "";
    const bt = b.runs[b.runs.length - 1]?.timestamp ?? "";
    return bt.localeCompare(at);
  });
  return trends;
}
