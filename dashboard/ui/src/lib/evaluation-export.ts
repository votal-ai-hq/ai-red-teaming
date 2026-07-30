import type { QualityEvalReport } from "@/api/datasets";

const CSV_COLUMNS = [
  "record",
  "timestamp",
  "dataset",
  "target_url",
  "pass_threshold",
  "task",
  "name",
  "input",
  "reference",
  "expected_tools",
  "metric",
  "score",
  "pass",
  "scorer",
  "response",
  "actual_tools",
  "status_code",
  "response_time_ms",
  "reasoning",
  "error",
] as const;

function csvCell(value: unknown): string {
  const text =
    value == null
      ? ""
      : Array.isArray(value) || typeof value === "object"
        ? JSON.stringify(value)
        : String(value);
  return `"${text.replace(/"/g, '""')}"`;
}

export function evaluationReportCsv(report: QualityEvalReport): string {
  const rows = report.results.map((result, index) => ({
    record: index + 1,
    timestamp: report.timestamp,
    dataset: report.dataset ?? "",
    target_url: report.targetUrl,
    pass_threshold: report.passThreshold,
    task: result.row.task ?? "",
    name: result.row.name ?? "",
    input: result.row.input ?? "",
    reference: result.row.reference ?? "",
    expected_tools: result.row.expectedTools ?? [],
    metric: result.metric,
    score: result.score,
    pass: result.pass,
    scorer: result.scorer,
    response: result.response,
    actual_tools: result.actualTools ?? [],
    status_code: result.statusCode,
    response_time_ms: result.responseTimeMs,
    reasoning: result.reasoning ?? "",
    error: result.error ?? "",
  }));

  return [
    CSV_COLUMNS.map(csvCell).join(","),
    ...rows.map((row) =>
      CSV_COLUMNS.map((column) => csvCell(row[column])).join(","),
    ),
  ].join("\r\n");
}

export function evaluationReportJson(report: QualityEvalReport): string {
  return JSON.stringify(report, null, 2);
}

export function evaluationExportBaseName(filename: string): string {
  const base = filename.replace(/\.json$/i, "").replace(/[^a-z0-9._-]+/gi, "-");
  return base || "quality-evaluation";
}
