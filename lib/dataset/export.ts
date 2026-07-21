/**
 * Convert a saved dataset to interop formats for other eval tooling.
 *
 * Pure (no I/O). The dashboard reads the .json off disk and calls these to
 * serve a download. Two formats cover the common consumers:
 *   - jsonl: one JSON object per line (promptfoo, OpenAI evals, most harnesses)
 *   - csv:   flat table (spreadsheets, quick review, deepeval CSV import)
 */

export type ExportFormat = "jsonl" | "csv";

export function isExportFormat(x: unknown): x is ExportFormat {
  return x === "jsonl" || x === "csv";
}

/** One compact JSON object per line. */
export function toJsonl(rows: unknown[]): string {
  return rows.map((r) => JSON.stringify(r)).join("\n") + (rows.length ? "\n" : "");
}

/** RFC-4180-ish CSV escaping. */
function csvCell(v: unknown): string {
  let s: string;
  if (v == null) s = "";
  else if (Array.isArray(v)) s = v.map((x) => String(x)).join("; ");
  else if (typeof v === "object") s = JSON.stringify(v);
  else s = String(v);
  if (/[",\n\r]/.test(s)) s = `"${s.replace(/"/g, '""')}"`;
  return s;
}

/**
 * Flatten rows to CSV. Columns are the union of keys across all rows, with a
 * stable preferred ordering for the common security/quality fields first.
 */
export function toCsv(rows: unknown[]): string {
  const objs = rows.filter(
    (r): r is Record<string, unknown> => !!r && typeof r === "object",
  );
  const PREFERRED = [
    "category",
    "task",
    "name",
    "prompt",
    "input",
    "severity",
    "metric",
    "successCriteria",
    "reference",
    "expectedTools",
    "role",
    "description",
    "note",
  ];
  const present = new Set<string>();
  for (const o of objs) for (const k of Object.keys(o)) present.add(k);
  const cols = [
    ...PREFERRED.filter((c) => present.has(c)),
    ...[...present].filter((c) => !PREFERRED.includes(c)).sort(),
  ];
  const header = cols.map(csvCell).join(",");
  const lines = objs.map((o) => cols.map((c) => csvCell(o[c])).join(","));
  return [header, ...lines].join("\n") + "\n";
}

export function exportDataset(rows: unknown[], format: ExportFormat): string {
  return format === "csv" ? toCsv(rows) : toJsonl(rows);
}

export function exportContentType(format: ExportFormat): string {
  return format === "csv" ? "text/csv" : "application/x-ndjson";
}
