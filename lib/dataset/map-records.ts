/**
 * Map raw Data Designer records into dataset rows (pre-validation).
 * Kept separate from the client so it can be unit-tested against fixtures.
 *
 * See docs/specs/nemo-data-designer-datasets.md §3.1, §7.
 */
import type { NemoRecord } from "./nemo-client.js";
import type { DatasetFamily } from "./category-set.js";
import { executionFromMcpRecord } from "./mcp-execution.js";
import { toText } from "./to-text.js";
import { decodeQualityPair } from "./quality-set.js";

/**
 * A DD record carries one value per column (category, severity, strategy, role,
 * surface, prompt, grading{successCriteria,expectation}). Flatten into the row
 * shape the custom-attacks loader consumes. Validation happens downstream in
 * `validate.ts` — this mapper never drops or "fixes" values silently.
 */
export function recordToRow(
  rec: NemoRecord,
  family: DatasetFamily,
): Record<string, unknown> {
  const grading = (rec.grading ?? {}) as Record<string, unknown>;
  const category = str(rec.category);
  const strategy = str(rec.strategy);
  const surface = str(rec.surface);
  // Same structured-value hazard as the quality mapper: a grading column may
  // return an object, and str() would flatten it to "[object Object]" — here
  // that would corrupt the criteria the grader judges the attack against.
  const successCriteria =
    toText(grading.successCriteria).trim() || toText(rec.successCriteria).trim();
  const expectation =
    toText(grading.expectation).trim() || toText(rec.expectation).trim();

  const name =
    surface && category
      ? `${category} via ${strategy || "direct"} (${surface})`.slice(0, 120)
      : `${category} case`;

  const descParts = [
    `Synthetic (nemo). family=${family}`,
    strategy ? `strategy=${strategy}` : "",
    surface ? `surface=${surface}` : "",
  ].filter(Boolean);

  const execution = family === "mcp" ? executionFromMcpRecord(rec) : null;

  return {
    category,
    name,
    prompt: str(rec.prompt),
    role: str(rec.role) || undefined,
    severity: str(rec.severity).toLowerCase(),
    successCriteria,
    description:
      descParts.join(" ") + (expectation ? ` | expected: ${expectation}` : ""),
    note: "generator=nemo-data-designer version=1",
    ...(execution ?? {}),
  };
}

export function recordsToRows(
  records: NemoRecord[],
  family: DatasetFamily,
): Record<string, unknown>[] {
  return records.map((r) => recordToRow(r, family));
}

/** Map a DD record into a functional-quality row (task + reference/tools). */
export function recordToQualityRow(rec: NemoRecord): Record<string, unknown> {
  const grading = (rec.grading ?? {}) as Record<string, unknown>;
  const pair = decodeQualityPair(rec.taskMetric);
  const task = str(rec.task) || pair?.task || "";
  const metric = str(rec.metric) || pair?.metric || "";
  // The grading column can hand back a STRUCTURED reference (an object/array).
  // str() would flatten it to "[object Object]" here — before validation ever
  // sees it — which silently destroys the ideal answer the judge grades against
  // (and made every judge-scored metric, e.g. goal_accuracy, fail).
  const reference = toText(grading.reference).trim() || toText(rec.reference).trim();
  let expectedTools: string[] = [];
  const raw = grading.expectedTools ?? rec.expectedTools;
  if (Array.isArray(raw)) {
    expectedTools = raw.map((t) => str(t)).filter(Boolean);
  } else if (typeof raw === "string" && raw.trim()) {
    // DD structured output may hand back a JSON-array string.
    try {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) expectedTools = parsed.map((t) => str(t)).filter(Boolean);
    } catch {
      expectedTools = raw.split(",").map((t) => str(t)).filter(Boolean);
    }
  }
  return {
    task,
    name: `${task} · ${metric}`.slice(0, 120),
    input: str(rec.input),
    reference,
    expectedTools,
    metric,
    note: "generator=nemo-data-designer kind=quality version=1",
  };
}

export function recordsToQualityRows(
  records: NemoRecord[],
): Record<string, unknown>[] {
  return records.map((r) => recordToQualityRow(r));
}

function str(v: unknown): string {
  return v == null ? "" : String(v).trim();
}
