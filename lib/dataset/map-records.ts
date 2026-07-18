/**
 * Map raw Data Designer records into dataset rows (pre-validation).
 * Kept separate from the client so it can be unit-tested against fixtures.
 *
 * See docs/specs/nemo-data-designer-datasets.md §3.1, §7.
 */
import type { NemoRecord } from "./nemo-client.js";
import type { DatasetFamily } from "./category-set.js";

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
  const successCriteria =
    str(grading.successCriteria) || str(rec.successCriteria);
  const expectation = str(grading.expectation) || str(rec.expectation);

  const name =
    surface && category
      ? `${category} via ${strategy || "direct"} (${surface})`.slice(0, 120)
      : `${category} case`;

  const descParts = [
    `Synthetic (nemo). family=${family}`,
    strategy ? `strategy=${strategy}` : "",
    surface ? `surface=${surface}` : "",
  ].filter(Boolean);

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
  };
}

export function recordsToRows(
  records: NemoRecord[],
  family: DatasetFamily,
): Record<string, unknown>[] {
  return records.map((r) => recordToRow(r, family));
}

function str(v: unknown): string {
  return v == null ? "" : String(v).trim();
}
