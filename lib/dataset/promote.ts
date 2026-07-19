/**
 * Promote a real scan finding into a permanent regression case.
 *
 * The findings → dataset flywheel: when a scan confirms a compromise, that exact
 * attack becomes a versioned regression row so future runs re-test it. This is
 * the white-box product's compounding asset — no black-box tool can do it
 * because it doesn't see your target's real breaches.
 *
 * Pure + I/O-free (append logic + row shaping) so it's unit-tested; the endpoint
 * handles file read/write and fail-closed validation.
 *
 * See docs/specs/nemo-data-designer-datasets.md — findings → dataset.
 */
import type { DatasetRow, Severity } from "./types.js";

export interface PromoteInput {
  category: string;
  prompt: string;
  successCriteria: string;
  severity?: string;
  name?: string;
  /** Provenance: the report/run this was promoted from. */
  source?: string;
}

function normSeverity(s: string | undefined): Severity {
  const v = (s ?? "high").toLowerCase();
  return v === "critical" || v === "high" || v === "medium" || v === "low"
    ? (v as Severity)
    : "high";
}

/** Shape a finding into a regression DatasetRow with provenance in `note`. */
export function buildRegressionRow(input: PromoteInput): DatasetRow {
  const source = input.source ? ` from ${input.source}` : "";
  return {
    category: input.category,
    name: (input.name || `Regression: ${input.category}`).slice(0, 120),
    prompt: input.prompt,
    severity: normSeverity(input.severity),
    successCriteria:
      input.successCriteria ||
      "The target reproduced the previously confirmed compromise.",
    description: `Promoted from a confirmed finding${source}.`,
    note: "source=promoted-finding version=1",
  };
}

function normalizePrompt(p: string): string {
  return p.trim().toLowerCase().replace(/\s+/g, " ");
}

/**
 * Append a row to an existing dataset, deduped by normalized prompt.
 * Returns the new array and whether the row was actually added.
 */
export function appendRow(
  existing: DatasetRow[],
  row: DatasetRow,
): { rows: DatasetRow[]; added: boolean } {
  const key = normalizePrompt(row.prompt);
  const dup = existing.some((r) => normalizePrompt(r.prompt) === key);
  if (dup) return { rows: existing, added: false };
  return { rows: [...existing, row], added: true };
}
