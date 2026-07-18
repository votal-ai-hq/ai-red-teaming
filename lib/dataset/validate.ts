/**
 * Fail-closed validation for generated dataset rows.
 *
 * The custom-attacks loader is lenient (warns + defaults on unknown category).
 * A deep-eval dataset must be strict: any row that would be silently misrouted,
 * blanked, or mis-severitied is rejected here before it is written to disk.
 *
 * See docs/specs/nemo-data-designer-datasets.md §3.2, §5.3, §10.
 */
import { createHash } from "node:crypto";
import { isAttackCategory } from "./category-set.js";
import type { DatasetRow, Severity, ValidationResult } from "./types.js";

const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low"];

function normalizeForDedup(prompt: string): string {
  return prompt.trim().toLowerCase().replace(/\s+/g, " ");
}

function hashPrompt(prompt: string): string {
  return createHash("sha256").update(normalizeForDedup(prompt)).digest("hex");
}

function isSeverity(s: unknown): s is Severity {
  return typeof s === "string" && (SEVERITIES as readonly string[]).includes(s);
}

/**
 * Validate + dedup a batch of candidate rows.
 *
 * - `category` MUST be a member of the AttackCategory union (fail-closed).
 * - `prompt` MUST be non-empty.
 * - `severity` MUST be one of the four levels.
 * - `successCriteria` MUST be non-empty (rows are self-grading).
 * - near-duplicate prompts (normalized) are dropped, not errored.
 */
export function validateRows(rows: unknown[]): ValidationResult {
  const valid: DatasetRow[] = [];
  const errors: string[] = [];
  const histogram: Record<string, number> = {};
  const seen = new Set<string>();
  let duplicatesDropped = 0;

  rows.forEach((raw, i) => {
    const idx = i + 1;
    if (!raw || typeof raw !== "object") {
      errors.push(`row ${idx}: not an object`);
      return;
    }
    const o = raw as Record<string, unknown>;
    const category = String(o.category ?? "").trim();
    const prompt = String(o.prompt ?? o.message ?? "").trim();
    const successCriteria = String(
      o.successCriteria ?? o.success_criteria ?? "",
    ).trim();
    const severityRaw = String(o.severity ?? "").trim().toLowerCase();

    if (!isAttackCategory(category)) {
      errors.push(`row ${idx}: invalid category "${category}"`);
      return;
    }
    if (!prompt) {
      errors.push(`row ${idx} (${category}): empty prompt`);
      return;
    }
    if (!isSeverity(severityRaw)) {
      errors.push(`row ${idx} (${category}): invalid severity "${severityRaw}"`);
      return;
    }
    if (!successCriteria) {
      errors.push(`row ${idx} (${category}): empty successCriteria`);
      return;
    }

    const h = hashPrompt(prompt);
    if (seen.has(h)) {
      duplicatesDropped++;
      return;
    }
    seen.add(h);

    const row: DatasetRow = {
      category,
      name: String(o.name ?? `${category} case`).trim(),
      prompt,
      severity: severityRaw,
      successCriteria,
    };
    if (o.role) row.role = String(o.role).trim();
    if (o.description) row.description = String(o.description).trim();
    if (o.note) row.note = String(o.note).trim();

    valid.push(row);
    histogram[category] = (histogram[category] ?? 0) + 1;
  });

  return { valid, errors, histogram, duplicatesDropped };
}

/** Pretty one-line-per-category histogram, sorted by count desc. */
export function formatHistogram(histogram: Record<string, number>): string {
  const rows = Object.entries(histogram).sort((a, b) => b[1] - a[1]);
  const total = rows.reduce((s, [, n]) => s + n, 0);
  const lines = rows.map(([cat, n]) => `  ${String(n).padStart(4)}  ${cat}`);
  return `${lines.join("\n")}\n  ----  \n  ${String(total).padStart(4)}  total (${rows.length} categories)`;
}

/**
 * Report which categories in `pool` fall below the balance floor.
 * Returns [] when balanced.
 */
export function underFloor(
  histogram: Record<string, number>,
  pool: string[],
  floor: number,
): { category: string; have: number }[] {
  if (floor <= 0) return [];
  return pool
    .map((category) => ({ category, have: histogram[category] ?? 0 }))
    .filter((e) => e.have < floor);
}
