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
import type { DatasetFamily } from "./category-set.js";
import { isQualityTask, isQualityMetric } from "./quality-set.js";
import {
  validateMcpQualityContract,
  validateMcpSecurityContract,
} from "./mcp-contract.js";
import { toText } from "./to-text.js";
import type {
  DatasetRow,
  McpDatasetContract,
  QualityRow,
  Severity,
  ValidationResult,
} from "./types.js";

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
export function validateRows(
  rows: unknown[],
  opts?: { family?: DatasetFamily; mcpContract?: McpDatasetContract },
): ValidationResult {
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

    const operation = String(o._mcpOperation ?? "").trim();
    if (opts?.family === "mcp") {
      if (
        operation !== "tools/call" &&
        operation !== "resources/read" &&
        operation !== "prompts/get"
      ) {
        errors.push(
          `row ${idx} (${category}): missing or invalid _mcpOperation`,
        );
        return;
      }
      if (operation === "tools/call" && !String(o._mcpTool ?? "").trim()) {
        errors.push(`row ${idx} (${category}): tools/call requires _mcpTool`);
        return;
      }
      if (
        (operation === "tools/call" || operation === "prompts/get") &&
        (!o._mcpArguments ||
          typeof o._mcpArguments !== "object" ||
          Array.isArray(o._mcpArguments))
      ) {
        errors.push(
          `row ${idx} (${category}): ${operation} requires object _mcpArguments`,
        );
        return;
      }
      if (
        operation === "resources/read" &&
        !String(o._mcpResourceUri ?? "").trim()
      ) {
        errors.push(
          `row ${idx} (${category}): resources/read requires _mcpResourceUri`,
        );
        return;
      }
      if (operation === "prompts/get" && !String(o._mcpPrompt ?? "").trim()) {
        errors.push(`row ${idx} (${category}): prompts/get requires _mcpPrompt`);
        return;
      }
    }

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
    if (
      operation === "tools/call" ||
      operation === "resources/read" ||
      operation === "prompts/get"
    ) {
      row._mcpOperation = operation;
    }
    if (o._mcpTool) row._mcpTool = String(o._mcpTool).trim();
    if (o._mcpResourceUri) {
      row._mcpResourceUri = String(o._mcpResourceUri).trim();
    }
    if (o._mcpPrompt) row._mcpPrompt = String(o._mcpPrompt).trim();
    if (
      o._mcpArguments &&
      typeof o._mcpArguments === "object" &&
      !Array.isArray(o._mcpArguments)
    ) {
      row._mcpArguments = o._mcpArguments as Record<string, unknown>;
    }

    if (opts?.family === "mcp" && opts.mcpContract) {
      const contractErrors = validateMcpSecurityContract(row, opts.mcpContract);
      if (contractErrors.length > 0) {
        errors.push(
          `row ${idx} (${category}): MCP contract violation: ${contractErrors.join("; ")}`,
        );
        return;
      }
    }

    const h = hashPrompt(prompt);
    if (seen.has(h)) {
      duplicatesDropped++;
      return;
    }
    seen.add(h);

    valid.push(row);
    histogram[category] = (histogram[category] ?? 0) + 1;
  });

  return { valid, errors, histogram, duplicatesDropped };
}

export interface QualityValidationResult {
  valid: QualityRow[];
  errors: string[];
  histogram: Record<string, number>;
  duplicatesDropped: number;
}

/**
 * Validate + dedup functional-quality rows. Fail-closed, mirroring the security
 * validator: `task` must be a known quality task, `metric` a known metric,
 * `input` non-empty, and at least one of `reference` / `expectedTools` present
 * (a row with no grading reference can't be scored).
 */
/**
 * @param opts.allowedTasks extra task labels accepted beyond the known pool —
 *   user-defined custom focus tasks (quality datasets only). A row's `task` is
 *   valid if it's a known QualityTask OR listed here. `metric` stays strict
 *   because the scorer grades on it.
 */
export function validateQualityRows(
  rows: unknown[],
  opts?: {
    allowedTasks?: Iterable<string>;
    mcpContract?: McpDatasetContract;
  },
): QualityValidationResult {
  const valid: QualityRow[] = [];
  const errors: string[] = [];
  const histogram: Record<string, number> = {};
  const seen = new Set<string>();
  const allowedTasks = new Set(opts?.allowedTasks ?? []);
  let duplicatesDropped = 0;

  rows.forEach((raw, i) => {
    const idx = i + 1;
    if (!raw || typeof raw !== "object") {
      errors.push(`row ${idx}: not an object`);
      return;
    }
    const o = raw as Record<string, unknown>;
    const task = String(o.task ?? "").trim();
    const input = String(o.input ?? "").trim();
    const metric = String(o.metric ?? "").trim();
    // A generated reference may come back structured (an object/array). Plain
    // String() would store it as "[object Object]" and destroy the content.
    const reference = toText(o.reference).trim();
    const expectedTools = Array.isArray(o.expectedTools)
      ? (o.expectedTools as unknown[]).map((t) => String(t).trim()).filter(Boolean)
      : [];

    if (!isQualityTask(task) && !allowedTasks.has(task)) {
      errors.push(`row ${idx}: unknown quality task "${task}"`);
      return;
    }
    if (!input) {
      errors.push(`row ${idx} (${task}): empty input`);
      return;
    }
    if (!isQualityMetric(metric)) {
      errors.push(`row ${idx} (${task}): unknown metric "${metric}"`);
      return;
    }
    if (metric === "tool_call_accuracy" && expectedTools.length === 0) {
      errors.push(`row ${idx} (${task}): tool_call_accuracy requires expectedTools`);
      return;
    }
    if (metric !== "tool_call_accuracy" && !reference) {
      errors.push(`row ${idx} (${task}): metric "${metric}" requires a reference`);
      return;
    }

    const row: QualityRow = {
      task,
      name: String(o.name ?? `${task} case`).trim(),
      input,
      metric,
    };
    if (reference) row.reference = reference;
    if (expectedTools.length) row.expectedTools = expectedTools;
    if (o.note) row.note = String(o.note).trim();

    if (opts?.mcpContract) {
      const contractErrors = validateMcpQualityContract(row, opts.mcpContract);
      if (contractErrors.length > 0) {
        errors.push(
          `row ${idx} (${task}): MCP contract violation: ${contractErrors.join("; ")}`,
        );
        return;
      }
    }

    const h = hashPrompt(input);
    if (seen.has(h)) {
      duplicatesDropped++;
      return;
    }
    seen.add(h);

    valid.push(row);
    histogram[task] = (histogram[task] ?? 0) + 1;
  });

  return { valid, errors, histogram, duplicatesDropped };
}

/**
 * Merge new rows into an existing dataset (top-up / append), deduping across
 * BOTH sets. Existing rows come first so they win a near-duplicate tie — a
 * top-up never rewrites what's already there, it only adds genuinely new rows.
 * `added` is how many net-new rows survived (i.e. weren't dupes of existing).
 */
export function mergeDatasets(
  kind: "security" | "quality",
  existing: unknown[],
  incoming: unknown[],
  opts?: {
    allowedTasks?: Iterable<string>;
    family?: DatasetFamily;
    mcpContract?: McpDatasetContract;
  },
): (ValidationResult | QualityValidationResult) & { added: number } {
  const existingArr = Array.isArray(existing) ? existing : [];
  const existingCount = existingArr.length;
  const combined = [...existingArr, ...incoming];
  let res: ValidationResult | QualityValidationResult;
  if (kind === "quality") {
    // Existing rows were valid when saved — keep any custom task labels they
    // already carry so a top-up never drops what's already on disk.
    const allowed = new Set(opts?.allowedTasks ?? []);
    for (const r of existingArr) {
      if (r && typeof r === "object") {
        const t = String((r as Record<string, unknown>).task ?? "").trim();
        if (t) allowed.add(t);
      }
    }
    res = validateQualityRows(combined, {
      allowedTasks: allowed,
      mcpContract: opts?.mcpContract,
    });
  } else {
    res = validateRows(combined, {
      family: opts?.family,
      mcpContract: opts?.mcpContract,
    });
  }
  return { ...res, added: res.valid.length - existingCount };
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
