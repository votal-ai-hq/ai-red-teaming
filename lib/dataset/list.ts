/**
 * List generated dataset files with lightweight stats for the dashboard.
 * Pure-ish (fs read only) and testable.
 *
 * See docs/specs/nemo-data-designer-datasets.md — UI surface.
 */
import { readFileSync, existsSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";

export interface DatasetSummary {
  /** Path relative to the repo root (usable directly as customAttacksFile). */
  path: string;
  /** Basename without extension. */
  name: string;
  /** Family inferred from the containing directory (mcp/agent/unknown). */
  family: string;
  /** "security" (attack rows) or "quality" (task+reference rows), inferred from row shape. */
  kind: "security" | "quality";
  rowCount: number;
  /** category (security) or task (quality) -> count. */
  histogram: Record<string, number>;
  sizeBytes: number;
}

function inferFamily(relPath: string): string {
  const lower = relPath.toLowerCase();
  if (lower.includes("mcp")) return "mcp";
  if (lower.includes("agent")) return "agent";
  return "unknown";
}

function summarizeFile(root: string, absPath: string): DatasetSummary | null {
  let rows: unknown;
  try {
    rows = JSON.parse(readFileSync(absPath, "utf-8"));
  } catch {
    return null;
  }
  if (!Array.isArray(rows)) return null;

  // Quality rows carry `task` + `input`; security rows carry `category` + `prompt`.
  const first = rows.find((r) => r && typeof r === "object") as
    | Record<string, unknown>
    | undefined;
  const kind: "security" | "quality" =
    first && ("task" in first || "input" in first) ? "quality" : "security";
  const key = kind === "quality" ? "task" : "category";

  const histogram: Record<string, number> = {};
  for (const r of rows) {
    if (r && typeof r === "object") {
      const bucket = String((r as Record<string, unknown>)[key] ?? "unknown");
      histogram[bucket] = (histogram[bucket] ?? 0) + 1;
    }
  }
  const relPath = relative(root, absPath);
  return {
    path: relPath,
    name: absPath.split("/").pop()!.replace(/\.json$/i, ""),
    family: inferFamily(relPath),
    kind,
    rowCount: rows.length,
    histogram,
    sizeBytes: statSync(absPath).size,
  };
}

/**
 * Recursively list *.json dataset files under `<root>/data/datasets`.
 * Returns [] if the directory does not exist.
 */
export function listDatasets(root: string): DatasetSummary[] {
  const base = join(root, "data", "datasets");
  if (!existsSync(base)) return [];

  const out: DatasetSummary[] = [];
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const abs = join(dir, entry.name);
      if (entry.isDirectory()) walk(abs);
      else if (entry.isFile() && entry.name.toLowerCase().endsWith(".json")) {
        const s = summarizeFile(root, abs);
        if (s) out.push(s);
      }
    }
  };
  walk(base);
  return out.sort((a, b) => a.path.localeCompare(b.path));
}
