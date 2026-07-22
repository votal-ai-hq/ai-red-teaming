/**
 * Dataset storage — Postgres when DATABASE_URL is set, filesystem otherwise.
 *
 * Generated datasets used to live only as JSON files under data/datasets, which
 * is per-pod and ephemeral on a container platform (lost on every restart).
 * When a database is configured, datasets are stored in the `datasets` table
 * (tenant-scoped) so they persist and are shared across replicas. Without a DB,
 * the original file behavior is preserved unchanged.
 *
 * The logical `path` (e.g. data/datasets/nemo-mcp/v1.json) is the key in both
 * backends, so callers stay backend-agnostic.
 */
import { join, dirname } from "node:path";
import {
  readFileSync,
  writeFileSync,
  mkdirSync,
  existsSync,
  renameSync,
  rmSync,
} from "node:fs";
import { query, isDbConfigured } from "../db.js";
import { listDatasets, summarizeRows, type DatasetSummary } from "./list.js";

/** Repo root — this file is at <root>/lib/dataset, so up two levels. */
function repoRoot(): string {
  return join(import.meta.dirname, "..", "..");
}

function absFor(path: string): string {
  return join(repoRoot(), path);
}

/** True when datasets are stored in Postgres (vs. the filesystem). */
export function datasetDbEnabled(): boolean {
  return isDbConfigured();
}

interface DatasetRowRecord {
  path: string;
  name: string;
  family: string;
  kind: "security" | "quality";
  row_count: number;
  histogram: Record<string, number>;
  size_bytes: number;
}

/** List a tenant's datasets (DB) or all dataset files (file mode). */
export async function listDatasetsStore(
  tenantId: string,
): Promise<DatasetSummary[]> {
  if (!isDbConfigured()) return listDatasets(repoRoot());
  const res = await query<DatasetRowRecord>(
    `SELECT path, name, family, kind, row_count, histogram, size_bytes
       FROM datasets WHERE tenant_id = $1 ORDER BY path`,
    [tenantId],
  );
  return res.rows.map((r) => ({
    path: r.path,
    name: r.name,
    family: r.family,
    kind: r.kind,
    rowCount: r.row_count,
    histogram: r.histogram ?? {},
    sizeBytes: r.size_bytes,
  }));
}

/** Read one dataset's rows, or null if it doesn't exist. */
export async function readDatasetRowsStore(
  tenantId: string,
  path: string,
): Promise<unknown[] | null> {
  if (!isDbConfigured()) {
    const abs = absFor(path);
    if (!existsSync(abs)) return null;
    const parsed = JSON.parse(readFileSync(abs, "utf-8"));
    return Array.isArray(parsed) ? parsed : [];
  }
  const res = await query<{ rows: unknown }>(
    `SELECT rows FROM datasets WHERE tenant_id = $1 AND path = $2`,
    [tenantId, path],
  );
  if (res.rows.length === 0) return null;
  const rows = res.rows[0].rows;
  return Array.isArray(rows) ? rows : [];
}

/** Whether a dataset exists (used to decide append vs. fresh write). */
export async function datasetExistsStore(
  tenantId: string,
  path: string,
): Promise<boolean> {
  if (!isDbConfigured()) return existsSync(absFor(path));
  const res = await query<{ one: number }>(
    `SELECT 1 AS one FROM datasets WHERE tenant_id = $1 AND path = $2`,
    [tenantId, path],
  );
  return res.rows.length > 0;
}

/**
 * Upsert a dataset (full replace of its rows). Returns the computed summary.
 * In file mode this writes the JSON file exactly as before.
 */
export async function saveDatasetStore(
  tenantId: string,
  path: string,
  rows: unknown[],
): Promise<DatasetSummary> {
  const summary = summarizeRows(path, rows);
  if (!isDbConfigured()) {
    const abs = absFor(path);
    mkdirSync(dirname(abs), { recursive: true });
    writeFileSync(abs, JSON.stringify(rows, null, 2) + "\n", "utf-8");
    return summary;
  }
  await query(
    `INSERT INTO datasets
       (tenant_id, path, name, family, kind, row_count, histogram, rows, size_bytes, updated_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now())
     ON CONFLICT (tenant_id, path) DO UPDATE SET
       name       = EXCLUDED.name,
       family     = EXCLUDED.family,
       kind       = EXCLUDED.kind,
       row_count  = EXCLUDED.row_count,
       histogram  = EXCLUDED.histogram,
       rows       = EXCLUDED.rows,
       size_bytes = EXCLUDED.size_bytes,
       updated_at = now()`,
    [
      tenantId,
      path,
      summary.name,
      summary.family,
      summary.kind,
      summary.rowCount,
      JSON.stringify(summary.histogram),
      JSON.stringify(rows),
      summary.sizeBytes,
    ],
  );
  return summary;
}

/**
 * Rename a dataset (move it to a new logical path). The directory — and so the
 * family/kind — is unchanged; only the file's base name moves. Callers must
 * check the destination is free first (datasetExistsStore).
 */
export async function renameDatasetStore(
  tenantId: string,
  fromPath: string,
  toPath: string,
): Promise<DatasetSummary | null> {
  const name = toPath.split("/").pop()!.replace(/\.json$/i, "");
  if (!isDbConfigured()) {
    const fromAbs = absFor(fromPath);
    const toAbs = absFor(toPath);
    if (!existsSync(fromAbs)) return null;
    mkdirSync(dirname(toAbs), { recursive: true });
    renameSync(fromAbs, toAbs);
    const parsed = JSON.parse(readFileSync(toAbs, "utf-8"));
    return summarizeRows(toPath, Array.isArray(parsed) ? parsed : []);
  }
  const res = await query<{ one: number }>(
    `UPDATE datasets SET path = $3, name = $4, updated_at = now()
      WHERE tenant_id = $1 AND path = $2
      RETURNING 1 AS one`,
    [tenantId, fromPath, toPath, name],
  );
  if (res.rows.length === 0) return null;
  const rows = (await readDatasetRowsStore(tenantId, toPath)) ?? [];
  return summarizeRows(toPath, rows);
}

/** Delete a dataset from whichever backend holds it. */
export async function deleteDatasetStore(
  tenantId: string,
  path: string,
): Promise<void> {
  if (!isDbConfigured()) {
    const abs = absFor(path);
    if (existsSync(abs)) rmSync(abs);
    return;
  }
  await query(`DELETE FROM datasets WHERE tenant_id = $1 AND path = $2`, [
    tenantId,
    path,
  ]);
}
