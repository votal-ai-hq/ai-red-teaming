/**
 * Quality-eval report storage — Postgres (encrypted) when DATABASE_URL is set,
 * a JSON file under report/quality otherwise. Mirrors the guardrail/report
 * stores. The full report is encrypted per-tenant in the DB (it contains the
 * target's responses); plaintext summary columns support listing + trends.
 */
import { join } from "node:path";
import {
  readFileSync,
  writeFileSync,
  mkdirSync,
  existsSync,
  readdirSync,
} from "node:fs";
import { query, isDbConfigured } from "./db.js";
import { encryptWithTenantKey, decryptWithTenantKey } from "./encryption.js";
import type { QualityReport } from "./quality/types.js";

function reportDir(): string {
  return join(import.meta.dirname, "..", "report", "quality");
}

export interface QualityReportMeta {
  id: string;
  filename: string;
  timestamp: string;
  dataset: string;
  targetUrl: string;
  score: number; // 0..100
  passed: number;
  total: number;
  errors: number;
  threshold: number;
}

function summaryOf(report: QualityReport) {
  return {
    dataset: report.dataset ?? "",
    targetUrl: report.targetUrl ?? "",
    score: report.summary.score,
    passed: report.summary.passed,
    total: report.summary.total,
    errors: report.summary.errors,
    threshold: report.passThreshold,
    timestamp: report.timestamp,
  };
}

function filenameFor(report: QualityReport): string {
  return `quality-${report.timestamp.replace(/[:.]/g, "-")}.json`;
}

/** Persist a quality report. Returns its filename (the stable id in file mode). */
export async function storeQualityReport(
  report: QualityReport,
  tenantId: string,
): Promise<{ filename: string }> {
  const filename = filenameFor(report);

  if (!isDbConfigured()) {
    const dir = reportDir();
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, filename), JSON.stringify(report, null, 2) + "\n", "utf-8");
    return { filename };
  }

  const tenantResult = await query<{ encryption_key_enc: string }>(
    "SELECT encryption_key_enc FROM tenants WHERE id = $1",
    [tenantId],
  );
  if (tenantResult.rows.length === 0) {
    throw new Error(`Tenant not found: ${tenantId}`);
  }
  const tenantKeyEnc = tenantResult.rows[0].encryption_key_enc;
  const { ciphertext, iv, authTag } = encryptWithTenantKey(
    JSON.stringify(report),
    tenantKeyEnc,
  );
  const s = summaryOf(report);
  await query(
    `INSERT INTO quality_reports (
       tenant_id, filename, report_enc, iv, auth_tag,
       dataset, target_url, score, passed, total, errors, threshold, report_ts
     ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
     ON CONFLICT (tenant_id, filename) DO UPDATE SET
       report_enc = EXCLUDED.report_enc, iv = EXCLUDED.iv, auth_tag = EXCLUDED.auth_tag,
       dataset = EXCLUDED.dataset, target_url = EXCLUDED.target_url,
       score = EXCLUDED.score, passed = EXCLUDED.passed, total = EXCLUDED.total,
       errors = EXCLUDED.errors, threshold = EXCLUDED.threshold, report_ts = EXCLUDED.report_ts`,
    [
      tenantId,
      filename,
      ciphertext,
      iv,
      authTag,
      s.dataset,
      s.targetUrl,
      s.score,
      s.passed,
      s.total,
      s.errors,
      s.threshold,
      s.timestamp,
    ],
  );
  return { filename };
}

/** List quality reports for a tenant (summary only), newest first. */
export async function listQualityReports(
  tenantId: string,
): Promise<QualityReportMeta[]> {
  if (!isDbConfigured()) {
    const dir = reportDir();
    if (!existsSync(dir)) return [];
    const metas: QualityReportMeta[] = [];
    for (const f of readdirSync(dir)) {
      if (!f.endsWith(".json")) continue;
      try {
        const report = JSON.parse(
          readFileSync(join(dir, f), "utf-8"),
        ) as QualityReport;
        const s = summaryOf(report);
        metas.push({ id: f, filename: f, ...s });
      } catch {
        /* skip unreadable */
      }
    }
    return metas.sort((a, b) => b.timestamp.localeCompare(a.timestamp));
  }

  const res = await query<{
    id: string;
    filename: string;
    report_ts: string;
    dataset: string;
    target_url: string;
    score: number;
    passed: number;
    total: number;
    errors: number;
    threshold: number;
  }>(
    `SELECT id, filename, report_ts, dataset, target_url,
            score, passed, total, errors, threshold
       FROM quality_reports WHERE tenant_id = $1 ORDER BY report_ts DESC`,
    [tenantId],
  );
  return res.rows.map((r) => ({
    id: r.id,
    filename: r.filename,
    timestamp: r.report_ts,
    dataset: r.dataset ?? "",
    targetUrl: r.target_url ?? "",
    score: r.score,
    passed: r.passed,
    total: r.total,
    errors: r.errors,
    threshold: r.threshold,
  }));
}

/** Fetch one full quality report (decrypted) by filename, or null. */
export async function getQualityReport(
  filename: string,
  tenantId: string,
): Promise<QualityReport | null> {
  if (!isDbConfigured()) {
    const abs = join(reportDir(), filename);
    if (!existsSync(abs)) return null;
    try {
      return JSON.parse(readFileSync(abs, "utf-8")) as QualityReport;
    } catch {
      return null;
    }
  }
  const res = await query<{ report_enc: Buffer; iv: Buffer; auth_tag: Buffer }>(
    `SELECT report_enc, iv, auth_tag FROM quality_reports
      WHERE tenant_id = $1 AND filename = $2`,
    [tenantId, filename],
  );
  if (res.rows.length === 0) return null;
  const tenantResult = await query<{ encryption_key_enc: string }>(
    "SELECT encryption_key_enc FROM tenants WHERE id = $1",
    [tenantId],
  );
  if (tenantResult.rows.length === 0) return null;
  const json = decryptWithTenantKey(
    res.rows[0].report_enc,
    res.rows[0].iv,
    res.rows[0].auth_tag,
    tenantResult.rows[0].encryption_key_enc,
  );
  return JSON.parse(json) as QualityReport;
}
