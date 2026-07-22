import { describe, it, expect, afterEach } from "vitest";
import { rmSync, existsSync } from "node:fs";
import { join } from "node:path";
import {
  storeQualityReport,
  listQualityReports,
  getQualityReport,
} from "../lib/quality-report-store.js";
import { isDbConfigured } from "../lib/db.js";
import type { QualityReport } from "../lib/quality/types.js";

function makeReport(ts: string, dataset: string, score: number): QualityReport {
  return {
    timestamp: ts,
    targetUrl: "http://localhost:9/agent",
    dataset,
    passThreshold: 0.7,
    summary: {
      total: 2,
      scored: 2,
      errors: 0,
      score,
      passed: score >= 50 ? 2 : 1,
      byMetric: { exact_match: { count: 2, mean: score / 100, passed: 2 } },
      byTask: { rag_answer: { count: 2, mean: score / 100, passed: 2 } },
    },
    results: [
      {
        row: { task: "rag_answer", name: "e1", input: "hi", metric: "exact_match" },
        score: 1,
        pass: true,
        metric: "exact_match",
        scorer: "deterministic",
        response: "hi",
        statusCode: 200,
        responseTimeMs: 1,
      },
    ],
  } as unknown as QualityReport;
}

// File-mode store (skipped if a DB is configured — never touch a real DB here).
describe.skipIf(isDbConfigured())("quality-report-store (file mode)", () => {
  const TENANT = "unused-in-file-mode";
  const dir = join(import.meta.dirname, "..", "report", "quality");

  afterEach(() => {
    if (existsSync(dir)) rmSync(dir, { recursive: true, force: true });
  });

  it("store → list → get round-trips on disk, newest first", async () => {
    const { filename: f1 } = await storeQualityReport(
      makeReport("2026-07-01T10:00:00.000Z", "data/datasets/quality-agent/v1.json", 80),
      TENANT,
    );
    await storeQualityReport(
      makeReport("2026-07-02T10:00:00.000Z", "data/datasets/quality-agent/v1.json", 90),
      TENANT,
    );

    const list = await listQualityReports(TENANT);
    expect(list).toHaveLength(2);
    // newest first
    expect(list[0].timestamp).toBe("2026-07-02T10:00:00.000Z");
    expect(list[0].score).toBe(90);
    expect(list[0].dataset).toContain("v1.json");

    const full = await getQualityReport(f1, TENANT);
    expect(full).not.toBeNull();
    expect(full!.summary.score).toBe(80);
    expect(full!.results).toHaveLength(1);
  });

  it("getQualityReport returns null for a missing file", async () => {
    expect(await getQualityReport("quality-nope.json", TENANT)).toBeNull();
  });
});
