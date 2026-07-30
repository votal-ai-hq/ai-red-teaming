import { describe, expect, it } from "vitest";
import {
  evaluationExportBaseName,
  evaluationReportCsv,
  evaluationReportJson,
} from "../dashboard/ui/src/lib/evaluation-export.js";
import type { QualityEvalReport } from "../dashboard/ui/src/api/datasets.js";

const report: QualityEvalReport = {
  timestamp: "2026-07-30T05:12:18.632Z",
  targetUrl: "https://example.test/mcp",
  dataset: "data/datasets/quality-mcp/v1-20260730-044927.json",
  passThreshold: 0.7,
  summary: {
    total: 1,
    scored: 1,
    errors: 0,
    score: 100,
    passed: 1,
    byMetric: {},
    byTask: {},
  },
  results: [
    {
      row: {
        task: "tool_call_accuracy",
        name: "booking lookup",
        input: 'Find the booking for "Jane, Doe"',
        reference: "Use lookup_booking",
        expectedTools: ["lookup_booking"],
      },
      score: 1,
      pass: true,
      metric: "tool_call_accuracy",
      scorer: "deterministic",
      response: 'Found "Jane, Doe"',
      actualTools: ["lookup_booking"],
      statusCode: 200,
      responseTimeMs: 42,
    },
  ],
};

describe("evaluation export", () => {
  it("exports the complete report as formatted JSON", () => {
    expect(JSON.parse(evaluationReportJson(report))).toEqual(report);
  });

  it("exports trace rows as quoted CSV without losing commas or quotes", () => {
    const csv = evaluationReportCsv(report);
    expect(csv).toContain('"record","timestamp","dataset"');
    expect(csv).toContain('"Find the booking for ""Jane, Doe"""');
    expect(csv).toContain('"[""lookup_booking""]"');
  });

  it("creates a safe download filename", () => {
    expect(evaluationExportBaseName("quality run 01.json")).toBe("quality-run-01");
  });
});
