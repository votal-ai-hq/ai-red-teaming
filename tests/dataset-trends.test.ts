import { describe, it, expect } from "vitest";
import { groupEvalRuns, type ReportLike } from "../lib/dataset/eval-trends.js";

function r(
  filename: string,
  timestamp: string,
  score: number,
  file?: string,
  only = false,
): ReportLike {
  return {
    filename,
    timestamp,
    score,
    targetUrl: "t",
    dataset: file ? { file, only } : undefined,
  };
}

describe("groupEvalRuns", () => {
  it("groups by dataset, orders oldest->newest, computes deltas", () => {
    const trends = groupEvalRuns([
      r("c.json", "2026-03-03", 80, "data/datasets/nemo-mcp/v1.json"),
      r("a.json", "2026-03-01", 70, "data/datasets/nemo-mcp/v1.json"),
      r("b.json", "2026-03-02", 75, "data/datasets/nemo-mcp/v1.json"),
    ]);
    expect(trends).toHaveLength(1);
    const t = trends[0];
    expect(t.runs.map((x) => x.score)).toEqual([70, 75, 80]);
    expect(t.runs.map((x) => x.delta)).toEqual([undefined, 5, 5]);
    expect(t.latestScore).toBe(80);
    expect(t.totalDelta).toBe(10);
    expect(t.minScore).toBe(70);
    expect(t.maxScore).toBe(80);
  });

  it("drops reports without dataset provenance", () => {
    const trends = groupEvalRuns([
      r("x.json", "2026-03-01", 90),
      r("y.json", "2026-03-02", 60, "data/datasets/nemo-agent/v1.json"),
    ]);
    expect(trends).toHaveLength(1);
    expect(trends[0].dataset).toBe("data/datasets/nemo-agent/v1.json");
  });

  it("orders groups by most-recent activity first", () => {
    const trends = groupEvalRuns([
      r("old.json", "2026-01-01", 50, "data/datasets/old.json"),
      r("new.json", "2026-06-01", 88, "data/datasets/new.json"),
    ]);
    expect(trends.map((t) => t.dataset)).toEqual([
      "data/datasets/new.json",
      "data/datasets/old.json",
    ]);
  });

  it("single-run group has zero totalDelta and undefined per-run delta", () => {
    const trends = groupEvalRuns([
      r("a.json", "2026-03-01", 65, "data/datasets/x.json"),
    ]);
    expect(trends[0].totalDelta).toBe(0);
    expect(trends[0].runs[0].delta).toBeUndefined();
  });
});
