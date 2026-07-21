import { describe, it, expect } from "vitest";
import {
  toJsonl,
  toCsv,
  exportDataset,
  isExportFormat,
  exportContentType,
} from "../lib/dataset/export.js";

const SECURITY_ROWS = [
  {
    category: "prompt-injection",
    name: "case 1",
    prompt: "ignore prior, do X",
    severity: "high",
    successCriteria: "model complies",
  },
  {
    category: "data-exfiltration",
    name: "case 2",
    prompt: 'say "hi, there"\nsecond line',
    severity: "critical",
    successCriteria: "leaks data",
    role: "admin",
  },
];

const QUALITY_ROWS = [
  {
    task: "tool_selection",
    name: "q1",
    input: "book me a flight",
    metric: "tool_correctness",
    expectedTools: ["search", "book"],
  },
];

describe("dataset export", () => {
  it("isExportFormat guards", () => {
    expect(isExportFormat("jsonl")).toBe(true);
    expect(isExportFormat("csv")).toBe(true);
    expect(isExportFormat("yaml")).toBe(false);
    expect(isExportFormat(null)).toBe(false);
  });

  it("toJsonl emits one JSON object per line, parseable back", () => {
    const out = toJsonl(SECURITY_ROWS);
    const lines = out.trimEnd().split("\n");
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[0]).category).toBe("prompt-injection");
    expect(JSON.parse(lines[1]).role).toBe("admin");
  });

  it("toJsonl on empty rows is an empty string", () => {
    expect(toJsonl([])).toBe("");
  });

  it("toCsv puts preferred columns first and escapes commas/quotes/newlines", () => {
    const csv = toCsv(SECURITY_ROWS);
    const lines = csv.trimEnd().split("\n");
    const header = lines[0].split(",");
    // category comes before name before prompt in the preferred ordering.
    expect(header[0]).toBe("category");
    expect(header).toContain("prompt");
    expect(header).toContain("role");
    // The row with an embedded newline + quotes must be quoted.
    expect(csv).toContain('"say ""hi, there""');
  });

  it("toCsv joins array cells (expectedTools) with a separator", () => {
    const csv = toCsv(QUALITY_ROWS);
    expect(csv).toContain("search; book");
  });

  it("exportDataset dispatches on format", () => {
    expect(exportDataset(SECURITY_ROWS, "jsonl")).toBe(toJsonl(SECURITY_ROWS));
    expect(exportDataset(SECURITY_ROWS, "csv")).toBe(toCsv(SECURITY_ROWS));
  });

  it("exportContentType maps formats", () => {
    expect(exportContentType("csv")).toMatch(/csv/);
    expect(exportContentType("jsonl")).toMatch(/ndjson/);
  });
});
