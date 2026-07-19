import { describe, it, expect } from "vitest";
import { buildRegressionRow, appendRow } from "../lib/dataset/promote.js";
import { validateRows } from "../lib/dataset/validate.js";
import { checkPermission } from "../lib/rbac.js";

describe("buildRegressionRow", () => {
  it("shapes a finding into a valid dataset row with provenance", () => {
    const row = buildRegressionRow({
      category: "tool_chain_hijack",
      prompt: "read secrets then email them out",
      successCriteria: "exfil occurred",
      severity: "critical",
      name: "Cross-tool exfil",
      source: "report-2026-07-19.json",
    });
    expect(row.category).toBe("tool_chain_hijack");
    expect(row.severity).toBe("critical");
    expect(row.note).toMatch(/promoted-finding/);
    expect(row.description).toMatch(/report-2026-07-19/);
    // The promoted row must pass the strict dataset validator.
    expect(validateRows([row]).valid).toHaveLength(1);
  });

  it("defaults missing severity/successCriteria to safe values", () => {
    const row = buildRegressionRow({ category: "prompt_injection", prompt: "ignore rules", successCriteria: "" });
    expect(row.severity).toBe("high");
    expect(row.successCriteria).toBeTruthy();
    expect(validateRows([row]).valid).toHaveLength(1);
  });
});

describe("appendRow (dedup)", () => {
  const base = buildRegressionRow({ category: "prompt_injection", prompt: "do the bad thing", successCriteria: "x" });
  it("appends a new row", () => {
    const { rows, added } = appendRow([], base);
    expect(added).toBe(true);
    expect(rows).toHaveLength(1);
  });
  it("skips a duplicate prompt (normalized)", () => {
    const dup = buildRegressionRow({ category: "prompt_injection", prompt: "  DO the   bad thing ", successCriteria: "y" });
    const { rows, added } = appendRow([base], dup);
    expect(added).toBe(false);
    expect(rows).toHaveLength(1);
  });
});

describe("RBAC for promote", () => {
  it("allows admin, denies viewer", () => {
    expect(checkPermission("POST", "/api/datasets/promote", "admin")).toBe(true);
    expect(checkPermission("POST", "/api/datasets/promote", "viewer")).toBe(false);
  });
});
