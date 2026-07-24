import { describe, it, expect } from "vitest";
import {
  reconcileSeverity,
  highestSeverity,
  normalizeFindingText,
  dedupeFindings,
  deriveMappingConfidence,
  controlOutcomeRationale,
  auditFrameworkBalance,
  SEVERITY_RANK,
  type Severity,
} from "../lib/compliance-refine.js";

describe("reconcileSeverity", () => {
  it("returns the more severe of two", () => {
    expect(reconcileSeverity("high", "medium")).toBe("high");
    expect(reconcileSeverity("medium", "high")).toBe("high");
    expect(reconcileSeverity("critical", "low")).toBe("critical");
    expect(reconcileSeverity("low", "low")).toBe("low");
  });

  it("ranks critical > high > medium > low", () => {
    expect(SEVERITY_RANK.critical).toBeGreaterThan(SEVERITY_RANK.high);
    expect(SEVERITY_RANK.high).toBeGreaterThan(SEVERITY_RANK.medium);
    expect(SEVERITY_RANK.medium).toBeGreaterThan(SEVERITY_RANK.low);
  });
});

describe("highestSeverity", () => {
  it("finds the worst in a list", () => {
    expect(highestSeverity(["low", "critical", "medium"])).toBe("critical");
    expect(highestSeverity(["low", "medium"])).toBe("medium");
  });

  it("returns undefined for an empty list", () => {
    expect(highestSeverity([])).toBeUndefined();
  });
});

describe("normalizeFindingText", () => {
  it("collapses whitespace, casing, and trailing punctuation", () => {
    expect(normalizeFindingText("  .git  directory   Exposed.  ")).toBe(
      ".git directory exposed",
    );
  });

  it("treats formatting-only variants as equal", () => {
    expect(normalizeFindingText("Sensitive file exposed")).toBe(
      normalizeFindingText("sensitive file exposed;"),
    );
  });
});

describe("dedupeFindings (Gap 4)", () => {
  it("collapses duplicate findings to the highest observed severity", () => {
    const out = dedupeFindings([
      { text: ".git directory exposed", severity: "high" },
      { text: ".git directory exposed", severity: "medium" },
    ]);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("high");
    expect(out[0].text).toBe(".git directory exposed");
  });

  it("reconciles regardless of which duplicate is more severe first", () => {
    const out = dedupeFindings([
      { text: "Backup file exposed", severity: "medium" },
      { text: "Backup file exposed", severity: "high" },
    ]);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("high");
  });

  it("keeps the first display text but dedupes on normalized form", () => {
    const out = dedupeFindings([
      { text: "Sensitive file exposed", severity: "high" },
      { text: "sensitive file exposed.", severity: "critical" },
    ]);
    expect(out).toHaveLength(1);
    expect(out[0].text).toBe("Sensitive file exposed");
    expect(out[0].severity).toBe("critical");
  });

  it("preserves distinct findings and first-appearance order", () => {
    const out = dedupeFindings([
      { text: "B finding", severity: "low" },
      { text: "A finding", severity: "high" },
      { text: "B finding", severity: "critical" },
    ]);
    expect(out.map((f) => f.text)).toEqual(["B finding", "A finding"]);
    expect(out[0].severity).toBe("critical");
  });

  it("drops empty findings and carries severity from any duplicate", () => {
    const out = dedupeFindings([
      { text: "   " },
      { text: "Real finding" },
      { text: "Real finding", severity: "medium" },
    ]);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("medium");
  });

  it("is deterministic — identical input yields identical output", () => {
    const input = [
      { text: "X", severity: "high" as Severity },
      { text: "X", severity: "low" as Severity },
    ];
    expect(dedupeFindings(input)).toEqual(dedupeFindings(input));
  });
});

describe("deriveMappingConfidence (Gap 8)", () => {
  it("returns undefined for untested controls", () => {
    expect(
      deriveMappingConfidence("not_tested", {
        passed: 0,
        partial: 0,
        failed: 0,
        total: 0,
      }),
    ).toBeUndefined();
  });

  it("is highest when all evidence agrees and volume is high", () => {
    const c = deriveMappingConfidence("vulnerable", {
      passed: 5,
      partial: 0,
      failed: 0,
      total: 5,
    });
    expect(c).toBe(99);
  });

  it("is lower for a single ambiguous data point than for consistent evidence", () => {
    const weak = deriveMappingConfidence("vulnerable", {
      passed: 1,
      partial: 0,
      failed: 2,
      total: 3,
    })!;
    const strong = deriveMappingConfidence("vulnerable", {
      passed: 3,
      partial: 0,
      failed: 0,
      total: 3,
    })!;
    expect(weak).toBeLessThan(strong);
  });

  it("produces non-decorative, varying values (not all round numbers)", () => {
    const values = [
      deriveMappingConfidence("vulnerable", {
        passed: 1,
        partial: 0,
        failed: 2,
        total: 3,
      }),
      deriveMappingConfidence("vulnerable", {
        passed: 1,
        partial: 0,
        failed: 0,
        total: 1,
      }),
      deriveMappingConfidence("at_risk", {
        passed: 0,
        partial: 2,
        failed: 3,
        total: 5,
      }),
    ];
    // At least one value is not a multiple of 5 — i.e. not decorative.
    expect(values.some((v) => v !== undefined && v % 5 !== 0)).toBe(true);
  });

  it("stays within [40, 99]", () => {
    for (let p = 1; p <= 10; p++) {
      const c = deriveMappingConfidence("vulnerable", {
        passed: p,
        partial: 0,
        failed: 10 - p,
        total: 10,
      });
      expect(c).toBeGreaterThanOrEqual(40);
      expect(c).toBeLessThanOrEqual(99);
    }
  });

  it("scores the 'secure' assessment from defended attacks", () => {
    const c = deriveMappingConfidence("secure", {
      passed: 0,
      partial: 0,
      failed: 4,
      total: 4,
    });
    expect(c).toBe(99);
  });
});

describe("controlOutcomeRationale (Gap 1)", () => {
  const tally = { passed: 3, partial: 1, failed: 1, total: 5 };

  it("describes the target failing to enforce, not the scanner succeeding", () => {
    const r = controlOutcomeRationale("vulnerable", tally, "Access Enforcement");
    expect(r).toContain("not enforced");
    expect(r.toLowerCase()).not.toContain("scan successfully");
    expect(r.toLowerCase()).not.toContain("identified");
  });

  it("phrases secure as the control being enforced", () => {
    const r = controlOutcomeRationale(
      "secure",
      { passed: 0, partial: 0, failed: 5, total: 5 },
      "Access Enforcement",
    );
    expect(r).toContain("blocked");
    expect(r).toContain("enforced");
  });

  it("marks not_tested as unverified", () => {
    const r = controlOutcomeRationale(
      "not_tested",
      { passed: 0, partial: 0, failed: 0, total: 0 },
      "Audit Logging",
    );
    expect(r).toContain("unverified");
  });

  it("never reads as circular self-reference for any status", () => {
    for (const status of ["vulnerable", "at_risk", "secure"] as const) {
      const r = controlOutcomeRationale(status, tally, "Some Control");
      expect(r.toLowerCase()).not.toMatch(
        /the scan (successfully )?(identified|confirmed|found)/,
      );
    }
  });
});

describe("auditFrameworkBalance (Gaps 2/6/7)", () => {
  it("flags a catch-all control that absorbs a disproportionate share", () => {
    const framework = {
      name: "Test FW",
      items: [
        {
          code: "MISC",
          title: "Security Misconfiguration",
          categories: [
            "a",
            "b",
            "c",
            "d",
            "e",
            "f",
            "g",
            "h",
            "i",
            "j",
          ],
        },
        { code: "AUTH", title: "Auth", categories: ["k", "l"] },
      ],
    };
    const report = auditFrameworkBalance(framework);
    expect(report.overloaded).toHaveLength(1);
    expect(report.overloaded[0].code).toBe("MISC");
    expect(report.overloaded[0].share).toBeGreaterThan(0.4);
  });

  it("does not flag a balanced framework", () => {
    const framework = {
      name: "Balanced",
      items: [
        { code: "A", title: "A", categories: ["1", "2", "3"] },
        { code: "B", title: "B", categories: ["4", "5", "6"] },
        { code: "C", title: "C", categories: ["7", "8", "9"] },
      ],
    };
    expect(auditFrameworkBalance(framework).overloaded).toHaveLength(0);
  });

  it("spares small frameworks below the absolute threshold", () => {
    const framework = {
      name: "Small",
      items: [
        { code: "A", title: "A", categories: ["1", "2", "3"] },
        { code: "B", title: "B", categories: ["4"] },
      ],
    };
    // A covers 3 of 4 categories (75% share) but only 3 absolute — under minAbsolute.
    expect(auditFrameworkBalance(framework).overloaded).toHaveLength(0);
  });

  it("reports categories in the universe that map to no control", () => {
    const framework = {
      name: "Gapped",
      items: [{ code: "A", title: "A", categories: ["mapped_cat"] }],
    };
    const report = auditFrameworkBalance(framework, {
      universe: ["mapped_cat", "orphan_cat", "another_orphan"],
    });
    expect(report.uncovered).toEqual(["another_orphan", "orphan_cat"]);
  });

  it("is deterministic", () => {
    const framework = {
      name: "FW",
      items: [
        { code: "A", title: "A", categories: ["1", "2"] },
        { code: "B", title: "B", categories: ["3", "4"] },
      ],
    };
    expect(auditFrameworkBalance(framework)).toEqual(
      auditFrameworkBalance(framework),
    );
  });
});
