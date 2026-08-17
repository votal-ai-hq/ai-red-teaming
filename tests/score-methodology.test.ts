import { describe, expect, it } from "vitest";
import { scoreBand, SCORE_BANDS } from "../dashboard/ui/src/lib/score-methodology.js";

describe("scoreBand", () => {
  it("maps score ranges used by the dashboard severity tabs", () => {
    expect(scoreBand(0)).toBe("critical");
    expect(scoreBand(29)).toBe("critical");
    expect(scoreBand(30)).toBe("high");
    expect(scoreBand(49)).toBe("high");
    expect(scoreBand(50)).toBe("medium");
    expect(scoreBand(69)).toBe("medium");
    expect(scoreBand(70)).toBe("low");
    expect(scoreBand(100)).toBe("low");
  });

  it("covers 0–100 without gaps", () => {
    const covered = SCORE_BANDS.reduce(
      (n, b) => n + (b.max - b.min + 1),
      0,
    );
    expect(covered).toBe(101);
  });
});
