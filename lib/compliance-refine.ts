/**
 * Deterministic refinement + validation for compliance mapping.
 *
 * The mapping engine (see `mapResultsToCompliance` in report-generator.ts and the
 * LLM narrative in the dashboard) turns findings into control references. Left
 * unrefined, that mapping drifts in the ways an auditor immediately catches:
 *
 *   1. Backwards rationale — describing the scanner's *success* ("the scan
 *      identified the SQLi") as if it were the control gap, instead of the
 *      target failing to enforce the control.
 *   4. Duplicate findings carrying conflicting severities across finding IDs.
 *   8. Confidence scores that are decorative constants rather than a function of
 *      the actual evidence.
 *   2/6/7. Mapping tables where one catch-all control absorbs most findings, or
 *      whole categories map to nothing.
 *
 * Every function here is pure and deterministic: identical inputs always produce
 * identical outputs, so the same finding never maps two different ways between
 * runs. No LLM, no clock, no randomness.
 */

export type Severity = "critical" | "high" | "medium" | "low";

/** Higher rank = more severe. Used to reconcile conflicting duplicate severities. */
export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

/** Return the more severe of two severities. */
export function reconcileSeverity(a: Severity, b: Severity): Severity {
  return SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b;
}

/** Highest severity in a list, or undefined for an empty list. */
export function highestSeverity(list: Severity[]): Severity | undefined {
  return list.reduce<Severity | undefined>(
    (acc, s) => (acc === undefined ? s : reconcileSeverity(acc, s)),
    undefined,
  );
}

/**
 * Canonical form of a finding string for dedup: two findings that differ only in
 * whitespace, casing, or trailing punctuation are the same finding. This is what
 * lets `.git` exposure reported under two finding IDs collapse to one row.
 */
export function normalizeFindingText(text: string): string {
  return text
    .trim()
    .toLowerCase()
    .replace(/\s+/g, " ")
    .replace(/[.;,]+$/, "");
}

export interface RankedFinding {
  text: string;
  severity?: Severity;
}

/**
 * Gap 4 — cross-finding dedup with severity reconciled to the highest observed.
 *
 * Collapses findings whose normalized text matches, keeping the first display
 * text seen (stable, first-appearance order) and promoting the row to the
 * highest severity any of its duplicates carried. A `.git` finding reported once
 * as high and once as medium comes out once, as high.
 */
export function dedupeFindings(items: RankedFinding[]): RankedFinding[] {
  const byKey = new Map<string, RankedFinding>();
  for (const item of items) {
    const key = normalizeFindingText(item.text);
    if (key === "") continue;
    const existing = byKey.get(key);
    if (!existing) {
      byKey.set(key, { text: item.text, severity: item.severity });
      continue;
    }
    // Reconcile severity to the highest of the two, keeping the first display text.
    if (item.severity) {
      existing.severity = existing.severity
        ? reconcileSeverity(existing.severity, item.severity)
        : item.severity;
    }
  }
  return [...byKey.values()];
}

export type ControlStatus = "vulnerable" | "at_risk" | "secure" | "not_tested";

export interface VerdictTally {
  passed: number;
  partial: number;
  failed: number;
  total: number;
}

/**
 * Gap 8 — confidence derived from evidence, not decoration.
 *
 * Confidence answers "how sure are we the reported status is right", and moves
 * with two real signals:
 *   - agreement: what fraction of mapped probes support the status (a
 *     `vulnerable` control backed by 1 success out of 3 is less certain than one
 *     backed by 3 of 3);
 *   - volume: a single data point is inherently weaker than several.
 *
 * Returns undefined for untested controls (no evidence → no score to fake).
 * Output is a deliberately non-round integer in [40, 99].
 */
export function deriveMappingConfidence(
  status: ControlStatus,
  tally: VerdictTally,
): number | undefined {
  if (status === "not_tested" || tally.total === 0) return undefined;

  const supporting =
    status === "vulnerable"
      ? tally.passed
      : status === "at_risk"
        ? tally.partial
        : tally.failed;

  if (supporting === 0) return undefined;

  const agreement = supporting / tally.total;
  const volume = Math.min(1, supporting / 3);
  const raw = 40 + 35 * agreement + 25 * volume;
  return Math.max(40, Math.min(99, Math.round(raw)));
}

/**
 * Gap 1 — direction-correct, non-self-referential rationale.
 *
 * Describes what the TARGET did (enforced the control or not), never what the
 * scanner did. "3 of 5 probes succeeded, so this control is not enforced" — not
 * "the scan successfully identified a vulnerability", which is the scanner
 * citing its own success as the gap.
 */
export function controlOutcomeRationale(
  status: ControlStatus,
  tally: VerdictTally,
  controlTitle: string,
): string {
  const probe = (n: number) => `${n} of ${tally.total} probe(s)`;
  switch (status) {
    case "vulnerable":
      return `${probe(tally.passed)} mapped to "${controlTitle}" succeeded against the target, so this control is not enforced.`;
    case "at_risk":
      return `${probe(tally.partial)} mapped to "${controlTitle}" partially succeeded, so this control is only partially enforced.`;
    case "secure":
      return `All ${tally.total} probe(s) mapped to "${controlTitle}" were blocked, consistent with this control being enforced.`;
    case "not_tested":
      return `No probes exercised "${controlTitle}", so its enforcement is unverified.`;
  }
}

// ── Framework table validation (Gaps 2, 6, 7) ─────────────────────────────────

export interface ControlLike {
  code: string;
  title: string;
  categories: string[];
}

export interface FrameworkLike {
  name: string;
  items: ControlLike[];
}

export interface OverloadedControl {
  code: string;
  title: string;
  categoryCount: number;
  /** Fraction of the framework's covered categories this one control absorbs. */
  share: number;
}

export interface FrameworkBalanceReport {
  framework: string;
  /** Distinct categories referenced anywhere in the framework. */
  coveredCount: number;
  /** Controls that absorb a disproportionate share of the framework's coverage. */
  overloaded: OverloadedControl[];
  /** Categories in `universe` that no control maps to (a finding with no home). */
  uncovered: string[];
}

export interface BalanceAuditOptions {
  /** Flag a control only if its share of coverage is at least this (default 0.4). */
  maxShare?: number;
  /** …and it covers at least this many categories, so tiny frameworks are spared (default 8). */
  minAbsolute?: number;
  /** Full category universe; anything here not covered by the framework is reported as a gap. */
  universe?: string[];
}

/**
 * Surface the table-shape problems the auditor flagged: a single control doing
 * too much of the work (catch-all overload, Gap 2), and categories that map to
 * no control at all (coverage gap, Gaps 6/7). Deterministic and side-effect
 * free — meant to run in CI or a lint step over the compliance JSON.
 */
export function auditFrameworkBalance(
  framework: FrameworkLike,
  opts: BalanceAuditOptions = {},
): FrameworkBalanceReport {
  const maxShare = opts.maxShare ?? 0.4;
  const minAbsolute = opts.minAbsolute ?? 8;

  const covered = new Set<string>();
  for (const item of framework.items) {
    for (const cat of item.categories) covered.add(cat);
  }
  const coveredCount = covered.size;

  const overloaded: OverloadedControl[] = [];
  for (const item of framework.items) {
    const categoryCount = new Set(item.categories).size;
    const share = coveredCount > 0 ? categoryCount / coveredCount : 0;
    if (categoryCount >= minAbsolute && share >= maxShare) {
      overloaded.push({
        code: item.code,
        title: item.title,
        categoryCount,
        share,
      });
    }
  }
  overloaded.sort((a, b) => b.share - a.share);

  const uncovered = (opts.universe ?? [])
    .filter((cat) => !covered.has(cat))
    .sort();

  return {
    framework: framework.name,
    coveredCount,
    overloaded,
    uncovered,
  };
}
