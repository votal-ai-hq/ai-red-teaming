import { Shield, CheckCircle } from "lucide-react";
import type { CategoryComplianceRef, ReferenceFramework } from "@/api/types";

/** Compact label for a (long) compliance framework name — drops the trailing
 *  "(Regulation …)" and long subtitles so preset chips stay tidy. */
export function shortFramework(name: string): string {
  const base = name.split(/[(—-]| - /)[0].trim();
  return base.length > 34 ? base.slice(0, 33) + "…" : base;
}

/**
 * Compliance-framework presets over an attack-category picker.
 *
 * Frameworks map to CATEGORIES (what to test), never to tactics (how to deliver),
 * so selecting a framework simply ADDS the union of categories its controls map
 * to — additive, because one category can serve many frameworks. Below the
 * presets we show the forward view: how many of each framework's controls the
 * current selection will actually exercise.
 *
 * Powered entirely by the `categoryCompliance` reverse index from /api/reference,
 * so it needs no extra data beyond what the picker already loads.
 */
export function CompliancePresets({
  frameworks,
  categoryCompliance,
  selectableCategories,
  selected,
  onAdd,
  className = "",
}: {
  frameworks: ReferenceFramework[];
  categoryCompliance: Record<string, CategoryComplianceRef[]>;
  /** Categories the user can actually pick (e.g. scoped to MCP or a taxonomy). */
  selectableCategories: string[];
  /** Currently-selected categories. */
  selected: string[];
  /** Add these categories to the selection (additive, dedup handled by caller). */
  onAdd: (categories: string[]) => void;
  className?: string;
}) {
  if (!frameworks.length) return null;

  // framework → its mapped categories, and → its controls (code → categories).
  const fwCats: Record<string, Set<string>> = {};
  const fwControls: Record<string, Record<string, Set<string>>> = {};
  const selectable = new Set(selectableCategories);
  for (const [cat, refs] of Object.entries(categoryCompliance)) {
    if (!selectable.has(cat)) continue;
    for (const cr of refs) {
      (fwCats[cr.framework] ??= new Set()).add(cat);
      ((fwControls[cr.framework] ??= {})[cr.code] ??= new Set()).add(cat);
    }
  }

  const selectedSet = new Set(selected);
  const categoriesFor = (fwName: string) => [...(fwCats[fwName] ?? [])];
  const coveredControls = (fwName: string) =>
    Object.values(fwControls[fwName] ?? {}).filter((cats) =>
      [...cats].some((c) => selectedSet.has(c)),
    ).length;

  // Only frameworks that have at least one selectable category are actionable.
  const actionable = frameworks.filter((fw) => (fwCats[fw.name]?.size ?? 0) > 0);
  if (actionable.length === 0) return null;

  const coverageRows = actionable
    .map((fw) => ({ fw, covered: coveredControls(fw.name) }))
    .filter((r) => r.covered > 0);

  return (
    <div
      className={`rounded-lg border border-dashed border-border p-3 space-y-2.5 ${className}`}
    >
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <span className="text-xs font-medium text-foreground flex items-center gap-1.5">
          <Shield className="w-3.5 h-3.5 text-primary" />
          Target a compliance framework
        </span>
        <span className="text-[11px] text-muted-foreground">
          adds the attack categories its controls map to
        </span>
      </div>

      <div className="flex flex-wrap gap-1.5">
        {actionable.map((fw) => {
          const cats = categoriesFor(fw.name);
          const allSel = cats.every((c) => selectedSet.has(c));
          return (
            <button
              key={fw.id}
              type="button"
              title={`${fw.name} — ${cats.length} categories across ${fw.controlCount} controls`}
              onClick={() => onAdd(cats)}
              className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-[11px] font-medium border transition-all ${
                allSel
                  ? "bg-primary/10 border-primary/40 text-foreground"
                  : "bg-card text-muted-foreground border-border hover:border-muted-foreground/30 hover:text-foreground"
              }`}
            >
              {allSel && <CheckCircle className="w-3 h-3 text-primary" />}
              {shortFramework(fw.name)}
              <span className="text-muted-foreground">+{cats.length}</span>
            </button>
          );
        })}
      </div>

      {coverageRows.length > 0 && (
        <div className="pt-1 border-t border-border/60">
          <p className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground/70 mb-1.5">
            Coverage from your selection
          </p>
          <div className="flex flex-wrap gap-x-4 gap-y-1">
            {coverageRows.map(({ fw, covered }) => (
              <span
                key={fw.id}
                className="text-[11px] text-muted-foreground"
                title={fw.name}
              >
                <span className="font-medium text-foreground">
                  {shortFramework(fw.name)}
                </span>{" "}
                <span
                  className={
                    covered >= fw.controlCount
                      ? "text-emerald-600 dark:text-emerald-400 tabular-nums"
                      : "tabular-nums"
                  }
                >
                  {covered}/{fw.controlCount}
                </span>{" "}
                controls
              </span>
            ))}
          </div>
          <p className="text-[10px] text-muted-foreground/70 mt-1.5">
            Controls with no testable category stay “Not Tested”. Coverage ≠
            certification — it reflects what your attacks exercise.
          </p>
        </div>
      )}
    </div>
  );
}

export default CompliancePresets;
