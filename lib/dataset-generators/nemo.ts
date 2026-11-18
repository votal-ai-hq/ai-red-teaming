/**
 * In-run (tight) NeMo Data Designer generator.
 *
 * Phase 3 of the dataset layer: when `attackConfig.datasetGenerator === "nemo"`,
 * a run generates a synthetic dataset seeded from the live CodebaseAnalysis and
 * merges the rows into the run's custom attacks — generate-then-execute in one
 * pass, no separate `npm run gen:dataset` step.
 *
 * This module is intentionally the ONLY place that couples a run to Data
 * Designer, and it is fail-soft by contract: any error (service down, bad
 * preset, quota) is caught by the caller and the run continues with whatever
 * file-based custom attacks exist. The offline script path (Phase 1/2) remains
 * the recommended, reproducible workflow; this hook is a convenience.
 *
 * See docs/specs/nemo-data-designer-datasets.md §8.
 */
import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import type { Attack, CodebaseAnalysis, Config } from "../types.js";
import { buildDataDesignerConfig } from "./../dataset/nemo-config-builder.js";
import { NemoDataDesignerClient } from "./../dataset/nemo-client.js";
import { recordsToRows } from "./../dataset/map-records.js";
import { validateRows } from "./../dataset/validate.js";
import { seedsFromAnalysis } from "./../dataset/seed-from-analysis.js";
import { resolveMcpGenerationContract } from "./../dataset/mcp-contract.js";
import type { DatasetPreset } from "./../dataset/types.js";
import { attacksFromCustomRows } from "../custom-attacks-loader.js";

export interface GenerateInRunOptions {
  configDir: string;
  analysis?: CodebaseAnalysis;
  log?: (msg: string) => void;
  /** Injectable fetch for testing (defaults to the Data Designer HTTP client). */
  fetchImpl?: typeof fetch;
}

/**
 * Generate a dataset in-run and return it as executable Attacks.
 * Throws on failure — the caller is responsible for making it non-fatal.
 */
export async function generateNemoDatasetInRun(
  config: Config,
  opts: GenerateInRunOptions,
): Promise<Attack[]> {
  const genCfg = config.attackConfig.datasetGeneratorConfig;
  if (!genCfg?.preset) {
    throw new Error(
      "datasetGenerator=nemo requires attackConfig.datasetGeneratorConfig.preset",
    );
  }
  const log = opts.log ?? (() => {});

  const presetPath = resolve(opts.configDir, genCfg.preset);
  if (!existsSync(presetPath)) {
    throw new Error(`preset not found: ${presetPath}`);
  }
  const preset = JSON.parse(readFileSync(presetPath, "utf-8")) as DatasetPreset;
  if (genCfg.count) preset.count = genCfg.count;
  if (preset.family !== "mcp" && preset.family !== "agent") {
    throw new Error(`preset.family must be "mcp" or "agent" (got "${preset.family}")`);
  }

  const seedFromAnalysis = genCfg.seedFromAnalysis ?? true;
  const seeds =
    seedFromAnalysis && opts.analysis
      ? seedsFromAnalysis(opts.analysis)
      : undefined;
  if (seeds) {
    log(
      `nemo seeds from analysis: roles=${seeds.roles?.length ?? 0} surfaces=${seeds.surfaces?.length ?? 0}`,
    );
  }

  const ddConfig = buildDataDesignerConfig(preset, seeds);
  const client = new NemoDataDesignerClient(
    opts.fetchImpl ? { fetchImpl: opts.fetchImpl } : {},
  );
  log(`nemo generating ${preset.count ?? ddConfig.count} rows (family=${preset.family})...`);

  const records = await client.generate(ddConfig, preset.count);
  const rows = recordsToRows(records, preset.family);
  const { valid, errors, duplicatesDropped } = validateRows(rows, {
    family: preset.family,
    mcpContract:
      preset.family === "mcp"
        ? resolveMcpGenerationContract(preset, seeds)
        : undefined,
  });
  if (errors.length > 0) {
    log(`nemo dropped ${errors.length} invalid row(s); kept ${valid.length}`);
  }
  if (duplicatesDropped > 0) {
    log(`nemo dropped ${duplicatesDropped} duplicate row(s)`);
  }
  if (valid.length === 0) {
    throw new Error("nemo produced zero valid rows");
  }

  const defaultAuth: Attack["authMethod"] =
    config.customAttacksDefaults?.authMethod ?? "body_role";
  return attacksFromCustomRows(
    config,
    valid as unknown as Record<string, unknown>[],
    defaultAuth,
    { idPrefix: "nemo-inrun", isLlmGenerated: true },
  );
}
