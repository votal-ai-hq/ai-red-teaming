#!/usr/bin/env tsx
/**
 * Run the white-box codebase analyzer against a config's target and dump the
 * resulting CodebaseAnalysis to JSON. That JSON is then fed to the dataset
 * generator via `--from-analysis` for target-tailored synthetic attacks.
 *
 * Usage:
 *   npm run analyze:dump -- <config.json> [--out analysis.json]
 *
 * See docs/specs/nemo-data-designer-datasets.md §8 (Phase 2), docs/datasets.md.
 */
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { loadConfig } from "../lib/config-loader.js";
import { analyzeCodebase } from "../lib/codebase-analyzer.js";

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const positional = argv.filter((a) => !a.startsWith("--"));
  const configPath = positional[0];
  if (!configPath) {
    console.error("usage: npm run analyze:dump -- <config.json> [--out analysis.json]");
    process.exit(1);
  }
  const outIdx = argv.indexOf("--out");
  const outPath = outIdx >= 0 ? argv[outIdx + 1] : "analysis.json";

  const config = loadConfig(resolve(configPath));
  if (!config.codebasePath) {
    console.error(
      "error: config has no codebasePath — analysis would be empty (API-only mode).",
    );
    process.exit(2);
  }

  console.log(`[analyze] analyzing codebase at ${config.codebasePath} ...`);
  const analysis = await analyzeCodebase(config);

  const abs = resolve(outPath);
  mkdirSync(dirname(abs), { recursive: true });
  writeFileSync(abs, JSON.stringify(analysis, null, 2) + "\n", "utf-8");

  console.log(
    `[analyze] tools=${analysis.tools.length} roles=${analysis.roles.length} ` +
      `toolChains=${analysis.toolChains.length} ` +
      `mcpPrompts=${analysis.mcpSurface?.prompts.length ?? 0} ` +
      `mcpResources=${analysis.mcpSurface?.resources.length ?? 0}`,
  );
  console.log(`[analyze] wrote ${abs}`);
}

main().catch((err) => {
  console.error(`[analyze] failed: ${(err as Error).message}`);
  process.exit(1);
});
