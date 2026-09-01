#!/usr/bin/env tsx
/**
 * Generate a synthetic eval dataset via NeMo Data Designer.
 *
 * The generator is out-of-band: it writes a versioned JSON dataset file that a
 * normal scan later consumes via `customAttacksFile`. A generator failure can
 * never break a scan.
 *
 * Usage:
 *   npm run gen:dataset -- --family mcp --preset configs/datasets/nemo-mcp.preset.json \
 *     --out data/datasets/nemo-mcp/v1.json [--count 400] [--preview] [--seed seed.json]
 *
 * Env (see lib/dataset/nemo-client.ts):
 *   NEMO_DATA_DESIGNER_URL, NVIDIA_API_KEY, NEMO_PREVIEW_PATH, NEMO_GENERATE_PATH
 *
 * See docs/specs/nemo-data-designer-datasets.md §7.
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { buildDataDesignerConfig } from "../lib/dataset/nemo-config-builder.js";
import { buildQualityDataDesignerConfig } from "../lib/dataset/quality-config-builder.js";
import { NemoDataDesignerClient } from "../lib/dataset/nemo-client.js";
import { recordsToRows, recordsToQualityRows } from "../lib/dataset/map-records.js";
import {
  validateRows,
  validateQualityRows,
  formatHistogram,
  underFloor,
} from "../lib/dataset/validate.js";
import { resolveCategoryPool } from "../lib/dataset/category-set.js";
import {
  decodeQualityPair,
  resolveQualityPool,
} from "../lib/dataset/quality-set.js";
import { seedsFromAnalysis, mergeSeeds } from "../lib/dataset/seed-from-analysis.js";
import { resolveMcpGenerationContract } from "../lib/dataset/mcp-contract.js";
import type { DatasetPreset, DatasetSeeds } from "../lib/dataset/types.js";
import type { CodebaseAnalysis } from "../lib/types.js";

interface Args {
  family?: string;
  preset?: string;
  out?: string;
  count?: number;
  preview: boolean;
  seed?: string;
  fromAnalysis?: string;
}

function parseArgs(argv: string[]): Args {
  const a: Args = { preview: false };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    const next = () => argv[++i];
    switch (flag) {
      case "--family": a.family = next(); break;
      case "--preset": a.preset = next(); break;
      case "--out": a.out = next(); break;
      case "--count": a.count = Number(next()); break;
      case "--seed": a.seed = next(); break;
      case "--from-analysis": a.fromAnalysis = next(); break;
      case "--preview": a.preview = true; break;
      case "-h": case "--help": printHelpAndExit(); break;
      default:
        console.error(`Unknown flag: ${flag}`);
        printHelpAndExit(1);
    }
  }
  return a;
}

function printHelpAndExit(code = 0): never {
  console.log(
    `gen-dataset-nemo — generate a synthetic eval dataset via NeMo Data Designer\n\n` +
      `  --family <mcp|agent>     dataset family (or read from preset)\n` +
      `  --preset <file.json>     generation preset (required)\n` +
      `  --out <file.json>        output dataset path (required unless --preview)\n` +
      `  --count <n>              override row count from preset\n` +
      `  --seed <file.json>       optional {roles,surfaces} seed inputs\n` +
      `  --from-analysis <file>   CodebaseAnalysis JSON (see npm run analyze:dump)\n` +
      `                           to derive target-tailored role/surface seeds\n` +
      `  --preview                fetch a small preview batch, print, do not write\n`,
  );
  process.exit(code);
}

function loadJson<T>(path: string): T {
  const abs = resolve(path);
  if (!existsSync(abs)) throw new Error(`file not found: ${abs}`);
  return JSON.parse(readFileSync(abs, "utf-8")) as T;
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  if (!args.preset) {
    console.error("error: --preset is required");
    printHelpAndExit(1);
  }
  if (!args.preview && !args.out) {
    console.error("error: --out is required (unless --preview)");
    printHelpAndExit(1);
  }

  const preset = loadJson<DatasetPreset>(args.preset);
  if (args.family) preset.family = args.family as DatasetPreset["family"];
  if (args.count) preset.count = args.count;
  if (preset.family !== "mcp" && preset.family !== "agent") {
    throw new Error(`preset.family must be "mcp" or "agent" (got "${preset.family}")`);
  }

  // Seeds: explicit --seed takes priority, unioned with seeds derived from a
  // CodebaseAnalysis (--from-analysis) for target-tailored generation.
  const explicitSeeds: DatasetSeeds | undefined = args.seed
    ? loadJson<DatasetSeeds>(args.seed)
    : undefined;
  const analysisSeeds: DatasetSeeds | undefined = args.fromAnalysis
    ? seedsFromAnalysis(loadJson<CodebaseAnalysis>(args.fromAnalysis))
    : undefined;
  const seeds = mergeSeeds(explicitSeeds, analysisSeeds);
  const mcpContract =
    preset.family === "mcp"
      ? resolveMcpGenerationContract(preset, seeds)
      : undefined;
  if (analysisSeeds) {
    console.log(
      `[gen] analysis seeds: roles=${analysisSeeds.roles?.length ?? 0} ` +
        `surfaces=${analysisSeeds.surfaces?.length ?? 0}`,
    );
  }

  const kind = preset.kind ?? "security";
  if (kind === "quality" && preset.family === "mcp" && !mcpContract?.tools.length) {
    throw new Error(
      "MCP quality generation requires at least one declared tool; provide an MCP profile or seed from target analysis",
    );
  }
  // Resolve pool early so a bad preset fails before any network call.
  const requestedPool =
    kind === "quality"
      ? resolveQualityPool(preset.family, preset.tasks)
      : resolveCategoryPool(preset.family, preset.categories);
  const config =
    kind === "quality"
      ? buildQualityDataDesignerConfig(preset, seeds)
      : buildDataDesignerConfig(preset, seeds);
  const axisName = kind === "quality"
    ? preset.family === "mcp" ? "taskMetric" : "task"
    : "category";
  const axis = config.columns.find((column) => column.name === axisName);
  const pool =
    axis && "values" in axis
      ? [...new Set(
          axis.values
            .map((value) => decodeQualityPair(value)?.task ?? value)
            .filter(Boolean),
        )]
      : requestedPool;
  const client = new NemoDataDesignerClient();

  console.log(
    `[gen] kind=${kind} family=${preset.family} ${kind === "quality" ? "tasks" : "categories"}=${pool.length} ` +
      `count=${preset.count ?? config.count} model=${config.model} ` +
      `mode=${args.preview ? "preview" : "generate"}`,
  );

  const records = args.preview
    ? await client.preview(config, Math.min(args.count ?? 5, 10))
    : await client.generate(config, preset.count);

  const { valid, errors, histogram, duplicatesDropped } =
    kind === "quality"
      ? validateQualityRows(recordsToQualityRows(records), { mcpContract })
      : validateRows(recordsToRows(records, preset.family), {
          family: preset.family,
          mcpContract,
        });

  console.log(`\n[gen] produced ${records.length} record(s)`);
  console.log(`[gen] valid ${valid.length}, dropped-duplicate ${duplicatesDropped}, invalid ${errors.length}`);
  if (errors.length > 0) {
    console.error(`\n[gen] validation errors (fail-closed):`);
    for (const e of errors.slice(0, 25)) console.error(`  - ${e}`);
    if (errors.length > 25) console.error(`  ... and ${errors.length - 25} more`);
  }

  console.log(`\n[gen] category histogram:\n${formatHistogram(histogram)}`);

  const floor = preset.perCategoryFloor ?? 0;
  const short = underFloor(histogram, pool, floor);
  if (short.length > 0) {
    console.warn(
      `\n[gen] WARNING: ${short.length} categor${short.length === 1 ? "y" : "ies"} below floor of ${floor}:`,
    );
    for (const s of short) console.warn(`  - ${s.category}: ${s.have}/${floor}`);
  }

  if (args.preview) {
    console.log(`\n[gen] preview sample (first row):`);
    console.log(JSON.stringify(valid[0] ?? null, null, 2));
    console.log(`\n[gen] preview only — nothing written.`);
    return;
  }

  // Fail-closed: never write a dataset that contains invalid rows.
  if (errors.length > 0) {
    console.error(`\n[gen] refusing to write: ${errors.length} invalid row(s). Fix generation and retry.`);
    process.exit(2);
  }
  if (valid.length === 0) {
    console.error(`\n[gen] refusing to write: zero valid rows.`);
    process.exit(2);
  }

  const outPath = resolve(args.out!);
  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, JSON.stringify(valid, null, 2) + "\n", "utf-8");
  console.log(`\n[gen] wrote ${valid.length} rows -> ${outPath}`);
}

main().catch((err) => {
  console.error(`\n[gen] failed: ${(err as Error).message}`);
  process.exit(1);
});
