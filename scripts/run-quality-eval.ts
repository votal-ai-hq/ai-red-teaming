#!/usr/bin/env tsx
/**
 * Run a functional-quality evaluation: score a quality dataset against a target
 * with the native correctness scorer (deterministic metrics + LLM judge).
 *
 * Usage:
 *   npm run eval:quality -- <config.json> [--dataset <quality.json>] \
 *     [--threshold 0.7] [--concurrency 4] [--out report/quality-report.json]
 *
 * The dataset defaults to the config's customAttacksFile if --dataset is omitted.
 * See docs/datasets.md — quality scorer.
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { loadConfig } from "../lib/config-loader.js";
import { validateQualityRows } from "../lib/dataset/validate.js";
import { runQualityEval } from "../lib/quality/scorer.js";
import type { QualityRow } from "../lib/dataset/types.js";

function flag(argv: string[], name: string): string | undefined {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : undefined;
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const configPath = argv.find((a) => !a.startsWith("--"));
  if (!configPath) {
    console.error(
      "usage: npm run eval:quality -- <config.json> [--dataset <quality.json>] [--threshold 0.7] [--concurrency 4] [--out <file>]",
    );
    process.exit(1);
  }
  const config = loadConfig(resolve(configPath));

  const datasetPath = flag(argv, "--dataset") ?? config.customAttacksFile;
  if (!datasetPath) {
    console.error("error: no dataset — pass --dataset or set customAttacksFile in the config");
    process.exit(1);
  }
  const datasetAbs = resolve(datasetPath);
  if (!existsSync(datasetAbs)) {
    console.error(`error: dataset not found: ${datasetAbs}`);
    process.exit(1);
  }

  const raw = JSON.parse(readFileSync(datasetAbs, "utf-8"));
  const { valid, errors } = validateQualityRows(Array.isArray(raw) ? raw : []);
  if (errors.length > 0) {
    console.error(`[eval] ${errors.length} invalid quality row(s) skipped:`);
    for (const e of errors.slice(0, 10)) console.error(`  - ${e}`);
  }
  if (valid.length === 0) {
    console.error("[eval] no valid quality rows to score");
    process.exit(2);
  }

  const threshold = flag(argv, "--threshold") ? Number(flag(argv, "--threshold")) : 0.7;
  const concurrency = flag(argv, "--concurrency") ? Number(flag(argv, "--concurrency")) : undefined;

  console.log(`[eval] scoring ${valid.length} quality rows against ${datasetPath} (threshold ${threshold})`);
  const report = await runQualityEval(config, valid as QualityRow[], {
    passThreshold: threshold,
    concurrency,
    dataset: datasetPath,
    onProgress: (done, total, last) => {
      const mark = last.error ? "ERR" : last.pass ? "PASS" : "FAIL";
      process.stdout.write(
        `\r[eval] ${done}/${total}  last: ${last.metric} ${last.score.toFixed(2)} ${mark}   `,
      );
    },
  });
  process.stdout.write("\n");

  const s = report.summary;
  console.log(`\n[eval] quality score: ${s.score}/100  (${s.passed}/${s.scored} passed, ${s.errors} errors)`);
  console.log("[eval] by metric:");
  for (const [m, v] of Object.entries(s.byMetric)) {
    console.log(`  ${m.padEnd(20)} mean ${v.mean.toFixed(2)}  (${v.passed}/${v.count})`);
  }

  const outPath = resolve(
    flag(argv, "--out") ??
      `report/quality-report-${report.timestamp.replace(/[:.]/g, "-")}.json`,
  );
  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, JSON.stringify(report, null, 2) + "\n", "utf-8");
  console.log(`\n[eval] report → ${outPath}`);
}

main().catch((err) => {
  console.error(`\n[eval] failed: ${(err as Error).message}`);
  process.exit(1);
});
