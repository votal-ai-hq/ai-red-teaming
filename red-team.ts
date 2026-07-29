#!/usr/bin/env npx tsx

import { bootstrapProxy } from "./lib/proxy-bootstrap.js";
bootstrapProxy();

import { createInterface } from "node:readline/promises";
import { dirname, resolve } from "node:path";
import {
  mkdtempSync,
  mkdirSync,
  rmSync,
  writeFileSync,
  readFileSync,
  existsSync,
  unlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { execSync } from "node:child_process";

// Color coding for security results
function getColoredIcon(verdict: string): string {
  const colors = {
    reset: "\x1b[0m",
    red: "\x1b[91m", // PASS = RED (attack succeeded - bad for security)
    green: "\x1b[92m", // FAIL = GREEN (defense held - good for security)
    yellow: "\x1b[93m", // PARTIAL = YELLOW (uncertain)
    gray: "\x1b[90m", // ERROR = GRAY
  };

  switch (verdict) {
    case "PASS":
      return `${colors.red}[!!]${colors.reset}`;
    case "FAIL":
      return `${colors.green}[OK]${colors.reset}`;
    case "PARTIAL":
      return `${colors.yellow}[~]${colors.reset}`;
    default:
      return `${colors.gray}[??]${colors.reset}`;
  }
}
const COLORS = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  red: "\x1b[91m",
  green: "\x1b[92m",
  yellow: "\x1b[93m",
  blue: "\x1b[94m",
  gray: "\x1b[90m",
  cyan: "\x1b[96m",
};

function progressBar(current: number, total: number, width = 30): string {
  const pct = total > 0 ? Math.min(current / total, 1) : 0;
  const filled = Math.min(Math.round(pct * width), width);
  const empty = width - filled;
  const bar = "█".repeat(filled) + "░".repeat(empty);
  return `${bar} ${Math.round(pct * 100)}%`;
}

function printProgressLine(
  current: number,
  total: number,
  passes: number,
  fails: number,
  partials: number,
  errors: number,
  elapsed: number,
): void {
  const mins = Math.floor(elapsed / 60);
  const secs = elapsed % 60;
  const timeStr = mins > 0 ? `${mins}m ${secs}s` : `${secs}s`;
  const bar = progressBar(current, total);
  const stats = [
    passes > 0 ? `${COLORS.red}${passes} vulns${COLORS.reset}` : "",
    fails > 0 ? `${COLORS.green}${fails} blocked${COLORS.reset}` : "",
    partials > 0 ? `${COLORS.yellow}${partials} partial${COLORS.reset}` : "",
    errors > 0 ? `${COLORS.gray}${errors} errors${COLORS.reset}` : "",
  ]
    .filter(Boolean)
    .join(" ");
  process.stdout.write(
    `\r\x1b[K  ${COLORS.blue}${bar}${COLORS.reset} ${stats} ${COLORS.gray}(${timeStr})${COLORS.reset}`,
  );
}

/** Clone a git repo for white-box analysis. Returns temp dir path or null. */
function cloneCodebaseRepo(
  config: import("./lib/types.js").Config,
): string | null {
  if (!config.codebaseRepo || config.codebasePath) return null;

  const tmpDir = mkdtempSync(`${tmpdir()}/redteam-cli-`);
  let repoUrl = config.codebaseRepo;

  const token =
    config.codebaseRepoToken || process.env.CODEBASE_REPO_TOKEN || "";
  if (token && repoUrl.startsWith("https://")) {
    repoUrl = repoUrl.replace("https://", `https://${token}@`);
  }

  const branch = config.codebaseRepoBranch || "";
  const branchFlag = branch ? `--branch ${branch}` : "";

  console.log(
    `  Cloning ${config.codebaseRepo}${branch ? ` (branch: ${branch})` : ""}...`,
  );
  execSync(`git clone --depth 1 ${branchFlag} ${repoUrl} ${tmpDir}`, {
    stdio: "pipe",
    timeout: 120_000,
  });
  console.log(`  Clone complete → white-box analysis enabled`);
  return tmpDir;
}

import { loadEnvFile } from "./lib/env-loader.js";
import { loadConfig } from "./lib/config-loader.js";
import { describeTarget, getTargetAdapter } from "./lib/target-adapter.js";
import { analyzeCodebase } from "./lib/codebase-analyzer.js";
import { planAttacks, refinePartialAttacks } from "./lib/attack-planner.js";
import {
  estimatePreRun,
  estimateRun,
  formatEstimate,
} from "./lib/run-estimator.js";
import { getAllStrategies } from "./lib/attack-strategies.js";
import {
  preAuthenticate,
  prepareConversation,
  runPreSetup,
  executeAttack,
  executeMultiTurn,
  executeAdaptiveMultiTurn,
  executeRapidFire,
  sleep,
  withSessionScope,
} from "./lib/attack-runner.js";
import { analyzeResponse, type AppContext } from "./lib/response-analyzer.js";
import {
  generateReport,
  writeReport,
  printConsoleSummary,
} from "./lib/report-generator.js";
import { enterUsageContext, formatUsageSummary } from "./lib/llm-usage.js";
import { runStaticAnalysis } from "./lib/static-analyzer.js";
import { analyzeRound } from "./lib/round-analyzer.js";
import { generateIdealResponse } from "./lib/ideal-response-generator.js";
import {
  loadCustomAttacksFromConfig,
  mergeCustomAttacksForRound,
} from "./lib/custom-attacks-loader.js";
import { generateAppTailoredCustomAttacks } from "./lib/app-tailored-custom-prompts.js";
import {
  runDiscoveryRound,
  applyDiscoveryIntel,
} from "./lib/discovery-round.js";
import {
  ALL_MODULES,
  MCP_MODULES,
  enrichAnalysisWithTargetSurface,
  createDynamicModule,
} from "./lib/run.js";
import { isAttackCategory } from "./lib/types.js";
import type {
  Attack,
  AttackResult,
  AttackCategory,
  CategoryDefenseProfile,
  CodebaseAnalysis,
  Config,
  Report,
  RoundResult,
} from "./lib/types.js";

loadEnvFile();

function summarizeAffectedFiles(
  analysis: CodebaseAnalysis,
  category: AttackCategory,
  max = 3,
): string {
  const files = analysis.affectedFiles?.[category] ?? [];
  if (files.length === 0) return "none mapped";
  const shown = files
    .slice(0, max)
    .map((f) => (f.line ? `${f.file}:${f.line}` : f.file));
  const suffix = files.length > max ? ` (+${files.length - max} more)` : "";
  return `${shown.join(", ")}${suffix}`;
}

function printPlannedAttackReview(
  round: number,
  attacks: Attack[],
  analysis: CodebaseAnalysis,
  label = "planned",
): void {
  console.log(`\n  Attack review for round ${round} (${label}):`);
  for (let i = 0; i < attacks.length; i++) {
    const a = attacks[i];
    const msg = (a.payload as Record<string, unknown>)?.message;
    const preview =
      typeof msg === "string"
        ? msg.replace(/\s+/g, " ").slice(0, 140)
        : "(no message)";
    console.log(
      `    ${i + 1}. [${a.severity}] ${a.category} :: ${a.name} (${a.authMethod}/${a.role})`,
    );
    console.log(
      `       files: ${summarizeAffectedFiles(analysis, a.category)} | prompt: ${preview}${preview.length >= 140 ? "..." : ""}`,
    );
  }
}

async function confirmAttackExecution(
  promptText: string,
  requireConfirmation: boolean,
): Promise<boolean> {
  if (!requireConfirmation) {
    return true;
  }
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    console.log(
      "  Non-interactive terminal detected — auto-approving attack execution.",
    );
    return true;
  }
  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  try {
    const answer = (await rl.question(`${promptText} [y/N]: `))
      .trim()
      .toLowerCase();
    return answer === "y" || answer === "yes";
  } finally {
    rl.close();
  }
}

function logFindings(result: AttackResult): void {
  const deterministicFindings = result.findings.filter(
    (f) => !f.startsWith("LLM judge"),
  );
  const judgeFindings = result.findings.filter((f) =>
    f.startsWith("LLM judge"),
  );
  for (const f of deterministicFindings) {
    console.log(`    ${f}`);
  }
  for (const f of judgeFindings) {
    console.log(`    ${f}`);
  }
  if (judgeFindings.length === 0 && result.llmReasoning) {
    console.log(
      `    LLM judge: ${result.llmReasoning}${result.judgeConfidence != null ? ` (confidence ${result.judgeConfidence}%)` : ""}`,
    );
  }
}

/** Group attacks by their category, preserving order within each group. */
function groupAttacksByCategory(attacks: Attack[]): Map<string, Attack[]> {
  const groups = new Map<string, Attack[]>();
  for (const attack of attacks) {
    const list = groups.get(attack.category) || [];
    list.push(attack);
    groups.set(attack.category, list);
  }
  return groups;
}

/** Run async tasks with a concurrency limit (worker-pool pattern). */
async function runWithConcurrency<T>(
  tasks: (() => Promise<T>)[],
  maxConcurrency: number,
): Promise<T[]> {
  const results: T[] = new Array(tasks.length);
  let nextIndex = 0;

  async function worker(): Promise<void> {
    while (nextIndex < tasks.length) {
      const i = nextIndex++;
      results[i] = await tasks[i]();
    }
  }

  const workers = Array.from(
    { length: Math.min(maxConcurrency, tasks.length) },
    () => worker(),
  );
  await Promise.all(workers);
  return results;
}

async function maybeGenerateIdealResponse(
  config: Config,
  result: AttackResult,
): Promise<void> {
  const enabled =
    config.attackConfig.enableIdealResponses ??
    config.attackConfig.enableLlmGeneration;
  if (!enabled) return;
  if (result.verdict !== "PASS" && result.verdict !== "PARTIAL") return;

  const ideal = await generateIdealResponse(config, result);
  if (!ideal) return;

  result.idealResponse = ideal;
  const idealPreview =
    typeof ideal.response === "string"
      ? ideal.response
      : JSON.stringify(ideal.response);
  console.log(
    `    [Ideal Response] ${idealPreview.slice(0, 120)}${idealPreview.length > 120 ? "..." : ""}`,
  );
  if (ideal.remediationHints.length > 0) {
    console.log(`    [Remediation] ${ideal.remediationHints[0]}`);
  }
}

async function main() {
  const configPath = process.argv[2]?.trim();
  console.log("=== Red-Team Security Testing Framework ===\n");

  // 1. Load config
  console.log("[1/5] Loading configuration...");
  const config = loadConfig(configPath);
  const configDir = dirname(resolve(configPath ?? "config.json"));
  // Track LLM usage for this scan (tokens, cost, latency, errors). The CLI is a
  // single run, so binding the collector to this async context is safe here.
  const usageCollector = enterUsageContext();
  let customAttacks: Attack[] = [];
  try {
    customAttacks = loadCustomAttacksFromConfig(config, { configDir });
  } catch (e) {
    console.error(`  ${(e as Error).message}`);
    console.error(
      "  Fix or remove customAttacksFile in config.json to run without file-based custom attacks.",
    );
    process.exit(1);
  }
  if (customAttacks.length > 0) {
    console.log(`  Custom attacks loaded: ${customAttacks.length} case(s)`);
  }
  const targetLabel = describeTarget(config);
  console.log(`  Target: ${targetLabel}`);
  console.log(`  Adaptive rounds: ${config.attackConfig.adaptiveRounds}`);
  console.log(
    `  LLM generation: ${config.attackConfig.enableLlmGeneration ? "enabled" : "disabled"}`,
  );
  console.log(
    `  Attack mode: ${config.attackConfig.attackMode ?? "balanced"}`,
  );

  // Filter modules based on enabledCategories (empty/absent = all enabled)
  const moduleSet =
    (config.target.type ?? "http_agent") === "mcp" ? MCP_MODULES : ALL_MODULES;
  const enabledSet = config.attackConfig.enabledCategories;
  let activeModules = enabledSet?.length
    ? moduleSet.filter((m) => enabledSet.includes(m.category))
    : moduleSet;

  // Create dynamic modules for enabled categories that have no hardcoded module
  if (enabledSet?.length) {
    const coveredCategories = new Set(activeModules.map((m) => m.category));
    const uncovered = enabledSet.filter((cat) => !coveredCategories.has(cat));
    if (uncovered.length > 0) {
      const known = uncovered.filter((cat) => isAttackCategory(cat));
      const custom = uncovered.filter((cat) => !isAttackCategory(cat));
      if (known.length > 0) {
        console.log(
          `  Dynamic modules for ${known.length} categories (no hardcoded attacks): ${known.join(", ")}`,
        );
      }
      if (custom.length > 0) {
        console.log(
          `  Dynamic modules for ${custom.length} custom categories: ${custom.join(", ")}`,
        );
      }
      const dynamicModules = uncovered.map((cat) => createDynamicModule(cat));
      activeModules = [...activeModules, ...dynamicModules];
    }
    console.log(
      `  Active categories (${activeModules.length}): ${enabledSet.join(", ")}`,
    );
  } else {
    console.log(`  Active categories: all (${moduleSet.length})`);
  }

  // 1.5. Clone codebaseRepo if set (for white-box analysis)
  let clonedDir: string | null = null;
  if (config.codebaseRepo && !config.codebasePath) {
    try {
      clonedDir = cloneCodebaseRepo(config);
      if (clonedDir) config.codebasePath = clonedDir;
    } catch (cloneErr) {
      console.log(
        `  Clone failed: ${cloneErr instanceof Error ? cloneErr.message.slice(0, 100) : String(cloneErr)}`,
      );
      console.log(`  Continuing in black-box mode`);
    }
  }

  // 2. Analyze codebase
  console.log("\n[2/5] Analyzing target codebase...");
  const analysis = await analyzeCodebase(config);
  await enrichAnalysisWithTargetSurface(config, analysis, console.warn);
  console.log(
    `  Found ${analysis.tools.length} tools, ${analysis.roles.length} roles`,
  );
  if (analysis.detectedFrameworks.length > 0) {
    console.log(
      `  Frameworks: ${analysis.detectedFrameworks.map((f) => `${f.name} (${f.confidence})`).join(", ")}`,
    );
  }
  if (analysis.toolChains.length > 0) {
    console.log(`  Dangerous tool chains: ${analysis.toolChains.length}`);
  }
  console.log(
    `  Identified ${analysis.knownWeaknesses.length} potential weaknesses`,
  );
  if (analysis.knownWeaknesses.length > 0) {
    for (const w of analysis.knownWeaknesses.slice(0, 5)) {
      console.log(`    - ${w}`);
    }
  }
  if (
    analysis.affectedFiles &&
    Object.keys(analysis.affectedFiles).length > 0
  ) {
    const totalFiles = new Set(
      Object.values(analysis.affectedFiles)
        .flat()
        .map((f) => f.file),
    ).size;
    console.log(
      `  Mapped ${Object.keys(analysis.affectedFiles).length} attack categories to ${totalFiles} target source files`,
    );
  }

  if (Math.max(0, config.attackConfig.appTailoredCustomPromptCount ?? 0) > 0) {
    console.log("\n  Generating app-tailored custom prompts from analysis...");
    const generated = await generateAppTailoredCustomAttacks(config, analysis);
    if (generated.length > 0) {
      console.log(`  App-tailored custom cases: ${generated.length}`);
      customAttacks = [...customAttacks, ...generated];
    } else {
      console.log(
        "  App-tailored generation returned no cases (see errors above if any).",
      );
    }
  }

  // 2.25. Category applicability gating — skip categories with no relevant source files
  const skipIrrelevant =
    (config.target.type ?? "http_agent") === "mcp"
      ? false
      : (config.attackConfig.skipIrrelevantCategories ?? true);
  let relevantModules = activeModules;
  if (
    skipIrrelevant &&
    analysis.affectedFiles &&
    Object.keys(analysis.affectedFiles).length > 0
  ) {
    const before = relevantModules.length;
    relevantModules = relevantModules.filter((m) => {
      const files = analysis.affectedFiles?.[m.category];
      return files && files.length > 0;
    });
    const skipped = before - relevantModules.length;
    if (skipped > 0) {
      console.log(
        `  Applicability gating: skipped ${skipped} categories with no relevant source files`,
      );
    }
  }

  // Build app context for the LLM judge (reduces false positives)
  const appContext: AppContext = {
    tools: analysis.tools,
    roles: analysis.roles,
    systemPromptHints: analysis.systemPromptHints,
  };

  // 2.5. Static analysis
  let staticResult;
  if (config.codebasePath) {
    console.log("\n[2.5/5] Running static analysis...");
    staticResult = await runStaticAnalysis(config);
    console.log(
      `  Checked ${staticResult.checkedFiles} files, found ${staticResult.findings.length} issues`,
    );
    console.log(`  Static score: ${staticResult.score}/100`);
  }

  // 3. Pre-authenticate
  console.log("\n[3/5] Pre-authenticating...");
  await preAuthenticate(config);

  // 3.5. Discovery round (optional — probes target to enrich sensitivePatterns and applicationDetails)
  let discoveryIntel: Report["discovery"] | undefined;
  if (config.attackConfig.enableDiscovery) {
    console.log("\n[3.5/5] Running discovery round...");
    const intel = await runDiscoveryRound(config);
    applyDiscoveryIntel(config, intel);
    discoveryIntel = {
      discoveredTools: intel.discoveredTools,
      discoveredDataStores: intel.discoveredDataStores,
      discoveredPatterns: intel.discoveredPatterns,
      architectureHints: intel.architectureHints,
      guardrailProfile: intel.guardrailProfile,
      weaknesses: intel.weaknesses,
      authMechanisms: intel.authMechanisms,
      sessionArtifacts: intel.sessionArtifacts,
      privilegeBoundaries: intel.privilegeBoundaries,
      integrationPoints: intel.integrationPoints,
      dataFlows: intel.dataFlows,
      sensitiveDataClasses: intel.sensitiveDataClasses,
      fileHandlingSurfaces: intel.fileHandlingSurfaces,
      inputParsers: intel.inputParsers,
      configSources: intel.configSources,
      secretHandlingLocations: intel.secretHandlingLocations,
      detectionGaps: intel.detectionGaps,
      featureFlags: intel.featureFlags,
      defaultAssumptions: intel.defaultAssumptions,
      unknowns: intel.unknowns,
      targetSurfaces: intel.targetSurfaces,
      attackObjectives: intel.attackObjectives,
      promptManipulationSurfaces: intel.promptManipulationSurfaces,
      jailbreakRiskCategories: intel.jailbreakRiskCategories,
      systemPromptExposureSignals: intel.systemPromptExposureSignals,
      retrievalAttackSurfaces: intel.retrievalAttackSurfaces,
      memoryAttackSurfaces: intel.memoryAttackSurfaces,
      toolUseAttackSurfaces: intel.toolUseAttackSurfaces,
      agenticFailureModes: intel.agenticFailureModes,
      privacyAndLeakageRisks: intel.privacyAndLeakageRisks,
      unsafeCapabilityAreas: intel.unsafeCapabilityAreas,
      deceptionAndManipulationRisks: intel.deceptionAndManipulationRisks,
      boundaryConditions: intel.boundaryConditions,
      multimodalRiskSurfaces: intel.multimodalRiskSurfaces,
      summary: intel.summary,
      probeCount: intel.probeResults.length,
    };
    console.log(
      `  Discovery complete: ${intel.discoveredTools.length} tools, ${intel.discoveredDataStores.length} data stores, ${intel.discoveredPatterns.length} patterns, ${intel.weaknesses.length} weaknesses`,
    );
  }

  // 4. Run adaptive attack rounds
  console.log("\n[4/5] Running attacks...");

  // -- Checkpoint helpers (CLI) --
  const CHECKPOINT_DIR = resolve("report", ".checkpoints");
  const checkpointConfigPath = resolve(configPath ?? "config.json");
  const cpConfigKey = JSON.stringify({
    configPath: checkpointConfigPath,
    url: config.target.baseUrl || config.target.agentEndpoint || "",
    model: config.attackConfig.llmModel,
    rounds: config.attackConfig.adaptiveRounds,
  });
  let cpHash = 0;
  for (let i = 0; i < cpConfigKey.length; i++) {
    cpHash = ((cpHash << 5) - cpHash + cpConfigKey.charCodeAt(i)) | 0;
  }
  const cpFile = resolve(
    CHECKPOINT_DIR,
    `checkpoint-${Math.abs(cpHash).toString(36)}.json`,
  );

  function saveCliCheckpoint(
    completedRounds: RoundResult[],
    lastRound: number,
    partialResults?: AttackResult[],
    completedCategories?: string[],
  ): void {
    mkdirSync(CHECKPOINT_DIR, { recursive: true });
    writeFileSync(
      cpFile,
      JSON.stringify({
        timestamp: new Date().toISOString(),
        completedRounds,
        lastCompletedRound: lastRound,
        partialRoundResults: partialResults || [],
        completedCategories: completedCategories || [],
      }),
      "utf-8",
    );
  }

  function loadCliCheckpoint(): {
    completedRounds: RoundResult[];
    lastCompletedRound: number;
    partialRoundResults?: AttackResult[];
    completedCategories?: string[];
  } | null {
    if (!existsSync(cpFile)) return null;
    try {
      return JSON.parse(readFileSync(cpFile, "utf-8"));
    } catch {
      return null;
    }
  }

  function clearCliCheckpoint(): void {
    if (existsSync(cpFile)) {
      try {
        unlinkSync(cpFile);
      } catch {
        /* ignore */
      }
    }
  }

  // Resume from checkpoint if available
  const checkpoint = loadCliCheckpoint();
  const rounds: RoundResult[] = checkpoint
    ? [...checkpoint.completedRounds]
    : [];
  let allPreviousResults: AttackResult[] = rounds.flatMap((r) => r.results);
  let defenseProfiles: Map<AttackCategory, CategoryDefenseProfile> | undefined;

  // Determine where to resume
  const hasPartialResults =
    checkpoint?.partialRoundResults &&
    checkpoint.partialRoundResults.length > 0;
  const startRound = hasPartialResults
    ? checkpoint!.lastCompletedRound + 1 // resume the partial round
    : checkpoint
      ? checkpoint.lastCompletedRound + 1
      : 1;
  const resumedPartialResults: AttackResult[] = hasPartialResults
    ? checkpoint!.partialRoundResults!
    : [];
  const resumedCategories: Set<string> = new Set(
    checkpoint?.completedCategories || [],
  );

  if (checkpoint && (startRound > 1 || hasPartialResults)) {
    const totalRecovered =
      allPreviousResults.length + resumedPartialResults.length;
    console.log(
      `  ✅ Checkpoint found — resuming round ${startRound} (${totalRecovered} results recovered, ${resumedCategories.size} categories done in current round)`,
    );
    for (const r of rounds) {
      defenseProfiles = analyzeRound(r.results, config, defenseProfiles);
    }
  }
  let cancelledByUser = false;
  const requireReviewConfirmation =
    config.attackConfig.requireReviewConfirmation ?? true;
  let globalAttackCount = 0;
  let globalPasses = 0;
  let globalFails = 0;
  let globalPartials = 0;
  let globalErrors = 0;
  const attackStartTime = Date.now();
  console.log(
    `  Review confirmation: ${requireReviewConfirmation ? "enabled" : "disabled"}`,
  );

  // Track actual total attacks for progress bar (updated as rounds are planned)
  let knownTotalAttacks = 0;

  for (
    let round = startRound;
    round <= config.attackConfig.adaptiveRounds;
    round++
  ) {
    console.log(
      `\n  ── Round ${round}/${config.attackConfig.adaptiveRounds} ──`,
    );

    // Refresh tokens + session before each round (if configured)
    if (config.target.refreshPerRound && round > 1) {
      console.log("  Refreshing pre-auth tokens and session...");
      await runPreSetup(config);
    }

    // Plan attacks for this round (with defense profiles from prior rounds)
    const skipBuiltinPlanner =
      round === 1 &&
      config.attackConfig.customAttacksOnly === true &&
      customAttacks.length > 0;

    // Pre-run estimate — print BEFORE planning so the user sees expected
    // attack count and wall time before the LLM starts churning.
    if (!skipBuiltinPlanner) {
      const totalStrategies = getAllStrategies(
        config.attackConfig.customStrategiesFile,
      ).length;
      const est = estimatePreRun(
        config,
        relevantModules.length,
        totalStrategies,
      );
      const concurrency = Math.max(1, config.attackConfig.concurrency || 1);
      console.log("");
      console.log("  Pre-run estimate");
      console.log("  ────────────────");
      for (const line of formatEstimate(est, concurrency)) {
        console.log(`    ${line}`);
      }
      console.log("");
    }

    console.log(
      skipBuiltinPlanner
        ? "  Skipping built-in planner (customAttacksOnly)."
        : "  Planning attacks with LLM... this may take a while.",
    );
    const planned = skipBuiltinPlanner
      ? []
      : await planAttacks(
          config,
          analysis,
          relevantModules,
          allPreviousResults,
          round,
          defenseProfiles,
        );
    const attacks = mergeCustomAttacksForRound(
      config,
      round,
      planned,
      customAttacks,
    );
    knownTotalAttacks += attacks.length;
    console.log(`  Planned ${attacks.length} attacks`);
    {
      const est = estimateRun(attacks, config);
      const concurrency = Math.max(1, config.attackConfig.concurrency || 1);
      for (const line of formatEstimate(est, concurrency)) {
        console.log(`    ${line}`);
      }
    }
    printPlannedAttackReview(round, attacks, analysis, "initial");
    const approved = await confirmAttackExecution(
      "  Proceed with these planned attacks?",
      requireReviewConfirmation,
    );
    if (!approved) {
      console.log("  Attack execution cancelled by user after review.");
      cancelledByUser = true;
      break;
    }

    // Seed with partial results from checkpoint (if resuming mid-round)
    const roundResults: AttackResult[] =
      round === startRound && resumedPartialResults.length > 0
        ? [...resumedPartialResults]
        : [];
    const skipCategories: Set<string> =
      round === startRound ? new Set(resumedCategories) : new Set();
    const doneCategories: string[] = Array.from(skipCategories);

    if (skipCategories.size > 0) {
      console.log(
        `  Skipping already-completed categories: ${Array.from(skipCategories).join(", ")}`,
      );
    }

    // Determine effective category parallelism
    const categoryParallelism = config.attackConfig.categoryParallelism ?? 1;

    // Group attacks by category and filter out already-completed ones
    const categoryGroups = groupAttacksByCategory(attacks);
    for (const cat of skipCategories) {
      categoryGroups.delete(cat);
    }
    const categoryNames = Array.from(categoryGroups.keys());

    if (categoryParallelism > 1) {
      console.log(
        `  Running ${categoryNames.length} categories with parallelism=${categoryParallelism}`,
      );
    }

    // Shared progress index across concurrent categories
    const sharedIndex = { value: roundResults.length };
    const totalAttacksInRound = attacks.length;

    // Build one task per category
    const categoryTasks = categoryNames.map((categoryName) => {
      const categoryAttacks = categoryGroups.get(categoryName)!;
      return (): Promise<void> =>
        withSessionScope(async () => {
          const catPrefix = categoryParallelism > 1 ? `[${categoryName}] ` : "";
          const categoryResults: AttackResult[] = [];

          for (let j = 0; j < categoryAttacks.length; j++) {
            const attack = categoryAttacks[j];
            sharedIndex.value++;
            const progress = `[${sharedIndex.value}/${totalAttacksInRound}]`;

            // Handle rate-limit rapid-fire attacks specially
            const rapidFire = (
              attack.payload as Record<string, unknown> | undefined
            )?._rapidFire as number | undefined;
            if (rapidFire && attack.category === "rate_limit") {
              console.log(
                `  ${catPrefix}${progress} ${attack.name} (${rapidFire}x rapid-fire)...`,
              );
              const cleanPayload = { ...attack.payload };
              delete (cleanPayload as Record<string, unknown>)._rapidFire;
              const cleanAttack = { ...attack, payload: cleanPayload };

              await prepareConversation(config);
              const responses = await executeRapidFire(
                config,
                cleanAttack,
                rapidFire,
              );
              const got429 = responses.some((r) => r.statusCode === 429);
              const allOk = responses.every((r) => r.statusCode === 200);
              const lastResponse = responses[responses.length - 1];

              const result = await analyzeResponse(
                config,
                attack,
                lastResponse.statusCode,
                lastResponse.body,
                lastResponse.timeMs,
                appContext,
                lastResponse.executionTrace,
              );

              if (!got429 && allOk) {
                result.verdict = "PASS";
                result.findings.push(
                  `All ${rapidFire} requests succeeded — rate limit not enforced`,
                );
              } else if (got429) {
                result.verdict = "FAIL";
                result.findings.push(
                  `Rate limit correctly enforced — got 429 after ${responses.filter((r) => r.statusCode === 200).length} requests`,
                );
              }

              console.log(
                `    ${catPrefix}${getColoredIcon(result.verdict)} ${result.verdict}`,
              );
              logFindings(result);
              await maybeGenerateIdealResponse(config, result);
              categoryResults.push(result);
            } else {
              try {
                // Multi-turn attack (predefined steps) or Adaptive multi-turn attack
                if (attack.steps && attack.steps.length > 0) {
                  const totalSteps = 1 + attack.steps.length;
                  process.stdout.write(
                    `  ${catPrefix}${progress} ${attack.name} (${totalSteps} steps)...`,
                  );

                  await prepareConversation(config);
                  const { results: stepResults, stoppedEarly } =
                    await executeMultiTurn(
                      config,
                      attack,
                      async (cfg, atk, sc, b, t) => {
                        const r = await analyzeResponse(
                          cfg,
                          atk,
                          sc,
                          b,
                          t,
                          appContext,
                        );
                        return { verdict: r.verdict, findings: r.findings };
                      },
                    );

                  const lastStep = stepResults[stepResults.length - 1];
                  const result = await analyzeResponse(
                    config,
                    attack,
                    lastStep.statusCode,
                    lastStep.body,
                    lastStep.timeMs,
                    appContext,
                    lastStep.executionTrace,
                  );
                  result.stepIndex = lastStep.stepIndex;
                  result.totalSteps = stepResults.length;
                  result.conversation = stepResults.map((sr) => ({
                    stepIndex: sr.stepIndex,
                    payload:
                      sr.stepIndex === 0
                        ? attack.payload
                        : (attack.steps?.[sr.stepIndex - 1]?.payload ?? {}),
                    statusCode: sr.statusCode,
                    responseBody: sr.body,
                    responseTimeMs: sr.timeMs,
                  }));

                  const icon = getColoredIcon(result.verdict);
                  const earlyTag = stoppedEarly
                    ? ` (stopped at step ${lastStep.stepIndex + 1})`
                    : "";
                  console.log(
                    ` ${icon}${result.verdict} (${lastStep.statusCode}, ${lastStep.timeMs}ms)${earlyTag}`,
                  );
                  logFindings(result);
                  await maybeGenerateIdealResponse(config, result);

                  categoryResults.push(result);
                } else if (
                  config.attackConfig.enableAdaptiveMultiTurn &&
                  config.attackConfig.enableMultiTurnGeneration
                ) {
                  const maxTurns = config.attackConfig.maxAdaptiveTurns ?? 15;
                  process.stdout.write(
                    `  ${catPrefix}${progress} ${attack.name} (adaptive, max ${maxTurns} turns)...`,
                  );

                  await prepareConversation(config);
                  const {
                    results: stepResults,
                    stoppedEarly,
                    conversationHistory,
                  } = await executeAdaptiveMultiTurn(
                    config,
                    attack,
                    async (cfg, atk, sc, b, t) => {
                      const r = await analyzeResponse(
                        cfg,
                        atk,
                        sc,
                        b,
                        t,
                        appContext,
                      );
                      return { verdict: r.verdict, findings: r.findings };
                    },
                  );

                  const lastStep = stepResults[stepResults.length - 1];
                  const result = await analyzeResponse(
                    config,
                    attack,
                    lastStep.statusCode,
                    lastStep.body,
                    lastStep.timeMs,
                    appContext,
                    lastStep.executionTrace,
                  );
                  result.stepIndex = lastStep.stepIndex;
                  result.totalSteps = stepResults.length;

                  const icon = getColoredIcon(result.verdict);
                  result.conversation = conversationHistory.map((ch) => ({
                    stepIndex: ch.stepIndex,
                    payload: { message: ch.userMessage },
                    statusCode: stepResults[ch.stepIndex]?.statusCode ?? 0,
                    responseBody: ch.aiResponse,
                    responseTimeMs: stepResults[ch.stepIndex]?.timeMs ?? 0,
                  }));

                  const earlyTag = stoppedEarly
                    ? ` (stopped at step ${lastStep.stepIndex + 1})`
                    : "";
                  console.log(
                    ` ${icon}${result.verdict} (${lastStep.statusCode}, ${lastStep.timeMs}ms)${earlyTag}`,
                  );
                  logFindings(result);
                  await maybeGenerateIdealResponse(config, result);

                  categoryResults.push(result);
                } else {
                  // Single-turn attack
                  process.stdout.write(
                    `  ${catPrefix}${progress} ${attack.name}...`,
                  );
                  await prepareConversation(config);
                  const { statusCode, body, timeMs, executionTrace } =
                    await executeAttack(config, attack);
                  const result = await analyzeResponse(
                    config,
                    attack,
                    statusCode,
                    body,
                    timeMs,
                    appContext,
                    executionTrace,
                  );

                  const icon = getColoredIcon(result.verdict);
                  console.log(
                    ` ${icon}${result.verdict} (${statusCode}, ${timeMs}ms)`,
                  );
                  logFindings(result);
                  await maybeGenerateIdealResponse(config, result);

                  categoryResults.push(result);
                }
              } catch (attackErr) {
                console.log(
                  ` ${catPrefix}[??] ERROR — ${attackErr instanceof Error ? attackErr.message : String(attackErr)}`,
                );
                categoryResults.push({
                  attack,
                  statusCode: 0,
                  responseBody: "",
                  responseTimeMs: 0,
                  verdict: "ERROR" as const,
                  findings: [
                    `Attack execution failed: ${attackErr instanceof Error ? attackErr.message : String(attackErr)}`,
                  ],
                });
              }
            }

            // Update progress counters
            const lastResult = categoryResults[categoryResults.length - 1];
            if (lastResult) {
              globalAttackCount++;
              if (lastResult.verdict === "PASS") globalPasses++;
              else if (lastResult.verdict === "FAIL") globalFails++;
              else if (lastResult.verdict === "PARTIAL") globalPartials++;
              else globalErrors++;
              const elapsed = Math.round((Date.now() - attackStartTime) / 1000);
              printProgressLine(
                globalAttackCount,
                knownTotalAttacks,
                globalPasses,
                globalFails,
                globalPartials,
                globalErrors,
                elapsed,
              );
              console.log(); // newline after progress bar
            }

            // Delay between requests
            if (config.attackConfig.delayBetweenRequestsMs > 0) {
              await sleep(config.attackConfig.delayBetweenRequestsMs);
            }
          }

          // Category complete — merge results and checkpoint
          roundResults.push(...categoryResults);
          if (!doneCategories.includes(categoryName)) {
            doneCategories.push(categoryName);
          }
          try {
            saveCliCheckpoint(
              rounds,
              round - 1,
              [...roundResults],
              [...doneCategories],
            );
            console.log(
              `  ${catPrefix}✅ Checkpoint saved after category "${categoryName}" (${roundResults.length} attacks, ${doneCategories.length} categories done)`,
            );
          } catch {
            /* ignore */
          }
        });
    });

    // Execute categories with concurrency pool
    await runWithConcurrency(categoryTasks, categoryParallelism);

    // ── Refinement pass: convert PARTIALs from this round ──
    const roundPartials = roundResults.filter((r) => r.verdict === "PARTIAL");
    if (roundPartials.length > 0 && config.attackConfig.enableLlmGeneration) {
      console.log(`\n  ── Refining ${roundPartials.length} PARTIAL results ──`);
      console.log(
        `  Generating refined attacks with LLM... this may take a while.`,
      );
      const refinedAttacks = await refinePartialAttacks(
        config,
        analysis,
        roundResults,
        round,
      );

      if (refinedAttacks.length > 0) {
        console.log("  Refinement planning complete.");
        knownTotalAttacks += refinedAttacks.length;
        console.log(`  Executing ${refinedAttacks.length} refined attacks`);
        printPlannedAttackReview(round, refinedAttacks, analysis, "refined");
        const refineApproved = await confirmAttackExecution(
          "  Proceed with refined attacks?",
          requireReviewConfirmation,
        );
        if (!refineApproved) {
          console.log("  Skipping refined attacks (user declined).");
        } else {
          // Group refined attacks by category and run with parallelism
          const refinedGroups = groupAttacksByCategory(refinedAttacks);
          const refinedCategoryNames = Array.from(refinedGroups.keys());
          const refinedSharedIndex = { value: 0 };
          const refinedResults: AttackResult[] = [];

          const refinedTasks = refinedCategoryNames.map((catName) => {
            const catAttacks = refinedGroups.get(catName)!;
            return (): Promise<void> =>
              withSessionScope(async () => {
                const catPrefix =
                  categoryParallelism > 1 ? `[${catName}] ` : "";

                for (const attack of catAttacks) {
                  refinedSharedIndex.value++;
                  const progress = `[R${refinedSharedIndex.value}/${refinedAttacks.length}]`;

                  try {
                    if (attack.steps && attack.steps.length > 0) {
                      const totalSteps = 1 + attack.steps.length;
                      process.stdout.write(
                        `  ${catPrefix}${progress} ${attack.name} (${totalSteps} steps)...`,
                      );

                      await prepareConversation(config);
                      const { results: stepResults, stoppedEarly } =
                        await executeMultiTurn(
                          config,
                          attack,
                          async (cfg, atk, sc, b, t) => {
                            const r = await analyzeResponse(
                              cfg,
                              atk,
                              sc,
                              b,
                              t,
                              appContext,
                            );
                            return { verdict: r.verdict, findings: r.findings };
                          },
                        );

                      const lastStep = stepResults[stepResults.length - 1];
                      const result = await analyzeResponse(
                        config,
                        attack,
                        lastStep.statusCode,
                        lastStep.body,
                        lastStep.timeMs,
                        appContext,
                        lastStep.executionTrace,
                      );
                      result.stepIndex = lastStep.stepIndex;
                      result.totalSteps = stepResults.length;
                      result.conversation = stepResults.map((sr) => ({
                        stepIndex: sr.stepIndex,
                        payload:
                          sr.stepIndex === 0
                            ? attack.payload
                            : (attack.steps?.[sr.stepIndex - 1]?.payload ?? {}),
                        statusCode: sr.statusCode,
                        responseBody: sr.body,
                        responseTimeMs: sr.timeMs,
                      }));

                      const icon = getColoredIcon(result.verdict);
                      const earlyTag = stoppedEarly
                        ? ` (stopped at step ${lastStep.stepIndex + 1})`
                        : "";
                      console.log(
                        ` ${icon}${result.verdict} (${lastStep.statusCode}, ${lastStep.timeMs}ms)${earlyTag}`,
                      );
                      logFindings(result);
                      await maybeGenerateIdealResponse(config, result);
                      refinedResults.push(result);
                    } else if (
                      config.attackConfig.enableAdaptiveMultiTurn &&
                      config.attackConfig.enableMultiTurnGeneration
                    ) {
                      const maxTurns =
                        config.attackConfig.maxAdaptiveTurns ?? 15;
                      process.stdout.write(
                        `  ${catPrefix}${progress} ${attack.name} (adaptive, max ${maxTurns} turns)...`,
                      );

                      await prepareConversation(config);
                      const {
                        results: stepResults,
                        stoppedEarly,
                        conversationHistory,
                      } = await executeAdaptiveMultiTurn(
                        config,
                        attack,
                        async (cfg, atk, sc, b, t) => {
                          const r = await analyzeResponse(
                            cfg,
                            atk,
                            sc,
                            b,
                            t,
                            appContext,
                          );
                          return { verdict: r.verdict, findings: r.findings };
                        },
                      );

                      const lastStep = stepResults[stepResults.length - 1];
                      const result = await analyzeResponse(
                        config,
                        attack,
                        lastStep.statusCode,
                        lastStep.body,
                        lastStep.timeMs,
                        appContext,
                        lastStep.executionTrace,
                      );
                      result.stepIndex = lastStep.stepIndex;
                      result.totalSteps = stepResults.length;
                      result.conversation = conversationHistory.map((ch) => ({
                        stepIndex: ch.stepIndex,
                        payload: { message: ch.userMessage },
                        statusCode: stepResults[ch.stepIndex]?.statusCode ?? 0,
                        responseBody: ch.aiResponse,
                        responseTimeMs: stepResults[ch.stepIndex]?.timeMs ?? 0,
                      }));

                      const icon = getColoredIcon(result.verdict);
                      const earlyTag = stoppedEarly
                        ? ` (stopped at step ${lastStep.stepIndex + 1})`
                        : "";
                      console.log(
                        ` ${icon}${result.verdict} (${lastStep.statusCode}, ${lastStep.timeMs}ms)${earlyTag}`,
                      );
                      logFindings(result);
                      await maybeGenerateIdealResponse(config, result);
                      refinedResults.push(result);
                    } else {
                      process.stdout.write(
                        `  ${catPrefix}${progress} ${attack.name}...`,
                      );
                      await prepareConversation(config);
                      const { statusCode, body, timeMs, executionTrace } =
                        await executeAttack(config, attack);
                      const result = await analyzeResponse(
                        config,
                        attack,
                        statusCode,
                        body,
                        timeMs,
                        appContext,
                        executionTrace,
                      );

                      const icon = getColoredIcon(result.verdict);
                      console.log(
                        ` ${icon}${result.verdict} (${statusCode}, ${timeMs}ms)`,
                      );
                      logFindings(result);
                      await maybeGenerateIdealResponse(config, result);
                      refinedResults.push(result);
                    }
                  } catch (refineErr) {
                    console.log(
                      ` ${catPrefix}[??] ERROR — ${refineErr instanceof Error ? refineErr.message : String(refineErr)}`,
                    );
                    refinedResults.push({
                      attack,
                      statusCode: 0,
                      responseBody: "",
                      responseTimeMs: 0,
                      verdict: "ERROR" as const,
                      findings: [
                        `Refined attack execution failed: ${refineErr instanceof Error ? refineErr.message : String(refineErr)}`,
                      ],
                    });
                  }

                  if (config.attackConfig.delayBetweenRequestsMs > 0) {
                    await sleep(config.attackConfig.delayBetweenRequestsMs);
                  }
                }
              });
          });

          await runWithConcurrency(refinedTasks, categoryParallelism);
          roundResults.push(...refinedResults);

          const refinedPasses = refinedResults.filter(
            (r) => r.verdict === "PASS",
          ).length;
          const refinedPartials = refinedResults.filter(
            (r) => r.verdict === "PARTIAL",
          ).length;
          console.log(
            `  Refinement: ${refinedPasses} converted to PASS, ${refinedPartials} still PARTIAL`,
          );
        }
      }
    }

    rounds.push({ round, results: roundResults });
    allPreviousResults = allPreviousResults.concat(roundResults);

    // Save checkpoint — full round complete (no partial results)
    try {
      saveCliCheckpoint(rounds, round);
      console.log(
        `  ✅ Checkpoint saved — round ${round} complete (${allPreviousResults.length} total results)`,
      );
    } catch (cpErr) {
      console.warn(
        `  ⚠ Checkpoint save failed: ${cpErr instanceof Error ? cpErr.message : String(cpErr)}`,
      );
    }

    const passCount = roundResults.filter((r) => r.verdict === "PASS").length;
    const failCount = roundResults.filter((r) => r.verdict === "FAIL").length;
    console.log(
      `  Round ${round}: ${passCount} vulns found, ${failCount} blocked`,
    );

    // Analyze round results to build per-category defense profiles for next round
    if (round < config.attackConfig.adaptiveRounds) {
      defenseProfiles = analyzeRound(roundResults, config, defenseProfiles);

      const blockedCategories = [...defenseProfiles.values()]
        .filter((p) => p.blockRate > 0)
        .sort((a, b) => b.blockRate - a.blockRate);

      if (blockedCategories.length > 0) {
        console.log(
          `\n  Defense analysis (${blockedCategories.length} categories with blocks):`,
        );
        for (const p of blockedCategories.slice(0, 10)) {
          console.log(
            `    ${p.category}: ${p.blockRate}% blocked → dominant defense: ${p.dominantDefense}`,
          );
        }
        if (blockedCategories.length > 10) {
          console.log(`    ... and ${blockedCategories.length - 10} more`);
        }
      }
    }
  }

  // Final progress bar
  const totalElapsed = Math.round((Date.now() - attackStartTime) / 1000);
  const mins = Math.floor(totalElapsed / 60);
  const secs = totalElapsed % 60;
  const timeStr = mins > 0 ? `${mins}m ${secs}s` : `${secs}s`;
  console.log(
    `\n  ${COLORS.bold}Attacks complete${COLORS.reset} — ${globalAttackCount} attacks in ${timeStr}`,
  );
  console.log(
    `  ${COLORS.red}${globalPasses} vulns${COLORS.reset} | ${COLORS.green}${globalFails} blocked${COLORS.reset} | ${COLORS.yellow}${globalPartials} partial${COLORS.reset} | ${COLORS.gray}${globalErrors} errors${COLORS.reset}`,
  );

  // 5. Generate report
  console.log("\n[5/5] Generating report...");
  if (cancelledByUser) {
    console.log(
      "  Report includes results from rounds executed before cancellation.",
    );
  }
  const targetUrl = targetLabel;
  const report = generateReport(
    targetUrl,
    rounds,
    staticResult,
    analysis.affectedFiles,
    discoveryIntel,
  );
  // Attach + print the per-scan LLM usage metrics (real tokens/latency/errors +
  // an estimated cost) before writing, so they persist in the report JSON.
  report.usage = usageCollector.summarize();
  for (const line of formatUsageSummary(report.usage)) {
    console.log(line);
  }
  const { jsonPath, mdPath } = writeReport(report);
  console.log(`  JSON: ${jsonPath}`);
  console.log(`  Markdown: ${mdPath}`);
  clearCliCheckpoint();

  printConsoleSummary(report);

  // Cleanup cloned repo
  if (clonedDir) {
    try {
      rmSync(clonedDir, { recursive: true, force: true });
    } catch {}
  }
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
