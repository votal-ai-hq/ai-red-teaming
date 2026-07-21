/**
 * Builds a NeMo Data Designer config for FUNCTIONAL-QUALITY datasets.
 * Pure (no I/O). Mirrors nemo-config-builder.ts but generates legitimate tasks
 * with reference answers / expected tool calls instead of attacks.
 *
 * See docs/specs/nemo-data-designer-datasets.md — quality datasets.
 */
import { resolveQualityPool, defaultMetrics } from "./quality-set.js";
import type {
  DataDesignerConfig,
  SamplerColumn,
  LlmTextColumn,
  LlmStructuredColumn,
} from "./nemo-config-builder.js";
import type { DatasetPreset, DatasetSeeds } from "./types.js";

const DEFAULT_ROLES = ["end user", "power user", "support agent"];
const DEFAULT_SURFACES = ["the assistant's available tools"];
const DEFAULT_MODEL = "meta/llama-3.3-70b-instruct";
const DEFAULT_ALIAS = "generator";
const DEFAULT_PROVIDER = "nim";

/** A profile-derived context block, formatted as a prompt preamble (or ""). */
function contextPreamble(context?: string): string {
  if (!context || !context.trim()) return "";
  return [
    "",
    "TARGET APPLICATION CONTEXT (tailor the case to this specific app):",
    context.trim(),
    "",
  ].join("\n");
}

/** Operator-supplied custom instructions block (see nemo-config-builder). */
function instructionsBlock(instructions?: string): string {
  if (!instructions || !instructions.trim()) return "";
  return [
    "",
    "OPERATOR INSTRUCTIONS (follow these closely; they refine how to write the case):",
    instructions.trim(),
    "",
  ].join("\n");
}

/** Few-shot style examples block (see nemo-config-builder). */
function examplesBlock(examples?: string[]): string {
  const cleaned = (examples ?? [])
    .map((e) => String(e ?? "").trim())
    .filter(Boolean)
    .slice(0, 8)
    .map((e) => e.slice(0, 500));
  if (cleaned.length === 0) return "";
  return [
    "",
    "STYLE EXAMPLES (match their shape, tone, and difficulty; do NOT copy them",
    "verbatim — produce a NEW case in the same spirit):",
    ...cleaned.map((e) => `- ${e}`),
    "",
  ].join("\n");
}

function inputTemplate(
  context?: string,
  instructions?: string,
  examples?: string[],
): string {
  return [
    "You are authoring a FUNCTIONAL evaluation case for an AI agent — a",
    "legitimate task the agent should handle correctly (not an attack).",
    contextPreamble(context),
    "Task type: {{task}}",
    "Graded on metric: {{metric}}",
    "Acting as: {{role}}",
    "Available surface: {{surface}}",
    instructionsBlock(instructions),
    examplesBlock(examples),
    "Write one realistic user request for this task, specific to the target",
    "application's domain and tools when context is given. Output ONLY the",
    "user's message — concrete and specific, no preamble.",
  ].join("\n");
}

function multiTurnInputTemplate(
  context?: string,
  instructions?: string,
  examples?: string[],
): string {
  return [
    "You are authoring a MULTI-TURN FUNCTIONAL evaluation case for an AI agent —",
    "a legitimate {{turns}}-message task conversation (not an attack) where each",
    "turn builds on the previous ones.",
    contextPreamble(context),
    "Task type: {{task}}",
    "Graded on metric: {{metric}}",
    "Acting as: {{role}}",
    "Available surface: {{surface}}",
    instructionsBlock(instructions),
    examplesBlock(examples),
    "Write a realistic conversation where the user completes this task across",
    "turns — e.g. an initial request, then a refinement, added detail, or a",
    "follow-up that depends on the earlier turns (testing context retention).",
    "The FINAL turn is the one whose answer is graded against the reference.",
    "Be specific to the target application's domain and tools when context is",
    "given.",
    "",
    "Output EXACTLY {{turns}} lines, one per turn, each prefixed with its marker:",
    "[Turn 1] <first user message>",
    "[Turn 2] <builds on turn 1>",
    "...",
    "[Turn {{turns}}] <final message that completes the task>",
    "",
    "Output ONLY the [Turn N] lines — no preamble, no quotes, no explanation.",
  ].join("\n");
}

function referenceTemplate(context?: string): string {
  return [
    "Given this functional eval case, produce the grading reference.",
    contextPreamble(context),
    "Task type: {{task}}",
    "Metric: {{metric}}",
    "User request: {{input}}",
    "",
    "Return: reference = the ideal correct answer (concise); expectedTools = a",
    "JSON array of the tool name(s) a correct agent would call, in order (empty",
    "array if the task needs no tools).",
  ].join("\n");
}

/**
 * Build a quality-dataset Data Designer config. Sampler columns (task, metric,
 * role, surface) precede the LLM columns, satisfying DD's seed-before-LLM rule.
 */
export function buildQualityDataDesignerConfig(
  preset: DatasetPreset,
  seeds?: DatasetSeeds,
): DataDesignerConfig {
  const tasks = resolveQualityPool(preset.family, preset.tasks);
  const metrics = preset.metrics ?? defaultMetrics(preset.family);
  const roles = seeds?.roles ?? preset.roles ?? DEFAULT_ROLES;
  const surfaces = seeds?.surfaces ?? preset.surfaces ?? DEFAULT_SURFACES;
  const model = preset.generationModel ?? DEFAULT_MODEL;
  const modelAlias = preset.modelAlias ?? DEFAULT_ALIAS;
  const provider = preset.provider ?? DEFAULT_PROVIDER;
  const count = preset.count ?? 300;
  const multiTurn = preset.turnMode === "multi";

  const samplers: SamplerColumn[] = [
    { type: "sampler", name: "task", samplerType: "category", values: tasks },
    { type: "sampler", name: "metric", samplerType: "category", values: metrics },
    { type: "sampler", name: "role", samplerType: "category", values: roles },
    { type: "sampler", name: "surface", samplerType: "category", values: surfaces },
  ];
  // Multi-turn: sample a turn count (2..maxTurns) the template renders as
  // {{turns}}. The scorer replays the [Turn N] input turn-by-turn.
  if (multiTurn) {
    const maxTurns = Math.min(8, Math.max(2, preset.maxTurns ?? 3));
    samplers.push({
      type: "sampler",
      name: "turns",
      samplerType: "category",
      values: Array.from({ length: maxTurns - 1 }, (_, i) => String(i + 2)),
    });
  }

  const inputCol: LlmTextColumn = {
    type: "llm-text",
    name: "input",
    modelAlias,
    prompt: multiTurn
      ? multiTurnInputTemplate(seeds?.context, preset.customInstructions, preset.examples)
      : inputTemplate(seeds?.context, preset.customInstructions, preset.examples),
  };

  const refCol: LlmStructuredColumn = {
    type: "llm-structured",
    name: "grading",
    modelAlias,
    prompt: referenceTemplate(seeds?.context),
    outputFields: [
      { name: "reference", description: "the ideal correct answer" },
      { name: "expectedTools", description: "JSON array of tool names a correct agent would call" },
    ],
  };

  return {
    version: 1,
    model,
    modelAlias,
    modelProvider: provider,
    modelConfigs: [{ alias: modelAlias, model, provider }],
    count,
    columns: [...samplers, inputCol, refCol],
    validators: [
      { name: "input-non-empty", kind: "python", detail: "reject rows with empty input" },
      { name: "reference-or-tools", kind: "python", detail: "require reference or expectedTools" },
    ],
  };
}
