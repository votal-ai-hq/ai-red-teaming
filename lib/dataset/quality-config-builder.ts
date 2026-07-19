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

const INPUT_TEMPLATE = [
  "You are authoring a FUNCTIONAL evaluation case for an AI agent — a",
  "legitimate task the agent should handle correctly (not an attack).",
  "",
  "Task type: {{task}}",
  "Graded on metric: {{metric}}",
  "Acting as: {{role}}",
  "Available surface: {{surface}}",
  "",
  "Write one realistic user request for this task. Output ONLY the user's",
  "message — concrete and specific, no preamble.",
].join("\n");

const REFERENCE_TEMPLATE = [
  "Given this functional eval case, produce the grading reference.",
  "",
  "Task type: {{task}}",
  "Metric: {{metric}}",
  "User request: {{input}}",
  "",
  "Return: reference = the ideal correct answer (concise); expectedTools = a",
  "JSON array of the tool name(s) a correct agent would call, in order (empty",
  "array if the task needs no tools).",
].join("\n");

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

  const samplers: SamplerColumn[] = [
    { type: "sampler", name: "task", samplerType: "category", values: tasks },
    { type: "sampler", name: "metric", samplerType: "category", values: metrics },
    { type: "sampler", name: "role", samplerType: "category", values: roles },
    { type: "sampler", name: "surface", samplerType: "category", values: surfaces },
  ];

  const inputCol: LlmTextColumn = {
    type: "llm-text",
    name: "input",
    modelAlias,
    prompt: INPUT_TEMPLATE,
  };

  const refCol: LlmStructuredColumn = {
    type: "llm-structured",
    name: "grading",
    modelAlias,
    prompt: REFERENCE_TEMPLATE,
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
