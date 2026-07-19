/**
 * Generation-provider registry for dataset generation.
 *
 * Data Designer is the orchestrator; the provider here is the LLM backing it
 * (see docs/specs/nemo-data-designer-datasets.md §6). This is the single
 * source of truth for which providers the dashboard/API accept, their default
 * models, and which env var must hold the API key — the UI reads it via
 * GET /api/datasets/providers so the two can't drift.
 */
import type { DatasetPreset } from "./types.js";

export type DatasetProviderId = "nim" | "openai";

export interface DatasetProviderInfo {
  id: DatasetProviderId;
  label: string;
  defaultModel: string;
  /** Curated suggestions; any model id matching MODEL_ID_RE is accepted. */
  suggestedModels: string[];
  apiKeyEnv: string;
}

export const DATASET_PROVIDERS: DatasetProviderInfo[] = [
  {
    id: "nim",
    label: "NVIDIA NIM",
    defaultModel: "meta/llama-3.3-70b-instruct",
    suggestedModels: [
      "meta/llama-3.3-70b-instruct",
      "meta/llama-3.1-8b-instruct",
      "mistralai/mixtral-8x22b-instruct-v0.1",
    ],
    apiKeyEnv: "NVIDIA_API_KEY",
  },
  {
    id: "openai",
    label: "OpenAI",
    defaultModel: "gpt-4o-mini",
    suggestedModels: ["gpt-4o-mini", "gpt-4o", "gpt-4.1-mini"],
    apiKeyEnv: "OPENAI_API_KEY",
  },
];

export function isDatasetProvider(x: unknown): x is DatasetProviderId {
  return DATASET_PROVIDERS.some((p) => p.id === x);
}

/** Model ids look like "gpt-4o-mini" or "meta/llama-3.3-70b-instruct". */
const MODEL_ID_RE = /^[\w.:-]+(\/[\w.:-]+)*$/;

/**
 * Apply user-chosen provider/model overrides onto a loaded preset.
 * Returns an error string (for a 400) or null on success. A provider override
 * without a model falls back to that provider's default model rather than
 * keeping the preset's model, which likely belongs to the previous provider.
 */
export function applyGenerationOverrides(
  preset: DatasetPreset,
  overrides: { provider?: unknown; generationModel?: unknown },
): string | null {
  const { provider, generationModel } = overrides;

  if (provider !== undefined) {
    if (!isDatasetProvider(provider)) {
      const known = DATASET_PROVIDERS.map((p) => p.id).join(", ");
      return `unknown provider "${String(provider)}" (expected one of: ${known})`;
    }
    preset.provider = provider;
    preset.generationModel = DATASET_PROVIDERS.find(
      (p) => p.id === provider,
    )!.defaultModel;
  }

  if (generationModel !== undefined) {
    if (typeof generationModel !== "string") {
      return "generationModel must be a string";
    }
    const model = generationModel.trim();
    if (!model || model.length > 100 || !MODEL_ID_RE.test(model)) {
      return `invalid generationModel "${generationModel}"`;
    }
    preset.generationModel = model;
  }

  return null;
}
