/**
 * Generation engines for the "direct" dataset-generation path (no NeMo Data
 * Designer service). Single source of truth for which providers the dashboard
 * offers, their default models, and which env var holds the API key — the UI
 * reads it via GET /api/datasets/engines so the two can't drift.
 *
 * OpenAI, OpenRouter, and Ollama are OpenAI-compatible (same chat/completions
 * wire format) and share one ChatFn built on the OpenAI SDK with a per-engine
 * baseURL. Anthropic uses its own Messages API (raw fetch, see anthropic-chat).
 */
import { openAiChat, type ChatFn } from "./openai-generator.js";
import { anthropicChat } from "./anthropic-chat.js";

export type EngineId = "openai" | "anthropic" | "openrouter" | "ollama";

export interface EngineInfo {
  id: EngineId;
  label: string;
  /** "openai-compat" → OpenAI SDK + baseURL; "anthropic" → Messages API. */
  kind: "openai-compat" | "anthropic";
  defaultModel: string;
  suggestedModels: string[];
  /** Env var holding the API key. Absent for keyless local engines (Ollama). */
  apiKeyEnv?: string;
  /** Env var that can override the base URL. */
  baseUrlEnv?: string;
  /** Fallback base URL when baseUrlEnv is unset (OpenAI-compat engines). */
  defaultBaseUrl?: string;
}

export const GENERATION_ENGINES: EngineInfo[] = [
  {
    id: "openai",
    label: "OpenAI",
    kind: "openai-compat",
    defaultModel: "gpt-4o-mini",
    suggestedModels: ["gpt-4o-mini", "gpt-4o", "gpt-4.1-mini"],
    apiKeyEnv: "OPENAI_API_KEY",
  },
  {
    id: "anthropic",
    label: "Anthropic",
    kind: "anthropic",
    defaultModel: "claude-opus-4-8",
    suggestedModels: ["claude-opus-4-8", "claude-sonnet-5", "claude-haiku-4-5"],
    apiKeyEnv: "ANTHROPIC_API_KEY",
  },
  {
    id: "openrouter",
    label: "OpenRouter",
    kind: "openai-compat",
    defaultModel: "openai/gpt-4o-mini",
    suggestedModels: [
      "openai/gpt-4o-mini",
      "anthropic/claude-opus-4-8",
      "meta-llama/llama-3.1-70b-instruct",
    ],
    apiKeyEnv: "OPENROUTER_API_KEY",
    defaultBaseUrl: "https://openrouter.ai/api/v1",
  },
  {
    id: "ollama",
    label: "Ollama (local)",
    kind: "openai-compat",
    defaultModel: "llama3.1",
    suggestedModels: ["llama3.1", "qwen2.5", "mistral"],
    baseUrlEnv: "OLLAMA_BASE_URL",
    defaultBaseUrl: "http://localhost:11434/v1",
  },
];

export function getEngine(id: string): EngineInfo | undefined {
  return GENERATION_ENGINES.find((e) => e.id === id);
}

export function isEngineId(x: unknown): x is EngineId {
  return GENERATION_ENGINES.some((e) => e.id === x);
}

/** Whether the engine can run: its API key is set (or it's keyless). */
export function engineKeyConfigured(e: EngineInfo): boolean {
  if (!e.apiKeyEnv) return true; // keyless (Ollama)
  return Boolean(process.env[e.apiKeyEnv] || process.env.NEMO_API_KEY);
}

/**
 * Build a ChatFn for an engine. Throws if a required API key is missing.
 */
export function resolveChat(id: EngineId): ChatFn {
  const engine = getEngine(id);
  if (!engine) throw new Error(`unknown generation engine "${id}"`);

  if (engine.kind === "anthropic") {
    const key = process.env[engine.apiKeyEnv!];
    if (!key) {
      throw new Error(`${engine.apiKeyEnv} is required for the Anthropic engine`);
    }
    return anthropicChat(key);
  }

  // OpenAI-compatible (OpenAI / OpenRouter / Ollama)
  const key = engine.apiKeyEnv ? process.env[engine.apiKeyEnv] : undefined;
  if (engine.apiKeyEnv && !key) {
    throw new Error(`${engine.apiKeyEnv} is required for the ${engine.label} engine`);
  }
  const baseURL =
    (engine.baseUrlEnv ? process.env[engine.baseUrlEnv] : undefined) ??
    engine.defaultBaseUrl;
  // Ollama needs a non-empty key string even though it's ignored.
  return openAiChat(key ?? "ollama", baseURL);
}
