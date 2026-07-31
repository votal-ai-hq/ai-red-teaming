import OpenAI from "openai";
import type { ChatCompletionCreateParamsNonStreaming } from "openai/resources/chat/completions";
import type { Config } from "./types.js";
import { formatErrorDetails } from "./error-utils.js";
import { recordLlmUsage, classifyLlmError } from "./llm-usage.js";

export interface ChatMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

export interface ChatOptions {
  model: string;
  messages: ChatMessage[];
  temperature?: number;
  maxTokens?: number;
  /** Request JSON output from the model (OpenAI/OpenRouter only). */
  responseFormat?: "json_object";
  /** Coarse phase label for per-scan usage attribution (generation, judging, analysis, …). */
  phase?: string;
}

export interface LlmProvider {
  chat(options: ChatOptions): Promise<string>;
}

interface OpenAICompatibleRequestConfig {
  guardrails?: string[];
  /** Provider label for usage attribution, injected by createProvider(). */
  providerName?: string;
}

type TokenLimitField = "max_tokens" | "max_completion_tokens";

function prefersMaxCompletionTokens(model: string): boolean {
  return /(^|\/)(gpt-5|o1|o3|o4)(?:$|[-/])/i.test(model);
}

function shouldOmitTemperature(model: string): boolean {
  return prefersMaxCompletionTokens(model);
}

function buildOpenAIChatRequest(
  options: ChatOptions,
  tokenLimitField: TokenLimitField,
  requestConfig: OpenAICompatibleRequestConfig = {},
  omitTemperature = false,
): ChatCompletionCreateParamsNonStreaming & { guardrails?: string[] } {
  return {
    model: options.model,
    messages: options.messages,
    ...(omitTemperature ? {} : { temperature: options.temperature ?? 0 }),
    [tokenLimitField]: options.maxTokens ?? 4096,
    ...(options.responseFormat
      ? { response_format: { type: options.responseFormat } }
      : {}),
    ...(requestConfig.guardrails?.length
      ? { guardrails: requestConfig.guardrails }
      : {}),
  };
}

function shouldRetryWithAlternateTokenField(error: unknown): boolean {
  if (!(error instanceof OpenAI.BadRequestError)) {
    return false;
  }

  const message = error.message.toLowerCase();
  return (
    error.param === "max_tokens" ||
    error.param === "max_completion_tokens" ||
    (message.includes("unsupported parameter") &&
      (message.includes("max_tokens") ||
        message.includes("max_completion_tokens")))
  );
}

function shouldRetryWithoutTemperature(error: unknown): boolean {
  if (!(error instanceof OpenAI.BadRequestError)) {
    return false;
  }

  const message = error.message.toLowerCase();
  return (
    error.param === "temperature" ||
    (message.includes("temperature") &&
      (message.includes("unsupported") || message.includes("default (1)")))
  );
}

async function createOpenAICompatibleChatCompletion(
  client: OpenAI,
  options: ChatOptions,
  requestConfig: OpenAICompatibleRequestConfig = {},
): Promise<string> {
  const initialTokenLimitField: TokenLimitField = prefersMaxCompletionTokens(
    options.model,
  )
    ? "max_completion_tokens"
    : "max_tokens";
  const initialOmitTemperature = shouldOmitTemperature(options.model);

  // ── usage instrumentation ──
  const startedAt = Date.now();
  const providerName = requestConfig.providerName ?? "openai";

  try {
    const response = await client.chat.completions.create(
      buildOpenAIChatRequest(
        options,
        initialTokenLimitField,
        requestConfig,
        initialOmitTemperature,
      ),
    );
    recordLlmUsage({
      provider: providerName,
      model: options.model,
      phase: options.phase,
      inputTokens: response.usage?.prompt_tokens ?? 0,
      outputTokens: response.usage?.completion_tokens ?? 0,
      latencyMs: Date.now() - startedAt,
      ok: true,
      tokensReported: !!response.usage,
    });
    return response.choices[0]?.message?.content?.trim() ?? "";
  } catch (error) {
    const retryAlternateTokenField = shouldRetryWithAlternateTokenField(error);
    const retryWithoutTemperature =
      !initialOmitTemperature && shouldRetryWithoutTemperature(error);

    if (!retryAlternateTokenField && !retryWithoutTemperature) {
      recordLlmUsage({
        provider: providerName,
        model: options.model,
        phase: options.phase,
        latencyMs: Date.now() - startedAt,
        ok: false,
        errorKind: classifyLlmError(error),
        tokensReported: false,
      });
      const details = formatErrorDetails(error);
      const enriched = new Error(`LLM request failed: ${details}`);
      (enriched as any).skipConfig = true;
      throw enriched;
    }

    const fallbackTokenLimitField: TokenLimitField =
      retryAlternateTokenField && initialTokenLimitField === "max_tokens"
        ? "max_completion_tokens"
        : retryAlternateTokenField
          ? "max_tokens"
          : initialTokenLimitField;
    try {
      const response = await client.chat.completions.create(
        buildOpenAIChatRequest(
          options,
          fallbackTokenLimitField,
          requestConfig,
          initialOmitTemperature || retryWithoutTemperature,
        ),
      );
      recordLlmUsage({
        provider: providerName,
        model: options.model,
        phase: options.phase,
        inputTokens: response.usage?.prompt_tokens ?? 0,
        outputTokens: response.usage?.completion_tokens ?? 0,
        latencyMs: Date.now() - startedAt,
        ok: true,
        tokensReported: !!response.usage,
        retryCount: 1,
      });
      return response.choices[0]?.message?.content?.trim() ?? "";
    } catch (retryError) {
      recordLlmUsage({
        provider: providerName,
        model: options.model,
        phase: options.phase,
        latencyMs: Date.now() - startedAt,
        ok: false,
        errorKind: classifyLlmError(retryError),
        tokensReported: false,
        retryCount: 1,
      });
      throw retryError;
    }
  }
}

// ── OpenAI Provider ──

class OpenAIProvider implements LlmProvider {
  private client: OpenAI;
  private requestConfig: OpenAICompatibleRequestConfig;

  constructor(requestConfig: OpenAICompatibleRequestConfig = {}) {
    this.client = new OpenAI();
    this.requestConfig = requestConfig;
  }

  async chat(options: ChatOptions): Promise<string> {
    return createOpenAICompatibleChatCompletion(
      this.client,
      options,
      this.requestConfig,
    );
  }
}

// ── Anthropic Provider (uses fetch directly to avoid extra dependency) ──

class AnthropicProvider implements LlmProvider {
  private apiKey: string;

  constructor() {
    const key = process.env.ANTHROPIC_API_KEY;
    if (!key)
      throw new Error(
        "ANTHROPIC_API_KEY environment variable is required for anthropic provider",
      );
    this.apiKey = key;
  }

  async chat(options: ChatOptions): Promise<string> {
    const startedAt = Date.now();
    const systemMsg = options.messages.find((m) => m.role === "system");
    const nonSystemMsgs = options.messages.filter((m) => m.role !== "system");

    const body: Record<string, unknown> = {
      model: options.model,
      max_tokens: options.maxTokens ?? 4096,
      temperature: options.temperature ?? 0,
      messages: nonSystemMsgs.map((m) => ({
        role: m.role,
        content: m.content,
      })),
    };
    if (systemMsg) {
      body.system = systemMsg.content;
    }

    const MAX_RETRIES = 4;
    const RETRY_DELAYS_MS = [5000, 15000, 30000, 60000];
    let retries = 0;
    let retryInputTokens = 0;

    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
      let response: Response;
      try {
        response = await fetch("https://api.anthropic.com/v1/messages", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-api-key": this.apiKey,
            "anthropic-version": "2023-06-01",
          },
          body: JSON.stringify(body),
        });
      } catch (fetchErr) {
        if (attempt < MAX_RETRIES) {
          retries += 1;
          const delayMs = RETRY_DELAYS_MS[attempt];
          console.warn(
            `  [Anthropic] Network error – retrying in ${delayMs / 1000}s (attempt ${attempt + 1}/${MAX_RETRIES}): ${fetchErr instanceof Error ? fetchErr.message : String(fetchErr)}`,
          );
          await new Promise((resolve) => setTimeout(resolve, delayMs));
          continue;
        }
        recordLlmUsage({
          provider: "anthropic",
          model: options.model,
          phase: options.phase,
          latencyMs: Date.now() - startedAt,
          ok: false,
          errorKind: classifyLlmError(fetchErr),
          tokensReported: false,
          retryCount: retries,
          retryTokens: retryInputTokens,
        });
        throw new Error(
          `Anthropic API network error after ${MAX_RETRIES} retries: ${fetchErr instanceof Error ? fetchErr.message : String(fetchErr)}`,
        );
      }

      if (
        response.status === 529 ||
        response.status === 503 ||
        response.status === 429
      ) {
        if (attempt < MAX_RETRIES) {
          retries += 1;
          const delayMs = RETRY_DELAYS_MS[attempt];
          console.warn(
            `  [Anthropic] ${response.status} – retrying in ${delayMs / 1000}s (attempt ${attempt + 1}/${MAX_RETRIES})...`,
          );
          await new Promise((resolve) => setTimeout(resolve, delayMs));
          continue;
        }
      }

      if (!response.ok) {
        const err = await response.text();
        const apiError = new Error(`Anthropic API error ${response.status}: ${err}`);
        (apiError as { status?: number }).status = response.status;
        recordLlmUsage({
          provider: "anthropic",
          model: options.model,
          phase: options.phase,
          latencyMs: Date.now() - startedAt,
          ok: false,
          errorKind: classifyLlmError(apiError),
          tokensReported: false,
          retryCount: retries,
          retryTokens: retryInputTokens,
        });
        throw apiError;
      }

      const data = (await response.json()) as {
        content: { type: string; text: string }[];
        usage?: { input_tokens?: number; output_tokens?: number };
      };
      const textBlock = data.content.find((b) => b.type === "text");
      recordLlmUsage({
        provider: "anthropic",
        model: options.model,
        phase: options.phase,
        inputTokens: data.usage?.input_tokens ?? 0,
        outputTokens: data.usage?.output_tokens ?? 0,
        latencyMs: Date.now() - startedAt,
        ok: true,
        tokensReported: !!data.usage,
        retryCount: retries,
        retryTokens: retryInputTokens,
      });
      return textBlock?.text?.trim() ?? "";
    }

    recordLlmUsage({
      provider: "anthropic",
      model: options.model,
      phase: options.phase,
      latencyMs: Date.now() - startedAt,
      ok: false,
      errorKind: "other",
      tokensReported: false,
      retryCount: retries,
      retryTokens: retryInputTokens,
    });
    throw new Error(
      "Anthropic API error: max retries exceeded (529 Overloaded)",
    );
  }
}

// ── OpenRouter Provider (OpenAI-compatible API) ──

class OpenRouterProvider implements LlmProvider {
  private client: OpenAI;
  private requestConfig: OpenAICompatibleRequestConfig;

  constructor(requestConfig: OpenAICompatibleRequestConfig = {}) {
    const key = process.env.OPENROUTER_API_KEY;
    if (!key)
      throw new Error(
        "OPENROUTER_API_KEY environment variable is required for openrouter provider",
      );
    this.client = new OpenAI({
      baseURL: "https://openrouter.ai/api/v1",
      apiKey: key,
      defaultHeaders: {
        "HTTP-Referer":
          process.env.OPENROUTER_SITE_URL || "https://github.com/red-team-ai",
        "X-OpenRouter-Title": process.env.OPENROUTER_SITE_NAME || "Red Team AI",
      },
    });
    this.requestConfig = requestConfig;
  }

  async chat(options: ChatOptions): Promise<string> {
    return createOpenAICompatibleChatCompletion(
      this.client,
      options,
      this.requestConfig,
    );
  }
}

// ── Together AI Provider (OpenAI-compatible API) ──

class TogetherAIProvider implements LlmProvider {
  private client: OpenAI;
  private requestConfig: OpenAICompatibleRequestConfig;

  constructor(requestConfig: OpenAICompatibleRequestConfig = {}) {
    const key = process.env.TOGETHER_API_KEY;
    if (!key)
      throw new Error(
        "TOGETHER_API_KEY environment variable is required for together provider",
      );
    this.client = new OpenAI({
      baseURL: "https://api.together.xyz/v1",
      apiKey: key,
    });
    this.requestConfig = requestConfig;
  }

  async chat(options: ChatOptions): Promise<string> {
    return createOpenAICompatibleChatCompletion(
      this.client,
      options,
      this.requestConfig,
    );
  }
}

// ── Azure OpenAI Provider ──

class AzureOpenAIProvider implements LlmProvider {
  private client: OpenAI;
  private requestConfig: OpenAICompatibleRequestConfig;

  constructor(requestConfig: OpenAICompatibleRequestConfig = {}) {
    const apiKey = process.env.AZURE_OPENAI_API_KEY;
    const endpoint = process.env.AZURE_OPENAI_ENDPOINT; // e.g. https://myresource.openai.azure.com
    const apiVersion = process.env.AZURE_OPENAI_API_VERSION || "2024-06-01";

    if (!apiKey)
      throw new Error(
        "AZURE_OPENAI_API_KEY environment variable is required for azure provider",
      );
    if (!endpoint)
      throw new Error(
        "AZURE_OPENAI_ENDPOINT environment variable is required for azure provider (e.g. https://myresource.openai.azure.com)",
      );

    this.client = new OpenAI({
      apiKey,
      baseURL: `${endpoint.replace(/\/+$/, "")}/openai/deployments`,
      defaultQuery: { "api-version": apiVersion },
      defaultHeaders: { "api-key": apiKey },
    });
    this.requestConfig = requestConfig;
  }

  async chat(options: ChatOptions): Promise<string> {
    return createOpenAICompatibleChatCompletion(
      this.client,
      options,
      this.requestConfig,
    );
  }
}

// ── NVIDIA NIM Provider (OpenAI-compatible API) ──
// Cloud default: https://integrate.api.nvidia.com/v1
// Self-hosted: set NIM_BASE_URL to override (e.g. http://localhost:8000/v1)
// Env: NVIDIA_API_KEY (required for cloud; optional for self-hosted if NIM_BASE_URL is set)
// Model name is passed straight through — any model NIM exposes works.

function isNimModelNotFound(err: unknown): boolean {
  if (!(err instanceof Error)) return false;
  // NIM's gateway returns `404 page not found` when the model id doesn't
  // match a registered route — there is no structured "model not found" body.
  return /\b404\b/.test(err.message) && /page not found/i.test(err.message);
}

class NimProvider implements LlmProvider {
  private client: OpenAI;
  private requestConfig: OpenAICompatibleRequestConfig;

  constructor(requestConfig: OpenAICompatibleRequestConfig = {}) {
    const baseURL =
      process.env.NIM_BASE_URL || "https://integrate.api.nvidia.com/v1";
    const apiKey = process.env.NVIDIA_API_KEY;
    const isSelfHosted = Boolean(process.env.NIM_BASE_URL);

    if (!apiKey && !isSelfHosted) {
      throw new Error(
        "NVIDIA_API_KEY environment variable is required for nim provider (set NIM_BASE_URL to point at a self-hosted NIM endpoint that does not require auth)",
      );
    }

    this.client = new OpenAI({
      apiKey: apiKey || "no-key",
      baseURL,
    });
    this.requestConfig = requestConfig;
    console.log(`  [LLM nim] baseURL=${baseURL}`);
  }

  async chat(options: ChatOptions): Promise<string> {
    try {
      return await createOpenAICompatibleChatCompletion(
        this.client,
        options,
        this.requestConfig,
      );
    } catch (err) {
      if (isNimModelNotFound(err)) {
        const original = err instanceof Error ? err.message : String(err);
        const rewritten = new Error(
          `NIM model "${options.model}" not found. Verify the model id at https://build.nvidia.com/models (or your self-hosted NIM's /v1/models). [Original: ${original}]`,
        );
        (rewritten as any).skipConfig = true;
        throw rewritten;
      }
      throw err;
    }
  }
}

// ── HuggingFace Provider (OpenAI-compatible API) ──
// Serverless default: https://router.huggingface.co/v1 (Inference Providers router).
// Use the model id form "owner/model" or "owner/model:provider" (e.g.
// "meta-llama/Llama-3.3-70B-Instruct:nvidia") to pin a backend provider — the
// ":nvidia" suffix routes to NVIDIA NIM.
// Dedicated Inference Endpoints: set HF_BASE_URL to your endpoint's /v1 URL
// (e.g. https://<id>.<region>.aws.endpoints.huggingface.cloud/v1).
// Env: HF_TOKEN (preferred) or HUGGINGFACE_API_KEY. Required unless HF_BASE_URL
// points at an endpoint that does not require auth.

class HuggingFaceProvider implements LlmProvider {
  private client: OpenAI;
  private requestConfig: OpenAICompatibleRequestConfig;

  constructor(requestConfig: OpenAICompatibleRequestConfig = {}) {
    const baseURL =
      process.env.HF_BASE_URL || "https://router.huggingface.co/v1";
    const apiKey = process.env.HF_TOKEN || process.env.HUGGINGFACE_API_KEY;
    const isCustomBaseUrl = Boolean(process.env.HF_BASE_URL);

    if (!apiKey && !isCustomBaseUrl) {
      throw new Error(
        "HF_TOKEN (or HUGGINGFACE_API_KEY) environment variable is required for huggingface provider (set HF_BASE_URL to point at a dedicated/self-hosted endpoint that does not require auth)",
      );
    }

    this.client = new OpenAI({
      apiKey: apiKey || "no-key",
      baseURL,
    });
    this.requestConfig = requestConfig;
    console.log(`  [LLM huggingface] baseURL=${baseURL}`);
  }

  async chat(options: ChatOptions): Promise<string> {
    return createOpenAICompatibleChatCompletion(
      this.client,
      options,
      this.requestConfig,
    );
  }
}

// ── Custom OpenAI-compatible Provider ──
// For internal endpoints like Trussed AI, vLLM, LiteLLM, Ollama, etc.
// Env: CUSTOM_LLM_API_KEY, CUSTOM_LLM_BASE_URL

class CustomProvider implements LlmProvider {
  private client: OpenAI;
  private requestConfig: OpenAICompatibleRequestConfig;

  constructor(requestConfig: OpenAICompatibleRequestConfig = {}) {
    const baseURL = process.env.CUSTOM_LLM_BASE_URL;
    if (!baseURL)
      throw new Error(
        "CUSTOM_LLM_BASE_URL environment variable is required for custom provider (e.g. https://your-internal-gateway.com/v1)",
      );

    // Skip TLS verification for internal endpoints with self-signed/corporate certs
    if (
      process.env.CUSTOM_LLM_SKIP_TLS_VERIFY === "true" ||
      process.env.CUSTOM_LLM_SKIP_TLS_VERIFY === "1"
    ) {
      process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
    }

    this.client = new OpenAI({
      apiKey: process.env.CUSTOM_LLM_API_KEY || "no-key",
      baseURL,
    });
    this.requestConfig = requestConfig;
    console.log(`  [LLM custom] baseURL=${baseURL}`);
  }

  async chat(options: ChatOptions): Promise<string> {
    return createOpenAICompatibleChatCompletion(
      this.client,
      options,
      this.requestConfig,
    );
  }
}

// ── Factory ──

const providerCache = new Map<string, LlmProvider>();

function createProvider(
  name: string,
  requestConfig: OpenAICompatibleRequestConfig = {},
): LlmProvider {
  // Provider names are case-insensitive (callers may pass "OpenAI", "Anthropic").
  name = (name ?? "").toLowerCase();
  const cacheKey = `${name}:${JSON.stringify(requestConfig.guardrails ?? [])}`;
  if (providerCache.has(cacheKey)) {
    return providerCache.get(cacheKey)!;
  }
  // Label the provider so the OpenAI-compatible helper can attribute usage to it.
  requestConfig.providerName = name;

  let provider: LlmProvider;
  switch (name) {
    case "openai":
      provider = new OpenAIProvider(requestConfig);
      break;
    case "anthropic":
      provider = new AnthropicProvider();
      break;
    case "openrouter":
      provider = new OpenRouterProvider(requestConfig);
      break;
    case "together":
      provider = new TogetherAIProvider(requestConfig);
      break;
    case "azure":
      provider = new AzureOpenAIProvider(requestConfig);
      break;
    case "custom":
      provider = new CustomProvider(requestConfig);
      break;
    case "nim":
      provider = new NimProvider(requestConfig);
      break;
    case "huggingface":
      provider = new HuggingFaceProvider(requestConfig);
      break;
    default:
      throw new Error(
        `Unknown LLM provider: "${name}". Use "openai", "anthropic", "openrouter", "together", "azure", "custom", "nim", or "huggingface".`,
      );
  }

  providerCache.set(cacheKey, provider);
  return provider;
}

/** Get the LLM provider for attack generation. */
export function getLlmProvider(config: Config): LlmProvider {
  return createProvider(config.attackConfig.llmProvider, {
    guardrails: config.attackConfig.llmGuardrails,
  });
}

/** Get the LLM provider for the judge. Falls back to the attack provider if judgeProvider is not set. */
export function getJudgeProvider(config: Config): LlmProvider {
  const judgeName =
    config.attackConfig.judgeProvider ?? config.attackConfig.llmProvider;
  return createProvider(judgeName, {
    guardrails:
      config.attackConfig.judgeGuardrails ??
      (judgeName === config.attackConfig.llmProvider
        ? config.attackConfig.llmGuardrails
        : undefined),
  });
}

/**
 * Known-good default judge model per provider. Used when a caller specifies a
 * provider but no model. Keeping the model paired with its provider prevents the
 * cross-provider mismatch that breaks the on-demand analysis endpoints — e.g. an
 * OpenRouter slug ("anthropic/claude-sonnet-4.5") being POSTed to the Anthropic
 * API, which returns 404 and silently empties the analysis.
 */
export const DEFAULT_JUDGE_MODELS: Record<string, string> = {
  anthropic: "claude-sonnet-4-6",
  openai: "gpt-4o",
  openrouter: "anthropic/claude-sonnet-4.5",
};

/**
 * Resolve a COHERENT { provider, model } pair for the judge / on-demand analysis
 * LLM. Precedence for the model: explicit request model → the config model *only
 * when it belongs to the same provider* → the per-provider default. A provider is
 * never paired with a different provider's model.
 */
export function resolveJudgeProviderModel(opts: {
  requestProvider?: string | null;
  requestModel?: string | null;
  configProvider?: string | null;
  configModel?: string | null;
}): { provider: string; model: string } {
  const norm = (s?: string | null) => (s ?? "").trim().toLowerCase();
  const provider =
    norm(opts.requestProvider) || norm(opts.configProvider) || "anthropic";

  // An explicitly requested model always wins.
  let model = (opts.requestModel ?? "").trim();
  if (!model) {
    // Inherit the config model only when it belongs to the resolved provider;
    // otherwise fall back to that provider's known-good default.
    if (opts.configModel && norm(opts.configProvider) === provider) {
      model = opts.configModel.trim();
    } else {
      model = DEFAULT_JUDGE_MODELS[provider] || (opts.configModel ?? "").trim();
    }
  }
  if (!model) model = DEFAULT_JUDGE_MODELS.anthropic;
  return { provider, model };
}
