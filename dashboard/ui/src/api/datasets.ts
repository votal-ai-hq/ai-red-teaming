import { apiFetch, apiStream } from "./client";

export interface DatasetSummary {
  path: string;
  name: string;
  family: string;
  kind: "security" | "quality";
  rowCount: number;
  histogram: Record<string, number>;
  sizeBytes: number;
}

export interface GenerateDatasetRequest {
  preset: string;
  out: string;
  count?: number;
  /** Optional: config (under configs/) whose codebase analysis seeds generation. */
  seedConfigPath?: string;
  /** LLM provider backing generation (e.g. "nim", "openai"). */
  provider?: string;
  /** Model id for the chosen provider (e.g. "gpt-4o-mini"). */
  generationModel?: string;
  /** Name of a saved AppProfile to tailor generation. */
  profileId?: string;
  /** "single" (default) or "multi" — multi emits [Turn N] transcripts (security only). */
  turnMode?: "single" | "multi";
  /** Max turns for multi-turn generation (2..8). */
  maxTurns?: number;
  /** Generation engine: a direct LLM engine id (openai | anthropic | openrouter
   *  | ollama) or "data-designer". Defaults to "openai". */
  backend?: string;
  /** Custom instructions injected into the generation prompt (iterate lever). */
  instructions?: string;
  /** Few-shot style examples the generator should match. */
  examples?: string[];
  /** Focus generation on a subset of the taxonomy (empty = full pool). */
  categories?: string[];
  severities?: string[];
  tasks?: string[];
  metrics?: string[];
  /** Preview/curate: generate + validate but don't write; return the rows. */
  preview?: boolean;
  /** Top-up: merge generated rows into the existing `out` file. */
  append?: boolean;
}

export interface GenerationProvider {
  id: string;
  label: string;
  defaultModel: string;
  suggestedModels: string[];
  apiKeyEnv: string;
  /** Whether the server has this provider's API key (or NEMO_API_KEY) set. */
  keyConfigured: boolean;
}

export function listGenerationProviders() {
  return apiFetch<{ providers: GenerationProvider[] }>(
    "/api/datasets/providers",
  );
}

export interface GenerationEngine {
  id: string;
  label: string;
  defaultModel: string;
  suggestedModels: string[];
  apiKeyEnv: string | null;
  keyConfigured: boolean;
}

export function listGenerationEngines() {
  return apiFetch<{ engines: GenerationEngine[] }>("/api/datasets/engines");
}

export interface DatasetTaxonomy {
  kind: "security" | "quality";
  family: string;
  categories?: string[];
  severities?: string[];
  tasks?: string[];
  metrics?: string[];
}

export function getDatasetTaxonomy(kind: string, family: string) {
  return apiFetch<DatasetTaxonomy>(
    `/api/datasets/taxonomy?kind=${kind}&family=${family}`,
  );
}

// --- App profiles (tailor generation to a specific target app) ---

export interface ProfileTool {
  name: string;
  description?: string;
  sensitive?: boolean;
}

export interface Policy {
  name: string;
  criteria: string;
  types?: string[];
}

export interface AppProfile {
  name: string;
  description?: string;
  systemPrompt?: string;
  businessRules?: string[];
  policies?: Policy[];
  tools?: ProfileTool[];
  roles?: string[];
  dataClasses?: string[];
  source?: string;
}

export interface ProfileSummary {
  name: string;
  description?: string;
  source?: string;
  toolCount: number;
  ruleCount: number;
  policyCount: number;
  roleCount: number;
}

export type ImportFormat =
  | "system-prompt"
  | "mcp-manifest"
  | "openapi"
  | "policy-doc";

export function listProfiles() {
  return apiFetch<{ profiles: ProfileSummary[] }>("/api/datasets/profiles");
}

/** Parse an artifact into a draft profile (not saved). */
export function importProfile(format: ImportFormat, content: string) {
  return apiFetch<{ profile: Partial<AppProfile> }>(
    "/api/datasets/profiles/import",
    { method: "POST", body: JSON.stringify({ format, content }) },
  );
}

export function saveProfile(profile: AppProfile) {
  return apiFetch<{ ok: true; path: string }>("/api/datasets/profiles", {
    method: "POST",
    body: JSON.stringify(profile),
  });
}

export interface GenerateDatasetResponse {
  out: string;
  rowCount: number;
  duplicatesDropped: number;
  histogram: Record<string, number>;
  summary: string;
  /** Present when seedConfigPath was used. */
  seeds?: { roles: number; surfaces: number };
  /** Present when a profileId / inline profile tailored generation. */
  profile?: { name: string; tools: number; rules: number; policies: number };
  /** Present when multi-turn generation was used. */
  turnMode?: "multi";
  maxTurns?: number;
  /** Which engine produced the rows. */
  backend?: string;
  /** Present when rows were appended to an existing dataset (top-up). */
  appended?: boolean;
  added?: number;
}

export interface CostEstimate {
  usd: number;
  calls: number;
  inputTokens: number;
  outputTokens: number;
  priced: boolean;
  note: string;
}

/** Rough pre-generation cost estimate for a direct engine. */
export function estimateGenerationCost(params: {
  backend: string;
  model?: string;
  count: number;
  turnMode?: "single" | "multi";
  maxTurns?: number;
}) {
  const q = new URLSearchParams({
    backend: params.backend,
    count: String(params.count),
    turnMode: params.turnMode ?? "single",
    maxTurns: String(params.maxTurns ?? 3),
  });
  if (params.model) q.set("model", params.model);
  return apiFetch<CostEstimate>(`/api/datasets/cost?${q.toString()}`);
}

/** Rename a dataset (its base name only — the family/kind directory is kept). */
export function renameDataset(body: { path: string; name: string }) {
  return apiFetch<{ path: string; name: string }>("/api/datasets/rename", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

/** Fetch a dataset rendered in an interop format (jsonl | csv) as text. */
export function fetchDatasetExport(path: string, format: "jsonl" | "csv") {
  return apiFetch<string>(
    `/api/datasets/export?path=${encodeURIComponent(path)}&format=${format}`,
  );
}

export function listDatasets() {
  return apiFetch<{ datasets: DatasetSummary[] }>("/api/datasets");
}

/** A single dataset row — shape varies by kind (security vs quality). */
export type DatasetRow = Record<string, unknown>;

export function getDatasetRows(path: string, limit = 200) {
  return apiFetch<{ path: string; total: number; rows: DatasetRow[] }>(
    `/api/datasets/rows?path=${encodeURIComponent(path)}&limit=${limit}`,
  );
}

/** Save a curated subset of rows as a dataset (after preview/curate). */
export function saveDatasetRows(body: {
  out: string;
  kind: "security" | "quality";
  rows: DatasetRow[];
  /** Top-up: merge into the existing file instead of replacing. */
  append?: boolean;
}) {
  return apiFetch<GenerateDatasetResponse>("/api/datasets/save", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export function generateDataset(body: GenerateDatasetRequest) {
  return apiFetch<GenerateDatasetResponse>("/api/datasets/generate", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

// --- streaming generation (OpenAI-direct) ---

export type GenerateStreamEvent =
  | { type: "start"; total: number; backend: string }
  | {
      type: "row";
      index: number;
      total: number;
      category: string;
      severity?: string;
      preview: string;
    }
  | ({ type: "done"; preview?: boolean; rows?: DatasetRow[] } & GenerateDatasetResponse)
  | { type: "error"; error: string; detail?: string; sampleErrors?: string[] };

/**
 * Generate with row-by-row NDJSON streaming. Calls `onEvent` for each event as
 * it arrives; resolves when the stream ends. Falls back to a normal request if
 * the server doesn't stream (older build).
 */
export async function generateDatasetStream(
  body: GenerateDatasetRequest,
  onEvent: (e: GenerateStreamEvent) => void,
): Promise<void> {
  const res = await apiStream("/api/datasets/generate", {
    method: "POST",
    body: JSON.stringify({ ...body, stream: true }),
  });
  if (!res.ok || !res.body) {
    const text = await res.text().catch(() => "");
    throw new Error(`API error ${res.status}: ${text}`);
  }
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    let nl: number;
    while ((nl = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (line) onEvent(JSON.parse(line) as GenerateStreamEvent);
    }
  }
  const tail = buf.trim();
  if (tail) onEvent(JSON.parse(tail) as GenerateStreamEvent);
}

// --- streaming quality evaluation (dataset scored against a target) ---

/** One scored row of a quality eval — the full trace for debugging. */
export interface QualityResultRow {
  row: {
    task?: string;
    name?: string;
    input?: string;
    reference?: string;
    expectedTools?: string[];
    metric?: string;
    note?: string;
  };
  score: number;
  pass: boolean;
  metric: string;
  scorer: "deterministic" | "judge";
  /** The target's response text (truncated in the report). */
  response: string;
  /** Tool calls the target actually made (tool-call metrics). */
  actualTools?: string[];
  statusCode: number;
  responseTimeMs: number;
  /** Judge reasoning (judge-scored rows only). */
  reasoning?: string;
  /** Set when the row could not be executed/scored. */
  error?: string;
}

export interface QualityEvalReport {
  timestamp: string;
  targetUrl: string;
  dataset?: string;
  passThreshold: number;
  summary: {
    total: number;
    scored: number;
    errors: number;
    score: number;
    passed: number;
    byMetric: Record<string, { count: number; mean: number; passed: number }>;
    byTask: Record<string, { count: number; mean: number; passed: number }>;
  };
  results: QualityResultRow[];
}

export type EvalQualityStreamEvent =
  | { type: "start"; total: number; threshold: number; skipped: number }
  | {
      type: "row";
      done: number;
      total: number;
      metric: string;
      score: number;
      pass: boolean;
      task?: string;
      error?: string;
    }
  | { type: "done"; report: QualityEvalReport }
  | { type: "error"; error: string; detail?: string };

export interface EvalQualityRequest {
  /** Inline target config (new target). Omit when reusing a previous scan. */
  config?: Record<string, unknown>;
  /** Reuse a previous scan's target: its saved config is loaded server-side. */
  fromRunId?: string;
  dataset: string;
  threshold?: number;
  concurrency?: number;
}

/** Run a quality eval and stream per-row PASS/FAIL progress via NDJSON. */
export async function evalQualityStream(
  body: EvalQualityRequest,
  onEvent: (e: EvalQualityStreamEvent) => void,
): Promise<void> {
  const res = await apiStream("/api/datasets/eval-quality", {
    method: "POST",
    body: JSON.stringify(body),
  });
  if (!res.ok || !res.body) {
    const text = await res.text().catch(() => "");
    throw new Error(`API error ${res.status}: ${text}`);
  }
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    let nl: number;
    while ((nl = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (line) onEvent(JSON.parse(line) as EvalQualityStreamEvent);
    }
  }
  const tail = buf.trim();
  if (tail) onEvent(JSON.parse(tail) as EvalQualityStreamEvent);
}

// --- persisted quality-eval reports (Evaluations tab) ---

export interface QualityReportMeta {
  id: string;
  filename: string;
  timestamp: string;
  dataset: string;
  targetUrl: string;
  score: number; // 0..100
  passed: number;
  total: number;
  errors: number;
  threshold: number;
}

export function listQualityReports() {
  return apiFetch<{ reports: QualityReportMeta[] }>("/api/quality-reports");
}

export function getQualityReport(filename: string) {
  return apiFetch<{ report: QualityEvalReport }>(
    `/api/quality-report/${encodeURIComponent(filename)}`,
  );
}

export interface EvalRunPoint {
  filename: string;
  timestamp: string;
  score: number;
  targetUrl: string;
  only: boolean;
  delta?: number;
}

export interface EvalTrend {
  dataset: string;
  runs: EvalRunPoint[];
  latestScore: number;
  totalDelta: number;
  minScore: number;
  maxScore: number;
}

export function listEvalRuns() {
  return apiFetch<{ trends: EvalTrend[] }>("/api/eval-runs");
}

export interface PromoteFindingRequest {
  row: {
    category: string;
    prompt: string;
    successCriteria: string;
    severity?: string;
    name?: string;
    source?: string;
  };
  out?: string;
}

export function promoteFinding(body: PromoteFindingRequest) {
  return apiFetch<{ out: string; added: boolean; rowCount: number }>(
    "/api/datasets/promote",
    { method: "POST", body: JSON.stringify(body) },
  );
}
