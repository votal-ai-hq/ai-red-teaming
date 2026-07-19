import { apiFetch } from "./client";

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

// --- App profiles (tailor generation to a specific target app) ---

export interface ProfileTool {
  name: string;
  description?: string;
  sensitive?: boolean;
}

export interface AppProfile {
  name: string;
  description?: string;
  systemPrompt?: string;
  businessRules?: string[];
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
  roleCount: number;
}

export type ImportFormat = "system-prompt" | "mcp-manifest" | "openapi";

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
  profile?: { name: string; tools: number; rules: number };
}

export function listDatasets() {
  return apiFetch<{ datasets: DatasetSummary[] }>("/api/datasets");
}

export function generateDataset(body: GenerateDatasetRequest) {
  return apiFetch<GenerateDatasetResponse>("/api/datasets/generate", {
    method: "POST",
    body: JSON.stringify(body),
  });
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
