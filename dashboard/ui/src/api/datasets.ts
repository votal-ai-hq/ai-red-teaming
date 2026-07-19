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
}

export interface GenerateDatasetResponse {
  out: string;
  rowCount: number;
  duplicatesDropped: number;
  histogram: Record<string, number>;
  summary: string;
  /** Present when seedConfigPath was used. */
  seeds?: { roles: number; surfaces: number };
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
