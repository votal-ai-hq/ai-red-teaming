import { apiFetch } from "./client";

export interface DatasetSummary {
  path: string;
  name: string;
  family: string;
  rowCount: number;
  histogram: Record<string, number>;
  sizeBytes: number;
}

export interface GenerateDatasetRequest {
  preset: string;
  out: string;
  count?: number;
}

export interface GenerateDatasetResponse {
  out: string;
  rowCount: number;
  duplicatesDropped: number;
  histogram: Record<string, number>;
  summary: string;
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
