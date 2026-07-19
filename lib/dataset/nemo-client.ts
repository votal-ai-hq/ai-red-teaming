/**
 * Minimal HTTP client for the NeMo Data Designer microservice.
 *
 * Data Designer runs as a standalone microservice (Docker Compose for dev) and
 * exposes an HTTP API. Endpoint paths differ slightly across DD versions, so
 * they are configurable via env; the defaults target a local dev deployment.
 *
 *   NEMO_DATA_DESIGNER_URL   base url (default http://localhost:8080)
 *   NEMO_PREVIEW_PATH        default /v1/data-designer/preview
 *   NEMO_GENERATE_PATH       default /v1/data-designer/jobs
 *   API key (bearer): the first set of NEMO_API_KEY, NVIDIA_API_KEY (NIM), or
 *                     OPENAI_API_KEY — Data Designer is not NVIDIA-locked and
 *                     also backs generation with OpenAI (and other providers).
 *
 * This module is deliberately thin and network-only; all validation/writing
 * lives in `validate.ts` so it can be tested without a running service.
 *
 * See docs/specs/nemo-data-designer-datasets.md §4, §6, §7.
 */
import type { DataDesignerConfig } from "./nemo-config-builder.js";

export interface NemoClientOptions {
  baseUrl?: string;
  apiKey?: string;
  previewPath?: string;
  generatePath?: string;
  fetchImpl?: typeof fetch;
}

/** A raw record returned by Data Designer — column name → generated value. */
export type NemoRecord = Record<string, unknown>;

export class NemoDataDesignerClient {
  private readonly baseUrl: string;
  private readonly apiKey?: string;
  private readonly previewPath: string;
  private readonly generatePath: string;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: NemoClientOptions = {}) {
    this.baseUrl = (
      opts.baseUrl ??
      process.env.NEMO_DATA_DESIGNER_URL ??
      "http://localhost:8080"
    ).replace(/\/+$/, "");
    this.apiKey =
      opts.apiKey ??
      process.env.NEMO_API_KEY ??
      process.env.NVIDIA_API_KEY ??
      process.env.OPENAI_API_KEY;
    this.previewPath =
      opts.previewPath ??
      process.env.NEMO_PREVIEW_PATH ??
      "/v1/data-designer/preview";
    this.generatePath =
      opts.generatePath ??
      process.env.NEMO_GENERATE_PATH ??
      "/v1/data-designer/jobs";
    const f = opts.fetchImpl ?? globalThis.fetch;
    if (!f) {
      throw new Error(
        "global fetch is unavailable; Node >= 18 is required (see package.json engines)",
      );
    }
    this.fetchImpl = f;
  }

  private headers(): Record<string, string> {
    const h: Record<string, string> = { "Content-Type": "application/json" };
    if (this.apiKey) h.Authorization = `Bearer ${this.apiKey}`;
    return h;
  }

  private async post(path: string, body: unknown): Promise<unknown> {
    const url = `${this.baseUrl}${path}`;
    const res = await this.fetchImpl(url, {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify(body),
    });
    const text = await res.text();
    if (!res.ok) {
      throw new Error(
        `Data Designer ${path} -> HTTP ${res.status}: ${text.slice(0, 500)}`,
      );
    }
    return text ? JSON.parse(text) : {};
  }

  /**
   * Generate a small preview batch for inspection before a full run.
   * Returns whatever records the service produced (unvalidated).
   */
  async preview(config: DataDesignerConfig, n = 5): Promise<NemoRecord[]> {
    const out = await this.post(this.previewPath, {
      config,
      num_records: n,
    });
    return extractRecords(out);
  }

  /**
   * Generate the full dataset. Returns the produced records (unvalidated).
   * For large jobs a real deployment may return a job handle; this client
   * expects inline records or a `{ records: [...] }` envelope (see
   * `extractRecords`). Adjust `NEMO_GENERATE_PATH` if your DD version differs.
   */
  async generate(config: DataDesignerConfig, count?: number): Promise<NemoRecord[]> {
    const out = await this.post(this.generatePath, {
      config,
      num_records: count ?? config.count,
    });
    return extractRecords(out);
  }
}

/** Pull the record array out of a few common DD response envelopes. */
export function extractRecords(payload: unknown): NemoRecord[] {
  if (Array.isArray(payload)) return payload as NemoRecord[];
  if (payload && typeof payload === "object") {
    const o = payload as Record<string, unknown>;
    for (const key of ["records", "data", "results", "rows"]) {
      if (Array.isArray(o[key])) return o[key] as NemoRecord[];
    }
  }
  return [];
}
