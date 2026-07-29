import { useState, useEffect } from "react";
import {
  listDatasets,
  generateDataset,
  generateDatasetStream,
  listEvalRuns,
  listGenerationProviders,
  listGenerationEngines,
  getDatasetTaxonomy,
  saveDatasetRows,
  renameDataset,
  estimateGenerationCost,
  fetchDatasetExport,
  listProfiles,
  getDatasetRows,
  type DatasetRow,
  type DatasetSummary,
  type DatasetTaxonomy,
  type EvalTrend,
  type GenerationProvider,
  type GenerationEngine,
  type ProfileSummary,
  type CostEstimate,
} from "@/api/datasets";
import { ProfileWizard } from "./ProfileWizard";
import { getReference } from "@/api/reference";
import { CompliancePresets } from "@/components/shared/CompliancePresets";
import type { CategoryComplianceRef, ReferenceFramework } from "@/api/types";
import { useNavigate } from "react-router";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Database,
  Loader2,
  RefreshCw,
  Sparkles,
  AlertTriangle,
  CheckCircle2,
  TrendingUp,
  TrendingDown,
  Minus,
  LineChart,
  Wand2,
  ChevronRight,
  ChevronDown,
  ArrowRight,
  Download,
  Copy,
  Pencil,
} from "lucide-react";

const PRESETS: Record<string, string> = {
  "security-mcp": "configs/datasets/nemo-mcp.preset.json",
  "security-agent": "configs/datasets/nemo-agent.preset.json",
  "quality-mcp": "configs/datasets/nemo-mcp-quality.preset.json",
  "quality-agent": "configs/datasets/nemo-agent-quality.preset.json",
};

/** Used until /api/datasets/providers answers (or if it's unavailable). */
const FALLBACK_PROVIDERS: GenerationProvider[] = [
  {
    id: "nim",
    label: "NVIDIA NIM",
    defaultModel: "meta/llama-3.3-70b-instruct",
    suggestedModels: ["meta/llama-3.3-70b-instruct"],
    apiKeyEnv: "NVIDIA_API_KEY",
    keyConfigured: true,
  },
  {
    id: "openai",
    label: "OpenAI",
    defaultModel: "gpt-4o-mini",
    suggestedModels: ["gpt-4o-mini", "gpt-4o"],
    apiKeyEnv: "OPENAI_API_KEY",
    keyConfigured: true,
  },
];

/** Direct-generation engines, used until /api/datasets/engines answers. */
const FALLBACK_ENGINES: GenerationEngine[] = [
  { id: "openai", label: "OpenAI", defaultModel: "gpt-4o-mini", suggestedModels: ["gpt-4o-mini", "gpt-4o"], apiKeyEnv: "OPENAI_API_KEY", keyConfigured: true },
  { id: "anthropic", label: "Anthropic", defaultModel: "claude-opus-4-8", suggestedModels: ["claude-opus-4-8", "claude-sonnet-5"], apiKeyEnv: "ANTHROPIC_API_KEY", keyConfigured: true },
  { id: "openrouter", label: "OpenRouter", defaultModel: "openai/gpt-4o-mini", suggestedModels: ["openai/gpt-4o-mini", "anthropic/claude-opus-4-8"], apiKeyEnv: "OPENROUTER_API_KEY", keyConfigured: true },
  { id: "ollama", label: "Ollama (local)", defaultModel: "llama3.1", suggestedModels: ["llama3.1", "qwen2.5"], apiKeyEnv: null, keyConfigured: true },
];

function topCategories(hist: Record<string, number>, n = 4): string[] {
  return Object.entries(hist)
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([c, k]) => `${c} (${k})`);
}

/** Minimal dependency-free score sparkline (0–100 scale). */
function Sparkline({ scores }: { scores: number[] }) {
  const w = 120;
  const h = 28;
  const pad = 2;
  if (scores.length === 0) return null;
  if (scores.length === 1) {
    const y = h - pad - (scores[0] / 100) * (h - 2 * pad);
    return (
      <svg width={w} height={h} role="img" aria-label={`Score ${scores[0]}`}>
        <circle cx={w / 2} cy={y} r={2.5} className="fill-primary" />
      </svg>
    );
  }
  const step = (w - 2 * pad) / (scores.length - 1);
  const pts = scores.map((s, i) => {
    const x = pad + i * step;
    const y = h - pad - (s / 100) * (h - 2 * pad);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });
  return (
    <svg
      width={w}
      height={h}
      role="img"
      aria-label={`Score trend: ${scores.join(", ")}`}
    >
      <polyline
        points={pts.join(" ")}
        fill="none"
        strokeWidth={1.5}
        className="stroke-primary"
      />
      <circle
        cx={pts[pts.length - 1].split(",")[0]}
        cy={pts[pts.length - 1].split(",")[1]}
        r={2.5}
        className="fill-primary"
      />
    </svg>
  );
}

function DeltaBadge({ delta }: { delta: number }) {
  if (delta === 0)
    return (
      <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
        <Minus className="w-3 h-3" /> 0
      </span>
    );
  const up = delta > 0;
  return (
    <span
      className={`inline-flex items-center gap-1 text-xs font-medium ${up ? "text-emerald-600 dark:text-emerald-400" : "text-red-600 dark:text-red-400"}`}
    >
      {up ? (
        <TrendingUp className="w-3 h-3" />
      ) : (
        <TrendingDown className="w-3 h-3" />
      )}
      {up ? "+" : ""}
      {delta}
    </span>
  );
}

function datasetLabel(path: string): string {
  return path.replace(/^data\/datasets\//, "");
}

function str(v: unknown): string {
  return v == null ? "" : String(v);
}

/** One dataset row rendered for either kind (security prompt / quality input). */
function RowItem({ row }: { row: DatasetRow }) {
  const kindLabel = str(row.category) || str(row.task);
  const main = str(row.prompt) || str(row.input);
  const severity = str(row.severity);
  const criteria = str(row.successCriteria) || str(row.reference);
  const tools = Array.isArray(row.expectedTools)
    ? (row.expectedTools as unknown[]).map(String)
    : [];
  return (
    <div className="rounded-md border border-border p-2 space-y-1">
      <div className="flex flex-wrap items-center gap-1.5">
        {kindLabel && (
          <Badge variant="secondary" className="text-[10px]">
            {kindLabel}
          </Badge>
        )}
        {severity && (
          <Badge variant="outline" className="text-[10px]">
            {severity}
          </Badge>
        )}
        {str(row.name) && (
          <span className="text-[10px] text-muted-foreground truncate">
            {str(row.name)}
          </span>
        )}
      </div>
      <p className="text-xs text-foreground whitespace-pre-wrap break-words">
        {main}
      </p>
      {criteria && (
        <p className="text-[11px] text-muted-foreground">
          <span className="font-medium">grades as success if:</span> {criteria}
        </p>
      )}
      {tools.length > 0 && (
        <p className="text-[11px] text-muted-foreground">
          <span className="font-medium">expected tools:</span> {tools.join(", ")}
        </p>
      )}
    </div>
  );
}

/** A dataset summary card that expands to show its rows on demand. */
function DatasetCard({
  d,
  onChanged,
}: {
  d: DatasetSummary;
  onChanged: () => void;
}) {
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [rows, setRows] = useState<DatasetRow[] | null>(null);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [exporting, setExporting] = useState<"jsonl" | "csv" | null>(null);
  const [showEvalCmd, setShowEvalCmd] = useState(false);
  const [copied, setCopied] = useState(false);
  const [renaming, setRenaming] = useState(false);
  const [draftName, setDraftName] = useState(d.name);
  const [savingName, setSavingName] = useState(false);

  const submitRename = async () => {
    const next = draftName.trim();
    if (!next || next === d.name) {
      setRenaming(false);
      return;
    }
    setSavingName(true);
    setErr(null);
    try {
      await renameDataset({ path: d.path, name: next });
      setRenaming(false);
      onChanged();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setSavingName(false);
    }
  };

  // Quality datasets are scored by the CLI quality scorer (a different pipeline
  // than the red-team scan), so we surface the exact command instead of a
  // launch button.
  const evalCmd = `npm run eval:quality -- <your-target-config.json> --dataset ${d.path}`;
  const copyEvalCmd = async () => {
    try {
      await navigator.clipboard.writeText(evalCmd);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard blocked — the command is visible to copy manually */
    }
  };

  const doExport = async (format: "jsonl" | "csv") => {
    setExporting(format);
    setErr(null);
    try {
      const text = await fetchDatasetExport(d.path, format);
      const blob = new Blob([text], {
        type: format === "csv" ? "text/csv" : "application/x-ndjson",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${d.name}.${format}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setExporting(null);
    }
  };

  const toggle = async () => {
    const next = !open;
    setOpen(next);
    if (next && rows === null) {
      setLoading(true);
      setErr(null);
      try {
        const res = await getDatasetRows(d.path, 200);
        setRows(res.rows);
        setTotal(res.total);
      } catch (e) {
        setErr((e as Error).message);
      } finally {
        setLoading(false);
      }
    }
  };

  return (
    <div className="rounded-lg border border-border">
      <div className="p-3 flex items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            {renaming ? (
              <span className="flex items-center gap-1">
                <Input
                  className="h-7 text-sm w-44"
                  value={draftName}
                  autoFocus
                  disabled={savingName}
                  onChange={(e) => setDraftName(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") submitRename();
                    if (e.key === "Escape") {
                      setDraftName(d.name);
                      setRenaming(false);
                    }
                  }}
                />
                <Button
                  size="sm"
                  className="h-7"
                  onClick={submitRename}
                  disabled={savingName}
                >
                  {savingName ? (
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  ) : (
                    <CheckCircle2 className="w-3.5 h-3.5" />
                  )}
                  Save
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  className="h-7"
                  disabled={savingName}
                  onClick={() => {
                    setDraftName(d.name);
                    setRenaming(false);
                  }}
                >
                  Cancel
                </Button>
              </span>
            ) : (
              <span className="flex items-center gap-1 group">
                <span className="font-medium text-sm text-foreground">{d.name}</span>
                <button
                  type="button"
                  title="Rename dataset"
                  className="text-muted-foreground hover:text-foreground opacity-60 group-hover:opacity-100"
                  onClick={() => {
                    setDraftName(d.name);
                    setRenaming(true);
                  }}
                >
                  <Pencil className="w-3 h-3" />
                </button>
              </span>
            )}
            <Badge variant="outline">{d.family}</Badge>
            <Badge variant={d.kind === "quality" ? "secondary" : "outline"}>
              {d.kind}
            </Badge>
            <Badge>{d.rowCount} rows</Badge>
          </div>
          <code className="text-xs text-muted-foreground break-all">{d.path}</code>
          <div className="mt-1 flex flex-wrap gap-1">
            {topCategories(d.histogram).map((c) => (
              <Badge key={c} variant="secondary" className="text-[10px]">
                {c}
              </Badge>
            ))}
            {Object.keys(d.histogram).length > 4 && (
              <span className="text-[10px] text-muted-foreground">
                +{Object.keys(d.histogram).length - 4} more
              </span>
            )}
          </div>
        </div>
        <div className="flex flex-col items-end gap-1.5 shrink-0">
          {d.kind !== "quality" ? (
            <Button
              size="sm"
              onClick={() =>
                navigate(`/new-scan?dataset=${encodeURIComponent(d.path)}`)
              }
              title="Launch a scan using this dataset as the attack set"
            >
              Use for evaluation
              <ArrowRight className="w-3.5 h-3.5" />
            </Button>
          ) : (
            <div className="flex items-center gap-1.5">
              <Button
                size="sm"
                variant="ghost"
                className="h-7 px-2 text-[11px]"
                onClick={() => setShowEvalCmd((v) => !v)}
                title="Show the equivalent CLI command"
              >
                CLI
                {showEvalCmd ? (
                  <ChevronDown className="w-3 h-3" />
                ) : (
                  <ChevronRight className="w-3 h-3" />
                )}
              </Button>
              <Button
                size="sm"
                onClick={() =>
                  navigate(
                    `/new-scan?dataset=${encodeURIComponent(d.path)}&mode=quality`,
                  )
                }
                title="Score this dataset against a target from the UI"
              >
                Use for evaluation
                <ArrowRight className="w-3.5 h-3.5" />
              </Button>
            </div>
          )}
          <Button size="sm" variant="outline" onClick={toggle}>
            {open ? (
              <ChevronDown className="w-3.5 h-3.5" />
            ) : (
              <ChevronRight className="w-3.5 h-3.5" />
            )}
            View rows
          </Button>
          <div className="flex items-center gap-1">
            <span className="text-[10px] text-muted-foreground">Export:</span>
            <Button
              size="sm"
              variant="ghost"
              className="h-6 px-2 text-[11px]"
              disabled={exporting !== null}
              onClick={() => doExport("jsonl")}
              title="Download as newline-delimited JSON (promptfoo, OpenAI evals)"
            >
              {exporting === "jsonl" ? (
                <Loader2 className="w-3 h-3 animate-spin" />
              ) : (
                <Download className="w-3 h-3" />
              )}
              JSONL
            </Button>
            <Button
              size="sm"
              variant="ghost"
              className="h-6 px-2 text-[11px]"
              disabled={exporting !== null}
              onClick={() => doExport("csv")}
              title="Download as CSV (spreadsheets, deepeval CSV import)"
            >
              {exporting === "csv" ? (
                <Loader2 className="w-3 h-3 animate-spin" />
              ) : (
                <Download className="w-3 h-3" />
              )}
              CSV
            </Button>
          </div>
        </div>
      </div>
      {d.kind === "quality" && showEvalCmd && (
        <div className="border-t border-border p-3 space-y-2 text-xs">
          <p className="text-muted-foreground">
            Quality datasets are scored on correctness by the CLI quality scorer
            (a separate pipeline from red-team scans). Point it at the app you're
            evaluating with a target config, then run:
          </p>
          <div className="flex items-start gap-2">
            <code className="flex-1 rounded bg-muted p-2 break-all font-mono text-[11px]">
              {evalCmd}
            </code>
            <Button size="sm" variant="outline" className="shrink-0" onClick={copyEvalCmd}>
              {copied ? (
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
              ) : (
                <Copy className="w-3.5 h-3.5" />
              )}
              {copied ? "Copied" : "Copy"}
            </Button>
          </div>
          <p className="text-[11px] text-muted-foreground">
            Replace <code>&lt;your-target-config.json&gt;</code> with a scan
            config for your app (target URL + auth). Optional flags:{" "}
            <code>--threshold 0.7</code>, <code>--concurrency 4</code>,{" "}
            <code>--out report/quality.json</code>.
          </p>
        </div>
      )}
      {open && (
        <div className="border-t border-border p-3 space-y-2 max-h-96 overflow-y-auto">
          {loading && (
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <Loader2 className="w-3.5 h-3.5 animate-spin" /> Loading rows…
            </div>
          )}
          {err && <p className="text-xs text-destructive">{err}</p>}
          {rows && (
            <>
              {rows.map((r, i) => (
                <RowItem key={i} row={r} />
              ))}
              {total > rows.length && (
                <p className="text-[11px] text-muted-foreground pt-1">
                  Showing first {rows.length} of {total} rows.
                </p>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}

/** A segmented control — grouped pill toggles in a single track. */
function Segmented<T extends string>({
  options,
  value,
  onChange,
  className = "",
}: {
  options: { value: T; label: string; title?: string }[];
  value: T;
  onChange: (v: T) => void;
  className?: string;
}) {
  return (
    <div
      className={`inline-flex flex-wrap items-center gap-1 rounded-lg border border-border bg-muted/40 p-1 ${className}`}
    >
      {options.map((o) => {
        const active = o.value === value;
        return (
          <button
            key={o.value}
            type="button"
            title={o.title}
            onClick={() => onChange(o.value)}
            className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors ${
              active
                ? "bg-background text-foreground shadow-sm ring-1 ring-border"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            {o.label}
          </button>
        );
      })}
    </div>
  );
}

/** A labeled form field with consistent spacing and an optional hint. */
function Field({
  label,
  hint,
  children,
  className = "",
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={`space-y-1.5 ${className}`}>
      <Label className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
        {label}
      </Label>
      {children}
      {hint && <p className="text-[11px] text-muted-foreground">{hint}</p>}
    </div>
  );
}

export function DatasetsPage() {
  const navigate = useNavigate();
  const [datasets, setDatasets] = useState<DatasetSummary[]>([]);
  const [trends, setTrends] = useState<EvalTrend[]>([]);
  const [loading, setLoading] = useState(true);
  const [kind, setKind] = useState<"security" | "quality">("security");
  // Compliance-framework mapping (for the security-focus presets), loaded once.
  const [frameworks, setFrameworks] = useState<ReferenceFramework[]>([]);
  const [categoryCompliance, setCategoryCompliance] = useState<
    Record<string, CategoryComplianceRef[]>
  >({});
  const [family, setFamily] = useState<"mcp" | "agent">("mcp");
  const [providers, setProviders] = useState<GenerationProvider[]>(
    FALLBACK_PROVIDERS,
  );
  const [providerId, setProviderId] = useState("nim");
  const [model, setModel] = useState(FALLBACK_ENGINES[0].defaultModel);
  const [count, setCount] = useState(200);
  const [outName, setOutName] = useState("v1");
  // Timestamp the generated file name so each run is its own dataset instead of
  // silently overwriting the previous one at the same path.
  const [timestampName, setTimestampName] = useState(true);
  const [profiles, setProfiles] = useState<ProfileSummary[]>([]);
  const [profileId, setProfileId] = useState<string>("");
  const [wizardOpen, setWizardOpen] = useState(false);
  const [turnMode, setTurnMode] = useState<"single" | "multi">("single");
  const [maxTurns, setMaxTurns] = useState(3);
  // Custom instructions injected into the generation prompt — the iterate lever.
  const [instructions, setInstructions] = useState("");
  // Few-shot style examples (one per line) the generator should match.
  const [examples, setExamples] = useState("");
  // Top-up: append generated rows to an existing dataset instead of replacing.
  const [append, setAppend] = useState(false);
  // Live pre-generation cost estimate for the current engine/model/count.
  const [cost, setCost] = useState<CostEstimate | null>(null);
  // Taxonomy focus: available options for the current kind/family + the user's
  // selection. Empty selection = the full pool (no override).
  const [taxonomy, setTaxonomy] = useState<DatasetTaxonomy | null>(null);
  const [selCategories, setSelCategories] = useState<string[]>([]);
  const [selSeverities, setSelSeverities] = useState<string[]>([]);
  // User-defined focus tasks (quality datasets only — a quality row's task is a
  // report label, so custom ones are safe; security categories stay fixed).
  const [customTasks, setCustomTasks] = useState<string[]>([]);
  const [taskDraft, setTaskDraft] = useState("");
  // Curate-before-save: generate into a review list, keep the good rows.
  const [reviewMode, setReviewMode] = useState(false);
  const [curate, setCurate] = useState<
    { rows: { row: DatasetRow; keep: boolean }[]; out: string; append: boolean } | null
  >(null);
  const [saving, setSaving] = useState(false);
  // Generation engine: a direct LLM engine id, or "data-designer". Default is
  // OpenAI (the direct path — no NeMo service required).
  const [engines, setEngines] = useState<GenerationEngine[]>(FALLBACK_ENGINES);
  const [engine, setEngine] = useState<string>("openai");
  const [seedConfigPath, setSeedConfigPath] = useState("");
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [ok, setOk] = useState<string | null>(null);
  // Live streaming progress (OpenAI-direct).
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(
    null,
  );
  const [liveRows, setLiveRows] = useState<
    { category: string; severity?: string; preview: string }[]
  >([]);

  const refresh = async () => {
    setLoading(true);
    try {
      const [ds, tr, pr] = await Promise.all([
        listDatasets(),
        listEvalRuns().catch(() => ({ trends: [] as EvalTrend[] })),
        listProfiles().catch(() => ({ profiles: [] as ProfileSummary[] })),
      ]);
      setDatasets(ds.datasets);
      setTrends(tr.trends);
      setProfiles(pr.profiles);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refresh();
    listGenerationProviders()
      .then((r) => r.providers.length > 0 && setProviders(r.providers))
      .catch(() => {}); // older server — keep fallback
    listGenerationEngines()
      .then((r) => {
        if (r.engines.length > 0) {
          setEngines(r.engines);
          setModel(
            (m) => r.engines.find((e) => e.id === "openai")?.defaultModel ?? m,
          );
        }
      })
      .catch(() => {});
    // Compliance mapping powers the security-focus framework presets.
    getReference()
      .then((r) => {
        setFrameworks(r.frameworks ?? []);
        setCategoryCompliance(r.categoryCompliance ?? {});
      })
      .catch(() => {});
  }, []);

  // Load the selectable taxonomy whenever kind/family change; clear any stale
  // selection so it can't carry a category from the other family.
  useEffect(() => {
    getDatasetTaxonomy(kind, family)
      .then((t) => setTaxonomy(t))
      .catch(() => setTaxonomy(null));
    setSelCategories([]);
    setSelSeverities([]);
    setCustomTasks([]);
    setTaskDraft("");
  }, [kind, family]);

  // Add the current draft (or comma-separated drafts) as custom focus tasks.
  const addCustomTasks = (raw: string) => {
    const slugs = raw
      .split(",")
      .map((s) =>
        s
          .trim()
          .toLowerCase()
          .replace(/[^a-z0-9]+/g, "_")
          .replace(/^_+|_+$/g, "")
          .slice(0, 40)
          .replace(/_+$/g, ""),
      )
      .filter(Boolean);
    if (!slugs.length) return;
    const taxonomyTasks = new Set(taxonomy?.tasks ?? []);
    setCustomTasks((prev) => {
      const next = [...prev];
      for (const s of slugs) {
        if (!taxonomyTasks.has(s) && !next.includes(s)) next.push(s);
      }
      return next;
    });
    setTaskDraft("");
  };

  // Live cost estimate — debounced so typing in the count field doesn't spam
  // the endpoint. Cleared on unmount / dependency change.
  useEffect(() => {
    let cancelled = false;
    const t = setTimeout(() => {
      estimateGenerationCost({
        backend: engine,
        model: model.trim() || undefined,
        count,
        turnMode,
        maxTurns,
      })
        .then((c) => !cancelled && setCost(c))
        .catch(() => !cancelled && setCost(null));
    }, 300);
    return () => {
      cancelled = true;
      clearTimeout(t);
    };
  }, [engine, model, count, turnMode, maxTurns]);

  const toggle = (
    list: string[],
    setList: (v: string[]) => void,
    value: string,
  ) =>
    setList(
      list.includes(value) ? list.filter((v) => v !== value) : [...list, value],
    );

  const provider =
    providers.find((p) => p.id === providerId) ?? providers[0];
  const directEngine = engines.find((e) => e.id === engine);
  const isDirect = engine !== "data-designer";
  const baseOutName = outName.replace(/[^a-z0-9._-]/gi, "-") || "v1";
  // Append targets an existing file by exact name, so it wins over timestamping.
  const willTimestamp = timestampName && !append;
  // Normalized info for the model input / key hint / footer — from the direct
  // engine when one is selected, else the Data Designer provider.
  const effInfo = directEngine
    ? {
        label: directEngine.label,
        defaultModel: directEngine.defaultModel,
        suggestedModels: directEngine.suggestedModels,
        apiKeyEnv: directEngine.apiKeyEnv,
        keyConfigured: directEngine.keyConfigured,
      }
    : {
        label: provider.label,
        defaultModel: provider.defaultModel,
        suggestedModels: provider.suggestedModels,
        apiKeyEnv: provider.apiKeyEnv as string | null,
        keyConfigured: provider.keyConfigured,
      };

  const selectProvider = (p: GenerationProvider) => {
    setProviderId(p.id);
    setModel(p.defaultModel);
  };

  const selectEngine = (id: string) => {
    setEngine(id);
    const e = engines.find((x) => x.id === id);
    if (e) setModel(e.defaultModel);
    else setModel(provider.defaultModel); // data-designer
  };

  const okMessage = (res: {
    rowCount: number;
    out: string;
    duplicatesDropped: number;
    seeds?: { roles: number; surfaces: number };
    profile?: { name: string; tools: number; policies: number; rules: number };
    turnMode?: "multi";
    maxTurns?: number;
    appended?: boolean;
    added?: number;
  }) => {
    const seedNote = res.seeds
      ? ` — seeded from analysis (${res.seeds.roles} roles, ${res.seeds.surfaces} surfaces)`
      : "";
    const profileNote = res.profile
      ? ` — tailored to "${res.profile.name}" (${res.profile.tools} tools, ${res.profile.policies} policies, ${res.profile.rules} rules)`
      : "";
    const turnNote =
      res.turnMode === "multi" ? ` — multi-turn (up to ${res.maxTurns} turns)` : "";
    const lead = res.appended
      ? `Appended ${res.added} new rows -> ${res.out} (now ${res.rowCount} total, `
      : `Generated ${res.rowCount} rows -> ${res.out} (`;
    return `${lead}dropped ${res.duplicatesDropped} duplicates)${seedNote}${profileNote}${turnNote}`;
  };

  const onGenerate = async () => {
    setGenerating(true);
    setError(null);
    setOk(null);
    setProgress(null);
    setLiveRows([]);
    setCurate(null);
    const dir = kind === "quality" ? `quality-${family}` : `nemo-${family}`;
    // A top-up has to target the existing file, so it never gets a timestamp.
    const stamp = new Date()
      .toISOString()
      .slice(0, 19)
      .replace(/[-:]/g, "")
      .replace("T", "-");
    const fileName = timestampName && !append ? `${baseOutName}-${stamp}` : baseOutName;
    const out = `data/datasets/${dir}/${fileName}.json`;
    // Review/curate only makes sense for direct engines (they stream + return rows).
    const isPreview = isDirect && reviewMode;
    // Few-shot examples: one per line, blank lines dropped.
    const examplesList = examples
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean)
      .slice(0, 8);
    const body = {
      preset: PRESETS[`${kind}-${family}`],
      out,
      count,
      backend: engine,
      ...(isPreview ? { preview: true } : {}),
      ...(!isDirect ? { provider: providerId } : {}),
      ...(model.trim() ? { generationModel: model.trim() } : {}),
      ...(profileId ? { profileId } : {}),
      ...(turnMode === "multi" && !(kind === "security" && family === "mcp")
        ? { turnMode: "multi" as const, maxTurns }
        : {}),
      ...(instructions.trim() ? { instructions: instructions.trim() } : {}),
      ...(examplesList.length ? { examples: examplesList } : {}),
      ...(append && !isPreview ? { append: true } : {}),
      ...(kind === "security" && selCategories.length ? { categories: selCategories } : {}),
      ...(kind === "security" && selSeverities.length ? { severities: selSeverities } : {}),
      ...(kind === "quality" && (selCategories.length || customTasks.length)
        ? { tasks: [...selCategories, ...customTasks] }
        : {}),
      ...(kind === "quality" && selSeverities.length ? { metrics: selSeverities } : {}),
      ...(seedConfigPath.trim() ? { seedConfigPath: seedConfigPath.trim() } : {}),
    };
    try {
      if (isDirect) {
        // Stream row-by-row so results appear as they're generated.
        let done = 0;
        await generateDatasetStream(body, (e) => {
          if (e.type === "start") setProgress({ done: 0, total: e.total });
          else if (e.type === "row") {
            done += 1;
            setProgress({ done, total: e.total });
            setLiveRows((rows) =>
              [
                { category: e.category, severity: e.severity, preview: e.preview },
                ...rows,
              ].slice(0, 8),
            );
          } else if (e.type === "done") {
            if (e.preview && e.rows) {
              setCurate({
                rows: e.rows.map((r) => ({ row: r, keep: true })),
                out,
                append,
              });
              setOk(
                `Generated ${e.rows.length} rows for review — untick any you don't want, then Save.`,
              );
            } else setOk(okMessage(e));
          } else if (e.type === "error")
            setError(`${e.error}${e.detail ? ` — ${e.detail}` : ""}`);
        });
      } else {
        setOk(okMessage(await generateDataset(body)));
      }
      if (!isPreview) await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setGenerating(false);
      setProgress(null);
    }
  };

  const saveCurated = async () => {
    if (!curate) return;
    const kept = curate.rows.filter((c) => c.keep).map((c) => c.row);
    if (kept.length === 0) {
      setError("Select at least one row to save.");
      return;
    }
    setSaving(true);
    setError(null);
    try {
      const res = await saveDatasetRows({
        out: curate.out,
        kind,
        family,
        rows: kept,
        append: curate.append,
      });
      setOk(
        res.appended
          ? `Appended ${res.added} new rows -> ${res.out} (now ${res.rowCount} total, dropped ${res.duplicatesDropped} duplicates).`
          : `Saved ${res.rowCount} rows -> ${res.out} (dropped ${res.duplicatesDropped} duplicates).`,
      );
      setCurate(null);
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="p-6 space-y-6">
      <ProfileWizard
        open={wizardOpen}
        onOpenChange={setWizardOpen}
        onSaved={async (name) => {
          await refresh();
          setProfileId(name);
          setOk(`Saved app profile "${name}" — it will tailor the next dataset.`);
        }}
      />
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <Database className="w-5 h-5 text-primary" />
          <div>
            <h1 className="text-lg font-semibold text-foreground">
              Eval Datasets
            </h1>
            <p className="text-xs text-muted-foreground">
              Synthetic attack datasets generated with NeMo Data Designer. Point
              a scan's <code>customAttacksFile</code> at one for a reproducible
              evaluation.
            </p>
          </div>
        </div>
        <Button variant="outline" size="sm" onClick={refresh} disabled={loading}>
          <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </Button>
      </div>

      {/* Generate */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm">
            <Sparkles className="w-4 h-4 text-primary" />
            Generate a dataset
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-5">
          {/* Blueprint — what kind of dataset */}
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <Field label="Kind">
              <Segmented
                options={[
                  { value: "security", label: "Security" },
                  { value: "quality", label: "Quality" },
                ]}
                value={kind}
                onChange={setKind}
              />
            </Field>
            <Field label="Family">
              <Segmented
                options={[
                  { value: "mcp", label: "MCP" },
                  { value: "agent", label: "Agent" },
                ]}
                value={family}
                onChange={setFamily}
              />
            </Field>
            <Field label="Conversation">
              <div className="flex items-center gap-2">
                <Segmented
                  options={
                    kind === "security" && family === "mcp"
                      ? [
                          {
                            value: "single",
                            label: "Single operation",
                            title: "One direct MCP protocol operation per case",
                          },
                        ]
                      : [
                          {
                            value: "single",
                            label: "Single-turn",
                            title: "One message per case",
                          },
                          {
                            value: "multi",
                            label: "Multi-turn",
                            title:
                              kind === "security"
                                ? "A [Turn N] escalation transcript"
                                : "A [Turn N] multi-step task conversation",
                          },
                        ]
                  }
                  value={
                    kind === "security" && family === "mcp"
                      ? "single"
                      : turnMode
                  }
                  onChange={setTurnMode}
                />
                {turnMode === "multi" &&
                  !(kind === "security" && family === "mcp") && (
                  <Input
                    type="number"
                    className="w-16 h-9"
                    min={2}
                    max={8}
                    value={maxTurns}
                    onChange={(e) =>
                      setMaxTurns(
                        Math.min(8, Math.max(2, Number(e.target.value) || 2)),
                      )
                    }
                    title="Max turns"
                  />
                )}
              </div>
            </Field>
          </div>

          {/* Engine + provider — where rows are generated */}
          <div className="grid gap-4 lg:grid-cols-2">
            <Field label="Engine" hint="Where the rows are generated">
              <Segmented
                options={[
                  ...engines.map((e) => ({
                    value: e.id,
                    label: e.label,
                    title: `Generate directly via ${e.label}${e.apiKeyEnv ? ` (needs ${e.apiKeyEnv})` : " (local, no key)"}`,
                  })),
                  {
                    value: "data-designer",
                    label: "Data Designer",
                    title: "Generate via the NeMo Data Designer microservice",
                  },
                ]}
                value={engine}
                onChange={selectEngine}
              />
            </Field>
            {!isDirect && (
              <Field label="Provider">
                <Segmented
                  options={providers.map((p) => ({
                    value: p.id,
                    label: p.label,
                    title: `Generate with ${p.label} (needs ${p.apiKeyEnv})`,
                  }))}
                  value={providerId}
                  onChange={(id) => {
                    const p = providers.find((x) => x.id === id);
                    if (p) selectProvider(p);
                  }}
                />
              </Field>
            )}
          </div>

          {/* Model, size, name */}
          <div className="grid gap-4 sm:grid-cols-[minmax(0,1fr)_8rem_10rem] lg:max-w-3xl">
            <Field label="Model">
              <Input
                id="model"
                className="font-mono text-xs h-9"
                value={model}
                onChange={(e) => setModel(e.target.value)}
                placeholder={effInfo.defaultModel}
                list="model-suggestions"
              />
              <datalist id="model-suggestions">
                {effInfo.suggestedModels.map((m) => (
                  <option key={m} value={m} />
                ))}
              </datalist>
            </Field>
            <Field label="Rows">
              <Input
                id="count"
                type="number"
                className="h-9"
                value={count}
                min={1}
                onChange={(e) => setCount(Number(e.target.value))}
              />
            </Field>
            <Field label="Version name">
              <Input
                id="out"
                className="h-9"
                value={outName}
                onChange={(e) => setOutName(e.target.value)}
                placeholder="v1"
              />
            </Field>
          </div>

          {/* Action bar — generate + options + cost */}
          <div className="flex items-center gap-x-4 gap-y-3 flex-wrap rounded-xl border border-border bg-muted/30 px-4 py-3">
            <Button onClick={onGenerate} disabled={generating}>
              {generating ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Sparkles className="w-4 h-4" />
              )}
              {isDirect && reviewMode ? "Generate for review" : "Generate"}
            </Button>
            <div className="hidden sm:block h-6 w-px bg-border" />
            {isDirect && (
              <label className="flex items-center gap-1.5 text-xs text-muted-foreground cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={reviewMode}
                  onChange={(e) => setReviewMode(e.target.checked)}
                />
                Review before saving
              </label>
            )}
            <label className="flex items-center gap-1.5 text-xs text-muted-foreground cursor-pointer select-none">
              <input
                type="checkbox"
                checked={append}
                onChange={(e) => setAppend(e.target.checked)}
              />
              Append to existing (top up)
            </label>
            <label
              className={`flex items-center gap-1.5 text-xs select-none ${append ? "text-muted-foreground/50 cursor-not-allowed" : "text-muted-foreground cursor-pointer"}`}
              title={
                append
                  ? "A top-up writes into the existing dataset, so it keeps that exact name."
                  : "Adds a timestamp so each run is saved as its own dataset instead of overwriting the last one."
              }
            >
              <input
                type="checkbox"
                checked={willTimestamp}
                disabled={append}
                onChange={(e) => setTimestampName(e.target.checked)}
              />
              Timestamp the name
            </label>
            {cost && (
              <span
                className="text-xs text-muted-foreground ml-auto text-right"
                title={cost.note}
              >
                {cost.priced
                  ? cost.usd === 0
                    ? "Est. cost: free (local)"
                    : `Est. cost: ~$${cost.usd < 0.01 ? cost.usd.toFixed(4) : cost.usd.toFixed(2)}`
                  : "Est. cost: n/a"}
                <span className="opacity-60"> · {cost.calls} calls</span>
              </span>
            )}
          </div>
          {!effInfo.apiKeyEnv ? (
            <p className="text-[11px] text-muted-foreground flex items-center gap-1">
              <CheckCircle2 className="w-3 h-3 text-emerald-600 dark:text-emerald-400" />
              {effInfo.label} runs locally — no API key needed (set{" "}
              <code>OLLAMA_BASE_URL</code> if not on localhost).
            </p>
          ) : effInfo.keyConfigured ? (
            <p className="text-[11px] text-muted-foreground flex items-center gap-1">
              <CheckCircle2 className="w-3 h-3 text-emerald-600 dark:text-emerald-400" />
              <code>{effInfo.apiKeyEnv}</code> is configured on the server.
              {isDirect && " No Data Designer service needed."}
            </p>
          ) : (
            <p className="text-[11px] text-amber-600 dark:text-amber-400 flex items-center gap-1">
              <AlertTriangle className="w-3 h-3" />
              <code>{effInfo.apiKeyEnv}</code> is not set on the server —
              generation with {effInfo.label} will fail until it is.
            </p>
          )}
          <div className="flex items-center gap-3 pt-1">
            <div className="h-px flex-1 bg-border" />
            <span className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
              Fine-tune — optional
            </span>
            <div className="h-px flex-1 bg-border" />
          </div>

          {taxonomy &&
            (() => {
              const primary = taxonomy.categories ?? taxonomy.tasks ?? [];
              const secondary = taxonomy.severities ?? taxonomy.metrics ?? [];
              const primaryLabel = kind === "security" ? "Categories" : "Tasks";
              const secondaryLabel = kind === "security" ? "Severities" : "Metrics";
              return (
                <div className="space-y-2 rounded-lg border border-dashed border-border p-3">
                  <Label className="text-xs">
                    Focus (optional) — leave empty to cover the full set
                  </Label>
                  {/* Compliance-framework presets — generate rows for the categories
                      a framework's controls map to. Security datasets only (quality
                      datasets focus on tasks, which don't map to frameworks). */}
                  {kind === "security" && frameworks.length > 0 && (
                    <CompliancePresets
                      frameworks={frameworks}
                      categoryCompliance={categoryCompliance}
                      selectableCategories={primary}
                      selected={selCategories}
                      onAdd={(cats) =>
                        setSelCategories((prev) => [...new Set([...prev, ...cats])])
                      }
                    />
                  )}
                  <div className="space-y-1">
                    <span className="text-[11px] text-muted-foreground">
                      {primaryLabel}
                      {selCategories.length || customTasks.length
                        ? ` (${selCategories.length + customTasks.length} selected)`
                        : " (all)"}
                    </span>
                    <div className="flex flex-wrap gap-1">
                      {primary.map((c) => (
                        <button
                          key={c}
                          type="button"
                          onClick={() => toggle(selCategories, setSelCategories, c)}
                        >
                          <Badge
                            variant={selCategories.includes(c) ? "default" : "outline"}
                            className="cursor-pointer text-[10px]"
                          >
                            {c}
                          </Badge>
                        </button>
                      ))}
                      {kind === "quality" &&
                        customTasks.map((c) => (
                          <button
                            key={c}
                            type="button"
                            title="Remove custom task"
                            onClick={() =>
                              setCustomTasks((prev) => prev.filter((t) => t !== c))
                            }
                          >
                            <Badge
                              variant="default"
                              className="cursor-pointer text-[10px] gap-0.5"
                            >
                              {c}
                              <span className="opacity-70">×</span>
                            </Badge>
                          </button>
                        ))}
                    </div>
                    {kind === "quality" && (
                      <div className="flex items-center gap-1.5 pt-1">
                        <Input
                          className="h-7 text-xs max-w-64"
                          placeholder="Add your own task, e.g. refund_policy_qa — Enter"
                          value={taskDraft}
                          onChange={(e) => setTaskDraft(e.target.value)}
                          onKeyDown={(e) => {
                            if (e.key === "Enter" || e.key === ",") {
                              e.preventDefault();
                              addCustomTasks(taskDraft);
                            }
                          }}
                        />
                        <Button
                          size="sm"
                          variant="outline"
                          className="h-7"
                          disabled={!taskDraft.trim()}
                          onClick={() => addCustomTasks(taskDraft)}
                        >
                          Add
                        </Button>
                      </div>
                    )}
                    {kind === "quality" && (
                      <p className="text-[10px] text-muted-foreground">
                        Custom tasks let you focus a functional/agent eval on your
                        own scenarios. (Security categories are fixed — the
                        red-team engine routes on them.)
                      </p>
                    )}
                  </div>
                  <div className="space-y-1">
                    <span className="text-[11px] text-muted-foreground">
                      {secondaryLabel}
                      {selSeverities.length ? ` (${selSeverities.length} selected)` : " (all)"}
                    </span>
                    <div className="flex flex-wrap gap-1">
                      {secondary.map((s) => (
                        <button
                          key={s}
                          type="button"
                          onClick={() => toggle(selSeverities, setSelSeverities, s)}
                        >
                          <Badge
                            variant={selSeverities.includes(s) ? "default" : "outline"}
                            className="cursor-pointer text-[10px]"
                          >
                            {s}
                          </Badge>
                        </button>
                      ))}
                    </div>
                  </div>
                </div>
              );
            })()}

          <div className="space-y-1">
            <Label className="text-xs" htmlFor="instructions">
              Custom instructions (optional) — iterate on the generation prompt
            </Label>
            <Textarea
              id="instructions"
              className="w-full min-h-16 text-xs"
              value={instructions}
              onChange={(e) => setInstructions(e.target.value)}
              placeholder={
                kind === "security"
                  ? "e.g. Make the attacks subtle and conversational; target the checkout/payment flow; use British English; avoid obvious jailbreak phrasing."
                  : "e.g. Write terse, realistic support questions; assume the user is non-technical; focus on refund and shipping scenarios."
              }
            />
            <p className="text-[11px] text-muted-foreground">
              Injected into the generation prompt to steer style and content, then
              regenerate. The output format and grading contract are preserved.
              Tweak these and hit Generate again to iterate.
            </p>
          </div>

          <div className="space-y-1">
            <Label className="text-xs" htmlFor="examples">
              Few-shot examples (optional) — one per line, up to 8
            </Label>
            <Textarea
              id="examples"
              className="w-full min-h-16 text-xs font-mono"
              value={examples}
              onChange={(e) => setExamples(e.target.value)}
              placeholder={
                kind === "security"
                  ? "Paste a few real (or realistic) attacker messages — one per line.\nThe generator matches their shape and difficulty without copying them."
                  : "Paste a few real user requests — one per line.\nThe generator matches their tone and shape without copying them."
              }
            />
            <p className="text-[11px] text-muted-foreground">
              The strongest lever for "make it look like my app's traffic." Examples
              steer shape/tone; they are never emitted verbatim.
            </p>
          </div>

          <div className="space-y-1 rounded-lg border border-dashed border-border p-3">
            <div className="flex items-center justify-between gap-2 flex-wrap">
              <Label className="text-xs flex items-center gap-1.5">
                <Wand2 className="w-3.5 h-3.5 text-primary" />
                Tailor to my app (optional)
              </Label>
              <Button size="sm" variant="outline" onClick={() => setWizardOpen(true)}>
                <Wand2 className="w-3.5 h-3.5" />
                Customize for my app
              </Button>
            </div>
            {profiles.length > 0 ? (
              <div className="flex items-center gap-1.5 flex-wrap pt-1">
                <Button
                  size="sm"
                  variant={profileId === "" ? "default" : "outline"}
                  onClick={() => setProfileId("")}
                >
                  Generic
                </Button>
                {profiles.map((p) => (
                  <Button
                    key={p.name}
                    size="sm"
                    variant={profileId === p.name ? "default" : "outline"}
                    onClick={() => setProfileId(p.name)}
                    title={
                      p.description
                        ? `${p.description} — ${p.toolCount} tools, ${p.ruleCount} rules`
                        : `${p.toolCount} tools, ${p.ruleCount} rules`
                    }
                  >
                    {p.name}
                  </Button>
                ))}
              </div>
            ) : (
              <p className="text-[11px] text-muted-foreground pt-1">
                No app profiles yet. Import your system prompt, MCP manifest, or
                OpenAPI spec — attacks will reference your app's real domain,
                rules, and high-value tools.
              </p>
            )}
          </div>

          <div className="space-y-1">
            <Label className="text-xs" htmlFor="seedConfig">
              Seed from target analysis (optional)
            </Label>
            <Input
              id="seedConfig"
              className="w-full max-w-xl"
              value={seedConfigPath}
              onChange={(e) => setSeedConfigPath(e.target.value)}
              placeholder="configs/config-nemo-inrun.example.json"
            />
            <p className="text-[11px] text-muted-foreground">
              Path (under <code>configs/</code>) to a scan config with a{" "}
              <code>codebasePath</code>. The target is analyzed and generation is
              seeded from its discovered tools, roles, and MCP surface — producing
              attacks tailored to that target. Leave blank for a generic dataset.
            </p>
          </div>
          <p className="text-xs text-muted-foreground">
            {append ? "Tops up " : "Writes to "}
            <code>
              data/datasets/{kind === "quality" ? "quality" : "nemo"}-{family}/
              {baseOutName}
              {willTimestamp ? "-<timestamp>" : ""}.json
            </code>
            .{" "}
            {willTimestamp
              ? "Each run is saved separately — untick to overwrite the same name instead."
              : append
                ? "New rows are merged into that dataset (duplicates dropped)."
                : "Generating again with this name REPLACES that dataset."}
            {kind === "quality" ? " Quality datasets grade correctness against a reference and run on the quality scorer (not the security engine)." : " Security datasets are adversarial and run through the red-team engine."}
            {" "}Rows are generated by <strong>{effInfo.label}</strong> (
            <code>{model || effInfo.defaultModel}</code>){" "}
            {isDirect ? (
              <>directly via the {effInfo.label} API — no Data Designer service required.</>
            ) : (
              <>
                via the NeMo Data Designer service, which must be reachable (
                <code>NEMO_DATA_DESIGNER_URL</code>).
              </>
            )}
          </p>

          {progress && (
            <div className="rounded-lg border border-border p-3 space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="flex items-center gap-1.5 text-foreground">
                  <Loader2 className="w-3.5 h-3.5 animate-spin text-primary" />
                  Generating with OpenAI…
                </span>
                <span className="font-mono text-muted-foreground">
                  {progress.done} / {progress.total}
                </span>
              </div>
              <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted">
                <div
                  className="h-full bg-primary transition-all"
                  style={{
                    width: `${progress.total ? (progress.done / progress.total) * 100 : 0}%`,
                  }}
                />
              </div>
              {liveRows.length > 0 && (
                <div className="space-y-1 pt-1">
                  {liveRows.map((r, i) => (
                    <div
                      key={`${progress.done}-${i}`}
                      className="flex items-start gap-2 text-[11px] animate-in fade-in slide-in-from-top-1"
                    >
                      <Badge variant="secondary" className="shrink-0 text-[10px]">
                        {r.category}
                      </Badge>
                      <span className="text-muted-foreground truncate">
                        {r.preview}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {error && (
            <Alert variant="destructive">
              <AlertTriangle className="w-4 h-4" />
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
          {ok && (
            <Alert>
              <CheckCircle2 className="w-4 h-4" />
              <AlertDescription>{ok}</AlertDescription>
            </Alert>
          )}

          {curate && (
            <div className="rounded-lg border border-border">
              <div className="flex items-center justify-between gap-2 flex-wrap p-3 border-b border-border">
                <span className="text-sm font-medium">
                  Review {curate.rows.length} rows —{" "}
                  {curate.rows.filter((c) => c.keep).length} selected
                </span>
                <div className="flex items-center gap-1.5">
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() =>
                      setCurate((c) =>
                        c ? { ...c, rows: c.rows.map((r) => ({ ...r, keep: true })) } : c,
                      )
                    }
                  >
                    All
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() =>
                      setCurate((c) =>
                        c ? { ...c, rows: c.rows.map((r) => ({ ...r, keep: false })) } : c,
                      )
                    }
                  >
                    None
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => setCurate(null)}>
                    Discard
                  </Button>
                  <Button size="sm" onClick={saveCurated} disabled={saving}>
                    {saving ? (
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    ) : (
                      <CheckCircle2 className="w-3.5 h-3.5" />
                    )}
                    Save {curate.rows.filter((c) => c.keep).length}
                  </Button>
                </div>
              </div>
              <div className="max-h-96 overflow-y-auto p-3 space-y-2">
                {curate.rows.map((c, i) => (
                  <label
                    key={i}
                    className={`flex items-start gap-2 rounded-md border p-2 cursor-pointer ${c.keep ? "border-border" : "border-border/40 opacity-50"}`}
                  >
                    <input
                      type="checkbox"
                      className="mt-1 shrink-0"
                      checked={c.keep}
                      onChange={() =>
                        setCurate((cur) =>
                          cur
                            ? {
                                ...cur,
                                rows: cur.rows.map((r, j) =>
                                  j === i ? { ...r, keep: !r.keep } : r,
                                ),
                              }
                            : cur,
                        )
                      }
                    />
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <Badge variant="secondary" className="text-[10px]">
                          {str(c.row.category) || str(c.row.task)}
                        </Badge>
                        {str(c.row.severity) && (
                          <Badge variant="outline" className="text-[10px]">
                            {str(c.row.severity)}
                          </Badge>
                        )}
                      </div>
                      <p className="text-xs text-foreground whitespace-pre-wrap break-words mt-0.5">
                        {str(c.row.prompt) || str(c.row.input)}
                      </p>
                      {(str(c.row.successCriteria) || str(c.row.reference)) && (
                        <p className="text-[11px] text-muted-foreground mt-0.5">
                          <span className="font-medium">grades as success if:</span>{" "}
                          {str(c.row.successCriteria) || str(c.row.reference)}
                        </p>
                      )}
                    </div>
                  </label>
                ))}
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Score over time (regression tracking) */}
      {trends.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm">
              <LineChart className="w-4 h-4 text-primary" />
              Eval score over time
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <p className="text-xs text-muted-foreground">
              Runs grouped by dataset. An eval is a scan whose attack set is a
              dataset — click a run to open its report.
            </p>
            {trends.map((t) => (
              <div
                key={t.dataset}
                className="rounded-lg border border-border p-3 space-y-2"
              >
                <div className="flex items-center justify-between gap-4 flex-wrap">
                  <code className="text-xs text-foreground break-all">
                    {datasetLabel(t.dataset)}
                  </code>
                  <div className="flex items-center gap-4">
                    <Sparkline scores={t.runs.map((r) => r.score)} />
                    <div className="text-right">
                      <div className="text-sm font-semibold text-foreground">
                        {t.latestScore}
                        <span className="text-xs text-muted-foreground">
                          /100
                        </span>
                      </div>
                      <div className="flex items-center gap-1 justify-end">
                        <span className="text-[10px] text-muted-foreground">
                          {t.runs.length} run{t.runs.length === 1 ? "" : "s"}
                        </span>
                        {t.runs.length > 1 && <DeltaBadge delta={t.totalDelta} />}
                      </div>
                    </div>
                  </div>
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {t.runs.map((r) => (
                    <button
                      key={r.filename}
                      type="button"
                      onClick={() => navigate(`/reports/${r.filename}`)}
                      title={`${r.timestamp} — score ${r.score}${r.only ? " (dataset-only)" : ""}`}
                      className="inline-flex items-center gap-1 rounded border border-border px-1.5 py-0.5 text-[10px] text-muted-foreground hover:border-primary hover:text-foreground transition-colors"
                    >
                      {r.score}
                      {r.delta !== undefined && r.delta !== 0 && (
                        <span
                          className={
                            r.delta > 0
                              ? "text-emerald-600 dark:text-emerald-400"
                              : "text-red-600 dark:text-red-400"
                          }
                        >
                          {r.delta > 0 ? "▲" : "▼"}
                        </span>
                      )}
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {/* List */}
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">
            Datasets ({datasets.length})
          </CardTitle>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex items-center gap-2 text-sm text-muted-foreground py-6">
              <Loader2 className="w-4 h-4 animate-spin" /> Loading…
            </div>
          ) : datasets.length === 0 ? (
            <p className="text-sm text-muted-foreground py-6">
              No datasets yet. Generate one above, or run{" "}
              <code>npm run gen:dataset</code> from the CLI.
            </p>
          ) : (
            <div className="space-y-3">
              {datasets.map((d) => (
                <DatasetCard key={d.path} d={d} onChanged={refresh} />
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

export default DatasetsPage;
