import { useState, useEffect } from "react";
import {
  listDatasets,
  generateDataset,
  listEvalRuns,
  listGenerationProviders,
  listProfiles,
  type DatasetSummary,
  type EvalTrend,
  type GenerationProvider,
  type ProfileSummary,
} from "@/api/datasets";
import { ProfileWizard } from "./ProfileWizard";
import { useNavigate } from "react-router";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
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

export function DatasetsPage() {
  const navigate = useNavigate();
  const [datasets, setDatasets] = useState<DatasetSummary[]>([]);
  const [trends, setTrends] = useState<EvalTrend[]>([]);
  const [loading, setLoading] = useState(true);
  const [kind, setKind] = useState<"security" | "quality">("security");
  const [family, setFamily] = useState<"mcp" | "agent">("mcp");
  const [providers, setProviders] = useState<GenerationProvider[]>(
    FALLBACK_PROVIDERS,
  );
  const [providerId, setProviderId] = useState("nim");
  const [model, setModel] = useState(FALLBACK_PROVIDERS[0].defaultModel);
  const [count, setCount] = useState(200);
  const [outName, setOutName] = useState("v1");
  const [profiles, setProfiles] = useState<ProfileSummary[]>([]);
  const [profileId, setProfileId] = useState<string>("");
  const [wizardOpen, setWizardOpen] = useState(false);
  const [turnMode, setTurnMode] = useState<"single" | "multi">("single");
  const [maxTurns, setMaxTurns] = useState(3);
  const [seedConfigPath, setSeedConfigPath] = useState("");
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [ok, setOk] = useState<string | null>(null);

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
      .then((r) => {
        if (r.providers.length > 0) {
          setProviders(r.providers);
          setModel(
            (m) => r.providers.find((p) => p.id === "nim")?.defaultModel ?? m,
          );
        }
      })
      .catch(() => {}); // older server without the endpoint — keep fallback
  }, []);

  const provider =
    providers.find((p) => p.id === providerId) ?? providers[0];

  const selectProvider = (p: GenerationProvider) => {
    setProviderId(p.id);
    setModel(p.defaultModel);
  };

  const onGenerate = async () => {
    setGenerating(true);
    setError(null);
    setOk(null);
    try {
      const dir = kind === "quality" ? `quality-${family}` : `nemo-${family}`;
      const res = await generateDataset({
        preset: PRESETS[`${kind}-${family}`],
        out: `data/datasets/${dir}/${outName.replace(/[^a-z0-9._-]/gi, "-")}.json`,
        count,
        provider: providerId,
        ...(model.trim() ? { generationModel: model.trim() } : {}),
        ...(profileId ? { profileId } : {}),
        ...(turnMode === "multi" ? { turnMode: "multi" as const, maxTurns } : {}),
        ...(seedConfigPath.trim()
          ? { seedConfigPath: seedConfigPath.trim() }
          : {}),
      });
      const seedNote = res.seeds
        ? ` — seeded from analysis (${res.seeds.roles} roles, ${res.seeds.surfaces} surfaces)`
        : "";
      const profileNote = res.profile
        ? ` — tailored to "${res.profile.name}" (${res.profile.tools} tools, ${res.profile.policies} policies, ${res.profile.rules} rules)`
        : "";
      const turnNote =
        res.turnMode === "multi" ? ` — multi-turn (up to ${res.maxTurns} turns)` : "";
      setOk(
        `Generated ${res.rowCount} rows -> ${res.out} (dropped ${res.duplicatesDropped} duplicates)${seedNote}${profileNote}${turnNote}`,
      );
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setGenerating(false);
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
        <CardContent className="space-y-4">
          <div className="flex flex-wrap items-end gap-4">
            <div className="space-y-1">
              <Label className="text-xs">Kind</Label>
              <div className="flex gap-1">
                {(["security", "quality"] as const).map((k) => (
                  <Button
                    key={k}
                    size="sm"
                    variant={kind === k ? "default" : "outline"}
                    onClick={() => setKind(k)}
                  >
                    {k}
                  </Button>
                ))}
              </div>
            </div>
            <div className="space-y-1">
              <Label className="text-xs">Family</Label>
              <div className="flex gap-1">
                {(["mcp", "agent"] as const).map((f) => (
                  <Button
                    key={f}
                    size="sm"
                    variant={family === f ? "default" : "outline"}
                    onClick={() => setFamily(f)}
                  >
                    {f}
                  </Button>
                ))}
              </div>
            </div>
            <div className="space-y-1">
              <Label className="text-xs">Conversation</Label>
              <div className="flex items-center gap-1">
                {(["single", "multi"] as const).map((m) => (
                  <Button
                    key={m}
                    size="sm"
                    variant={turnMode === m ? "default" : "outline"}
                    onClick={() => setTurnMode(m)}
                    title={
                      m === "single"
                        ? "One message per case"
                        : kind === "security"
                          ? "A [Turn N] escalation transcript"
                          : "A [Turn N] multi-step task conversation"
                    }
                  >
                    {m === "single" ? "single-turn" : "multi-turn"}
                  </Button>
                ))}
                {turnMode === "multi" && (
                  <Input
                    type="number"
                    className="w-16"
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
            </div>
            <div className="space-y-1">
              <Label className="text-xs">Provider</Label>
              <div className="flex gap-1">
                {providers.map((p) => (
                  <Button
                    key={p.id}
                    size="sm"
                    variant={providerId === p.id ? "default" : "outline"}
                    onClick={() => selectProvider(p)}
                    title={`Generate with ${p.label} (needs ${p.apiKeyEnv})`}
                  >
                    {p.label}
                  </Button>
                ))}
              </div>
            </div>
            <div className="space-y-1">
              <Label className="text-xs" htmlFor="model">
                Model
              </Label>
              <Input
                id="model"
                className="w-64 font-mono text-xs"
                value={model}
                onChange={(e) => setModel(e.target.value)}
                placeholder={provider.defaultModel}
                list="model-suggestions"
              />
              <datalist id="model-suggestions">
                {provider.suggestedModels.map((m) => (
                  <option key={m} value={m} />
                ))}
              </datalist>
            </div>
            <div className="space-y-1">
              <Label className="text-xs" htmlFor="count">
                Rows
              </Label>
              <Input
                id="count"
                type="number"
                className="w-28"
                value={count}
                min={1}
                onChange={(e) => setCount(Number(e.target.value))}
              />
            </div>
            <div className="space-y-1">
              <Label className="text-xs" htmlFor="out">
                Version name
              </Label>
              <Input
                id="out"
                className="w-40"
                value={outName}
                onChange={(e) => setOutName(e.target.value)}
                placeholder="v1"
              />
            </div>
            <Button onClick={onGenerate} disabled={generating}>
              {generating ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Sparkles className="w-4 h-4" />
              )}
              Generate
            </Button>
          </div>
          {provider.keyConfigured ? (
            <p className="text-[11px] text-muted-foreground flex items-center gap-1">
              <CheckCircle2 className="w-3 h-3 text-emerald-600 dark:text-emerald-400" />
              <code>{provider.apiKeyEnv}</code> is configured on the server.
            </p>
          ) : (
            <p className="text-[11px] text-amber-600 dark:text-amber-400 flex items-center gap-1">
              <AlertTriangle className="w-3 h-3" />
              <code>{provider.apiKeyEnv}</code> is not set on the server —
              generation with {provider.label} will fail until it is.
            </p>
          )}
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
            Writes to{" "}
            <code>data/datasets/{kind === "quality" ? "quality" : "nemo"}-{family}/{outName || "v1"}.json</code>.
            {kind === "quality" ? " Quality datasets grade correctness against a reference and run on the quality scorer (not the security engine)." : " Security datasets are adversarial and run through the red-team engine."}
            {" "}Rows are generated by <strong>{provider.label}</strong> (
            <code>{model || provider.defaultModel}</code>) via the NeMo Data
            Designer service, which must be reachable (
            <code>NEMO_DATA_DESIGNER_URL</code>).
          </p>

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
                <div
                  key={d.path}
                  className="rounded-lg border border-border p-3 flex items-start justify-between gap-4"
                >
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-sm text-foreground">
                        {d.name}
                      </span>
                      <Badge variant="outline">{d.family}</Badge>
                      <Badge variant={d.kind === "quality" ? "secondary" : "outline"}>
                        {d.kind}
                      </Badge>
                      <Badge>{d.rowCount} rows</Badge>
                    </div>
                    <code className="text-xs text-muted-foreground break-all">
                      {d.path}
                    </code>
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
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

export default DatasetsPage;
