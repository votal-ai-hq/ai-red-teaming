import { useState, useEffect } from "react";
import {
  listDatasets,
  generateDataset,
  listEvalRuns,
  type DatasetSummary,
  type EvalTrend,
} from "@/api/datasets";
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
} from "lucide-react";

const PRESETS: Record<string, string> = {
  mcp: "configs/datasets/nemo-mcp.preset.json",
  agent: "configs/datasets/nemo-agent.preset.json",
};

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
  const [family, setFamily] = useState<"mcp" | "agent">("mcp");
  const [count, setCount] = useState(200);
  const [outName, setOutName] = useState("v1");
  const [seedConfigPath, setSeedConfigPath] = useState("");
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [ok, setOk] = useState<string | null>(null);

  const refresh = async () => {
    setLoading(true);
    try {
      const [ds, tr] = await Promise.all([
        listDatasets(),
        listEvalRuns().catch(() => ({ trends: [] as EvalTrend[] })),
      ]);
      setDatasets(ds.datasets);
      setTrends(tr.trends);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refresh();
  }, []);

  const onGenerate = async () => {
    setGenerating(true);
    setError(null);
    setOk(null);
    try {
      const res = await generateDataset({
        preset: PRESETS[family],
        out: `data/datasets/nemo-${family}/${outName.replace(/[^a-z0-9._-]/gi, "-")}.json`,
        count,
        ...(seedConfigPath.trim()
          ? { seedConfigPath: seedConfigPath.trim() }
          : {}),
      });
      const seedNote = res.seeds
        ? ` — seeded from analysis (${res.seeds.roles} roles, ${res.seeds.surfaces} surfaces)`
        : "";
      setOk(
        `Generated ${res.rowCount} rows -> ${res.out} (dropped ${res.duplicatesDropped} duplicates)${seedNote}`,
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
            <code>data/datasets/nemo-{family}/{outName || "v1"}.json</code>.
            Requires the NeMo Data Designer service to be reachable
            (<code>NEMO_DATA_DESIGNER_URL</code>) and <code>NVIDIA_API_KEY</code>.
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
