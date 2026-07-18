import { useState, useEffect } from "react";
import {
  listDatasets,
  generateDataset,
  type DatasetSummary,
} from "@/api/datasets";
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

export function DatasetsPage() {
  const [datasets, setDatasets] = useState<DatasetSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [family, setFamily] = useState<"mcp" | "agent">("mcp");
  const [count, setCount] = useState(200);
  const [outName, setOutName] = useState("v1");
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [ok, setOk] = useState<string | null>(null);

  const refresh = async () => {
    setLoading(true);
    try {
      const res = await listDatasets();
      setDatasets(res.datasets);
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
      });
      setOk(
        `Generated ${res.rowCount} rows -> ${res.out} (dropped ${res.duplicatesDropped} duplicates)`,
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
