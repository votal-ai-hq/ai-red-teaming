import { useState, useEffect } from "react";
import { useNavigate, useParams } from "react-router";
import {
  listDatasets,
  listQualityReports,
  getQualityReport,
  type DatasetSummary,
  type QualityReportMeta,
  type QualityEvalReport,
  type QualityResultRow,
} from "@/api/datasets";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Swords,
  Gauge,
  Target,
  ShieldCheck,
  Scale,
  Wrench,
  Search,
  FileSearch,
  Bot,
  ListChecks,
  ArrowRight,
  ArrowLeft,
  Database,
  Loader2,
  ChevronDown,
  ChevronUp,
  TrendingUp,
  TrendingDown,
  Copy,
  Check,
  Clock,
  AlertTriangle,
} from "lucide-react";

type Status = "live" | "cli" | "planned";
type Axis = "security" | "quality";

interface EvalType {
  id: string;
  axis: Axis;
  title: string;
  desc: string;
  metrics: string[];
  status: Status;
  icon: React.ComponentType<{ className?: string }>;
  action?: { label: string; to: string };
  note?: string;
}

const STATUS_LABEL: Record<Status, string> = {
  live: "Live",
  cli: "CLI",
  planned: "Planned",
};

const EVALS: EvalType[] = [
  {
    id: "redteam",
    axis: "security",
    title: "Red-team scan",
    desc: "Source-aware attacks generated from your tools, auth, and guardrails.",
    metrics: ["141 categories", "tool-chain", "white-box"],
    status: "live",
    icon: Target,
    action: { label: "Launch a scan", to: "/new-scan" },
  },
  {
    id: "guardrails",
    axis: "security",
    title: "Guardrails",
    desc: "Block rate on bad prompts and preservation of good ones.",
    metrics: ["block-rate", "preservation"],
    status: "live",
    icon: ShieldCheck,
    action: { label: "View guardrails", to: "/policies" },
  },
  {
    id: "judge",
    axis: "security",
    title: "LLM-as-a-Judge",
    desc: "Per-category judge policies score each response for compromise.",
    metrics: ["rubrics", "custom-scoring"],
    status: "live",
    icon: Scale,
    action: { label: "See reports", to: "/reports" },
  },
  {
    id: "quality-tooling",
    axis: "quality",
    title: "Tool-use & goal accuracy",
    desc: "Runs quality datasets through the native correctness scorer: tool-call accuracy, goal accuracy, topic adherence.",
    metrics: ["tool_call_accuracy", "goal_accuracy", "topic_adherence"],
    status: "cli",
    icon: Wrench,
    action: { label: "Manage datasets", to: "/datasets" },
    note: "npm run eval:quality",
  },
  {
    id: "quality-answer",
    axis: "quality",
    title: "Answer quality (RAG)",
    desc: "Grades answers against a reference: faithfulness, relevancy, and text-similarity metrics.",
    metrics: ["faithfulness", "answer_relevancy", "exact_match", "f1", "rouge"],
    status: "cli",
    icon: FileSearch,
    action: { label: "Manage datasets", to: "/datasets" },
    note: "npm run eval:quality",
  },
  {
    id: "benchmarks",
    axis: "quality",
    title: "Industry benchmarks",
    desc: "Standard benchmarks via NeMo Evaluator: BFCL (tool-calling), Safety Harness, LM Harness, Simple Evals.",
    metrics: ["code-generation", "safety", "reasoning", "tool-calling"],
    status: "planned",
    icon: ListChecks,
  },
  {
    id: "retrieval",
    axis: "quality",
    title: "Retrieval & RAG pipeline",
    desc: "Retriever and end-to-end RAG metrics via NeMo Evaluator.",
    metrics: ["recall@k", "ndcg@k", "context_recall"],
    status: "planned",
    icon: Search,
  },
  {
    id: "agentic",
    axis: "quality",
    title: "Agentic (Evaluator)",
    desc: "Multi-step agent scoring via NeMo Evaluator: topic adherence, tool-call accuracy, goal accuracy at benchmark scale.",
    metrics: ["topic-adherence", "tool-call-accuracy", "goal-accuracy"],
    status: "planned",
    icon: Bot,
  },
];

function StatusBadge({ status }: { status: Status }) {
  const cls =
    status === "live"
      ? "bg-emerald-500/12 text-emerald-600 dark:text-emerald-400 border-emerald-500/30"
      : status === "cli"
        ? "bg-amber-500/12 text-amber-600 dark:text-amber-400 border-amber-500/30"
        : "bg-muted text-muted-foreground border-border";
  return (
    <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${cls}`}>
      {STATUS_LABEL[status]}
    </span>
  );
}

function EvalCard({ e, hue }: { e: EvalType; hue: string }) {
  const navigate = useNavigate();
  const Icon = e.icon;
  return (
    <Card className="h-full">
      <CardContent className="p-4 flex flex-col gap-3 h-full">
        <div className="flex items-start gap-3">
          <div
            className="w-9 h-9 rounded-lg grid place-items-center shrink-0"
            style={{ background: `color-mix(in srgb, ${hue} 15%, transparent)`, color: hue }}
          >
            <Icon className="w-4 h-4" />
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-semibold text-foreground">{e.title}</h3>
              <StatusBadge status={e.status} />
            </div>
          </div>
        </div>
        <p className="text-xs text-muted-foreground flex-1">{e.desc}</p>
        <div className="flex flex-wrap gap-1">
          {e.metrics.map((m) => (
            <Badge key={m} variant="secondary" className="text-[10px] font-mono">
              {m}
            </Badge>
          ))}
        </div>
        {e.note && (
          <code className="text-[11px] text-muted-foreground">{e.note}</code>
        )}
        {e.action ? (
          <Button
            variant="outline"
            size="sm"
            className="self-start"
            onClick={() => navigate(e.action!.to)}
          >
            {e.action.label}
            <ArrowRight className="w-3.5 h-3.5" />
          </Button>
        ) : (
          <span className="text-[11px] text-muted-foreground">
            NeMo Evaluator adapter — coming soon
          </span>
        )}
      </CardContent>
    </Card>
  );
}

const SEC = "var(--eval-sec, #e05365)";
const QUAL = "var(--eval-qual, #12a594)";

/** Score change vs the previous run of the SAME dataset (regression signal). */
function scoreDelta(reports: QualityReportMeta[], idx: number): number | null {
  const r = reports[idx];
  for (let j = idx + 1; j < reports.length; j++) {
    if (reports[j].dataset === r.dataset) return r.score - reports[j].score;
  }
  return null;
}

function shortName(path: string): string {
  return path.split("/").slice(-2).join("/").replace(/\.json$/i, "") || path;
}

// A failing row is one of three very different problems. Separating them is
// the single most useful thing for a dev: an HTTP/execution failure means the
// endpoint (their code) is broken; a correctness failure means the endpoint
// answered fine but the output was wrong (a prompt/logic/quality issue).
type FailCause = "http" | "error" | "correctness";
function classify(r: QualityResultRow): FailCause | null {
  if (r.pass) return null;
  if (r.error) return "error";
  if (r.statusCode && (r.statusCode < 200 || r.statusCode >= 300)) return "http";
  return "correctness";
}
const CAUSE_META: Record<
  FailCause,
  { label: string; hint: string; cls: string }
> = {
  http: {
    label: "Endpoint (HTTP)",
    hint: "The endpoint returned a non-2xx status — a transport/server-side failure, not a wrong answer. Start here: it's your code.",
    cls: "text-destructive border-destructive/40 bg-destructive/10",
  },
  error: {
    label: "Execution error",
    hint: "The row couldn't be executed or scored (timeout, malformed response, parse failure). Usually the endpoint or the response schema.",
    cls: "text-amber-700 dark:text-amber-300 border-amber-500/40 bg-amber-500/10",
  },
  correctness: {
    label: "Wrong answer",
    hint: "The endpoint responded fine (2xx) but the output was scored incorrect — a prompt / logic / quality issue, not a transport bug.",
    cls: "text-muted-foreground border-border bg-muted",
  },
};

function CopyButton({ text, title }: { text: string; title?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      title={title ?? "Copy"}
      onClick={async (e) => {
        e.stopPropagation();
        try {
          await navigator.clipboard.writeText(text);
          setDone(true);
          setTimeout(() => setDone(false), 1200);
        } catch {
          /* clipboard blocked */
        }
      }}
      className="text-muted-foreground hover:text-foreground shrink-0"
    >
      {done ? (
        <Check className="w-3 h-3 text-emerald-600 dark:text-emerald-400" />
      ) : (
        <Copy className="w-3 h-3" />
      )}
    </button>
  );
}

/**
 * Render any value as readable text. Rows can carry structured references /
 * responses (and older rows even stored the literal string "[object Object]"),
 * so never rely on the value already being a string.
 */
function asText(v: unknown): string {
  if (v == null) return "";
  if (typeof v === "string") return v;
  try {
    return JSON.stringify(v, null, 2);
  } catch {
    return String(v);
  }
}

/** Row state — the single most important at-a-glance signal. */
type RowState = "PASS" | "FAIL" | "ERR";
function rowState(r: QualityResultRow): RowState {
  return r.error ? "ERR" : r.pass ? "PASS" : "FAIL";
}
const STATE_STYLE: Record<RowState, string> = {
  PASS: "bg-emerald-500/12 text-emerald-700 dark:text-emerald-400 border-emerald-500/30",
  FAIL: "bg-destructive/10 text-destructive border-destructive/40",
  ERR: "bg-amber-500/12 text-amber-700 dark:text-amber-400 border-amber-500/30",
};

/** The colored PASS / FAIL / ERR chip, used in the list and the detail header. */
function StatePill({ state }: { state: RowState }) {
  return (
    <span
      className={`inline-flex items-center text-[10.5px] font-bold tracking-wide px-1.5 py-0.5 rounded-md border ${STATE_STYLE[state]}`}
    >
      {state}
    </span>
  );
}

/** A labeled field block — generous spacing, readable monospace. */
function TraceField({
  label,
  value,
  mono = true,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  if (!value) return null;
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between gap-2">
        <span className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
          {label}
        </span>
        <CopyButton text={value} title={`Copy ${label.toLowerCase()}`} />
      </div>
      <pre
        className={`whitespace-pre-wrap break-words rounded-md border border-border bg-muted/40 p-3 text-[12.5px] leading-relaxed max-h-72 overflow-y-auto ${mono ? "font-mono" : ""}`}
      >
        {value}
      </pre>
    </div>
  );
}

/** Expected vs actual tool calls, with missing (red) and extra (amber) marked. */
function ToolDiff({
  expected,
  actual,
}: {
  expected: string[];
  actual: string[];
}) {
  const actSet = new Set(actual);
  const expSet = new Set(expected);
  const extra = actual.filter((t) => !expSet.has(t));
  return (
    <div className="space-y-1.5">
      <span className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
        Tool calls (expected vs actual)
      </span>
      <div className="flex flex-wrap gap-1.5">
        {expected.map((t) => (
          <span
            key={`e-${t}`}
            className={`text-[11px] font-mono rounded-md px-2 py-1 border ${
              actSet.has(t)
                ? "border-emerald-500/40 bg-emerald-500/5 text-emerald-700 dark:text-emerald-300"
                : "border-destructive/50 bg-destructive/5 text-destructive line-through"
            }`}
            title={actSet.has(t) ? "called ✓" : "expected but NOT called"}
          >
            {actSet.has(t) ? "✓" : "✗"} {t}
          </span>
        ))}
        {extra.map((t) => (
          <span
            key={`x-${t}`}
            className="text-[11px] font-mono rounded-md px-2 py-1 border border-amber-500/50 bg-amber-500/5 text-amber-700 dark:text-amber-300"
            title="called but NOT expected (extra)"
          >
            +{t}
          </span>
        ))}
        {expected.length === 0 && actual.length === 0 && (
          <span className="text-[11px] text-muted-foreground">no tools</span>
        )}
      </div>
    </div>
  );
}

/** Left column: one scannable record in the list. Selecting it (not expanding)
 *  loads the full trace into the detail panel on the right. */
function RecordListItem({
  r,
  index,
  active,
  onSelect,
}: {
  r: QualityResultRow;
  index: number;
  active: boolean;
  onSelect: () => void;
}) {
  const state = rowState(r);
  const cause = classify(r);
  return (
    <button
      type="button"
      onClick={onSelect}
      aria-current={active}
      className={`w-full text-left rounded-lg border px-3 py-2.5 transition-colors ${
        active
          ? "border-primary/50 bg-primary/5 ring-1 ring-primary/20"
          : "border-border hover:bg-muted/50"
      }`}
    >
      <div className="flex items-center gap-2">
        <span className="text-[11px] tabular-nums text-muted-foreground w-7 shrink-0">
          #{index + 1}
        </span>
        <StatePill state={state} />
        {cause && (
          <span
            className={`text-[10px] rounded px-1.5 py-0.5 border shrink-0 ${CAUSE_META[cause].cls}`}
            title={CAUSE_META[cause].hint}
          >
            {CAUSE_META[cause].label}
          </span>
        )}
        <span className="ml-auto text-[11px] font-semibold tabular-nums text-muted-foreground shrink-0">
          {r.score.toFixed(2)}
        </span>
      </div>
      <p className="mt-1.5 text-[12.5px] leading-snug text-foreground/90 line-clamp-2">
        {r.row.input || r.row.name || "—"}
      </p>
      <div className="mt-1.5 flex items-center gap-2 text-[10.5px] text-muted-foreground">
        <span className="font-mono">{r.metric}</span>
        <span aria-hidden>·</span>
        <span>{r.scorer}</span>
        {r.statusCode ? (
          <>
            <span aria-hidden>·</span>
            <span
              className={
                r.statusCode < 200 || r.statusCode >= 300
                  ? "text-destructive font-medium"
                  : ""
              }
            >
              {r.statusCode}
            </span>
          </>
        ) : null}
      </div>
    </button>
  );
}

/** Right column: the full trace for the selected record — every field laid out
 *  with room to breathe, plus prev/next so you can walk the whole run. */
function RecordDetail({
  r,
  index,
  position,
  total,
  hasPrev,
  hasNext,
  onPrev,
  onNext,
}: {
  r: QualityResultRow;
  index: number;
  position: number;
  total: number;
  hasPrev: boolean;
  hasNext: boolean;
  onPrev: () => void;
  onNext: () => void;
}) {
  const state = rowState(r);
  const cause = classify(r);
  const httpBad = !r.statusCode || r.statusCode < 200 || r.statusCode >= 300;
  const hasTools =
    (r.row.expectedTools && r.row.expectedTools.length > 0) ||
    (r.actualTools && r.actualTools.length > 0);
  const rowJson = JSON.stringify(r, null, 2);
  return (
    <div className="rounded-xl border border-border bg-card">
      {/* header: identity + navigation */}
      <div className="flex items-center gap-2 flex-wrap border-b border-border px-4 py-3">
        <span className="text-sm font-semibold tabular-nums text-muted-foreground">
          #{index + 1}
        </span>
        <StatePill state={state} />
        {cause && (
          <span
            className={`text-[11px] rounded-md px-2 py-0.5 border ${CAUSE_META[cause].cls}`}
            title={CAUSE_META[cause].hint}
          >
            {CAUSE_META[cause].label}
          </span>
        )}
        <span className="font-mono text-xs text-foreground">{r.metric}</span>
        <span className="text-xs text-muted-foreground">
          score{" "}
          <span className="font-semibold tabular-nums text-foreground">
            {r.score.toFixed(2)}
          </span>
        </span>
        <div className="ml-auto flex items-center gap-1">
          <span className="text-[11px] tabular-nums text-muted-foreground mr-1">
            {position} / {total}
          </span>
          <button
            type="button"
            onClick={onPrev}
            disabled={!hasPrev}
            title="Previous record (↑)"
            className="grid place-items-center w-7 h-7 rounded-md border border-border text-muted-foreground hover:bg-muted disabled:opacity-40 disabled:pointer-events-none"
          >
            <ChevronUp className="w-4 h-4" />
          </button>
          <button
            type="button"
            onClick={onNext}
            disabled={!hasNext}
            title="Next record (↓)"
            className="grid place-items-center w-7 h-7 rounded-md border border-border text-muted-foreground hover:bg-muted disabled:opacity-40 disabled:pointer-events-none"
          >
            <ChevronDown className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* meta strip */}
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 border-b border-border px-4 py-2.5 text-[11.5px] text-muted-foreground">
        {r.row.task && (
          <Badge variant="secondary" className="text-[10.5px]">
            {r.row.task}
          </Badge>
        )}
        <Badge variant="outline" className="text-[10.5px]">
          {r.scorer}-scored
        </Badge>
        <span
          className={`flex items-center gap-1 ${httpBad ? "text-destructive font-medium" : ""}`}
        >
          HTTP {r.statusCode || "—"}
        </span>
        <span className="flex items-center gap-1">
          <Clock className="w-3.5 h-3.5" />
          {r.responseTimeMs} ms
        </span>
        <span className="ml-auto flex items-center gap-1.5">
          <CopyButton text={rowJson} title="Copy this record as JSON" />
          copy JSON
        </span>
      </div>

      <div className="p-4 space-y-4">
        {/* why it failed */}
        {cause && (
          <div className={`rounded-lg border p-3 text-[12px] leading-relaxed ${CAUSE_META[cause].cls}`}>
            <span className="font-semibold">{CAUSE_META[cause].label}: </span>
            {CAUSE_META[cause].hint}
            {r.error && (
              <div className="mt-1.5 font-mono break-words text-[11.5px]">
                {r.error}
              </div>
            )}
          </div>
        )}

        {/* the fields, top to bottom in the order you read them */}
        <div className="grid gap-4 lg:grid-cols-2">
          <TraceField label="Input (sent to endpoint)" value={asText(r.row.input)} />
          <TraceField
            label="Expected"
            value={
              r.row.expectedTools && r.row.expectedTools.length
                ? `tools: ${r.row.expectedTools.join(", ")}`
                : asText(r.row.reference)
            }
          />
        </div>
        <TraceField label="Endpoint response" value={asText(r.response)} />
        {hasTools && (
          <ToolDiff
            expected={r.row.expectedTools ?? []}
            actual={r.actualTools ?? []}
          />
        )}
        <TraceField label="Judge reasoning" value={r.reasoning ?? ""} />
      </div>
    </div>
  );
}

/** A compact stat tile for the per-metric summary strip. */
function MetricStat({
  name,
  mean,
  passed,
  count,
}: {
  name: string;
  mean: number;
  passed: number;
  count: number;
}) {
  const pct = Math.round(mean * 100);
  const tone =
    pct >= 80
      ? "text-emerald-600 dark:text-emerald-400"
      : pct >= 50
        ? "text-amber-600 dark:text-amber-400"
        : "text-destructive";
  return (
    <div className="rounded-lg border border-border bg-card px-3 py-2 min-w-[9rem]">
      <div className="text-[10.5px] font-mono text-muted-foreground truncate" title={name}>
        {name}
      </div>
      <div className="flex items-baseline gap-1.5">
        <span className={`text-lg font-semibold tabular-nums ${tone}`}>{pct}%</span>
        <span className="text-[11px] text-muted-foreground tabular-nums">
          {passed}/{count}
        </span>
      </div>
    </div>
  );
}

/** The per-metric summary + a master–detail records browser: a scannable list
 *  on the left, the full trace of the selected record on the right. */
function ReportTrace({ report }: { report: QualityEvalReport }) {
  const [failuresOnly, setFailuresOnly] = useState(false);
  const [causeFilter, setCauseFilter] = useState<FailCause | null>(null);
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState(0); // index into report.results

  // Failure-cause breakdown — the triage summary.
  const causeCounts = { http: 0, error: 0, correctness: 0 };
  for (const r of report.results) {
    const c = classify(r);
    if (c) causeCounts[c]++;
  }
  const failing = report.results.filter((r) => !r.pass).length;

  const q = query.trim().toLowerCase();
  const rows = report.results
    .map((r, i) => ({ r, i }))
    .filter(({ r }) => {
      if (failuresOnly && r.pass) return false;
      if (causeFilter && classify(r) !== causeFilter) return false;
      if (q) {
        const hay = [
          r.row.input,
          r.response,
          r.reasoning,
          r.metric,
          r.row.task,
          (r.actualTools ?? []).join(" "),
        ]
          .join(" ")
          .toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });

  // Keep a valid selection: if the filtered list no longer contains it, fall
  // back to the first visible record. `pos` is the selection's spot in the
  // *filtered* list, which is what prev/next walk through.
  const visiblePos = rows.findIndex((x) => x.i === selected);
  const pos = visiblePos >= 0 ? visiblePos : 0;
  const active = rows[pos] ?? null;
  const goPrev = () => pos > 0 && setSelected(rows[pos - 1].i);
  const goNext = () => pos < rows.length - 1 && setSelected(rows[pos + 1].i);

  return (
    <div className="space-y-4">
      {/* per-metric scores */}
      <div className="flex flex-wrap gap-2">
        {Object.entries(report.summary.byMetric).map(([m, v]) => (
          <MetricStat key={m} name={m} mean={v.mean} passed={v.passed} count={v.count} />
        ))}
      </div>

      {/* failure triage — click a cause to filter */}
      {failing > 0 && (
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
            {failing} failing
          </span>
          {(["http", "error", "correctness"] as FailCause[])
            .filter((c) => causeCounts[c] > 0)
            .map((c) => {
              const on = causeFilter === c;
              return (
                <button
                  key={c}
                  type="button"
                  title={CAUSE_META[c].hint}
                  onClick={() => setCauseFilter(on ? null : c)}
                  className={`text-[11px] rounded-md px-2 py-1 border ${CAUSE_META[c].cls} ${on ? "ring-1 ring-current" : ""}`}
                >
                  {CAUSE_META[c].label}: {causeCounts[c]}
                </button>
              );
            })}
          {(causeCounts.http > 0 || causeCounts.error > 0) && (
            <span className="text-[11px] text-muted-foreground">
              ← endpoint/transport issues (your code) vs. wrong answers
            </span>
          )}
        </div>
      )}

      {/* controls */}
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div className="relative flex-1 min-w-52 max-w-md">
          <Search className="w-4 h-4 absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
          <input
            className="w-full h-9 rounded-md border border-border bg-background pl-8 pr-2 text-[13px]"
            placeholder="Search input / response / reasoning / tool…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
        <label className="flex items-center gap-1.5 text-xs text-muted-foreground cursor-pointer select-none">
          <input
            type="checkbox"
            checked={failuresOnly}
            onChange={(e) => setFailuresOnly(e.target.checked)}
          />
          Failures only
        </label>
      </div>

      <p className="text-xs text-muted-foreground">
        {rows.length} of {report.results.length} record
        {report.results.length === 1 ? "" : "s"}
        {causeFilter ? ` · ${CAUSE_META[causeFilter].label}` : ""} · select a
        record to see its full trace
      </p>

      {rows.length === 0 ? (
        <p className="text-xs text-muted-foreground py-6 text-center">
          No records match the current filter.
        </p>
      ) : (
        <div className="grid gap-4 lg:grid-cols-[minmax(0,20rem)_minmax(0,1fr)]">
          {/* master: the record list */}
          <div className="lg:max-h-[38rem] overflow-y-auto space-y-1.5 pr-0.5">
            {rows.map(({ r, i }) => (
              <RecordListItem
                key={i}
                r={r}
                index={i}
                active={i === active?.i}
                onSelect={() => setSelected(i)}
              />
            ))}
          </div>

          {/* detail: the selected record's full trace */}
          {active && (
            <RecordDetail
              r={active.r}
              index={active.i}
              position={pos + 1}
              total={rows.length}
              hasPrev={pos > 0}
              hasNext={pos < rows.length - 1}
              onPrev={goPrev}
              onNext={goNext}
            />
          )}
        </div>
      )}
    </div>
  );
}

/** Threshold values are stored as a 0..1 fraction, but be defensive. */
function pctOfThreshold(t: number): number {
  return Math.round((t <= 1 ? t * 100 : t));
}
function scoreHue(score: number): string {
  return score >= 70 ? "#12a594" : score >= 40 ? "#f59e0b" : "#e05365";
}

/** A compact themed score dial for the run cards / focused header. */
function ScoreDial({ score, size = 64 }: { score: number; size?: number }) {
  const sw = size * 0.1;
  const r = (size - sw) / 2;
  const c = 2 * Math.PI * r;
  const s = Math.max(0, Math.min(100, score));
  const off = c - (s / 100) * c;
  const hue = scoreHue(s);
  return (
    <svg
      width={size}
      height={size}
      viewBox={`0 0 ${size} ${size}`}
      className="shrink-0"
    >
      <circle
        cx={size / 2}
        cy={size / 2}
        r={r}
        fill="none"
        stroke="currentColor"
        className="text-border"
        strokeWidth={sw}
      />
      <circle
        cx={size / 2}
        cy={size / 2}
        r={r}
        fill="none"
        stroke={hue}
        strokeWidth={sw}
        strokeLinecap="round"
        strokeDasharray={c}
        strokeDashoffset={off}
        transform={`rotate(-90 ${size / 2} ${size / 2})`}
      />
      <text
        x="50%"
        y="50%"
        dominantBaseline="central"
        textAnchor="middle"
        fill={hue}
        fontSize={size * 0.3}
        className="font-bold tabular-nums"
      >
        {s}
      </text>
    </svg>
  );
}

/** A run in the list — a rich card that opens its own focused trace page. */
function QualityRunCard({
  meta,
  delta,
}: {
  meta: QualityReportMeta;
  delta: number | null;
}) {
  const navigate = useNavigate();
  const failing = Math.max(0, meta.total - meta.passed - meta.errors);
  const passPct = meta.total ? Math.round((meta.passed / meta.total) * 100) : 0;
  const hue = scoreHue(meta.score);
  return (
    <button
      type="button"
      onClick={() => navigate(`/evaluations/${encodeURIComponent(meta.filename)}`)}
      className="group text-left rounded-xl border border-border bg-card p-4 transition-all hover:border-primary/40 hover:shadow-sm focus:outline-none focus-visible:ring-2 focus-visible:ring-primary/40"
    >
      <div className="flex items-start gap-4">
        <ScoreDial score={meta.score} />
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-semibold text-foreground truncate">
              {shortName(meta.dataset)}
            </h3>
            {delta !== null && delta !== 0 && (
              <span
                className={`inline-flex items-center gap-0.5 text-[11px] font-medium shrink-0 ${delta > 0 ? "text-emerald-600 dark:text-emerald-400" : "text-destructive"}`}
                title="vs. the previous run of the same dataset"
              >
                {delta > 0 ? (
                  <TrendingUp className="w-3 h-3" />
                ) : (
                  <TrendingDown className="w-3 h-3" />
                )}
                {delta > 0 ? "+" : ""}
                {delta}
              </span>
            )}
          </div>
          <p
            className="text-[11px] text-muted-foreground truncate mt-0.5"
            title={meta.targetUrl}
          >
            {meta.targetUrl || "unknown target"}
          </p>
          <p className="text-[11px] text-muted-foreground mt-0.5 flex items-center gap-1">
            <Clock className="w-3 h-3 shrink-0" />
            {new Date(meta.timestamp).toLocaleString()}
          </p>
        </div>
        <ArrowRight className="w-4 h-4 text-muted-foreground shrink-0 opacity-0 -translate-x-1 transition-all group-hover:opacity-100 group-hover:translate-x-0" />
      </div>

      {/* pass-rate bar + counts */}
      <div className="mt-3.5">
        <div className="h-1.5 rounded-full bg-muted overflow-hidden">
          <div
            className="h-full rounded-full"
            style={{ width: `${passPct}%`, background: hue }}
          />
        </div>
        <div className="mt-2 flex items-center gap-x-3 gap-y-1 text-[11px] text-muted-foreground flex-wrap">
          <span>
            <span className="font-semibold text-foreground tabular-nums">
              {meta.passed}
            </span>
            /{meta.total} passed
          </span>
          {failing > 0 && (
            <span className="text-destructive">{failing} failing</span>
          )}
          {meta.errors > 0 && (
            <span className="text-amber-600 dark:text-amber-400">
              {meta.errors} errors
            </span>
          )}
          <span className="ml-auto">pass ≥ {pctOfThreshold(meta.threshold)}%</span>
        </div>
      </div>
    </button>
  );
}

function QualityRunsSection() {
  const [reports, setReports] = useState<QualityReportMeta[]>([]);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    listQualityReports()
      .then((r) => setReports(r.reports))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);
  if (loading || reports.length === 0) return null;
  return (
    <section className="space-y-3">
      <div className="flex items-baseline gap-2">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-foreground">
          Recent quality evals
        </h2>
        <span className="text-[11px] text-muted-foreground">
          {reports.length} run{reports.length === 1 ? "" : "s"} · newest first ·
          ▲/▼ vs the previous run of the same dataset
        </span>
      </div>
      <div className="grid gap-3 md:grid-cols-2">
        {reports.map((r, i) => (
          <QualityRunCard key={r.id} meta={r} delta={scoreDelta(reports, i)} />
        ))}
      </div>
    </section>
  );
}

/** The focused, full-page trace for one run — reached from a run card. */
export function EvaluationRunPage() {
  const { filename } = useParams();
  const navigate = useNavigate();
  const [report, setReport] = useState<QualityEvalReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!filename) return;
    setLoading(true);
    setError(null);
    getQualityReport(filename)
      .then((r) => setReport(r.report))
      .catch(() => setError("This report could not be loaded."))
      .finally(() => setLoading(false));
  }, [filename]);

  const s = report?.summary;

  return (
    <div className="p-6 space-y-5">
      <button
        type="button"
        onClick={() => navigate("/evaluations")}
        className="inline-flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="w-4 h-4" />
        Back to Evaluations
      </button>

      {loading && (
        <div className="flex items-center gap-2 text-sm text-muted-foreground py-12 justify-center">
          <Loader2 className="w-4 h-4 animate-spin" /> Loading report…
        </div>
      )}

      {error && !loading && (
        <div className="flex items-center gap-2 text-sm text-destructive py-12 justify-center">
          <AlertTriangle className="w-4 h-4" /> {error}
        </div>
      )}

      {report && s && (
        <>
          {/* focused run header */}
          <div className="rounded-xl border border-border bg-card p-5">
            <div className="flex items-start gap-5 flex-wrap">
              <ScoreDial score={s.score} size={84} />
              <div className="min-w-0 flex-1">
                <h1 className="text-lg font-semibold text-foreground break-words">
                  {shortName(report.dataset ?? filename ?? "report")}
                </h1>
                <div className="mt-1.5 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                  <Badge variant="outline" className="text-[10.5px]">
                    {report.targetUrl || "unknown target"}
                  </Badge>
                  <span className="flex items-center gap-1">
                    <Clock className="w-3.5 h-3.5" />
                    {new Date(report.timestamp).toLocaleString()}
                  </span>
                  <span>pass threshold ≥ {pctOfThreshold(report.passThreshold)}%</span>
                </div>
                {/* headline counts */}
                <div className="mt-3 flex flex-wrap gap-4 text-sm">
                  <span>
                    <span className="font-semibold tabular-nums text-emerald-600 dark:text-emerald-400">
                      {s.passed}
                    </span>{" "}
                    <span className="text-muted-foreground">passed</span>
                  </span>
                  <span>
                    <span className="font-semibold tabular-nums text-destructive">
                      {Math.max(0, s.total - s.passed - s.errors)}
                    </span>{" "}
                    <span className="text-muted-foreground">failing</span>
                  </span>
                  {s.errors > 0 && (
                    <span>
                      <span className="font-semibold tabular-nums text-amber-600 dark:text-amber-400">
                        {s.errors}
                      </span>{" "}
                      <span className="text-muted-foreground">errors</span>
                    </span>
                  )}
                  <span>
                    <span className="font-semibold tabular-nums text-foreground">
                      {s.total}
                    </span>{" "}
                    <span className="text-muted-foreground">total</span>
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* the records browser, full width */}
          <ReportTrace report={report} />
        </>
      )}
    </div>
  );
}

export function EvaluationsPage() {
  const [datasets, setDatasets] = useState<DatasetSummary[]>([]);
  useEffect(() => {
    listDatasets()
      .then((r) => setDatasets(r.datasets))
      .catch(() => {});
  }, []);
  const securityCount = datasets.filter((d) => d.kind !== "quality").length;
  const qualityCount = datasets.filter((d) => d.kind === "quality").length;

  const sec = EVALS.filter((e) => e.axis === "security");
  const qual = EVALS.filter((e) => e.axis === "quality");

  return (
    <div className="p-6 space-y-6" style={{ ["--eval-sec" as string]: "#e05365", ["--eval-qual" as string]: "#12a594" }}>
      <div className="flex items-center gap-2.5">
        <Gauge className="w-5 h-5 text-primary" />
        <div>
          <h1 className="text-lg font-semibold text-foreground">Evaluations</h1>
          <p className="text-xs text-muted-foreground">
            Every eval runs against a target and produces a scored report. Pick a
            type to see how to run it.
          </p>
        </div>
      </div>

      {/* Live: persisted quality-eval runs (score-over-time) */}
      <QualityRunsSection />

      {/* Two axes */}
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardContent className="p-4 border-l-2" style={{ borderColor: SEC }}>
            <h2 className="text-sm font-semibold text-foreground flex items-center gap-2">
              <Swords className="w-4 h-4" style={{ color: SEC }} /> Adversarial — is it safe?
            </h2>
            <p className="text-xs text-muted-foreground mt-1">
              Attacks the target and judges whether it was compromised. Red-Team
              AI's native engine — white-box, tool-graph aware, per-category
              policies.
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 border-l-2" style={{ borderColor: QUAL }}>
            <h2 className="text-sm font-semibold text-foreground flex items-center gap-2">
              <Gauge className="w-4 h-4" style={{ color: QUAL }} /> Quality — is it good?
            </h2>
            <p className="text-xs text-muted-foreground mt-1">
              Measures correctness against a reference: tool-call accuracy, goal
              accuracy, answer quality. Native scorer today; NeMo Evaluator
              benchmarks planned.
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Security */}
      <section className="space-y-3">
        <div className="flex items-baseline gap-2">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-foreground">
            Security &amp; Safety
          </h2>
          <span className="text-[11px] text-muted-foreground">
            native engine · {securityCount} dataset{securityCount === 1 ? "" : "s"}
          </span>
        </div>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {sec.map((e) => (
            <EvalCard key={e.id} e={e} hue={SEC} />
          ))}
        </div>
      </section>

      {/* Quality */}
      <section className="space-y-3">
        <div className="flex items-baseline gap-2">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-foreground">
            Quality &amp; Accuracy
          </h2>
          <span className="text-[11px] text-muted-foreground">
            native scorer + NeMo Evaluator · {qualityCount} dataset{qualityCount === 1 ? "" : "s"}
          </span>
        </div>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {qual.map((e) => (
            <EvalCard key={e.id} e={e} hue={QUAL} />
          ))}
        </div>
      </section>

      <div className="flex items-center gap-2 text-xs text-muted-foreground pt-2">
        <Database className="w-3.5 h-3.5" />
        Generate the datasets these evals run on in the{" "}
        <button
          className="text-primary underline underline-offset-2"
          onClick={() => window.location.assign("#/datasets")}
        >
          Datasets
        </button>{" "}
        tab.
      </div>
    </div>
  );
}

export default EvaluationsPage;
