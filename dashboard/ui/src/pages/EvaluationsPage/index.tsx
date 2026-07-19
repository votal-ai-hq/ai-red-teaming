import { useState, useEffect } from "react";
import { useNavigate } from "react-router";
import { listDatasets, type DatasetSummary } from "@/api/datasets";
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
  Database,
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
