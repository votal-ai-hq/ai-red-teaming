import { useState, useEffect, useCallback, type ReactNode } from "react";
import { useParams, useNavigate } from "react-router";
import { getReportsMeta, getReport } from "@/api/reports";
import { getStaticCompliance } from "@/api/compliance";
import { promoteFinding } from "@/api/datasets";
import type { ReportMeta, FullReport, ReportResult, ReportSummary, ComplianceResult, UsageSummary } from "@/api/types";
import { useDebounce } from "@/hooks/useDebounce";
import { ScoreRing } from "@/components/shared/ScoreRing";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { LoadingSpinner } from "@/components/shared/LoadingSpinner";
import { EmptyState } from "@/components/shared/EmptyState";
import {
  ExpandableText,
  InteractionFlow,
  ProtocolTrace,
  RequestPanel,
  ResponsePanel,
} from "./Interaction";
import {
  buildInteractionFlow,
  describeRequest,
  describeResponse,
  isMcpResult,
} from "@/lib/mcp-report";
import {
  FileText,
  ArrowLeft,
  ArrowRight,
  Clock,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  Zap,
  AlertCircle,
  ShieldCheck,
  ShieldOff,
  AlertTriangle,
  Filter,
  Download,
  FileDown,
  Printer,
  Loader2,
  Cpu,
  Coins,
  Hash,
  CheckCircle2,
  RefreshCw,
  type LucideIcon,
} from "lucide-react";

/* ─── helpers ─── */

function truncate(str: string, max: number) {
  return str.length > max ? str.slice(0, max) + "..." : str;
}

function fmtDate(iso: string) {
  const d = new Date(iso);
  return d.toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function scoreBadgeClasses(score: number) {
  if (score >= 70) return "bg-emerald-100 text-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-300 ring-emerald-200 dark:ring-emerald-800";
  if (score >= 40) return "bg-orange-100 text-orange-700 dark:bg-orange-900/40 dark:text-orange-300 ring-orange-200 dark:ring-orange-800";
  return "bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300 ring-red-200 dark:ring-red-800";
}

function scoreHue(score: number): string {
  return score >= 70 ? "#12a594" : score >= 40 ? "#f59e0b" : "#e05365";
}

/** A compact themed score dial — matches the Evaluations run cards. */
function ScoreDial({ score, size = 64 }: { score: number; size?: number }) {
  const sw = size * 0.1;
  const r = (size - sw) / 2;
  const c = 2 * Math.PI * r;
  const s = Math.max(0, Math.min(100, score));
  const off = c - (s / 100) * c;
  const hue = scoreHue(s);
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="shrink-0">
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

/** One report as a rich card, matching the Evaluations run-card layout. */
function ReportCard({
  r,
  onOpen,
}: {
  r: ReportMeta;
  onOpen: () => void;
}) {
  // In red-team reports, a "passed" attack means the target was compromised
  // (vulnerable); "failed" means the attack was defended.
  const vulnerable = r.passed;
  const defended = r.failed;
  const total = r.totalAttacks || vulnerable + defended + r.errors || 1;
  const pct = (n: number) => `${Math.min(100, (n / total) * 100)}%`;
  return (
    <button
      type="button"
      onClick={onOpen}
      className="group text-left rounded-xl border border-border bg-card p-4 transition-all hover:border-primary/40 hover:shadow-sm focus:outline-none focus-visible:ring-2 focus-visible:ring-primary/40"
    >
      <div className="flex items-start gap-4">
        <ScoreDial score={r.score} />
        <div className="min-w-0 flex-1">
          <h3 className="text-sm font-semibold text-foreground truncate" title={r.targetUrl || r.filename}>
            {r.targetUrl || truncate(r.filename, 50)}
          </h3>
          <p className="text-[11px] font-mono text-muted-foreground truncate mt-0.5" title={r.filename}>
            {r.filename}
          </p>
          <p className="text-[11px] text-muted-foreground mt-0.5 flex items-center gap-1">
            <Clock className="w-3 h-3 shrink-0" />
            {fmtDate(r.timestamp)}
          </p>
        </div>
        <ArrowRight className="w-4 h-4 text-muted-foreground shrink-0 opacity-0 -translate-x-1 transition-all group-hover:opacity-100 group-hover:translate-x-0" />
      </div>

      {/* defense bar: defended (green) · vulnerable (red) · errors (amber) */}
      <div className="mt-3.5">
        <div className="h-1.5 rounded-full bg-muted overflow-hidden flex">
          <div className="h-full bg-emerald-500" style={{ width: pct(defended) }} />
          <div className="h-full bg-destructive" style={{ width: pct(vulnerable) }} />
          <div className="h-full bg-amber-500" style={{ width: pct(r.errors) }} />
        </div>
        <div className="mt-2 flex items-center gap-x-3 gap-y-1 text-[11px] text-muted-foreground flex-wrap">
          <span>
            <span className="font-semibold text-foreground tabular-nums">{r.totalAttacks}</span> attacks
          </span>
          <span className="text-emerald-600 dark:text-emerald-400">{defended} defended</span>
          {vulnerable > 0 && (
            <span className="text-destructive">{vulnerable} vulnerable</span>
          )}
          {r.errors > 0 && (
            <span className="text-amber-600 dark:text-amber-400">{r.errors} errors</span>
          )}
        </div>
      </div>
    </button>
  );
}

function severityVariant(s: string): "default" | "secondary" | "destructive" | "outline" {
  const l = s.toLowerCase();
  if (l === "critical" || l === "high") return "destructive";
  if (l === "medium") return "default";
  if (l === "low") return "secondary";
  return "outline";
}

/** Extract summary stats from a FullReport, handling both top-level and nested summary object */
function getReportStats(report: FullReport) {
  const s = typeof report.summary === "object" && report.summary ? report.summary as ReportSummary : null;
  return {
    score: s?.score ?? report.score ?? 0,
    passed: s?.passed ?? report.passed ?? 0,
    failed: s?.failed ?? report.failed ?? 0,
    errors: s?.errors ?? report.errors ?? 0,
    totalAttacks: s?.totalAttacks ?? report.totalAttacks ?? 0,
  };
}

/** Get the display name for a result's attack */
function getAttackName(result: ReportResult): string {
  const atk = result.attack;
  if (typeof atk === "object" && atk !== null) return (atk as Record<string, unknown>).name as string ?? "Unknown";
  if (typeof atk === "string") return atk;
  return result.attackName ?? "Unknown";
}

/** Get category from result, falling back to attack object */
function getCategory(result: ReportResult): string {
  if (result.category) return result.category;
  const atk = result.attack;
  if (typeof atk === "object" && atk !== null) return (atk as Record<string, unknown>).category as string ?? "";
  return "";
}

/** Get severity from result, falling back to attack object */
function getSeverity(result: ReportResult): string {
  if (result.severity) return result.severity;
  const atk = result.attack;
  if (typeof atk === "object" && atk !== null) return (atk as Record<string, unknown>).severity as string ?? "";
  return "";
}

/** Get the round number from a round object */
function getRoundNumber(round: { round?: number; roundNumber?: number }): number {
  return round.round ?? round.roundNumber ?? 0;
}

/*
 * Verdict semantics (from lib/response-analyzer.ts — the source of truth):
 *   PASS    = the attack SUCCEEDED → a vulnerability was found (BAD, red)
 *   FAIL    = the agent DEFENDED → the attack was blocked (GOOD, green)
 *   PARTIAL = partial leak / incomplete defense
 * The raw verdict strings are kept in the data; we only relabel/recolor them in
 * the UI so a held defense reads as a positive outcome instead of a scary "FAIL".
 */

/** Defender-friendly display label for a raw verdict. */
function verdictLabel(v: string | undefined | null): string {
  const l = (v ?? "").toUpperCase();
  if (l === "PASS") return "Vulnerable";
  if (l === "FAIL") return "Defended";
  if (l === "PARTIAL") return "Partial";
  if (l === "ERROR") return "Error";
  return v ?? "—";
}

/** Badge variant + extra classes for a raw verdict. */
function verdictBadge(v: string | undefined | null): {
  variant: "destructive" | "default" | "secondary" | "outline";
  className: string;
} {
  const l = (v ?? "").toUpperCase();
  if (l === "PASS") return { variant: "destructive", className: "" };
  if (l === "FAIL")
    return {
      variant: "outline",
      className:
        "text-emerald-600 dark:text-emerald-400 border-emerald-200 dark:border-emerald-800",
    };
  if (l === "PARTIAL")
    return {
      variant: "outline",
      className:
        "text-amber-600 dark:text-amber-400 border-amber-200 dark:border-amber-800",
    };
  return { variant: "secondary", className: "" };
}

function prettyCat(cat: string) {
  return cat.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function verdictDotColor(v: string | undefined | null) {
  const l = (v ?? "").toUpperCase();
  if (l === "PASS") return "bg-red-500";
  if (l === "FAIL") return "bg-emerald-500";
  if (l === "PARTIAL") return "bg-amber-500";
  return "bg-gray-400";
}

/* ─── Grid Mode (Table-based list) ─── */

function ReportsGrid() {
  const navigate = useNavigate();
  const [search, setSearch] = useState("");
  const debouncedSearch = useDebounce(search, 300);
  const [page, setPage] = useState(1);
  const [reports, setReports] = useState<ReportMeta[]>([]);
  const [totalPages, setTotalPages] = useState(1);
  const [loading, setLoading] = useState(true);

  const fetchReports = useCallback(async () => {
    setLoading(true);
    try {
      const res = await getReportsMeta(page, 50, debouncedSearch);
      setReports(res.items);
      setTotalPages(res.totalPages);
    } catch {
      setReports([]);
    } finally {
      setLoading(false);
    }
  }, [page, debouncedSearch]);

  useEffect(() => {
    fetchReports();
  }, [fetchReports]);

  useEffect(() => {
    setPage(1);
  }, [debouncedSearch]);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-32">
        <LoadingSpinner size="lg" />
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      {/* Search */}
      <div>
        <input
          type="text"
          placeholder="Search reports..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full max-w-md px-4 py-2.5 rounded-lg border border-border bg-card text-sm text-foreground placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/40 focus:border-primary/40"
        />
      </div>

      {reports.length === 0 ? (
        <EmptyState
          title="No reports found"
          description="Run a scan to generate your first report."
          icon={<FileText size={48} />}
        />
      ) : (
        <>
          <div className="grid gap-3 md:grid-cols-2">
            {reports.map((r) => (
              <ReportCard
                key={r.filename}
                r={r}
                onOpen={() => navigate(`/reports/${encodeURIComponent(r.filename)}`)}
              />
            ))}
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-center gap-2 pt-2">
              <button
                disabled={page <= 1}
                onClick={() => setPage((p) => p - 1)}
                className="px-3 py-1.5 text-sm rounded-lg border border-border bg-card disabled:opacity-40 hover:bg-muted"
              >
                Previous
              </button>
              <span className="text-sm text-muted-foreground">
                Page {page} of {totalPages}
              </span>
              <button
                disabled={page >= totalPages}
                onClick={() => setPage((p) => p + 1)}
                className="px-3 py-1.5 text-sm rounded-lg border border-border bg-card disabled:opacity-40 hover:bg-muted"
              >
                Next
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}

/* ─── Per-vulnerability compliance mapping ─── */

interface ComplianceControlRef {
  framework: string;
  code: string;
  title: string;
  status: string;
}

/**
 * Invert the report-level control→attacks mapping into category→controls, so
 * each finding can show the compliance controls its category maps against.
 * Controls map onto attacks by category, so every finding in a tested category
 * resolves to the same set of relevant controls.
 */
function buildComplianceByCategory(
  results: ComplianceResult[],
): Map<string, ComplianceControlRef[]> {
  const byCat = new Map<string, ComplianceControlRef[]>();
  for (const control of results) {
    const cats = new Set(
      (control.attacks ?? []).map((a) => a.category).filter(Boolean),
    );
    for (const cat of cats) {
      const list = byCat.get(cat) ?? [];
      if (!list.some((c) => c.framework === control.framework && c.code === control.code)) {
        list.push({
          framework: control.framework,
          code: control.code,
          title: control.title,
          status: control.status,
        });
      }
      byCat.set(cat, list);
    }
  }
  return byCat;
}

function complianceStatusDot(status: string): string {
  if (status === "vulnerable") return "bg-red-500";
  if (status === "at_risk") return "bg-orange-500";
  if (status === "secure") return "bg-emerald-500";
  return "bg-gray-400";
}

/* ─── Save a confirmed finding as a permanent regression test ─── */

function RegressionButton({ result }: { result: ReportResult }) {
  const [state, setState] = useState<"idle" | "saving" | "saved" | "dup" | "error">("idle");
  const [msg, setMsg] = useState("");

  const atk =
    typeof result.attack === "object" && result.attack
      ? (result.attack as Record<string, unknown>)
      : null;
  const payload = (atk?.payload as Record<string, unknown> | undefined) ?? undefined;
  const prompt = String(
    payload?.message ??
      (typeof result.payload === "string" ? result.payload : "") ??
      "",
  ).trim();
  const category = String(atk?.category ?? getCategory(result) ?? "").trim();
  const successCriteria = String(
    atk?.expectation ?? (result.findings ?? []).join("; ") ?? "",
  ).trim();

  if (!prompt || !category) return null;

  const onClick = async () => {
    setState("saving");
    try {
      const r = await promoteFinding({
        row: {
          category,
          prompt,
          successCriteria,
          severity: String(atk?.severity ?? "high"),
          name: getAttackName(result),
        },
      });
      setState(r.added ? "saved" : "dup");
      setMsg(r.added ? `Saved · ${r.rowCount} in regression set` : "Already in regression set");
    } catch (e) {
      setState("error");
      setMsg((e as Error).message);
    }
  };

  return (
    <div className="flex items-center gap-2">
      <button
        type="button"
        onClick={onClick}
        disabled={state === "saving" || state === "saved" || state === "dup"}
        className="inline-flex items-center gap-1.5 rounded-md border border-border px-2.5 py-1 text-xs font-medium text-foreground hover:border-primary hover:text-primary disabled:opacity-60 transition-colors"
      >
        {state === "saved" || state === "dup" ? "✓ " : "＋ "}
        Save as regression test
      </button>
      {msg && (
        <span className={`text-[11px] ${state === "error" ? "text-red-600" : "text-muted-foreground"}`}>
          {msg}
        </span>
      )}
    </div>
  );
}

/* ─── Finding Row (rich expandable detail) ─── */

function FindingRow({ result, controls = [] }: { result: ReportResult; controls?: ComplianceControlRef[] }) {
  const [expanded, setExpanded] = useState(false);
  const conversations = result.conversation ?? result.steps ?? [];
  const atk = typeof result.attack === "object" && result.attack ? result.attack as Record<string, unknown> : null;
  const strategyName = atk?.strategyName as string | undefined;
  const idealResp = typeof result.idealResponse === "object" && result.idealResponse
    ? result.idealResponse as { content?: string; explanation?: string }
    : typeof result.idealResponse === "string" ? { content: result.idealResponse } : null;

  // MCP (and agent) traffic is stored as nested JSON. Turn it into structured
  // summaries — labelled operation/tool/arguments and the server's text — while
  // keeping the raw object for the per-panel "raw JSON" toggle.
  const attackPayload = atk?.payload;
  const request = describeRequest(attackPayload ?? result.payload);
  const response = describeResponse(result.responseBody);
  const isMcp = isMcpResult({
    attackPayload,
    responseBody: result.responseBody,
    executionTrace: result.executionTrace,
  });
  // The full ordered sequence of interactions: every request the scanner sent,
  // every response it got, and — when the target was driven agent-in-the-loop —
  // the model's own turns between the two.
  const flow = buildInteractionFlow({
    attackPayload: attackPayload ?? result.payload,
    responseBody: result.responseBody,
    statusCode: result.statusCode,
    responseTimeMs: result.responseTimeMs,
    conversation: conversations,
    executionTrace: result.executionTrace,
  });
  // Whether this row represents an actual request/response interaction (so a
  // Response panel belongs even when there's no text — vs. static findings).
  const hasInteraction =
    !request.isEmpty ||
    !response.isEmpty ||
    result.statusCode != null ||
    result.responseTimeMs != null ||
    conversations.length > 0;
  // With more than one exchange the flow IS the request/response view; the
  // single-exchange case reads better as two side-by-side panels.
  const showPanels = hasInteraction && flow.length <= 2;

  return (
    <>
      <TableRow
        className="cursor-pointer"
        onClick={() => setExpanded((v) => !v)}
      >
        <TableCell className="text-sm align-top whitespace-normal">
          <span className="flex items-start gap-1.5">
            {expanded ? (
              <ChevronDown size={14} className="mt-0.5 shrink-0 text-muted-foreground" />
            ) : (
              <ChevronRight size={14} className="mt-0.5 shrink-0 text-muted-foreground" />
            )}
            <span className={`mt-1.5 w-2 h-2 rounded-full shrink-0 ${verdictDotColor(result.verdict)}`} />
            <span className="min-w-0 break-words">{getAttackName(result)}</span>
          </span>
        </TableCell>
        <TableCell className="text-sm text-muted-foreground align-top whitespace-normal break-words">{prettyCat(getCategory(result) || "-")}</TableCell>
        <TableCell>
          <Badge variant={severityVariant(getSeverity(result) || "unknown")}>{getSeverity(result) || "unknown"}</Badge>
        </TableCell>
        <TableCell>
          <Badge variant={verdictBadge(result.verdict).variant} className={verdictBadge(result.verdict).className}>{verdictLabel(result.verdict)}</Badge>
        </TableCell>
        <TableCell className="text-sm text-muted-foreground max-w-xs align-top">
          {/* Show the full reasoning in the cell (no clamp) so it never cuts off
              mid-sentence; the fixed 40% column keeps it wrapping neatly. */}
          <span className="whitespace-normal break-words">
            {result.llmReasoning || result.reasoning || "-"}
          </span>
        </TableCell>
      </TableRow>

      {expanded && (
        <TableRow className="bg-muted/20">
          {/* whitespace-normal overrides TableCell's default `whitespace-nowrap`,
              which otherwise inherits into every child (findings, policy lists,
              threat description) and makes long text render as one clipped line. */}
          <TableCell colSpan={5} className="px-6 py-5 whitespace-normal">
            <div className="space-y-4">
              {/* ── Top bar: verdict + severity + category + response time ── */}
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant={verdictBadge(result.verdict).variant} className={verdictBadge(result.verdict).className}>{verdictLabel(result.verdict)}</Badge>
                <Badge variant={severityVariant(getSeverity(result))}>{getSeverity(result)}</Badge>
                <span className="text-xs text-muted-foreground">
                  {prettyCat(getCategory(result))}
                </span>
                {strategyName && (
                  <span className="text-xs text-muted-foreground">· {strategyName}</span>
                )}
                {result.statusCode && (
                  <span className="text-xs text-muted-foreground">· HTTP {result.statusCode}</span>
                )}
                {result.responseTimeMs != null && (
                  <span className="text-xs text-muted-foreground">{result.responseTimeMs}ms</span>
                )}
              </div>

              {/* ── Compliance mapping — controls this vulnerability maps to ── */}
              {controls.length > 0 && (
                <div>
                  <div className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground mb-1.5">
                    Compliance Mapping
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {controls.map((c) => (
                      <span
                        key={`${c.framework}-${c.code}`}
                        title={`${c.framework} · ${c.title} — ${c.status.replace(/_/g, " ")}`}
                        className="inline-flex items-center gap-1.5 rounded-md border border-border bg-card px-2 py-1 text-[11px] text-foreground"
                      >
                        <span className={`w-1.5 h-1.5 rounded-full ${complianceStatusDot(c.status)}`} />
                        <span className="font-mono font-medium">{c.code}</span>
                        <span className="text-muted-foreground">{c.title}</span>
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* ── Request & Response (single exchange) ── */}
              {showPanels && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <RequestPanel request={request} />
                  {/* Always render the Response panel for an interaction — the
                      panel itself explains an empty body (e.g. output went via
                      tool calls / a side-channel). */}
                  <ResponsePanel
                    response={response}
                    statusCode={result.statusCode}
                    timeMs={result.responseTimeMs}
                  />
                </div>
              )}

              {/* ── Evidence For / Against ── */}
              {(result.llmEvidenceFor || result.llmEvidenceAgainst) && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {result.llmEvidenceFor && (
                    <div className="min-w-0 rounded-lg border border-red-200 dark:border-red-900 bg-red-50/30 dark:bg-red-950/10 p-3">
                      <div className="text-[10px] font-semibold uppercase tracking-wider text-red-600 dark:text-red-400 mb-1.5 flex items-center gap-1.5">
                        <span className="w-1.5 h-1.5 rounded-full bg-red-500" />
                        Evidence For Vulnerability
                      </div>
                      <ExpandableText text={result.llmEvidenceFor} maxLines={5} />
                    </div>
                  )}
                  {result.llmEvidenceAgainst && (
                    <div className="min-w-0 rounded-lg border border-emerald-200 dark:border-emerald-900 bg-emerald-50/30 dark:bg-emerald-950/10 p-3">
                      <div className="text-[10px] font-semibold uppercase tracking-wider text-emerald-600 dark:text-emerald-400 mb-1.5 flex items-center gap-1.5">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                        Evidence Against (Defense)
                      </div>
                      <ExpandableText text={result.llmEvidenceAgainst} maxLines={5} />
                    </div>
                  )}
                </div>
              )}

              {/* ── Findings ── */}
              {result.findings && result.findings.length > 0 && (
                <div>
                  <div className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground mb-1.5">Findings</div>
                  <ul className="list-disc list-inside text-sm text-muted-foreground space-y-0.5">
                    {result.findings.map((f, i) => <li key={i}>{f}</li>)}
                  </ul>
                </div>
              )}

              {/* ── Promote to regression dataset (confirmed compromises) ── */}
              {(result.verdict === "PASS" || result.verdict === "PARTIAL") && (
                <RegressionButton result={result} />
              )}

              {/* ── Threat Assessment + Confidence (compact row) ── */}
              {(result.threatAssessment || result.judgeConfidence != null || result.llmReasoning) && (
                <div className="flex flex-wrap items-start gap-4 rounded-lg border border-border bg-card p-3">
                  {result.threatAssessment && (
                    <div className="min-w-0 flex-1">
                      <div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground mb-1">Threat Assessment</div>
                      <Badge variant={severityVariant(result.threatAssessment.level)} className="mb-1">
                        {result.threatAssessment.level}
                      </Badge>
                      <p className="text-xs text-muted-foreground">{result.threatAssessment.description}</p>
                    </div>
                  )}
                  {result.judgeConfidence != null && (
                    <div className="shrink-0 text-center">
                      <div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground mb-1">Confidence</div>
                      <div className="flex items-center gap-2">
                        <span className={`text-lg font-bold tabular-nums ${
                          result.judgeConfidence >= 70 ? "text-emerald-600 dark:text-emerald-400" :
                          result.judgeConfidence >= 40 ? "text-amber-600 dark:text-amber-400" :
                          "text-red-600 dark:text-red-400"
                        }`}>{result.judgeConfidence}%</span>
                        <div className="w-16 h-1.5 bg-muted rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full ${
                              result.judgeConfidence >= 70 ? "bg-emerald-500" : result.judgeConfidence >= 40 ? "bg-amber-500" : "bg-red-500"
                            }`}
                            style={{ width: `${result.judgeConfidence}%` }}
                          />
                        </div>
                      </div>
                    </div>
                  )}
                  {result.llmReasoning && (
                    <div className="min-w-0 flex-1 basis-full">
                      <div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground mb-1">LLM Reasoning</div>
                      {/* Show the full reasoning once the row is expanded — no
                          secondary clamp — so it matches the downloadable report
                          instead of cutting off mid-sentence. */}
                      <p className="text-[13px] text-foreground whitespace-pre-wrap break-words leading-relaxed">
                        {result.llmReasoning}
                      </p>
                    </div>
                  )}
                </div>
              )}

              {/* ── Ideal Response ── */}
              {idealResp && idealResp.content && (
                <div className="rounded-lg border border-emerald-200 dark:border-emerald-900 bg-emerald-50/30 dark:bg-emerald-950/10 p-3">
                  <div className="text-[10px] font-semibold uppercase tracking-wider text-emerald-600 dark:text-emerald-400 mb-1.5 flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                    Ideal Response
                  </div>
                  <ExpandableText text={idealResp.content} maxLines={4} />
                  {idealResp.explanation && (
                    <p className="text-[11px] text-muted-foreground mt-1.5 italic">{idealResp.explanation}</p>
                  )}
                </div>
              )}

              {/* ── Interaction flow: the full user → model → server sequence ── */}
              {!showPanels && <InteractionFlow steps={flow} isMcp={isMcp} />}

              {/* ── Wire-level MCP transcript (collapsed) ── */}
              {result.executionTrace && <ProtocolTrace trace={result.executionTrace} />}

              {/* ── Judge Policy ── */}
              {result.policyUsed && (
                <div className="rounded-lg border border-border bg-card p-3">
                  <div className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground mb-1.5">
                    Judge Policy — {result.policyUsed.name}
                  </div>
                  {/* Stacked vertically so long criteria stay readable */}
                  <div className="space-y-2.5 text-xs">
                    {result.policyUsed.pass_criteria && result.policyUsed.pass_criteria.length > 0 && (
                      <div className="border-l-2 border-emerald-400/60 pl-2.5">
                        <div className="font-semibold text-emerald-600 dark:text-emerald-400">PASS criteria</div>
                        <ul className="list-disc pl-4 text-muted-foreground mt-0.5 space-y-0.5 break-words">
                          {result.policyUsed.pass_criteria.map((c, i) => <li key={i}>{c}</li>)}
                        </ul>
                      </div>
                    )}
                    {result.policyUsed.fail_criteria && result.policyUsed.fail_criteria.length > 0 && (
                      <div className="border-l-2 border-red-400/60 pl-2.5">
                        <div className="font-semibold text-red-600 dark:text-red-400">FAIL criteria</div>
                        <ul className="list-disc pl-4 text-muted-foreground mt-0.5 space-y-0.5 break-words">
                          {result.policyUsed.fail_criteria.map((c, i) => <li key={i}>{c}</li>)}
                        </ul>
                      </div>
                    )}
                    {result.policyUsed.partial_criteria && result.policyUsed.partial_criteria.length > 0 && (
                      <div className="border-l-2 border-amber-400/60 pl-2.5">
                        <div className="font-semibold text-amber-600 dark:text-amber-400">PARTIAL criteria</div>
                        <ul className="list-disc pl-4 text-muted-foreground mt-0.5 space-y-0.5 break-words">
                          {result.policyUsed.partial_criteria.map((c, i) => <li key={i}>{c}</li>)}
                        </ul>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          </TableCell>
        </TableRow>
      )}
    </>
  );
}

/* ─── Detail Mode ─── */

/* ─── LLM usage panel (report.usage) ─── */

function fmtUsd(n: number | null): string {
  if (n == null) return "n/a";
  return n < 0.01 ? `$${n.toFixed(4)}` : `$${n.toFixed(2)}`;
}
function fmtTokens(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(2)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}
function fmtDur(ms: number): string {
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  return `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, "0")}s`;
}

function UsagePanel({ usage }: { usage: UsageSummary }) {
  const stats: { label: string; value: string; sub?: string; accent?: string; icon: LucideIcon }[] = [
    {
      label: "est. cost",
      value: usage.costUsd == null ? "n/a" : `${fmtUsd(usage.costUsd)}${usage.costComplete ? "" : "+"}`,
      accent: "text-emerald-600 dark:text-emerald-400",
      icon: Coins,
    },
    {
      label: "tokens",
      value: fmtTokens(usage.totalTokens),
      sub: `${fmtTokens(usage.inputTokens)} in / ${fmtTokens(usage.outputTokens)} out`,
      icon: Hash,
    },
    { label: "LLM time", value: fmtDur(usage.llmLatencyMsTotal), icon: Clock },
    { label: "calls", value: String(usage.totalCalls), icon: Zap },
  ];
  // Always show the failure metric so it's clear failures are tracked; neutral
  // at zero (a red "0" reads as alarming), red with a breakdown when > 0.
  stats.push({
    label: "failed",
    value: String(usage.failedCalls),
    sub:
      usage.failedCalls > 0
        ? `${usage.errorsByKind.rate_limit} rate-limit · ${usage.errorsByKind.timeout} timeout · ${usage.errorsByKind.other} other`
        : "all calls succeeded",
    accent: usage.failedCalls > 0 ? "text-red-600 dark:text-red-400" : "text-foreground",
    icon: usage.failedCalls > 0 ? AlertTriangle : CheckCircle2,
  });
  const retries = usage.totalRetries ?? 0;
  if (retries > 0) {
    stats.push({
      label: "retries",
      value: String(retries),
      sub: (usage.retryTokens ?? 0) > 0
        ? `${fmtTokens(usage.retryTokens!)} tokens on failed attempts`
        : "no wasted tokens reported",
      accent: "text-amber-600 dark:text-amber-400",
      icon: RefreshCw,
    });
  }

  // Hide the by-phase table until calls carry meaningful phase labels.
  const showPhases =
    usage.byPhase.length > 1 ||
    (usage.byPhase.length === 1 && usage.byPhase[0].phase !== "uncategorized");

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-semibold flex items-center gap-2">
          <Cpu className="w-4 h-4 text-primary" />
          LLM Usage
          <span className="text-xs text-muted-foreground font-normal">
            what this scan spent on model calls
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
          {stats.map((s) => {
            const Icon = s.icon;
            return (
              <div
                key={s.label}
                className="rounded-xl border border-border bg-muted/20 px-4 py-3"
              >
                <div className="flex items-center gap-1.5 text-muted-foreground mb-1.5">
                  <Icon className="w-3.5 h-3.5 shrink-0" />
                  <span className="text-[11px] font-medium uppercase tracking-wide">{s.label}</span>
                </div>
                <div className={`text-2xl font-bold tracking-tight tabular-nums ${s.accent ?? "text-foreground"}`}>
                  {s.value}
                </div>
                {s.sub && <div className="text-[11px] text-muted-foreground/70 mt-1">{s.sub}</div>}
              </div>
            );
          })}
        </div>

        {(!usage.costComplete || !usage.tokensComplete) && (
          <div className="flex items-start gap-1.5 text-[11px] text-muted-foreground">
            <Coins className="w-3.5 h-3.5 shrink-0 mt-0.5" />
            <div>
              {!usage.costComplete && usage.unpricedModels.length > 0 && (
                <div>Cost is a partial estimate — no price for: {usage.unpricedModels.join(", ")}.</div>
              )}
              {!usage.tokensComplete && (
                <div>Some calls didn&rsquo;t report token usage — token totals are a lower bound.</div>
              )}
            </div>
          </div>
        )}

        {usage.byModel.length > 0 && (
          <UsageTable
            title="By model"
            rows={usage.byModel.map((m) => ({
              label: (
                <span>
                  <span className="text-muted-foreground">{m.provider}/</span>
                  <span className="font-medium text-foreground">{m.model}</span>
                </span>
              ),
              key: `${m.provider}/${m.model}`,
              calls: m.calls,
              tokens: m.totalTokens,
              latencyMs: m.latencyMs,
              costUsd: m.costUsd,
            }))}
          />
        )}

        {showPhases && (
          <UsageTable
            title="By phase"
            rows={usage.byPhase.map((p) => ({
              label: <span className="font-medium text-foreground">{p.phase}</span>,
              key: p.phase,
              calls: p.calls,
              tokens: p.totalTokens,
              latencyMs: p.latencyMs,
              costUsd: p.costUsd,
            }))}
          />
        )}

        <p className="text-[11px] text-muted-foreground/70">
          Tokens, latency and calls are measured. Cost is an estimate (tokens × a
          per-model price table) — labelled &ldquo;est.&rdquo;.
        </p>
      </CardContent>
    </Card>
  );
}

function UsageTable({
  title,
  rows,
}: {
  title: string;
  rows: { key: string; label: ReactNode; calls: number; tokens: number; latencyMs: number; costUsd: number | null }[];
}) {
  return (
    <div>
      <div className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground mb-1.5">
        {title}
      </div>
      <div className="overflow-x-auto rounded-lg border border-border">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-muted/40 text-left text-[11px] uppercase tracking-wider text-muted-foreground">
              <th className="py-1.5 px-3 font-medium">{title.replace("By ", "")}</th>
              <th className="py-1.5 px-3 font-medium text-right">Calls</th>
              <th className="py-1.5 px-3 font-medium text-right">Tokens</th>
              <th className="py-1.5 px-3 font-medium text-right">Latency</th>
              <th className="py-1.5 px-3 font-medium text-right">Cost</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.key} className="border-t border-border">
                <td className="py-1.5 px-3">{r.label}</td>
                <td className="py-1.5 px-3 text-right tabular-nums">{r.calls}</td>
                <td className="py-1.5 px-3 text-right tabular-nums">{fmtTokens(r.tokens)}</td>
                <td className="py-1.5 px-3 text-right tabular-nums text-muted-foreground">{fmtDur(r.latencyMs)}</td>
                <td className="py-1.5 px-3 text-right tabular-nums">
                  {r.costUsd == null ? <span className="text-muted-foreground">n/a</span> : fmtUsd(r.costUsd)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function ReportDetail({ filename }: { filename: string }) {
  const navigate = useNavigate();
  const [report, setReport] = useState<FullReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [activeRound, setActiveRound] = useState(0);
  const [findingsPage, setFindingsPage] = useState(1);
  const [verdictFilter, setVerdictFilter] = useState<string>("all");
  const [categoryFilter, setCategoryFilter] = useState<string>("all");
  const [preparingPdf, setPreparingPdf] = useState(false);
  const [complianceByCategory, setComplianceByCategory] = useState<
    Map<string, ComplianceControlRef[]>
  >(new Map());
  const perPage = 25;

  // Fetch the deterministic compliance mapping so each finding can show the
  // controls its category maps against. Non-blocking: the report renders
  // regardless, and chips simply don't appear if this fails.
  useEffect(() => {
    let cancelled = false;
    getStaticCompliance(filename)
      .then((res) => {
        if (!cancelled) setComplianceByCategory(buildComplianceByCategory(res.results));
      })
      .catch(() => {
        if (!cancelled) setComplianceByCategory(new Map());
      });
    return () => {
      cancelled = true;
    };
  }, [filename]);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    getReport(filename, false)
      .then((r) => {
        if (!cancelled) setReport(r);
      })
      .catch(() => {
        if (!cancelled) setError("Failed to load report");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [filename]);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-32">
        <LoadingSpinner size="lg" />
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="max-w-7xl mx-auto">
        <button
          onClick={() => navigate("/reports")}
          className="flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground mb-4"
        >
          <ArrowLeft size={16} /> Back to Reports
        </button>
        <EmptyState title={error || "Report not found"} icon={<FileText size={48} />} />
      </div>
    );
  }

  const stats = getReportStats(report);
  const rounds = report.rounds ?? [];
  const allResults: ReportResult[] = rounds.flatMap((r) => r.results ?? []);
  const currentRoundResults: ReportResult[] =
    rounds.length > 0 ? rounds[activeRound]?.results ?? [] : [];

  // Category breakdown from summary.byCategory
  const byCategory =
    typeof report.summary === "object" && report.summary
      ? ((report.summary as ReportSummary).byCategory as Record<string, { total: number; passed: number; findings: string[] }> | undefined) ?? {}
      : {};
  const categoryEntries = Object.entries(byCategory)
    .filter(([, v]) => v.total > 0)
    .sort((a, b) => b[1].passed - a[1].passed);
  const maxCatTotal = categoryEntries.length > 0 ? Math.max(...categoryEntries.map(([, v]) => v.total)) : 1;

  // Unique categories & verdicts for filters
  const uniqueCategories = [...new Set(currentRoundResults.map((r) => getCategory(r)).filter(Boolean))];
  const uniqueVerdicts = [...new Set(currentRoundResults.map((r) => r.verdict).filter(Boolean))];

  // Apply filters
  let filteredResults = currentRoundResults;
  if (verdictFilter !== "all") {
    filteredResults = filteredResults.filter((r) => r.verdict === verdictFilter);
  }
  if (categoryFilter !== "all") {
    filteredResults = filteredResults.filter((r) => getCategory(r) === categoryFilter);
  }

  const totalFindings = filteredResults.length;
  const totalFindingsPages = Math.max(1, Math.ceil(totalFindings / perPage));
  const pagedFindings = filteredResults.slice(
    (findingsPage - 1) * perPage,
    findingsPage * perPage,
  );

  // All results from all rounds (used by print table, always computed)
  const allRoundsResults = rounds.flatMap((r) => r.results ?? []);

  // Partial count
  const partialCount = allResults.filter((r) => r.verdict === "PARTIAL").length;

  return (
    <div className="max-w-7xl mx-auto space-y-5">
      {/* Back + Header */}
      <div className="flex items-center justify-between">
        <button
          onClick={() => navigate("/reports")}
          className="flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft size={16} /> Back to Reports
        </button>
        <div className="flex items-center gap-2">
          <Badge variant="secondary">Completed</Badge>
          <a
            href={`/api/report/${encodeURIComponent(filename)}?download=1`}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-foreground border border-border rounded-lg hover:bg-muted transition-colors"
            download
          >
            <Download className="w-3.5 h-3.5" />
            JSON
          </a>
          <a
            href={`/api/report-csv/${encodeURIComponent(filename)}`}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-foreground border border-border rounded-lg hover:bg-muted transition-colors"
            download
          >
            <FileDown className="w-3.5 h-3.5" />
            CSV
          </a>
          <button
            disabled={preparingPdf}
            onClick={() => {
              setPreparingPdf(true);
              // Give browser time to render the full table before opening print
              requestAnimationFrame(() => {
                setTimeout(() => {
                  window.print();
                  setPreparingPdf(false);
                }, 100);
              });
            }}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-white bg-primary rounded-lg hover:bg-primary/90 disabled:opacity-70 transition-colors no-print"
          >
            {preparingPdf ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                Preparing...
              </>
            ) : (
              <>
                <Printer className="w-3.5 h-3.5" />
                PDF
              </>
            )}
          </button>
        </div>
      </div>

      {/* Target URL header */}
      <div>
        <h1 className="text-lg font-bold text-foreground">{report.targetUrl}</h1>
        <p className="text-xs text-muted-foreground mt-0.5">{fmtDate(report.timestamp)}</p>
      </div>

      {/* ── Score + Stats row ── */}
      <Card>
        <CardContent className="py-5">
          <div className="grid grid-cols-6 gap-4 items-center">
            {/* Score ring */}
            <div className="flex flex-col items-center">
              <ScoreRing score={stats.score} size={80} />
              <span className="text-[11px] text-muted-foreground mt-1">Security Score</span>
            </div>

            {/* Stats cards */}
            {([
              { label: "TOTAL ATTACKS", value: stats.totalAttacks, icon: Zap, color: "text-foreground" },
              // PASS verdict = attack succeeded = vulnerability; FAIL = defended.
              { label: "VULNERABILITIES", value: stats.passed, icon: AlertCircle, color: "text-red-600 dark:text-red-400" },
              { label: "PARTIAL", value: partialCount, icon: AlertTriangle, color: "text-amber-600 dark:text-amber-400" },
              { label: "DEFENDED", value: stats.failed, icon: ShieldCheck, color: "text-emerald-600 dark:text-emerald-400" },
              { label: "ERRORS", value: stats.errors, icon: ShieldOff, color: "text-muted-foreground" },
            ] as const).map(({ label, value, icon: Icon, color }) => (
              <div key={label} className="text-center">
                <Icon className={`w-5 h-5 mx-auto mb-1 ${color}`} />
                <div className={`text-2xl font-bold tabular-nums ${color}`}>{value}</div>
                <div className="text-[10px] text-muted-foreground uppercase tracking-wider mt-0.5">
                  {label}
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* ── Verdict legend ── */}
      <div className="flex flex-wrap gap-4 text-xs text-muted-foreground">
        <span className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-red-500" />
          <strong>Vulnerable</strong> = attack succeeded, vulnerability found
        </span>
        <span className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
          <strong>Defended</strong> = defense held, attack was blocked
        </span>
        <span className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-amber-500" />
          <strong>Partial</strong> = partial leak or incomplete defense
        </span>
        <span className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-gray-400" />
          <strong>Error</strong> = indeterminate, could not complete normally
        </span>
      </div>

      {/* ── LLM Usage (per-scan token/cost/latency metrics) ── */}
      {report.usage && <UsagePanel usage={report.usage} />}

      {/* ── Category Breakdown ── */}
      {categoryEntries.length > 0 && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              Category Breakdown
              <span className="text-xs text-muted-foreground font-normal">
                {categoryEntries.length} categories
              </span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 lg:grid-cols-[200px_1fr] gap-6">
              {/* Donut-style summary */}
              <div className="flex flex-col items-center justify-center">
                <ScoreRing score={stats.score} size={100} />
                <div className="mt-3 space-y-1 text-xs">
                  <div className="flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-full bg-red-500" />
                    <span className="text-muted-foreground">Vulnerable</span>
                    <span className="font-semibold text-foreground ml-auto tabular-nums">{stats.passed}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
                    <span className="text-muted-foreground">Defended</span>
                    <span className="font-semibold text-foreground ml-auto tabular-nums">{stats.failed}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-full bg-amber-500" />
                    <span className="text-muted-foreground">PARTIAL</span>
                    <span className="font-semibold text-foreground ml-auto tabular-nums">{partialCount}</span>
                  </div>
                </div>
              </div>

              {/* Category bars */}
              <div className="space-y-2.5">
                <div className="grid grid-cols-[1fr_auto_auto] gap-4 text-[10px] font-semibold text-muted-foreground uppercase tracking-wider mb-1">
                  <span>Category</span>
                  <span className="text-right w-24">Distribution</span>
                  <span className="text-right w-10">Hits</span>
                </div>
                {categoryEntries.map(([cat, data]) => (
                  <div key={cat} className="grid grid-cols-[1fr_auto_auto] gap-4 items-center">
                    <span className="text-sm font-medium text-foreground truncate" title={prettyCat(cat)}>
                      {prettyCat(cat)}
                    </span>
                    <div className="w-48 h-2.5 bg-muted rounded-full overflow-hidden">
                      <div className="h-full flex">
                        {data.passed > 0 && (
                          <div
                            className="h-full bg-red-500"
                            style={{ width: `${(data.passed / data.total) * 100}%` }}
                          />
                        )}
                        <div
                          className="h-full bg-emerald-500"
                          style={{ width: `${((data.total - data.passed) / data.total) * 100}%` }}
                        />
                      </div>
                    </div>
                    <span className="text-sm font-semibold tabular-nums text-foreground w-10 text-right">
                      {data.total}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* ── Results section (hidden during print — print table below replaces it) ── */}
      <Card className="no-print">
        <CardHeader className="pb-0">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              Results
              <span className="text-xs text-muted-foreground font-normal">
                {allResults.length} total
              </span>
            </CardTitle>
          </div>

          {/* Filter tabs */}
          <div className="flex items-center gap-4 mt-3 border-b border-border -mx-[var(--card-spacing)] px-[var(--card-spacing)] overflow-x-auto">
            {/* Verdict filter */}
            <div className="flex items-center gap-1">
              <button
                onClick={() => { setVerdictFilter("all"); setFindingsPage(1); }}
                className={`px-2.5 py-2 text-xs font-medium border-b-2 transition-colors whitespace-nowrap ${
                  verdictFilter === "all"
                    ? "border-foreground text-foreground"
                    : "border-transparent text-muted-foreground hover:text-foreground"
                }`}
              >
                All
              </button>
              {uniqueVerdicts.map((v) => (
                <button
                  key={v}
                  onClick={() => { setVerdictFilter(v); setFindingsPage(1); }}
                  className={`px-2.5 py-2 text-xs font-medium border-b-2 transition-colors whitespace-nowrap inline-flex items-center gap-1.5 ${
                    verdictFilter === v
                      ? "border-foreground text-foreground"
                      : "border-transparent text-muted-foreground hover:text-foreground"
                  }`}
                >
                  <span className={`w-1.5 h-1.5 rounded-full ${verdictDotColor(v)}`} />
                  {verdictLabel(v)}
                </button>
              ))}
            </div>

            {/* Category filter */}
            {uniqueCategories.length > 1 && (
              <div className="flex items-center gap-1 ml-auto">
                <Filter className="w-3.5 h-3.5 text-muted-foreground" />
                <select
                  value={categoryFilter}
                  onChange={(e) => { setCategoryFilter(e.target.value); setFindingsPage(1); }}
                  className="text-xs border-none bg-transparent text-muted-foreground focus:outline-none cursor-pointer"
                >
                  <option value="all">All Categories</option>
                  {uniqueCategories.map((c) => (
                    <option key={c} value={c}>{prettyCat(c)}</option>
                  ))}
                </select>
              </div>
            )}
          </div>
        </CardHeader>

        <CardContent className="p-0">
          {/* Rounds tabs */}
          {rounds.length > 1 && (
            <div className="flex gap-1 px-4 pt-3">
              {rounds.map((r, idx) => (
                <button
                  key={getRoundNumber(r)}
                  onClick={() => {
                    setActiveRound(idx);
                    setFindingsPage(1);
                    setVerdictFilter("all");
                    setCategoryFilter("all");
                  }}
                  className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-colors ${
                    idx === activeRound
                      ? "bg-primary text-white"
                      : "text-muted-foreground hover:bg-muted"
                  }`}
                >
                  Round {getRoundNumber(r)}
                </button>
              ))}
            </div>
          )}

          {filteredResults.length === 0 ? (
            <div className="text-center py-12 text-sm text-muted-foreground">
              No findings match the current filters
            </div>
          ) : (
            <>
              <div className="px-4 py-2 text-xs text-muted-foreground">
                Showing {(findingsPage - 1) * perPage + 1}-{Math.min(findingsPage * perPage, totalFindings)} of {totalFindings} findings
              </div>
              {/* table-fixed + explicit column widths keep the table locked to
                  the container width. Without it, `table-layout: auto` sizes
                  columns to content (ignoring max-width on <td>), so long
                  reasoning/attack names blow the table past the viewport and the
                  expanded detail — which spans all columns — overflows with it. */}
              <Table className="table-fixed w-full">
                <TableHeader>
                  <TableRow className="bg-muted/40">
                    <TableHead className="w-[24%] text-xs font-semibold uppercase tracking-wider">
                      Attack Name
                    </TableHead>
                    <TableHead className="w-[15%] text-xs font-semibold uppercase tracking-wider">
                      Category
                    </TableHead>
                    <TableHead className="w-[10%] text-xs font-semibold uppercase tracking-wider">
                      Severity
                    </TableHead>
                    <TableHead className="w-[11%] text-xs font-semibold uppercase tracking-wider">
                      Verdict
                    </TableHead>
                    <TableHead className="w-[40%] text-xs font-semibold uppercase tracking-wider">
                      Reasoning
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {pagedFindings.map((result, i) => (
                    <FindingRow
                      key={`${getAttackName(result)}-${i}`}
                      result={result}
                      controls={complianceByCategory.get(getCategory(result)) ?? []}
                    />
                  ))}
                </TableBody>
              </Table>

              {/* Findings pagination */}
              {totalFindingsPages > 1 && (
                <div className="flex items-center justify-center gap-2 py-3 border-t border-border">
                  <button
                    disabled={findingsPage <= 1}
                    onClick={() => setFindingsPage((p) => p - 1)}
                    className="px-3 py-1.5 text-sm rounded-lg border border-border bg-card disabled:opacity-40 hover:bg-muted"
                  >
                    Previous
                  </button>
                  <span className="text-sm text-muted-foreground">
                    {findingsPage} / {totalFindingsPages}
                  </span>
                  <button
                    disabled={findingsPage >= totalFindingsPages}
                    onClick={() => setFindingsPage((p) => p + 1)}
                    className="px-3 py-1.5 text-sm rounded-lg border border-border bg-card disabled:opacity-40 hover:bg-muted"
                  >
                    Next
                  </button>
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>

      {/* Summary / LLM Analysis */}
      {report.llmAnalysis && (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-semibold">AI Analysis</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground whitespace-pre-wrap leading-relaxed">
              {report.llmAnalysis}
            </p>
          </CardContent>
        </Card>
      )}

      {/* ── Print-only: ALL attacks from all rounds (hidden on screen, visible in print) ── */}
      <div className="print-only" id="print-full-report">
        <div className="text-sm font-semibold text-foreground mb-2 mt-4">
          All Findings — {allRoundsResults.length} attacks across {rounds.length} round{rounds.length !== 1 ? "s" : ""}
        </div>
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b-2 border-foreground/20">
              <th className="text-[9px] font-semibold py-1.5 pr-2 w-6">#</th>
              <th className="text-[9px] font-semibold py-1.5 pr-2">ATTACK NAME</th>
              <th className="text-[9px] font-semibold py-1.5 pr-2">CATEGORY</th>
              <th className="text-[9px] font-semibold py-1.5 pr-2 w-16">SEVERITY</th>
              <th className="text-[9px] font-semibold py-1.5 pr-2 w-14">VERDICT</th>
              <th className="text-[9px] font-semibold py-1.5">REASONING</th>
            </tr>
          </thead>
          <tbody>
            {allRoundsResults.map((result, i) => (
              <tr key={i} className="border-b border-foreground/10" style={{ pageBreakInside: "avoid" }}>
                <td className="text-[9px] py-1 pr-2 text-muted-foreground tabular-nums align-top">{i + 1}</td>
                <td className="text-[9px] py-1 pr-2 font-medium align-top">
                  {getAttackName(result)}
                  {(() => {
                    const ctrls = complianceByCategory.get(getCategory(result)) ?? [];
                    return ctrls.length > 0 ? (
                      <div className="text-[8px] font-normal text-muted-foreground mt-0.5">
                        {ctrls.map((c) => c.code).join(", ")}
                      </div>
                    ) : null;
                  })()}
                </td>
                <td className="text-[9px] py-1 pr-2 text-muted-foreground align-top">{prettyCat(getCategory(result))}</td>
                <td className="text-[9px] py-1 pr-2 align-top">
                  <span className={`font-semibold ${
                    (getSeverity(result) || "").toLowerCase() === "critical" || (getSeverity(result) || "").toLowerCase() === "high"
                      ? "text-red-700" : "text-foreground"
                  }`}>{getSeverity(result) || "-"}</span>
                </td>
                <td className="text-[9px] py-1 pr-2 align-top">
                  <span className={`font-bold ${
                    result.verdict === "PASS" ? "text-red-700"
                      : result.verdict === "FAIL" ? "text-emerald-700"
                      : result.verdict === "PARTIAL" ? "text-amber-700"
                      : "text-muted-foreground"
                  }`}>{verdictLabel(result.verdict)}</span>
                </td>
                <td className="text-[9px] py-1 text-muted-foreground align-top">{result.llmReasoning || result.reasoning || "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ─── Page Root ─── */

export default function ReportsPage() {
  const { filename } = useParams<{ filename?: string }>();

  if (filename) {
    return <ReportDetail filename={decodeURIComponent(filename)} />;
  }

  return <ReportsGrid />;
}
