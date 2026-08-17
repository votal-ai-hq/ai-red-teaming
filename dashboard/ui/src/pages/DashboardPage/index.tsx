import { useEffect, useState } from "react";
import { useNavigate } from "react-router";
import { getReportsMeta, getReport } from "@/api/reports";
import { getRuns } from "@/api/runs";
import type { ReportMeta, RunMeta, ReportTrend, ReportSummary } from "@/api/types";
import { ScoreRing } from "@/components/shared/ScoreRing";
import { TrendChart } from "@/components/shared/TrendChart";
import { MethodologyInfo } from "@/components/shared/MethodologyInfo";
import { scoreBand, type ScoreBand } from "@/lib/score-methodology";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import {
  Shield,
  Zap,
  AlertCircle,
  ShieldCheck,
  Activity,
  ArrowRight,
  ExternalLink,
} from "lucide-react";

/* ─── helpers ─── */

type SeverityLevel = ScoreBand;

const SEVERITY_CONFIG: Record<
  SeverityLevel,
  { dot: string; text: string; bg: string; label: string }
> = {
  critical: { dot: "bg-red-500", text: "text-red-700 dark:text-red-400", bg: "bg-red-50 dark:bg-red-950/30", label: "Critical" },
  high: { dot: "bg-orange-500", text: "text-orange-700 dark:text-orange-400", bg: "bg-orange-50 dark:bg-orange-950/30", label: "High" },
  medium: { dot: "bg-amber-400", text: "text-amber-700 dark:text-amber-400", bg: "bg-amber-50 dark:bg-amber-950/30", label: "Medium" },
  low: { dot: "bg-emerald-500", text: "text-emerald-700 dark:text-emerald-400", bg: "bg-emerald-50 dark:bg-emerald-950/30", label: "Low" },
};

function prettyCat(cat: string) {
  return cat.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function getSeverity(score: number): SeverityLevel {
  return scoreBand(score);
}

function fmtDate(iso: string) {
  return new Date(iso).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

/* ─── severity pill component (matches Pepper style) ─── */

function SeverityBadge({ level }: { level: SeverityLevel }) {
  const cfg = SEVERITY_CONFIG[level];
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-semibold ${cfg.bg} ${cfg.text}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} />
      {cfg.label}
    </span>
  );
}

/* ─── stat card (Pepper-style: colored dot + number + label) ─── */

function StatCard({
  label,
  value,
  icon: Icon,
  dotColor,
  subtitle,
}: {
  label: string;
  value: string | number;
  icon: React.ElementType;
  dotColor?: string;
  subtitle?: string;
}) {
  return (
    <Card>
      <CardContent className="pt-5 pb-4 px-5">
        <div className="flex items-center gap-2 mb-3">
          {dotColor && <span className={`w-2 h-2 rounded-full ${dotColor}`} />}
          <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
            {label}
          </span>
        </div>
        <div className="flex items-end justify-between">
          <span className="text-3xl font-bold tracking-tight text-foreground">
            {typeof value === "number" ? value.toLocaleString() : value}
          </span>
          <Icon className="w-5 h-5 text-muted-foreground/40" />
        </div>
        {subtitle && (
          <span className="text-[11px] text-muted-foreground mt-1 block">{subtitle}</span>
        )}
      </CardContent>
    </Card>
  );
}

/* ─── main component ─── */

export default function DashboardPage() {
  const navigate = useNavigate();
  const [reportsMeta, setReportsMeta] = useState<ReportMeta[]>([]);
  const [trend, setTrend] = useState<ReportTrend[]>([]);
  const [runs, setRuns] = useState<RunMeta[]>([]);
  const [byCategory, setByCategory] = useState<Record<string, { total: number; passed: number; findings: string[] }>>({});
  const [loading, setLoading] = useState(true);
  const [tableFilter, setTableFilter] = useState<"all" | SeverityLevel>("all");

  useEffect(() => {
    Promise.all([getReportsMeta(1, 200), getRuns()])
      .then(async ([reportsRes, runsRes]) => {
        setReportsMeta(reportsRes.items);
        setTrend(reportsRes.trend ?? []);
        setRuns(runsRes);

        // Fetch latest report's summary.byCategory for category breakdown
        if (reportsRes.items.length > 0) {
          try {
            const latest = await getReport(reportsRes.items[0].filename, true);
            const s = typeof latest.summary === "object" && latest.summary
              ? latest.summary as ReportSummary
              : null;
            if (s?.byCategory) {
              setByCategory(s.byCategory as Record<string, { total: number; passed: number; findings: string[] }>);
            }
          } catch {
            // category data is optional, don't block dashboard
          }
        }
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="max-w-7xl mx-auto flex items-center justify-center py-32">
        <div className="flex flex-col items-center gap-3">
          <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
          <span className="text-sm text-muted-foreground">Loading dashboard...</span>
        </div>
      </div>
    );
  }

  // ── computed stats ──
  const totalVulns = reportsMeta.reduce((s, r) => s + r.passed, 0);
  const totalBlocked = reportsMeta.reduce((s, r) => s + r.failed, 0);
  const totalAttacks = reportsMeta.reduce((s, r) => s + r.totalAttacks, 0);
  const avgScore =
    reportsMeta.length > 0
      ? Math.round(reportsMeta.reduce((s, r) => s + r.score, 0) / reportsMeta.length)
      : 0;
  const latestScore = reportsMeta.length > 0 ? reportsMeta[0].score : 0;
  const scansCompleted = reportsMeta.length;

  // ── active runs ──
  const activeRuns = runs.filter((r) => r.status === "running" || r.status === "queued");

  // ── score distribution for severity cards ──
  const scoreBuckets = { critical: 0, high: 0, medium: 0, low: 0 };
  reportsMeta.forEach((r) => {
    scoreBuckets[getSeverity(r.score)]++;
  });

  // ── attack category analysis (from latest report's summary.byCategory) ──
  const topCategories = Object.entries(byCategory)
    .filter(([, v]) => v.total > 0)
    .sort((a, b) => b[1].passed - a[1].passed)
    .slice(0, 6);
  const maxCatVulns = topCategories.length > 0 ? topCategories[0][1].passed : 1;

  // ── top targets ──
  const targetVulns: Record<string, number> = {};
  reportsMeta.forEach((r) => {
    targetVulns[r.targetUrl] = (targetVulns[r.targetUrl] || 0) + r.passed;
  });
  const topTargets = Object.entries(targetVulns)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);
  const maxTargetVulns = topTargets.length > 0 ? topTargets[0][1] : 1;

  // ── filtered scans for table ──
  // Use the full report set so the tab counts (derived from scoreBuckets over
  // all reports) stay consistent with what the table actually shows. Slicing to
  // a "recent 20" here made "All Scans" disagree with the severity tab counts.
  const allScans = reportsMeta;
  const filteredScans =
    tableFilter === "all"
      ? allScans
      : allScans.filter((r) => getSeverity(r.score) === tableFilter);

  const filterTabs: { key: "all" | SeverityLevel; label: string; count: number }[] = [
    { key: "all", label: "All Scans", count: allScans.length },
    { key: "critical", label: "Critical", count: scoreBuckets.critical },
    { key: "high", label: "High", count: scoreBuckets.high },
    { key: "medium", label: "Medium", count: scoreBuckets.medium },
    { key: "low", label: "Low", count: scoreBuckets.low },
  ];

  const SEVERITY_EMPTY_LABEL: Record<SeverityLevel, string> = {
    critical: "critical",
    high: "high",
    medium: "medium",
    low: "low",
  };

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      {/* ── Active runs banner ── */}
      {activeRuns.length > 0 && (
        <div className="flex items-center gap-3 rounded-lg border border-blue-200 dark:border-blue-900/50 bg-blue-50/60 dark:bg-blue-950/20 px-4 py-2.5">
          <div className="w-2 h-2 rounded-full bg-blue-500 animate-pulse" />
          <span className="text-sm font-medium text-foreground">
            {activeRuns.length} scan{activeRuns.length > 1 ? "s" : ""} running
          </span>
          {activeRuns[0]?.targetUrl && (
            <span className="text-xs text-muted-foreground truncate max-w-[300px]">
              — {activeRuns[0].targetUrl}
            </span>
          )}
          <button
            onClick={() => navigate("/scans")}
            className="ml-auto text-xs font-medium text-blue-600 dark:text-blue-400 hover:underline inline-flex items-center gap-1"
          >
            View <ArrowRight className="w-3 h-3" />
          </button>
        </div>
      )}

      {/* ── Row 1: Score ring + stat cards ── */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        {/* Security Score — spans 2 cols on mobile */}
        <Card className="col-span-2 lg:col-span-1">
          <CardContent className="flex flex-col items-center justify-center pt-5 pb-4">
            <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2 inline-flex items-center gap-1">
              Score
              <MethodologyInfo topic="score" label="How the security score is calculated" />
            </span>
            <ScoreRing score={latestScore} size={88} />
            <span className="text-[11px] text-muted-foreground mt-1.5">Latest scan</span>
          </CardContent>
        </Card>

        <StatCard
          label="Total Attacks"
          value={totalAttacks}
          icon={Zap}
          subtitle={`${scansCompleted} scans completed`}
        />
        <StatCard
          label="Vulnerabilities"
          value={totalVulns}
          icon={AlertCircle}
          dotColor="bg-red-500"
          subtitle="Across all scans"
        />
        <StatCard
          label="Blocked"
          value={totalBlocked}
          icon={ShieldCheck}
          dotColor="bg-emerald-500"
          subtitle="Successfully defended"
        />
        <StatCard
          label="Avg Score"
          value={avgScore}
          icon={Activity}
          subtitle={`Risk: ${SEVERITY_CONFIG[getSeverity(avgScore)].label}`}
        />
      </div>

      <Card>
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between gap-2">
            <CardTitle className="text-base font-semibold">Score trend</CardTitle>
            <span className="text-[11px] text-muted-foreground">
              Y-axis is security score (0–100). X-axis is scan date.
            </span>
          </div>
        </CardHeader>
        <CardContent>
          {trend.length > 1 ? (
            <TrendChart data={trend} width={720} height={240} />
          ) : (
            <p className="text-xs text-muted-foreground py-6">
              Need 2+ completed scans to plot a trend.
            </p>
          )}
        </CardContent>
      </Card>

      {/* ── Row 2: Severity breakdown (Pepper-style colored dot + number row) ── */}
      <div>
      <div className="flex items-baseline justify-between mb-2">
        <h2 className="text-sm font-semibold text-foreground inline-flex items-center gap-1.5">
          Scans by Severity
          <MethodologyInfo topic="both" label="How Critical and High are defined" />
        </h2>
        <span className="text-[11px] text-muted-foreground">
          Scans grouped by overall risk score
        </span>
      </div>
      <div className="grid grid-cols-4 gap-4">
        {(["critical", "high", "medium", "low"] as const).map((level) => {
          const cfg = SEVERITY_CONFIG[level];
          return (
            <Card key={level}>
              <CardContent className="flex items-center gap-3 py-4 px-5">
                <span className={`w-3 h-3 rounded-full ${cfg.dot} shrink-0`} />
                <div className="min-w-0">
                  <div className="text-xs font-medium text-muted-foreground">{cfg.label}</div>
                  <div className={`text-2xl font-bold tracking-tight ${cfg.text}`}>
                    {scoreBuckets[level]}
                  </div>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>
      </div>

      {/* ── Row 3: Findings table with filter tabs ── */}
      <Card>
        <CardHeader className="pb-0">
          <div className="flex items-center justify-between">
            <CardTitle className="text-base font-semibold">
              Findings ({filteredScans.length})
            </CardTitle>
            <button
              onClick={() => navigate("/reports")}
              className="text-xs font-medium text-primary hover:underline inline-flex items-center gap-1"
            >
              View all reports <ExternalLink className="w-3 h-3" />
            </button>
          </div>
          {/* Filter tabs */}
          <div className="flex items-center gap-1 mt-3 border-b border-border -mx-[var(--card-spacing)] px-[var(--card-spacing)]">
            {filterTabs.map((tab) => (
              <button
                key={tab.key}
                onClick={() => setTableFilter(tab.key)}
                className={`px-3 py-2 text-xs font-medium border-b-2 transition-colors ${
                  tableFilter === tab.key
                    ? "border-foreground text-foreground"
                    : "border-transparent text-muted-foreground hover:text-foreground"
                }`}
              >
                {tab.label}
                <span className="ml-1.5 text-muted-foreground">
                  {tab.count}
                </span>
              </button>
            ))}
          </div>
        </CardHeader>
        <CardContent className="pt-0">
          {filteredScans.length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-12">Risk</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Target</TableHead>
                  <TableHead>Score</TableHead>
                  <TableHead>Attacks</TableHead>
                  <TableHead>Vulns</TableHead>
                  <TableHead className="text-right">Date</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredScans.map((r) => {
                  const severity = getSeverity(r.score);
                  const cfg = SEVERITY_CONFIG[severity];
                  return (
                    <TableRow
                      key={r.filename}
                      className="cursor-pointer group"
                      onClick={() => navigate(`/reports/${r.filename}`)}
                    >
                      <TableCell>
                        <span className={`w-2.5 h-2.5 rounded-full ${cfg.dot} inline-block`} />
                      </TableCell>
                      <TableCell>
                        <SeverityBadge level={severity} />
                      </TableCell>
                      <TableCell>
                        <span
                          className="font-medium text-foreground group-hover:text-primary transition-colors truncate block max-w-[260px]"
                          title={r.targetUrl}
                        >
                          {r.targetUrl}
                        </span>
                      </TableCell>
                      <TableCell>
                        <span className={`font-semibold tabular-nums ${cfg.text}`}>{r.score}</span>
                      </TableCell>
                      <TableCell className="tabular-nums">{r.totalAttacks}</TableCell>
                      <TableCell>
                        <span className="font-medium tabular-nums text-red-600 dark:text-red-400">
                          {r.passed}
                        </span>
                      </TableCell>
                      <TableCell className="text-right text-muted-foreground">
                        {fmtDate(r.timestamp)}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          ) : (
            <div className="flex flex-col items-center justify-center py-16 text-center">
              <Shield className="w-10 h-10 text-muted-foreground/30 mb-3" />
              {tableFilter === "all" ? (
                <>
                  <p className="text-sm font-medium text-muted-foreground">No scans found</p>
                  <p className="text-xs text-muted-foreground/70 mt-1">
                    Run your first security scan to see results here
                  </p>
                </>
              ) : (
                <>
                  <p className="text-sm font-medium text-muted-foreground">
                    No {SEVERITY_EMPTY_LABEL[tableFilter]} severity scans
                  </p>
                  <p className="text-xs text-muted-foreground/70 mt-1">
                    No scans fall into the {SEVERITY_EMPTY_LABEL[tableFilter]} severity range
                  </p>
                </>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* ── Row 4: Categories + Targets side-by-side ── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Top Vulnerable Categories */}
        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-semibold">Categories (Latest Scan)</CardTitle>
          </CardHeader>
          <CardContent>
            {topCategories.length > 0 ? (
              <div className="space-y-3">
                {topCategories.map(([cat, data], i) => (
                  <div key={cat} className="flex items-center gap-3">
                    <span className="text-xs text-muted-foreground w-4 text-right tabular-nums">
                      {i + 1}
                    </span>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm font-medium text-foreground truncate" title={prettyCat(cat)}>
                          {prettyCat(cat)}
                        </span>
                        <span className="text-xs font-semibold tabular-nums text-muted-foreground ml-2">
                          {data.passed}/{data.total}
                        </span>
                      </div>
                      <div className="h-1.5 bg-muted rounded-full overflow-hidden">
                        <div
                          className="h-full rounded-full bg-red-500/80 transition-all duration-500"
                          style={{ width: `${(data.passed / maxCatVulns) * 100}%` }}
                        />
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground text-center py-6">No data yet</p>
            )}
          </CardContent>
        </Card>

        {/* Top Targets */}
        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-semibold">Top Targets by Vulnerabilities</CardTitle>
          </CardHeader>
          <CardContent>
            {topTargets.length > 0 ? (
              <div className="space-y-3">
                {topTargets.map(([url, count], i) => (
                  <div key={url} className="flex items-center gap-3">
                    <span className="text-xs text-muted-foreground w-4 text-right tabular-nums">
                      {i + 1}
                    </span>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm font-medium text-foreground truncate" title={url}>
                          {url}
                        </span>
                        <span className="text-xs font-semibold tabular-nums text-muted-foreground ml-2">
                          {count}
                        </span>
                      </div>
                      <div className="h-1.5 bg-muted rounded-full overflow-hidden">
                        <div
                          className="h-full rounded-full bg-orange-500/80 transition-all duration-500"
                          style={{ width: `${(count / maxTargetVulns) * 100}%` }}
                        />
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground text-center py-6">No scan data</p>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
