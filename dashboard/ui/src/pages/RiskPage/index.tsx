import { useState, useEffect, useCallback, useRef } from "react";
import { getReportsMeta, getReport } from "@/api/reports";
import { analyzeRisk } from "@/api/risk";
import { useNDJSONStream } from "@/hooks/useNDJSONStream";
import { useRiskStore } from "@/stores/riskStore";
import type {
  ReportMeta,
  FullReport,
  RiskAnalysisResult,
  ReportSummary,
} from "@/api/types";
import { ScoreRing } from "@/components/shared/ScoreRing";
import { LoadingSpinner } from "@/components/shared/LoadingSpinner";
import { EmptyState } from "@/components/shared/EmptyState";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Shield, AlertTriangle, Play, Search } from "lucide-react";

/* ---------- helpers (unchanged logic) ---------- */

function severityBadgeVariant(
  severity: string
): "default" | "secondary" | "destructive" | "outline" {
  const s = severity.toLowerCase();
  if (s === "critical" || s === "high") return "destructive";
  if (s === "medium") return "default";
  if (s === "low") return "secondary";
  return "outline";
}

function severityPriority(severity: string): number {
  const s = severity.toLowerCase();
  if (s === "critical") return 0;
  if (s === "high") return 1;
  if (s === "medium") return 2;
  if (s === "low") return 3;
  return 4;
}

function getReportStats(report: FullReport) {
  const s =
    typeof report.summary === "object" && report.summary
      ? (report.summary as ReportSummary)
      : null;
  return {
    score: s?.score ?? report.score ?? 0,
    passed: s?.passed ?? report.passed ?? 0,
    failed: s?.failed ?? report.failed ?? 0,
    errors: s?.errors ?? report.errors ?? 0,
    totalAttacks: s?.totalAttacks ?? report.totalAttacks ?? 0,
  };
}

function getAttackName(result: {
  attack?: string | Record<string, unknown>;
  attackName?: string;
}): string {
  const atk = result.attack;
  if (typeof atk === "object" && atk !== null)
    return ((atk as Record<string, unknown>).name as string) ?? "Unknown";
  if (typeof atk === "string") return atk;
  return result.attackName ?? "Unknown";
}

function getCategory(result: {
  attack?: string | Record<string, unknown>;
  category?: string;
}): string {
  if (result.category) return result.category;
  const atk = result.attack;
  if (typeof atk === "object" && atk !== null)
    return ((atk as Record<string, unknown>).category as string) ?? "";
  return "";
}

function getSeverity(result: {
  attack?: string | Record<string, unknown>;
  severity?: string;
}): string {
  if (result.severity) return result.severity;
  const atk = result.attack;
  if (typeof atk === "object" && atk !== null)
    return ((atk as Record<string, unknown>).severity as string) ?? "";
  return "";
}

/* ---------- score badge color for report cards ---------- */

function scoreBadgeClasses(score: number): string {
  if (score >= 80)
    return "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-300";
  if (score >= 60)
    return "bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-300";
  return "bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300";
}

function truncateUrl(url: string, max = 32): string {
  if (url.length <= max) return url;
  try {
    const u = new URL(url);
    const host = u.hostname;
    const path = u.pathname;
    const short = host + path;
    return short.length > max ? short.slice(0, max - 1) + "\u2026" : short;
  } catch {
    return url.slice(0, max - 1) + "\u2026";
  }
}

/* ---------- severity bar colors ---------- */

const severityBarColors: Record<string, string> = {
  critical: "bg-red-500 dark:bg-red-400",
  high: "bg-orange-500 dark:bg-orange-400",
  medium: "bg-amber-500 dark:bg-amber-400",
  low: "bg-emerald-500 dark:bg-emerald-400",
  unknown: "bg-gray-400 dark:bg-gray-500",
};

const severityBorderColors: Record<string, string> = {
  critical: "border-l-red-500 dark:border-l-red-400",
  high: "border-l-orange-500 dark:border-l-orange-400",
  medium: "border-l-yellow-500 dark:border-l-yellow-400",
  low: "border-l-green-500 dark:border-l-green-400",
  unknown: "border-l-gray-400 dark:border-l-gray-500",
};

/* ========== component ========== */

export default function RiskPage() {
  const [reportSearch, setReportSearch] = useState("");
  const [reports, setReports] = useState<ReportMeta[]>([]);
  const [loading, setLoading] = useState(true);
  // Selected report + generated analyses live in a store so they survive
  // navigating away from this page and back within the same session.
  const selectedFile = useRiskStore((s) => s.selectedFile);
  const setSelectedFile = useRiskStore((s) => s.setSelectedFile);
  const analyses = useRiskStore((s) => s.analyses);
  const setAnalysis = useRiskStore((s) => s.setAnalysis);
  const [fullReport, setFullReport] = useState<FullReport | null>(null);
  const [reportLoading, setReportLoading] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  // Which report the in-flight/just-finished stream belongs to, so we never
  // display or persist one report's analysis against another.
  const analyzedFileRef = useRef<string>("");

  const {
    data: riskResults,
    isStreaming,
    error: streamError,
    start,
  } = useNDJSONStream<RiskAnalysisResult>();

  // Persist a completed analysis to the store, keyed by the report it ran
  // against — this is what lets it survive unmount/remount.
  useEffect(() => {
    if (!isStreaming && riskResults.length > 0 && analyzedFileRef.current) {
      setAnalysis(analyzedFileRef.current, riskResults);
    }
  }, [isStreaming, riskResults, setAnalysis]);

  /* Fetch reports list */
  useEffect(() => {
    getReportsMeta(1, 200)
      .then((res) => {
        setReports(res.items);
        // Auto-select the first report
        if (res.items.length > 0 && !selectedFile) {
          setSelectedFile(res.items[0].filename);
        }
      })
      .catch(console.error)
      .finally(() => setLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /* Fetch full report when selected */
  useEffect(() => {
    if (!selectedFile) {
      setFullReport(null);
      return;
    }
    setReportLoading(true);
    getReport(selectedFile, false)
      .then(setFullReport)
      .catch(console.error)
      .finally(() => setReportLoading(false));
  }, [selectedFile]);

  const handleRunAI = useCallback(async () => {
    if (!fullReport) return;
    const attacks = (fullReport.rounds ?? []).flatMap((r) =>
      (r.results ?? []).map((res) => ({
        name: getAttackName(res),
        category: getCategory(res),
        severity: getSeverity(res),
        findings: res.findings ?? [],
      }))
    );
    analyzedFileRef.current = selectedFile;
    const response = await analyzeRisk(attacks);
    start(response);
  }, [fullReport, selectedFile, start]);

  if (loading) {
    return (
      <div className="max-w-7xl mx-auto flex items-center justify-center py-32">
        <LoadingSpinner size="lg" />
      </div>
    );
  }

  /* ---- Derived data from full report ---- */
  const allResults = fullReport
    ? (fullReport.rounds ?? []).flatMap((r) => r.results ?? [])
    : [];

  const severityDist: Record<string, number> = {};
  const vulnerabilities = allResults.filter(
    (r) => r.verdict === "FAIL" || r.verdict === "PARTIAL"
  );
  allResults.forEach((r) => {
    const sev = getSeverity(r) || "unknown";
    severityDist[sev] = (severityDist[sev] || 0) + 1;
  });

  const maxSevCount = Math.max(...Object.values(severityDist), 1);

  /* Group vulnerabilities by priority for remediation matrix */
  const remediationGroups: Record<string, typeof vulnerabilities> = {};
  vulnerabilities.forEach((v) => {
    const key = getSeverity(v) || "unknown";
    if (!remediationGroups[key]) remediationGroups[key] = [];
    remediationGroups[key].push(v);
  });
  const sortedRemediationKeys = Object.keys(remediationGroups).sort(
    (a, b) => severityPriority(a) - severityPriority(b)
  );

  /* AI analysis to show: the live stream when it belongs to the selected
     report, otherwise the persisted analysis for that report (if any). */
  const liveForSelected =
    analyzedFileRef.current === selectedFile &&
    (isStreaming || riskResults.length > 0);
  const displayResults = liveForSelected
    ? riskResults
    : analyses[selectedFile] ?? [];

  return (
    <div className="max-w-7xl mx-auto space-y-5">
      {/* ===== Report selector — horizontal scrollable cards ===== */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-lg flex items-center gap-2">
            <Shield className="w-5 h-5 text-primary" />
            Risk Analysis
          </CardTitle>
        </CardHeader>
        <CardContent>
          {reports.length === 0 ? (
            <p className="text-sm text-muted-foreground py-2">
              No reports available. Run a scan first.
            </p>
          ) : (
            <>
            <div className="relative max-w-xs mb-3">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
              <input
                type="text"
                placeholder="Filter reports..."
                value={reportSearch}
                onChange={(e) => setReportSearch(e.target.value)}
                className="w-full pl-9 pr-3 py-1.5 bg-background border border-border rounded-lg text-xs text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:ring-2 focus:ring-primary/20 focus:border-primary"
              />
            </div>
            <div
              ref={scrollRef}
              className="flex gap-3 overflow-x-auto pb-2 scrollbar-thin scrollbar-thumb-border scrollbar-track-transparent"
            >
              {reports.filter((r) => !reportSearch || r.targetUrl.toLowerCase().includes(reportSearch.toLowerCase()) || r.filename.toLowerCase().includes(reportSearch.toLowerCase())).map((r) => {
                const isSelected = selectedFile === r.filename;
                const date = new Date(r.timestamp);
                return (
                  <button
                    key={r.filename}
                    onClick={() => setSelectedFile(r.filename)}
                    className={`
                      flex-shrink-0 w-56 rounded-lg border-2 p-3 text-left transition-all
                      hover:shadow-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary
                      ${
                        isSelected
                          ? "border-primary bg-primary/5 dark:bg-primary/10 shadow-sm"
                          : "border-border bg-card hover:border-muted-foreground/30 dark:bg-card"
                      }
                    `}
                  >
                    <p
                      className="text-sm font-medium text-foreground truncate"
                      title={r.targetUrl}
                    >
                      {truncateUrl(r.targetUrl)}
                    </p>
                    <p className="text-xs text-muted-foreground mt-1">
                      {date.toLocaleDateString("en-US", {
                        month: "short",
                        day: "numeric",
                        year: "numeric",
                      })}
                    </p>
                    <div className="mt-2 flex items-center justify-between">
                      <span
                        className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-semibold ${scoreBadgeClasses(
                          r.score
                        )}`}
                      >
                        {r.score}
                      </span>
                      <span className="text-xs text-muted-foreground">
                        {r.totalAttacks} attacks
                      </span>
                    </div>
                  </button>
                );
              })}
            </div>
            </>
          )}
        </CardContent>
      </Card>

      {/* ===== Loading state ===== */}
      {reportLoading && (
        <div className="flex items-center justify-center py-16">
          <LoadingSpinner />
        </div>
      )}

      {/* ===== Report breakdown ===== */}
      {fullReport && !reportLoading && (
        <>
          {/* Score + Severity Distribution */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Score Ring */}
            {(() => {
              const stats = getReportStats(fullReport);
              return (
                <Card className="flex flex-col items-center justify-center gap-3 py-6">
                  <CardContent className="flex flex-col items-center gap-3 p-0">
                    <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                      Security Score
                    </span>
                    <ScoreRing score={stats.score} size={140} />
                    <div className="text-center">
                      <p className="text-sm text-muted-foreground">
                        {stats.passed} passed / {stats.failed} failed /{" "}
                        {stats.errors} errors
                      </p>
                      <p className="text-xs text-muted-foreground mt-1">
                        {stats.totalAttacks} total attacks
                      </p>
                    </div>
                  </CardContent>
                </Card>
              );
            })()}

            {/* Severity Distribution */}
            <Card className="col-span-1 lg:col-span-2">
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  Severity Distribution
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {["critical", "high", "medium", "low", "unknown"]
                    .filter((sev) => severityDist[sev])
                    .map((sev) => {
                      const count = severityDist[sev] || 0;
                      return (
                        <div key={sev}>
                          <div className="flex items-center justify-between text-sm mb-1">
                            <span className="text-muted-foreground capitalize">
                              {sev}
                            </span>
                            <span className="font-semibold text-foreground">
                              {count}
                            </span>
                          </div>
                          <div className="h-2.5 bg-muted rounded-full overflow-hidden">
                            <div
                              className={`h-full rounded-full ${
                                severityBarColors[sev] || "bg-gray-400"
                              } transition-all duration-500`}
                              style={{
                                width: `${(count / maxSevCount) * 100}%`,
                              }}
                            />
                          </div>
                        </div>
                      );
                    })}
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Exploitability Section */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-orange-600 dark:text-orange-400" />
                Exploitable Vulnerabilities ({vulnerabilities.length})
              </CardTitle>
            </CardHeader>
            <CardContent>
              {vulnerabilities.length === 0 ? (
                <p className="text-sm text-muted-foreground py-4 text-center">
                  No exploitable vulnerabilities found.
                </p>
              ) : (
                <>
                  <div className="overflow-x-auto">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Attack</TableHead>
                          <TableHead>Category</TableHead>
                          <TableHead>Severity</TableHead>
                          <TableHead>Verdict</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {vulnerabilities.slice(0, 50).map((v, i) => (
                          <TableRow key={`${getAttackName(v)}-${i}`}>
                            <TableCell className="font-medium max-w-[300px] truncate">
                              {getAttackName(v)}
                            </TableCell>
                            <TableCell className="text-muted-foreground">
                              {getCategory(v)}
                            </TableCell>
                            <TableCell>
                              <Badge
                                variant={severityBadgeVariant(getSeverity(v))}
                              >
                                {getSeverity(v) || "unknown"}
                              </Badge>
                            </TableCell>
                            <TableCell>
                              <Badge variant="destructive">{v.verdict}</Badge>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                  {vulnerabilities.length > 50 && (
                    <p className="text-xs text-muted-foreground mt-2">
                      Showing 50 of {vulnerabilities.length} vulnerabilities
                    </p>
                  )}
                </>
              )}
            </CardContent>
          </Card>

          {/* Remediation Matrix */}
          {sortedRemediationKeys.length > 0 && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  Remediation Matrix (by priority)
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {sortedRemediationKeys.map((severity) => {
                    const items = remediationGroups[severity];
                    return (
                      <div
                        key={severity}
                        className={`border-l-4 ${
                          severityBorderColors[severity.toLowerCase()] ||
                          "border-l-gray-400 dark:border-l-gray-500"
                        } pl-4`}
                      >
                        <div className="flex items-center gap-2 mb-2">
                          <Badge
                            variant={severityBadgeVariant(severity)}
                          >
                            {severity}
                          </Badge>
                          <span className="text-sm text-muted-foreground">
                            {items.length} finding
                            {items.length !== 1 ? "s" : ""}
                          </span>
                        </div>
                        <ul className="space-y-1">
                          {items.slice(0, 10).map((item, idx) => (
                            <li
                              key={`${getAttackName(item)}-${idx}`}
                              className="text-sm text-foreground"
                            >
                              <span className="font-medium">
                                {getAttackName(item)}
                              </span>
                              <span className="text-muted-foreground ml-2">
                                ({getCategory(item)})
                              </span>
                            </li>
                          ))}
                          {items.length > 10 && (
                            <li className="text-xs text-muted-foreground">
                              +{items.length - 10} more
                            </li>
                          )}
                        </ul>
                      </div>
                    );
                  })}
                </div>
              </CardContent>
            </Card>
          )}

          {/* AI Risk Analysis */}
          <Card>
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <CardTitle className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  AI Risk Analysis
                </CardTitle>
                <button
                  onClick={handleRunAI}
                  disabled={isStreaming}
                  className="inline-flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground text-sm font-medium rounded-lg hover:bg-primary/90 disabled:opacity-50 transition-colors"
                >
                  {isStreaming ? (
                    <>
                      <LoadingSpinner size="sm" />
                      Analyzing...
                    </>
                  ) : (
                    <>
                      <Play className="w-4 h-4" />
                      Run AI Risk Analysis
                    </>
                  )}
                </button>
              </div>
            </CardHeader>
            <CardContent>
              {streamError && (
                <div className="mb-4 px-4 py-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-sm text-red-700 dark:text-red-300">
                  {streamError}
                </div>
              )}

              {displayResults.length > 0 ? (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {displayResults.map((result, i) => (
                    <div
                      key={`${result.attack}-${i}`}
                      className="border border-border rounded-lg p-4 space-y-2 bg-muted/30 dark:bg-muted/10"
                    >
                      <h4 className="font-semibold text-foreground text-sm">
                        {result.attack}
                      </h4>
                      <p className="text-xs text-muted-foreground">
                        {result.category}
                      </p>
                      <div className="grid grid-cols-2 gap-2 pt-2">
                        <div>
                          <span className="block text-xs text-muted-foreground">
                            Impact Level
                          </span>
                          <span className="text-sm font-medium text-foreground">
                            {result.impactLevel}
                          </span>
                        </div>
                        <div>
                          <span className="block text-xs text-muted-foreground">
                            Business Impact
                          </span>
                          <span className="text-sm font-medium text-foreground">
                            {result.businessImpact}
                          </span>
                        </div>
                        <div>
                          <span className="block text-xs text-muted-foreground">
                            Financial Exposure
                          </span>
                          <span className="text-sm font-medium text-foreground">
                            {result.financialExposure}
                          </span>
                        </div>
                        <div>
                          <span className="block text-xs text-muted-foreground">
                            Remediation Estimate
                          </span>
                          <span className="text-sm font-medium text-foreground">
                            {result.remediationEstimate}
                          </span>
                        </div>
                      </div>
                      {result.complianceRisk && (
                        <div className="pt-1">
                          <span className="block text-xs text-muted-foreground">
                            Compliance Risk
                          </span>
                          <span className="text-sm text-foreground">
                            {result.complianceRisk}
                          </span>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                !isStreaming && (
                  <EmptyState
                    title="No AI analysis yet"
                    description="Click 'Run AI Risk Analysis' to get detailed risk insights powered by AI."
                    icon={<Shield className="w-12 h-12" />}
                  />
                )
              )}
            </CardContent>
          </Card>
        </>
      )}

      {!selectedFile && !loading && (
        <EmptyState
          title="Select a report"
          description="Choose a scan report above to view its risk analysis breakdown."
          icon={<Shield className="w-12 h-12" />}
        />
      )}
    </div>
  );
}
