import { useState, useEffect, useCallback } from "react";
import { useNavigate } from "react-router";
import { getRuns, getRun, deleteRun, createRun, renameRun } from "@/api/runs";
import type { RunMeta, RunDetail } from "@/api/types";
import { usePolling } from "@/hooks/usePolling";
import {
  Card,
  CardContent,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Play,
  Clock,
  CheckCircle,
  XCircle,
  AlertCircle,
  Trash2,
  RotateCcw,
  ChevronDown,
  ChevronRight,
  Loader2,
  Search,
  Pencil,
  Check,
  X,
} from "lucide-react";
import { useDebounce } from "@/hooks/useDebounce";

/* ─── helpers ─── */

type RunStatus = RunMeta["status"];

const STATUS_CONFIG: Record<
  RunStatus,
  {
    label: string;
    dot: string;
    textColor: string;
    bg: string;
    icon: React.ElementType;
    pulse?: boolean;
    spin?: boolean;
  }
> = {
  running: {
    label: "Running",
    dot: "bg-blue-500",
    textColor: "text-blue-600 dark:text-blue-400",
    bg: "bg-blue-500/10",
    icon: Loader2,
    pulse: true,
    spin: true,
  },
  queued: {
    label: "Queued",
    dot: "bg-amber-500",
    textColor: "text-amber-600 dark:text-amber-400",
    bg: "bg-amber-500/10",
    icon: Clock,
  },
  done: {
    label: "Done",
    dot: "bg-emerald-500",
    textColor: "text-emerald-600 dark:text-emerald-400",
    bg: "bg-emerald-500/10",
    icon: CheckCircle,
  },
  error: {
    label: "Error",
    dot: "bg-red-500",
    textColor: "text-red-600 dark:text-red-400",
    bg: "bg-red-500/10",
    icon: XCircle,
  },
  cancelled: {
    label: "Cancelled",
    dot: "bg-red-400",
    textColor: "text-red-500 dark:text-red-400",
    bg: "bg-red-400/10",
    icon: AlertCircle,
  },
};

function fmtDateTime(iso: string) {
  return new Date(iso).toLocaleString("en-US", {
    month: "numeric",
    day: "numeric",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
    hour12: true,
  });
}

// Verdict semantics (lib/response-analyzer.ts): PASS = attack succeeded
// (vulnerability, bad/red); FAIL = agent defended (good/green).
function verdictColor(verdict: string | undefined) {
  const v = (verdict ?? "").toUpperCase();
  if (v === "PASS") return "text-red-600 dark:text-red-400";
  if (v === "FAIL") return "text-emerald-600 dark:text-emerald-400";
  if (v === "PARTIAL") return "text-amber-600 dark:text-amber-400";
  return "text-muted-foreground";
}

/** Defender-friendly label for a raw attack verdict. */
function verdictLabel(verdict: string | undefined) {
  const v = (verdict ?? "").toUpperCase();
  if (v === "PASS") return "Vulnerable";
  if (v === "FAIL") return "Defended";
  if (v === "PARTIAL") return "Partial";
  if (v === "ERROR") return "Error";
  return verdict ?? "—";
}

/* ─── main component ─── */

export default function RunsPage() {
  const navigate = useNavigate();
  const [runs, setRuns] = useState<RunMeta[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [runDetails, setRunDetails] = useState<Record<string, RunDetail>>({});
  const [detailLoading, setDetailLoading] = useState<Record<string, boolean>>({});
  const [deletingIds, setDeletingIds] = useState<Set<string>>(new Set());
  const [rerunningIds, setRerunningIds] = useState<Set<string>>(new Set());
  const [search, setSearch] = useState("");
  const debouncedSearch = useDebounce(search, 250);

  const refreshRuns = useCallback(() => {
    getRuns()
      .then((data) => setRuns(Array.isArray(data) ? data : []))
      .catch(console.error);
  }, []);

  useEffect(() => {
    getRuns()
      .then((data) => {
        const list = Array.isArray(data) ? data : [];
        setRuns(list);
        // Auto-expand the first running/queued run
        const activeRun = list.find((r) => r.status === "running" || r.status === "queued");
        if (activeRun && !expandedId) {
          setExpandedId(activeRun.runId);
          getRun(activeRun.runId, 0, true)
            .then((detail) =>
              setRunDetails((prev) => ({ ...prev, [activeRun.runId]: detail }))
            )
            .catch(console.error);
        }
      })
      .catch(console.error)
      .finally(() => setLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Poll active runs
  const activeRunIds = runs
    .filter((r) => r.status === "running" || r.status === "queued")
    .map((r) => r.runId);

  const pollActiveRuns = useCallback(() => {
    refreshRuns();
    // Poll ALL active runs for live progress (not just the expanded one)
    activeRunIds.forEach((id) => {
      getRun(id)
        .then((detail) =>
          setRunDetails((prev) => ({ ...prev, [id]: detail }))
        )
        .catch(console.error);
    });
  }, [activeRunIds, refreshRuns]);

  usePolling(pollActiveRuns, 2000, activeRunIds.length > 0);

  // Expand/collapse run detail
  const toggleExpand = useCallback(
    (runId: string) => {
      if (expandedId === runId) {
        setExpandedId(null);
        return;
      }
      setExpandedId(runId);
      if (!runDetails[runId]) {
        setDetailLoading((prev) => ({ ...prev, [runId]: true }));
        getRun(runId, 0, true)
          .then((detail) =>
            setRunDetails((prev) => ({ ...prev, [runId]: detail }))
          )
          .catch(console.error)
          .finally(() =>
            setDetailLoading((prev) => ({ ...prev, [runId]: false }))
          );
      }
    },
    [expandedId, runDetails],
  );

  // Delete run
  // Inline rename of a scan.
  const [renamingId, setRenamingId] = useState<string | null>(null);
  const [nameDraft, setNameDraft] = useState("");
  const [savingName, setSavingName] = useState(false);

  const startRename = useCallback((run: RunMeta, e: React.MouseEvent) => {
    e.stopPropagation();
    setRenamingId(run.runId);
    setNameDraft(run.name ?? "");
  }, []);

  const cancelRename = useCallback(() => {
    setRenamingId(null);
    setNameDraft("");
  }, []);

  const saveRename = useCallback(
    async (runId: string) => {
      const name = nameDraft.trim();
      setSavingName(true);
      try {
        await renameRun(runId, name);
        setRuns((prev) =>
          prev.map((r) => (r.runId === runId ? { ...r, name: name || undefined } : r)),
        );
        setRenamingId(null);
        setNameDraft("");
      } catch (err) {
        console.error("Failed to rename run:", err);
      } finally {
        setSavingName(false);
      }
    },
    [nameDraft],
  );

  const handleDelete = useCallback(
    async (runId: string, e: React.MouseEvent) => {
      e.stopPropagation();
      if (!confirm("Delete this run? This cannot be undone.")) return;
      setDeletingIds((prev) => new Set(prev).add(runId));
      try {
        await deleteRun(runId, true);
        setRuns((prev) => prev.filter((r) => r.runId !== runId));
        if (expandedId === runId) setExpandedId(null);
      } catch (err) {
        console.error("Failed to delete run:", err);
      } finally {
        setDeletingIds((prev) => {
          const next = new Set(prev);
          next.delete(runId);
          return next;
        });
      }
    },
    [expandedId],
  );

  // Edit & Rerun
  const handleRerun = useCallback(
    async (runId: string, e: React.MouseEvent) => {
      e.stopPropagation();
      setRerunningIds((prev) => new Set(prev).add(runId));
      try {
        // Fetch run detail with config
        let detail = runDetails[runId];
        if (!detail?.config) {
          detail = await getRun(runId, 0, true);
          setRunDetails((prev) => ({ ...prev, [runId]: detail }));
        }
        if (detail.config) {
          // Navigate to new scan page with the config pre-filled
          navigate("/new-scan", { state: { config: detail.config } });
        } else {
          // No config available — just navigate to new scan
          navigate("/new-scan");
        }
      } catch {
        navigate("/new-scan");
      } finally {
        setRerunningIds((prev) => {
          const next = new Set(prev);
          next.delete(runId);
          return next;
        });
      }
    },
    [runDetails, navigate],
  );

  // Cancel run
  const handleCancel = useCallback(
    async (runId: string, e: React.MouseEvent) => {
      e.stopPropagation();
      try {
        await deleteRun(runId, false); // cancel, not purge
        refreshRuns();
      } catch (err) {
        console.error("Failed to cancel run:", err);
      }
    },
    [refreshRuns],
  );

  if (loading) {
    return (
      <div className="max-w-5xl mx-auto flex items-center justify-center py-32">
        <div className="flex flex-col items-center gap-3">
          <Loader2 className="w-8 h-8 animate-spin text-primary" />
          <span className="text-sm text-muted-foreground">Loading runs...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-5xl mx-auto space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between mb-2">
        <div>
          <h1 className="text-xl font-bold text-foreground">Scan Activity</h1>
          <p className="text-sm text-muted-foreground">
            {runs.length} run{runs.length !== 1 ? "s" : ""}
            {activeRunIds.length > 0 && (
              <span className="text-primary ml-2 font-medium">
                ({activeRunIds.length} active)
              </span>
            )}
          </p>
        </div>
        <button
          onClick={() => navigate("/new-scan")}
          className="inline-flex items-center gap-2 px-4 py-2 bg-primary text-white text-sm font-medium rounded-lg hover:bg-primary/90 transition-colors"
        >
          <Play className="w-4 h-4" />
          New Scan
        </button>
      </div>

      {/* Search */}
      <div className="relative max-w-sm">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
        <input
          type="text"
          placeholder="Filter by target URL..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full pl-9 pr-3 py-2 bg-background border border-border rounded-lg text-sm text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:ring-2 focus:ring-primary/20 focus:border-primary"
        />
      </div>

      {/* Runs list */}
      {runs.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-16 text-center">
            <Clock className="w-10 h-10 text-muted-foreground/30 mb-3" />
            <p className="text-sm font-medium text-muted-foreground">No scan runs yet</p>
            <p className="text-xs text-muted-foreground/70 mt-1">
              Start a new scan to see activity here
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {runs.filter((r) => !debouncedSearch || `${r.name ?? ""} ${r.targetUrl ?? ""}`.toLowerCase().includes(debouncedSearch.toLowerCase())).map((run) => {
            const cfg = STATUS_CONFIG[run.status] ?? STATUS_CONFIG.queued;
            const Icon = cfg.icon;
            const isExpanded = expandedId === run.runId;
            const detail = runDetails[run.runId];
            const isDetailLoading = detailLoading[run.runId];
            const isDeleting = deletingIds.has(run.runId);
            const isRerunning = rerunningIds.has(run.runId);

            const title = run.name || run.targetUrl || "—";
            return (
              <div
                key={run.runId}
                className="rounded-xl border border-border bg-card overflow-hidden transition-all hover:border-primary/40 hover:shadow-sm"
              >
                {/* Run row — click anywhere to expand */}
                <div
                  className="flex items-center gap-4 px-4 py-3.5 cursor-pointer"
                  onClick={() => toggleExpand(run.runId)}
                >
                  {/* Tinted status icon */}
                  <div className={`w-10 h-10 rounded-full grid place-items-center shrink-0 ${cfg.bg}`}>
                    <Icon
                      className={`w-5 h-5 ${cfg.textColor} ${cfg.spin ? "animate-spin" : ""}`}
                    />
                  </div>

                  {/* Title + meta */}
                  <div className="min-w-0 flex-1">
                    {renamingId === run.runId ? (
                      <div
                        className="flex items-center gap-1.5"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <input
                          autoFocus
                          value={nameDraft}
                          onChange={(e) => setNameDraft(e.target.value)}
                          onKeyDown={(e) => {
                            if (e.key === "Enter") saveRename(run.runId);
                            if (e.key === "Escape") cancelRename();
                          }}
                          placeholder="Name this scan…"
                          className="h-7 min-w-0 flex-1 max-w-xs rounded border border-border bg-background px-2 text-sm"
                        />
                        <button
                          onClick={() => saveRename(run.runId)}
                          disabled={savingName}
                          title="Save name"
                          className="p-1 rounded text-emerald-600 dark:text-emerald-400 hover:bg-muted disabled:opacity-50"
                        >
                          {savingName ? (
                            <Loader2 className="w-3.5 h-3.5 animate-spin" />
                          ) : (
                            <Check className="w-3.5 h-3.5" />
                          )}
                        </button>
                        <button
                          onClick={cancelRename}
                          title="Cancel"
                          className="p-1 rounded text-muted-foreground hover:bg-muted"
                        >
                          <X className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    ) : (
                      <div className="group/name flex items-center gap-1.5 min-w-0">
                        <h3
                          className="text-sm font-semibold text-foreground truncate"
                          title={run.targetUrl ?? ""}
                        >
                          {title}
                        </h3>
                        <button
                          onClick={(e) => startRename(run, e)}
                          title={run.name ? "Rename scan" : "Name this scan"}
                          className="shrink-0 p-0.5 rounded text-muted-foreground/50 hover:text-foreground hover:bg-muted opacity-0 group-hover/name:opacity-100 transition-opacity"
                        >
                          <Pencil className="w-3 h-3" />
                        </button>
                      </div>
                    )}
                    <div className="mt-0.5 flex items-center gap-2 text-[11px] text-muted-foreground flex-wrap">
                      <span className={`font-semibold uppercase tracking-wide ${cfg.textColor}`}>
                        {cfg.label}
                      </span>
                      <span aria-hidden>·</span>
                      <span className="flex items-center gap-1 whitespace-nowrap">
                        <Clock className="w-3 h-3 shrink-0" />
                        {fmtDateTime(run.startedAt)}
                      </span>
                      {run.name && run.targetUrl && (
                        <>
                          <span aria-hidden>·</span>
                          <span className="truncate max-w-[16rem]" title={run.targetUrl}>
                            {run.targetUrl}
                          </span>
                        </>
                      )}
                      {run.progressCount != null && run.progressCount > 0 && (
                        <>
                          <span aria-hidden>·</span>
                          <span className="tabular-nums">{run.progressCount} attacks</span>
                        </>
                      )}
                    </div>
                  </div>

                  {/* Action buttons — subtle, icon-only on small screens */}
                  <div className="flex items-center gap-1 shrink-0" onClick={(e) => e.stopPropagation()}>
                    {(run.status === "running" || run.status === "queued") && (
                      <button
                        onClick={(e) => handleCancel(run.runId, e)}
                        className="text-xs text-muted-foreground hover:text-red-600 dark:hover:text-red-400 px-2 py-1 rounded hover:bg-muted transition-colors"
                      >
                        Cancel
                      </button>
                    )}
                    <button
                      onClick={(e) => handleRerun(run.runId, e)}
                      disabled={isRerunning}
                      className="text-xs text-muted-foreground hover:text-primary px-2 py-1 rounded hover:bg-muted transition-colors disabled:opacity-50"
                    >
                      {isRerunning ? (
                        <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      ) : (
                        "Edit & Rerun"
                      )}
                    </button>
                    <button
                      onClick={(e) => handleDelete(run.runId, e)}
                      disabled={isDeleting}
                      className="text-muted-foreground/50 hover:text-red-600 dark:hover:text-red-400 p-1 rounded hover:bg-muted transition-colors disabled:opacity-50"
                    >
                      {isDeleting ? (
                        <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      ) : (
                        <Trash2 className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </div>

                  {/* Expand chevron */}
                  <span className="text-muted-foreground/40 shrink-0">
                    {isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                  </span>
                </div>

                {/* Live progress for active runs (always visible) */}
                {(run.status === "running" || run.status === "queued") && detail && (() => {
                  // The API returns mixed progress: phase/message events AND attack results
                  const rawProgress = detail.progress as unknown as Record<string, unknown>[] | undefined;
                  const allEvents = rawProgress ?? [];
                  const attackResults = allEvents.filter((e) => e.attackName || e.result);
                  const phaseEvents = allEvents.filter((e) => e.phase || e.message);
                  const lastPhase = phaseEvents.length > 0 ? phaseEvents[phaseEvents.length - 1] : null;
                  const attackCount = attackResults.length;

                  return (
                    <div className="border-t border-border px-4 py-3">
                      {/* Status message (planning, cloning, analyzing...) */}
                      {lastPhase && attackCount === 0 && (
                        <div className="flex items-center gap-2 mb-2">
                          <Loader2 className="w-3.5 h-3.5 animate-spin text-primary shrink-0" />
                          <span className="text-sm text-foreground">
                            {String(lastPhase.message || lastPhase.phase || "Preparing...")}
                          </span>
                        </div>
                      )}

                      {/* Progress bar */}
                      <div className="flex items-center gap-3 mb-2">
                        <div className="flex-1 h-1.5 bg-muted rounded-full overflow-hidden">
                          <div
                            className="h-full bg-primary rounded-full transition-all duration-500"
                            style={{
                              width: detail.progressTotal
                                ? `${Math.min((attackCount / detail.progressTotal) * 100, 100)}%`
                                : attackCount > 0 ? "10%" : "0%",
                            }}
                          />
                        </div>
                        <span className="text-xs text-muted-foreground tabular-nums shrink-0">
                          {attackCount > 0
                            ? `${attackCount}${detail.progressTotal ? ` / ${detail.progressTotal}` : ""} attacks`
                            : lastPhase ? "Planning..." : "Starting..."}
                        </span>
                      </div>

                      {/* Latest attack results */}
                      {attackCount > 0 && (
                        <div className="space-y-0.5 max-h-32 overflow-y-auto">
                          {attackResults.slice(-5).map((p, i) => (
                            <div key={i} className="flex items-center gap-2 text-xs py-0.5">
                              <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                                p.verdict === "PASS" ? "bg-red-500" :
                                p.verdict === "FAIL" ? "bg-emerald-500" :
                                p.verdict === "PARTIAL" ? "bg-amber-500" : "bg-gray-400"
                              }`} />
                              <span className="text-muted-foreground tabular-nums w-5">
                                {typeof p.index === "number" ? p.index + 1 : i + 1}
                              </span>
                              <span className="text-foreground truncate flex-1">
                                {String(p.attackName ?? (p.result as Record<string, unknown> | undefined)?.name ?? "—")}
                              </span>
                              <span className="text-muted-foreground shrink-0">{String(p.category ?? "")}</span>
                              <span className={`font-semibold shrink-0 ${verdictColor(String(p.verdict ?? ""))}`}>
                                {p.verdict ? verdictLabel(String(p.verdict)) : "—"}
                              </span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })()}

                {/* Expanded detail */}
                {isExpanded && (
                  <div className="border-t border-border px-4 pb-4 pt-3 bg-muted/20">
                    {isDetailLoading ? (
                      <div className="flex items-center justify-center py-8">
                        <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
                      </div>
                    ) : detail ? (
                      <div className="space-y-4">
                        {/* Error message */}
                        {detail.error && (
                          <div className="flex items-start gap-2 p-3 bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900 rounded-lg">
                            <XCircle className="w-4 h-4 text-red-600 dark:text-red-400 mt-0.5 shrink-0" />
                            <div>
                              <p className="text-sm font-medium text-red-700 dark:text-red-400">
                                Run failed: Cancelled by user
                              </p>
                              <p className="text-xs text-red-600/80 dark:text-red-400/80 mt-0.5">
                                {detail.error}
                              </p>
                            </div>
                          </div>
                        )}

                        {/* Summary */}
                        {detail.summary && typeof detail.summary === "string" && (
                          <p className="text-sm text-muted-foreground">{detail.summary}</p>
                        )}

                        {/* Progress list */}
                        {(() => {
                          const rawItems = (detail.progress ?? []) as unknown as Record<string, unknown>[];
                          const attackItems = rawItems.filter((e) => e.attackName || e.result);
                          if (attackItems.length === 0) return null;
                          return (
                          <div>
                            <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">
                              Progress ({attackItems.length}
                              {detail.progressTotal ? ` / ${detail.progressTotal}` : ""})
                            </h4>
                            <div className="max-h-64 overflow-y-auto border border-border rounded-lg divide-y divide-border">
                              {attackItems.map((p, i) => {
                                const result = p.result as Record<string, unknown> | undefined;
                                const attack = result?.attack as Record<string, unknown> | undefined;
                                const name = String(p.attackName ?? result?.name ?? attack?.name ?? result?.attackName ?? "—");
                                const cat = String(p.category ?? attack?.category ?? result?.category ?? "");
                                const vrd = String(p.verdict ?? result?.verdict ?? "");
                                const idx = typeof p.index === "number" ? p.index : i;
                                return (
                                <div
                                  key={idx}
                                  className="flex items-center gap-3 text-sm py-2 px-3 hover:bg-muted/30"
                                >
                                  <span className="text-xs text-muted-foreground w-6 text-right tabular-nums shrink-0">
                                    {idx + 1}
                                  </span>
                                  <span className="font-medium text-foreground truncate flex-1">
                                    {name}
                                  </span>
                                  <span className="text-xs text-muted-foreground shrink-0">
                                    {cat}
                                  </span>
                                  <span className={`text-xs font-semibold shrink-0 ${verdictColor(vrd)}`}>
                                    {vrd ? verdictLabel(vrd) : "—"}
                                  </span>
                                </div>
                                );
                              })}
                            </div>
                          </div>
                          );
                        })()}

                        {/* Report link */}
                        {run.status === "done" && detail.reportFile && (
                          <button
                            onClick={() => navigate(`/reports/${detail.reportFile}`)}
                            className="inline-flex items-center gap-2 text-sm font-medium text-primary hover:text-primary/80 transition-colors"
                          >
                            <CheckCircle className="w-4 h-4" />
                            View Report
                          </button>
                        )}
                      </div>
                    ) : (
                      <p className="text-sm text-muted-foreground py-4">
                        Could not load run details.
                      </p>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
