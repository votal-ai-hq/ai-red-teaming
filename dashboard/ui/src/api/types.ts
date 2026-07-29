// ── Auth ──
export interface AuthConfig {
  mode: "none" | "simple" | "dev" | "oidc";
  clerkPublishableKey?: string | null;
  hcaptchaSiteKey?: string | null;
}

export interface AuthUser {
  username: string;
  role: string;
}

// ── Reports ──
export interface ReportMeta {
  filename: string;
  timestamp: string;
  targetUrl: string;
  score: number;
  totalAttacks: number;
  passed: number;
  partial: number;
  failed: number;
  errors: number;
  categoryCount?: number;
}

export interface ReportTrend {
  date: string;
  score: number;
}

export interface ReportsMetaResponse {
  items: ReportMeta[];
  total: number;
  page: number;
  totalPages: number;
  trend: ReportTrend[];
}

export interface ReportRound {
  roundNumber?: number;
  round?: number;
  results: ReportResult[];
}

export interface ReportResult {
  attackName?: string;
  attack?: string | Record<string, unknown>;
  category?: string;
  severity?: string;
  verdict: string;
  llmVerdict?: string;
  statusCode?: number;
  responseTimeMs?: number;
  reasoning?: string;
  llmReasoning?: string;
  llmEvidenceFor?: string;
  llmEvidenceAgainst?: string;
  judgeConfidence?: number;
  policyUsed?: {
    name: string;
    pass_criteria?: string[];
    fail_criteria?: string[];
    partial_criteria?: string[];
    instructions?: string;
    severity_override?: string | null;
  };
  payload?: string;
  // The captured agent response. Often a string, but many targets return a
  // structured body like { response, tool_calls, user, ... } or { error, ... }.
  responseBody?: string | Record<string, unknown>;
  findings?: string[];
  steps?: ConversationStep[];
  conversation?: ConversationStep[];
  affectedFiles?: AffectedFile[];
  executionTrace?: ExecutionTrace;
  threatAssessment?: ThreatAssessment;
  idealResponse?: string | { content?: string; explanation?: string };
}

export interface ConversationStep {
  role: string;
  content: string;
  statusCode?: number;
}

export interface AffectedFile {
  path: string;
  reason: string;
}

export interface ExecutionTrace {
  transcript?: string;
  stderr?: string;
}

export interface ThreatAssessment {
  level: string;
  description: string;
}

export interface ReportSummary {
  totalAttacks: number;
  passed: number;
  failed: number;
  partial: number;
  errors: number;
  score: number;
  byCategory?: Record<string, unknown>;
}

export interface ReportFinding {
  severity: string;
  category: string;
  description: string;
  attack: string;
}

// ── Per-scan LLM usage metrics (report.usage) ──
export interface UsageByPhase {
  phase: string;
  calls: number;
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
  latencyMs: number;
  costUsd: number | null;
}

export interface UsageByModel {
  provider: string;
  model: string;
  calls: number;
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
  latencyMs: number;
  costUsd: number | null;
  priced: boolean;
}

export interface UsageSummary {
  totalCalls: number;
  failedCalls: number;
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
  tokensComplete: boolean;
  costUsd: number | null;
  costComplete: boolean;
  unpricedModels: string[];
  llmLatencyMsTotal: number;
  errorsByKind: { rate_limit: number; timeout: number; other: number };
  byPhase: UsageByPhase[];
  byModel: UsageByModel[];
}

export interface FullReport {
  id?: string;
  filename?: string;
  targetUrl: string;
  timestamp: string;
  // These may exist at top level (from meta) or inside summary (from full API)
  score?: number;
  totalAttacks?: number;
  passed?: number;
  partial?: number;
  failed?: number;
  errors?: number;
  rounds: ReportRound[];
  summary?: ReportSummary | string;
  llmAnalysis?: string;
  findings?: ReportFinding[];
  attackCategories?: string[];
  /** Per-scan LLM usage metrics. Absent on reports from before this shipped. */
  usage?: UsageSummary;
}

// ── Runs ──
export interface RunMeta {
  runId: string;
  status: "queued" | "running" | "done" | "error" | "cancelled";
  startedAt: string;
  finishedAt?: string;
  /** Optional user-given name for the scan (stored in the run config). */
  name?: string;
  targetUrl?: string;
  error?: string;
  progressCount?: number;
  reportFile?: string;
  summary?: string;
}

export interface RunProgress {
  index: number;
  attackName: string;
  category: string;
  verdict: string;
  severity?: string;
  timestamp?: string;
}

export interface RunDetail {
  runId: string;
  status: string;
  progress: RunProgress[];
  progressTotal?: number;
  reportFile?: string;
  summary?: string;
  error?: string;
  config?: RunConfig;
}

export interface RunConfig {
  targetUrl?: string;
  attackCategories?: string[];
  strategies?: string[];
  [key: string]: unknown;
}

// ── Compliance ──
export interface ComplianceFramework {
  id: string;
  name: string;
  controlCount: number;
}

export interface ComplianceControlAttack {
  name: string;
  category: string;
  /** Delivery strategy / tactic used (e.g. crescendo, roleplay). */
  strategy?: string;
  severity: string;
  verdict: "PASS" | "PARTIAL" | "FAIL";
  detail?: string;
}

export interface ComplianceResult {
  framework: string;
  code: string;
  title: string;
  status: "vulnerable" | "at_risk" | "secure" | "not_tested" | "error";
  summary: string;
  findings?: string[];
  details?: string;
  recommendations?: string[];
  attacksAnalyzed?: number;
  /** Attack categories this control maps to (coverage basis) — present even for
   *  not_tested controls so the UI can show what would exercise the control. */
  categories?: string[];
  /** Per-attack breakdown for this control, returned by the static-mapping
   *  endpoint. Lets the UI associate controls back to individual vulnerabilities
   *  (each attack carries the category the control maps against). */
  attacks?: ComplianceControlAttack[];
}

// ── Risk ──
export interface RiskAnalysisResult {
  attack: string;
  category: string;
  impactLevel: string;
  businessImpact: string;
  financialExposure: string;
  relatedIncidents: string;
  complianceRisk: string;
  remediationEstimate: string;
}

// ── Audit ──
export interface AuditEntry {
  id: string;
  timestamp?: string;
  createdAt?: string;
  action: string;
  resource_type?: string;
  resource_id?: string;
  targetType?: string | null;
  targetId?: string | null;
  user_id?: string;
  userId?: string;
  details?: Record<string, unknown>;
  metadata?: Record<string, unknown> | null;
  [key: string]: unknown;
}

export interface AuditLogResponse {
  entries: AuditEntry[];
  total: number;
}

// ── Guardrails ──
export interface GuardrailReportMeta {
  filename: string;
  created_at: string;
  model?: string;
  guardrails?: string[];
  goodTotal: number;
  badTotal: number;
  blocked: number;
  total: number;
}

export interface GuardrailReport {
  filename: string;
  results: GuardrailResult[];
  model?: string;
  guardrails?: string[];
}

export interface GuardrailResultLeg {
  category?: string;
  message?: string;
  use_guardrails?: boolean;
  status_code?: number;
  latency_ms?: number;
  response_text?: string;
  guardrail_verdict?: string;
  /** Per-leg verdict emitted by the guardrail eval, e.g. "guardrail_blocked", "benign_answer". */
  verdict?: string;
}

export interface GuardrailAssessment {
  original_category?: string;
  guardrail_effect?: string;
  blocked?: boolean;
}

export interface GuardrailResult {
  // Legacy flat fields
  prompt?: string;
  response?: string;
  guardrail?: string;
  verdict?: string;
  blocked?: boolean;
  details?: string;
  // New nested structure
  without_guardrails?: GuardrailResultLeg;
  with_guardrails?: GuardrailResultLeg;
  assessment?: GuardrailAssessment;
}

// ── Reference ──
/** One compliance control an attack category maps to (from /api/reference). */
export interface CategoryComplianceRef {
  framework: string;
  code: string;
  title: string;
}
export interface ReferenceFramework {
  id: string;
  name: string;
  controlCount: number;
}
export interface ReferenceData {
  categories: string[];
  strategies: StrategyInfo[];
  /** category → the compliance controls it covers (reverse mapping). */
  categoryCompliance: Record<string, CategoryComplianceRef[]>;
  frameworks?: ReferenceFramework[];
  /** Whether this instance permits MCP stdio targets (self-hosted only). */
  allowMcpStdio?: boolean;
  /** Categories that have native MCP attacks (used to scope the form for MCP targets). */
  mcpCategories?: string[];
}

export interface McpDiscoverResult {
  ok: boolean;
  error?: string;
  transport?: string;
  serverInfo?: { name: string; version?: string } | null;
  protocolVersion?: string | null;
  capabilities?: string[];
  tools?: {
    name: string;
    description: string;
    inputSchema?: Record<string, unknown>;
  }[];
  prompts?: { name: string; description: string }[];
  resources?: { name: string; uri: string }[];
}

export interface StrategyInfo {
  slug: string;
  name: string;
  level: string;
}
