import { useState, useEffect, useCallback } from "react";
import { useNavigate, useLocation } from "react-router";
import { createRun, getRuns } from "@/api/runs";
import type { RunMeta } from "@/api/types";
import { getReference, discoverMcp } from "@/api/reference";
import { apiFetch } from "@/api/client";
import {
  listDatasets,
  evalQualityStream,
  type DatasetSummary,
  type QualityEvalReport,
} from "@/api/datasets";
import type { ReferenceData, StrategyInfo, McpDiscoverResult } from "@/api/types";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Play,
  Zap,
  Shield,
  Settings,
  Rocket,
  Target,
  Layers,
  Code,
  CheckCircle,
  AlertCircle,
  X,
  ChevronDown,
  ChevronRight,
  Globe,
  Key,
  FileText,
  Cpu,
  RotateCcw,
  Eye,
  Crosshair,
  Gauge,
  Lock,
  MessageSquare,
  Braces,
  Upload,
  Loader2,
  Search,
} from "lucide-react";

/* ─── constants ─── */

const LLM_PROVIDERS = [
  { value: "openai", label: "OpenAI" },
  { value: "anthropic", label: "Anthropic" },
  { value: "openrouter", label: "OpenRouter" },
  { value: "together", label: "Together" },
  { value: "azure", label: "Azure" },
  { value: "custom", label: "Custom" },
  { value: "nim", label: "NIM" },
  { value: "huggingface", label: "HuggingFace" },
] as const;

const ATTACK_MODES = [
  { value: "balanced", label: "Balanced", desc: "Standard attack generation" },
  { value: "aggressive", label: "Aggressive", desc: "Maximum exploitation attempts" },
  { value: "subtle", label: "Subtle", desc: "Stealthy, harder to detect" },
] as const;

const AUTH_METHODS = [
  { value: "none", label: "No Auth (public)" },
  { value: "api_key", label: "API Key" },
  { value: "body_role", label: "Body Role" },
  { value: "jwt", label: "JWT" },
  { value: "bearer", label: "Bearer Token" },
] as const;

const TEMPLATES = [
  {
    key: "quick",
    label: "Quick Scan",
    icon: Zap,
    description: "Core attack categories, single-shot strategy. Fast results in minutes.",
    color: "text-amber-600",
    bg: "bg-amber-50 dark:bg-amber-950/30",
    border: "border-amber-300 dark:border-amber-800",
    defaults: {
      categories: ["prompt_injection", "jailbreak"],
      strategySlugs: ["single-shot"],
      rounds: 1,
      concurrency: 3,
      maxAttacksPerCategory: 10,
    },
  },
  {
    key: "full",
    label: "Full Scan",
    icon: Shield,
    description: "All attack categories, multi-round strategy. Thorough coverage.",
    color: "text-blue-600",
    bg: "bg-blue-50 dark:bg-blue-950/30",
    border: "border-blue-300 dark:border-blue-800",
    defaults: {
      categories: [], // empty = all
      strategySlugs: [], // empty = all
      rounds: 3,
      concurrency: 3,
      maxAttacksPerCategory: 15,
    },
  },
  {
    key: "custom",
    label: "Custom",
    icon: Settings,
    description: "Full control over all configuration options.",
    color: "text-violet-600",
    bg: "bg-violet-50 dark:bg-violet-950/30",
    border: "border-violet-300 dark:border-violet-800",
    defaults: {
      categories: [],
      strategySlugs: [],
      rounds: 3,
      concurrency: 3,
      maxAttacksPerCategory: 15,
    },
  },
] as const;

/* ─── helpers ─── */

function prettyCat(cat: string) {
  return cat.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function SectionHeader({
  step,
  title,
  icon: Icon,
  hint,
}: {
  step: number;
  title: string;
  icon: React.ElementType;
  hint?: string;
}) {
  return (
    <div className="flex items-start gap-3 mb-4">
      <div className="w-7 h-7 rounded-lg bg-primary/10 text-primary text-xs font-bold grid place-items-center shrink-0">
        {step}
      </div>
      <div className="min-w-0">
        <h2 className="text-sm font-semibold text-foreground flex items-center gap-2">
          <Icon className="w-4 h-4 text-muted-foreground" />
          {title}
        </h2>
        {hint && <p className="text-xs text-muted-foreground mt-0.5">{hint}</p>}
      </div>
    </div>
  );
}

function CollapsibleSection({
  title,
  icon: Icon,
  defaultOpen = false,
  children,
}: {
  title: string;
  icon: React.ElementType;
  defaultOpen?: boolean;
  children: React.ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="border border-border rounded-xl overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="w-full flex items-center gap-2.5 px-5 py-3.5 text-left hover:bg-muted/50 transition-colors"
      >
        {open ? (
          <ChevronDown className="w-4 h-4 text-muted-foreground" />
        ) : (
          <ChevronRight className="w-4 h-4 text-muted-foreground" />
        )}
        <Icon className="w-4 h-4 text-muted-foreground" />
        <span className="text-sm font-medium text-foreground">{title}</span>
      </button>
      {open && <div className="px-5 pb-5 pt-1 border-t border-border">{children}</div>}
    </div>
  );
}

function FieldRow({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-1.5">
      <label className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
        {label}
      </label>
      {children}
      {hint && <p className="text-[11px] text-muted-foreground">{hint}</p>}
    </div>
  );
}

/** A segmented control — grouped pill toggles in a single track. */
function Segmented<T extends string>({
  options,
  value,
  onChange,
  size = "md",
}: {
  options: { value: T; label: string; title?: string }[];
  value: T;
  onChange: (v: T) => void;
  size?: "sm" | "md";
}) {
  const pad = size === "sm" ? "px-2.5 py-1 text-xs" : "px-3 py-1.5 text-sm";
  return (
    <div className="inline-flex flex-wrap items-center gap-1 rounded-lg border border-border bg-muted/40 p-1">
      {options.map((o) => {
        const active = o.value === value;
        return (
          <button
            key={o.value}
            type="button"
            title={o.title}
            onClick={() => onChange(o.value)}
            className={`rounded-md font-medium transition-colors ${pad} ${
              active
                ? "bg-background text-foreground shadow-sm ring-1 ring-border"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            {o.label}
          </button>
        );
      })}
    </div>
  );
}

const inputCls =
  "w-full h-10 px-3 text-sm border border-border rounded-lg bg-background text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:ring-2 focus:ring-primary/20 focus:border-primary transition-all";
const selectCls = `${inputCls} appearance-none cursor-pointer`;

/* ─── main component ─── */

export default function NewScanPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const prefillConfig = (location.state as { config?: Record<string, unknown> } | null)?.config;
  const [ref, setRef] = useState<ReferenceData | null>(null);
  const [refLoading, setRefLoading] = useState(true);
  const [activeTemplate, setActiveTemplate] = useState<string | null>(null);

  // ── Target ──
  const [scanName, setScanName] = useState("");
  const [targetType, setTargetType] = useState<"http_agent" | "mcp" | "websocket_agent">("http_agent");
  const [baseUrl, setBaseUrl] = useState("");
  const [agentEndpoint, setAgentEndpoint] = useState("/api/agent");
  const [authEndpoint, setAuthEndpoint] = useState("");
  const [applicationDetails, setApplicationDetails] = useState("");

  // ── MCP target (when targetType === "mcp") ──
  const [mcpTransport, setMcpTransport] = useState<"streamable_http" | "stdio">("streamable_http");
  const [mcpUrl, setMcpUrl] = useState("");
  const [mcpCommand, setMcpCommand] = useState("");
  const [mcpArgs, setMcpArgs] = useState(""); // whitespace-separated
  const [mcpHeaders, setMcpHeaders] = useState<{ key: string; value: string }[]>([{ key: "", value: "" }]);
  const [mcpAllowlist, setMcpAllowlist] = useState(""); // comma/newline-separated tool names
  const [mcpDenylist, setMcpDenylist] = useState("");
  const [mcpDiscovering, setMcpDiscovering] = useState(false);
  const [mcpDiscovery, setMcpDiscovery] = useState<McpDiscoverResult | null>(null);
  const [mcpDiscoverError, setMcpDiscoverError] = useState<string | null>(null);

  // ── WebSocket target (when targetType === "websocket_agent") ──
  const [wsPath, setWsPath] = useState("/ws/chat");
  const [wsToken, setWsToken] = useState("");
  const [wsSubprotocols, setWsSubprotocols] = useState(""); // comma-separated

  // ── Auth ──
  const [authMethods, setAuthMethods] = useState<string[]>(["api_key"]);
  const [apiKeys, setApiKeys] = useState<{ role: string; key: string }[]>([
    { role: "viewer", key: "" },
  ]);
  const [bearerToken, setBearerToken] = useState("");
  const [jwtSecret, setJwtSecret] = useState("");

  // ── Request / Response Schema ──
  const [messageField, setMessageField] = useState("message");
  const [roleField, setRoleField] = useState("role");
  const [apiKeyField, setApiKeyField] = useState("api_key");
  const [responsePath, setResponsePath] = useState("response");
  const [toolCallsPath, setToolCallsPath] = useState("tool_calls");

  // ── Attack config ──
  const [selectedCategories, setSelectedCategories] = useState<string[]>([]);
  const [selectedStrategies, setSelectedStrategies] = useState<string[]>([]);
  const [categorySearch, setCategorySearch] = useState("");
  const [strategySearch, setStrategySearch] = useState("");
  const [adaptiveRounds, setAdaptiveRounds] = useState(3);
  const [maxAttacksPerCategory, setMaxAttacksPerCategory] = useState(15);
  const [concurrency, setConcurrency] = useState(3);
  const [delayMs, setDelayMs] = useState(200);
  const [attackMode, setAttackMode] = useState("balanced");
  const [strategiesPerRound, setStrategiesPerRound] = useState(8);
  const [attacksPerStrategy, setAttacksPerStrategy] = useState(1);

  // ── LLM ──
  const [llmProvider, setLlmProvider] = useState("openai");
  const [llmModel, setLlmModel] = useState("gpt-4o");
  const [judgeProvider, setJudgeProvider] = useState("");
  const [judgeModel, setJudgeModel] = useState("");

  // ── Toggles ──
  const [enableLlmGeneration, setEnableLlmGeneration] = useState(true);
  const [includeSeedAttacks, setIncludeSeedAttacks] = useState(true);
  const [enableMultiTurn, setEnableMultiTurn] = useState(true);
  const [enableAdaptiveMultiTurn, setEnableAdaptiveMultiTurn] = useState(true);
  const [maxMultiTurnSteps, setMaxMultiTurnSteps] = useState(8);
  const [enableDiscovery, setEnableDiscovery] = useState(false);
  const [skipIrrelevant, setSkipIrrelevant] = useState(true);
  const [requireReview, setRequireReview] = useState(false);

  // ── Sensitive patterns ──
  const [sensitivePatterns, setSensitivePatterns] = useState("");

  // ── Advanced JSON ──
  const [showJsonOverride, setShowJsonOverride] = useState(false);
  const [jsonConfig, setJsonConfig] = useState("");

  // ── Policy ──
  const [policyFile, setPolicyFile] = useState("policies/default.json");
  const [availablePolicies, setAvailablePolicies] = useState<{ path: string; name: string; description: string }[]>([]);
  const [uploadingPolicy, setUploadingPolicy] = useState(false);
  const [policyUploadError, setPolicyUploadError] = useState<string | null>(null);

  // ── Evaluation dataset (customAttacksFile) ──
  // Deep link from the Datasets tab ("Use for evaluation"): ?dataset=<path>
  // preselects the dataset and opens the section.
  const deepLinkDataset =
    new URLSearchParams(location.search).get("dataset") || "";
  // ?mode=quality (from a quality dataset's "Use for evaluation") switches the
  // form to score the dataset with the quality scorer instead of a red-team scan.
  const deepLinkMode =
    new URLSearchParams(location.search).get("mode") === "quality"
      ? "quality"
      : "security";
  const [mode, setMode] = useState<"security" | "quality">(deepLinkMode);
  const [datasetFile, setDatasetFile] = useState(deepLinkDataset);
  const [datasetOnly, setDatasetOnly] = useState(false);
  const [availableDatasets, setAvailableDatasets] = useState<DatasetSummary[]>([]);
  // Quality-eval target source: a freshly-configured target ("new") or the
  // saved target of a previous scan ("previous", run as-is).
  const [targetSource, setTargetSource] = useState<"new" | "previous">("new");
  const [previousRunId, setPreviousRunId] = useState("");
  const [previousRuns, setPreviousRuns] = useState<RunMeta[]>([]);
  // Quality-eval knobs + live streaming state.
  const [evalThreshold, setEvalThreshold] = useState(0.7);
  const [evalRunning, setEvalRunning] = useState(false);
  const [evalProgress, setEvalProgress] = useState<{ done: number; total: number } | null>(
    null,
  );
  const [evalTail, setEvalTail] = useState<
    { metric: string; score: number; pass: boolean; error?: string }[]
  >([]);
  const [evalReport, setEvalReport] = useState<QualityEvalReport | null>(null);

  // ── UI state ──
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([
      getReference(),
      apiFetch<{ path: string; name: string; description: string }[]>("/api/policies").catch(() => []),
    ])
      .then(([data, policies]) => {
        setRef(data);
        if (policies.length > 0) setAvailablePolicies(policies);
      })
      .catch(() => setError("Failed to load reference data."))
      .finally(() => setRefLoading(false));
    listDatasets()
      .then((r) => setAvailableDatasets(r.datasets))
      .catch(() => {});
    // Recent runs — used to reuse a previous scan's target in quality-eval mode.
    getRuns()
      .then((rs) => setPreviousRuns(rs.filter((r) => r.targetUrl)))
      .catch(() => {});
  }, []);

  // If this instance disallows MCP stdio, never leave the form stuck on it.
  useEffect(() => {
    if (ref && !ref.allowMcpStdio && mcpTransport === "stdio") {
      setMcpTransport("streamable_http");
    }
  }, [ref, mcpTransport]);

  // Pre-fill form from "Edit & Rerun" config passed via router state
  useEffect(() => {
    if (!prefillConfig) return;
    const c = prefillConfig;
    const target = c.target as Record<string, unknown> | undefined;
    const auth = c.auth as Record<string, unknown> | undefined;
    const atk = c.attackConfig as Record<string, unknown> | undefined;
    const reqSchema = c.requestSchema as Record<string, unknown> | undefined;
    const resSchema = c.responseSchema as Record<string, unknown> | undefined;

    // Scan name
    if (typeof c.name === "string") setScanName(c.name);

    // Target
    if (target?.baseUrl) setBaseUrl(String(target.baseUrl));
    if (target?.agentEndpoint) setAgentEndpoint(String(target.agentEndpoint));
    if (target?.authEndpoint) setAuthEndpoint(String(target.authEndpoint));
    if (target?.applicationDetails) setApplicationDetails(String(target.applicationDetails));
    if (target?.type) setTargetType(target.type as "http_agent" | "mcp" | "websocket_agent");

    // MCP target
    const mcp = target?.mcp as Record<string, unknown> | undefined;
    if (mcp) {
      if (mcp.transport === "stdio" || mcp.transport === "streamable_http") {
        setMcpTransport(mcp.transport);
      }
      if (mcp.url) setMcpUrl(String(mcp.url));
      if (mcp.command) setMcpCommand(String(mcp.command));
      if (Array.isArray(mcp.args)) setMcpArgs((mcp.args as string[]).join(" "));
      if (mcp.headers && typeof mcp.headers === "object") {
        const hs = Object.entries(mcp.headers as Record<string, string>).map(([key, value]) => ({ key, value }));
        if (hs.length > 0) setMcpHeaders(hs);
      }
      if (Array.isArray(mcp.allowlistedTools)) setMcpAllowlist((mcp.allowlistedTools as string[]).join(", "));
      if (Array.isArray(mcp.denylistedTools)) setMcpDenylist((mcp.denylistedTools as string[]).join(", "));
    }

    // WebSocket target
    const ws = target?.websocket as Record<string, unknown> | undefined;
    if (ws) {
      if (ws.path) setWsPath(String(ws.path));
      if (ws.token) setWsToken(String(ws.token));
      if (Array.isArray(ws.subprotocols)) setWsSubprotocols((ws.subprotocols as string[]).join(", "));
    }

    // Auth
    if (auth?.methods && Array.isArray(auth.methods)) setAuthMethods(auth.methods as string[]);
    if (auth?.apiKeys && typeof auth.apiKeys === "object") {
      setApiKeys(Object.entries(auth.apiKeys as Record<string, string>).map(([role, key]) => ({ role, key })));
    }
    if (auth?.bearerToken) setBearerToken(String(auth.bearerToken));
    if (auth?.jwtSecret) setJwtSecret(String(auth.jwtSecret));

    // Attack config
    if (atk?.adaptiveRounds) setAdaptiveRounds(Number(atk.adaptiveRounds));
    if (atk?.maxAttacksPerCategory) setMaxAttacksPerCategory(Number(atk.maxAttacksPerCategory));
    if (atk?.concurrency) setConcurrency(Number(atk.concurrency));
    if (atk?.delayBetweenRequestsMs) setDelayMs(Number(atk.delayBetweenRequestsMs));
    if (atk?.llmProvider) setLlmProvider(String(atk.llmProvider));
    if (atk?.llmModel) setLlmModel(String(atk.llmModel));
    if (atk?.judgeProvider) setJudgeProvider(String(atk.judgeProvider));
    if (atk?.judgeModel) setJudgeModel(String(atk.judgeModel));
    if (atk?.attackMode) setAttackMode(String(atk.attackMode));
    if (atk?.strategiesPerRound) setStrategiesPerRound(Number(atk.strategiesPerRound));
    if (atk?.attacksPerStrategy) setAttacksPerStrategy(Number(atk.attacksPerStrategy));
    if (atk?.enableLlmGeneration !== undefined) setEnableLlmGeneration(!!atk.enableLlmGeneration);
    if (atk?.includeSeedAttacks !== undefined) setIncludeSeedAttacks(!!atk.includeSeedAttacks);
    if (atk?.enableMultiTurnGeneration !== undefined) setEnableMultiTurn(!!atk.enableMultiTurnGeneration);
    if (atk?.enableAdaptiveMultiTurn !== undefined) setEnableAdaptiveMultiTurn(!!atk.enableAdaptiveMultiTurn);
    if (atk?.maxMultiTurnSteps) setMaxMultiTurnSteps(Number(atk.maxMultiTurnSteps));
    if (atk?.enableDiscovery !== undefined) setEnableDiscovery(!!atk.enableDiscovery);
    if (atk?.skipIrrelevantCategories !== undefined) setSkipIrrelevant(!!atk.skipIrrelevantCategories);
    if (atk?.requireReviewConfirmation !== undefined) setRequireReview(!!atk.requireReviewConfirmation);
    if (atk?.enabledCategories && Array.isArray(atk.enabledCategories)) setSelectedCategories(atk.enabledCategories as string[]);
    if (atk?.enabledStrategies && Array.isArray(atk.enabledStrategies)) setSelectedStrategies(atk.enabledStrategies as string[]);

    // Request/Response schema
    if (reqSchema?.messageField) setMessageField(String(reqSchema.messageField));
    if (reqSchema?.roleField) setRoleField(String(reqSchema.roleField));
    if (reqSchema?.apiKeyField) setApiKeyField(String(reqSchema.apiKeyField));
    if (resSchema?.responsePath) setResponsePath(String(resSchema.responsePath));
    if (resSchema?.toolCallsPath) setToolCallsPath(String(resSchema.toolCallsPath));

    // Sensitive patterns
    if (c.sensitivePatterns && Array.isArray(c.sensitivePatterns)) {
      setSensitivePatterns((c.sensitivePatterns as string[]).join("\n"));
    }

    // Policy
    if (c.policyFile) setPolicyFile(String(c.policyFile));

    // Also populate the JSON config for reference
    setJsonConfig(JSON.stringify(c, null, 2));
    setShowJsonOverride(false);
  }, [prefillConfig]);

  const toggleCategory = (cat: string) => {
    setSelectedCategories((prev) =>
      prev.includes(cat) ? prev.filter((c) => c !== cat) : [...prev, cat],
    );
  };

  const toggleStrategy = (slug: string) => {
    setSelectedStrategies((prev) =>
      prev.includes(slug) ? prev.filter((s) => s !== slug) : [...prev, slug],
    );
  };

  const applyTemplate = useCallback(
    (key: string) => {
      if (!ref) return;
      const tpl = TEMPLATES.find((t) => t.key === key);
      if (!tpl) return;

      setActiveTemplate(key);
      const d = tpl.defaults;

      if (d.categories.length > 0) {
        setSelectedCategories(d.categories.filter((c) => ref.categories.includes(c)));
      } else {
        setSelectedCategories([...ref.categories]);
      }

      if (d.strategySlugs.length > 0) {
        setSelectedStrategies(
          d.strategySlugs.filter((s) => ref.strategies.some((st) => st.slug === s)),
        );
      } else {
        setSelectedStrategies(ref.strategies.map((s) => s.slug));
      }

      setAdaptiveRounds(d.rounds);
      setConcurrency(d.concurrency);
      setMaxAttacksPerCategory(d.maxAttacksPerCategory);
    },
    [ref],
  );

  const buildConfig = (): Record<string, unknown> => {
    // If JSON override is provided, use it
    if (showJsonOverride && jsonConfig.trim()) {
      const parsed = JSON.parse(jsonConfig);
      // Ensure target URL is set
      if (!parsed.target?.baseUrl) {
        parsed.target = { ...parsed.target, baseUrl };
      }
      return parsed;
    }

    const apiKeysObj: Record<string, string> = {};
    apiKeys.forEach(({ role, key }) => {
      if (role && key) apiKeysObj[role] = key;
    });

    const splitList = (s: string) =>
      s.split(/[\n,]/).map((x) => x.trim()).filter(Boolean);

    // Build the target block per target type.
    let target: Record<string, unknown>;
    if (targetType === "mcp") {
      const headersObj: Record<string, string> = {};
      mcpHeaders.forEach(({ key, value }) => {
        if (key && value) headersObj[key] = value;
      });
      const allow = splitList(mcpAllowlist);
      const deny = splitList(mcpDenylist);
      target = {
        type: "mcp",
        applicationDetails: applicationDetails || "",
        mcp: {
          transport: mcpTransport,
          ...(mcpTransport === "streamable_http"
            ? {
                url: mcpUrl,
                ...(Object.keys(headersObj).length > 0 ? { headers: headersObj } : {}),
              }
            : {
                command: mcpCommand,
                ...(mcpArgs.trim() ? { args: mcpArgs.trim().split(/\s+/) } : {}),
              }),
          ...(allow.length > 0 ? { allowlistedTools: allow } : {}),
          ...(deny.length > 0 ? { denylistedTools: deny } : {}),
        },
      };
    } else if (targetType === "websocket_agent") {
      const subs = splitList(wsSubprotocols);
      target = {
        type: "websocket_agent",
        baseUrl,
        applicationDetails: applicationDetails || "",
        websocket: {
          path: wsPath,
          ...(subs.length > 0 ? { subprotocols: subs } : {}),
          ...(wsToken ? { token: wsToken } : {}),
        },
      };
    } else {
      target = {
        type: "http_agent",
        baseUrl,
        agentEndpoint,
        authEndpoint: authEndpoint || "",
        applicationDetails: applicationDetails || "",
      };
    }

    const config: Record<string, unknown> = {
      ...(scanName.trim() ? { name: scanName.trim() } : {}),
      target,
      auth: {
        methods: authMethods,
        ...(Object.keys(apiKeysObj).length > 0 ? { apiKeys: apiKeysObj } : {}),
        ...(bearerToken ? { bearerToken } : {}),
        ...(jwtSecret ? { jwtSecret } : {}),
      },
      requestSchema: {
        messageField,
        roleField,
        apiKeyField,
        guardrailModeField: "guardrail_mode",
      },
      responseSchema: {
        responsePath,
        toolCallsPath,
        userInfoPath: "user",
        guardrailsPath: "guardrails",
      },
      sensitivePatterns: sensitivePatterns
        .split("\n")
        .map((s) => s.trim())
        .filter(Boolean),
      policyFile,
      ...(datasetFile ? { customAttacksFile: datasetFile } : {}),
      attackConfig: {
        adaptiveRounds,
        ...(datasetFile && datasetOnly ? { customAttacksOnly: true } : {}),
        maxAttacksPerCategory,
        concurrency,
        delayBetweenRequestsMs: delayMs,
        llmProvider,
        llmModel,
        ...(judgeProvider ? { judgeProvider } : {}),
        ...(judgeModel ? { judgeModel } : {}),
        enableLlmGeneration,
        includeSeedAttacks,
        enableMultiTurnGeneration: enableMultiTurn,
        enableAdaptiveMultiTurn,
        maxMultiTurnSteps,
        enableDiscovery,
        skipIrrelevantCategories: skipIrrelevant,
        requireReviewConfirmation: requireReview,
        strategiesPerRound,
        attacksPerStrategy,
        attackMode,
        enabledCategories:
          selectedCategories.length > 0 && ref && selectedCategories.length < ref.categories.length
            ? selectedCategories
            : undefined,
        enabledStrategies:
          selectedStrategies.length > 0 && ref && selectedStrategies.length < ref.strategies.length
            ? selectedStrategies
            : undefined,
      },
    };

    return config;
  };

  // Whether the minimum required target field for the chosen type is filled.
  const targetReady =
    (showJsonOverride && jsonConfig.trim().length > 0) ||
    (targetType === "mcp"
      ? mcpTransport === "streamable_http"
        ? mcpUrl.trim().length > 0
        : mcpCommand.trim().length > 0
      : baseUrl.trim().length > 0);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);

    // When reusing a previous scan's target (quality eval), the form's target
    // fields are ignored — its config comes from the saved run — so skip the
    // "target base URL required" guard.
    const usingPreviousTarget = mode === "quality" && targetSource === "previous";
    if (!usingPreviousTarget && !targetReady) {
      setError(
        targetType === "mcp"
          ? mcpTransport === "streamable_http"
            ? "MCP server URL is required."
            : "MCP command is required."
          : "Target base URL is required.",
      );
      return;
    }

    // Quality-eval mode: score the dataset against the target with the quality
    // scorer, streaming per-row progress inline (no red-team scan is launched).
    if (mode === "quality") {
      if (!datasetFile.trim()) {
        setError("Pick a quality dataset to evaluate.");
        return;
      }
      if (targetSource === "previous" && !previousRunId) {
        setError("Pick a previous scan whose target to reuse.");
        return;
      }
      setEvalRunning(true);
      setEvalReport(null);
      setEvalTail([]);
      setEvalProgress(null);
      try {
        const req =
          targetSource === "previous"
            ? { fromRunId: previousRunId, dataset: datasetFile.trim(), threshold: evalThreshold }
            : { config: buildConfig(), dataset: datasetFile.trim(), threshold: evalThreshold };
        await evalQualityStream(
          req,
          (ev) => {
            if (ev.type === "start")
              setEvalProgress({ done: 0, total: ev.total });
            else if (ev.type === "row") {
              setEvalProgress({ done: ev.done, total: ev.total });
              setEvalTail((t) =>
                [
                  { metric: ev.metric, score: ev.score, pass: ev.pass, error: ev.error },
                  ...t,
                ].slice(0, 12),
              );
            } else if (ev.type === "done") {
              setEvalReport(ev.report);
              setSuccess(
                `Eval complete — ${ev.report.summary.passed}/${ev.report.summary.total} passed (avg ${ev.report.summary.score}%).`,
              );
            } else if (ev.type === "error")
              setError(`${ev.error}${ev.detail ? ` — ${ev.detail}` : ""}`);
          },
        );
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : "Quality eval failed.");
      } finally {
        setEvalRunning(false);
        setEvalProgress(null);
      }
      return;
    }

    setSubmitting(true);
    try {
      const config = buildConfig();
      const result = await createRun(config);
      setSuccess(`Scan started! Run ID: ${result.runId}`);
      setTimeout(() => navigate("/scans"), 1500);
    } catch (err: unknown) {
      if (err instanceof SyntaxError) {
        setError("Invalid JSON in advanced config override.");
      } else {
        setError(err instanceof Error ? err.message : "Failed to start scan.");
      }
    } finally {
      setSubmitting(false);
    }
  };

  // Connect to the MCP target and list its tools/prompts/resources.
  const handleDiscover = async () => {
    setMcpDiscoverError(null);
    setMcpDiscovery(null);
    const missing =
      mcpTransport === "streamable_http" ? !mcpUrl.trim() : !mcpCommand.trim();
    if (missing) {
      setMcpDiscoverError(
        mcpTransport === "streamable_http"
          ? "Enter the MCP server URL first."
          : "Enter the MCP command first.",
      );
      return;
    }
    setMcpDiscovering(true);
    try {
      const result = await discoverMcp(buildConfig());
      if (result.ok) setMcpDiscovery(result);
      else setMcpDiscoverError(result.error || "Could not connect to the MCP server.");
    } catch (err) {
      setMcpDiscoverError(err instanceof Error ? err.message : "Discovery failed.");
    } finally {
      setMcpDiscovering(false);
    }
  };

  // Append a discovered tool name to the allowlist (dedup).
  const addToAllowlist = (tool: string) => {
    const current = mcpAllowlist.split(/[\n,]/).map((s) => s.trim()).filter(Boolean);
    if (current.includes(tool)) return;
    setMcpAllowlist([...current, tool].join(", "));
  };

  if (refLoading) {
    return (
      <div className="flex items-center justify-center py-32">
        <div className="flex flex-col items-center gap-3">
          <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
          <span className="text-sm text-muted-foreground">Loading configuration...</span>
        </div>
      </div>
    );
  }

  // For MCP targets, only categories with native MCP attacks are relevant —
  // scope the category picker to them so the scan targets the actual tools.
  const isMcpTarget = targetType === "mcp";
  const selectableCategories =
    isMcpTarget && ref?.mcpCategories?.length
      ? ref.categories.filter((c) => ref.mcpCategories!.includes(c))
      : (ref?.categories ?? []);

  const allCatsSelected =
    selectableCategories.length > 0 &&
    selectedCategories.length === selectableCategories.length;
  const allStratsSelected = ref && selectedStrategies.length === ref.strategies.length;

  // Group strategies by level
  const strategyGroups: Record<string, StrategyInfo[]> = {};
  ref?.strategies.forEach((s) => {
    const group = s.level || "other";
    if (!strategyGroups[group]) strategyGroups[group] = [];
    strategyGroups[group].push(s);
  });

  return (
    <div className="max-w-4xl mx-auto pb-8">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-1">
          <div className="w-10 h-10 rounded-xl bg-primary/10 flex items-center justify-center">
            <Rocket className="w-5 h-5 text-primary" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-foreground tracking-tight">Launch Scan</h1>
            <p className="text-sm text-muted-foreground">
              Configure and start a new security scan against your target
            </p>
          </div>
        </div>
      </div>

      {/* Alerts */}
      {error && (
        <div className="flex items-center gap-3 p-4 mb-6 bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900 rounded-xl text-sm text-red-700 dark:text-red-400">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span className="flex-1">{error}</span>
          <button onClick={() => setError(null)} className="hover:text-red-900 dark:hover:text-red-300">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}
      {success && (
        <div className="flex items-center gap-3 p-4 mb-6 bg-emerald-50 dark:bg-emerald-950/30 border border-emerald-200 dark:border-emerald-900 rounded-xl text-sm text-emerald-700 dark:text-emerald-400">
          <CheckCircle className="w-4 h-4 shrink-0" />
          <span className="flex-1">{success}</span>
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-8">
        {/* Mode: red-team security scan vs. functional-quality eval. */}
        <section>
          <Segmented
            options={[
              { value: "security", label: "Security scan" },
              { value: "quality", label: "Quality eval" },
            ]}
            value={mode}
            onChange={setMode}
          />
          <p className="text-xs text-muted-foreground mt-2">
            {mode === "quality"
              ? "Score a quality dataset for correctness against a target. Attack/template/policy settings are ignored in this mode."
              : "Run the red-team attack suite against the target."}
          </p>

          {/* Quality eval: target source — a new target or a previous scan's. */}
          {mode === "quality" && (
            <div className="mt-3 rounded-lg border border-border p-3 space-y-2">
              <span className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
                Target
              </span>
              <div>
                <Segmented
                  size="sm"
                  options={[
                    { value: "new", label: "Configure new target" },
                    { value: "previous", label: "Reuse a previous scan" },
                  ]}
                  value={targetSource}
                  onChange={setTargetSource}
                />
              </div>
              {targetSource === "previous" ? (
                previousRuns.length > 0 ? (
                  <div className="space-y-1">
                    <select
                      value={previousRunId}
                      onChange={(e) => setPreviousRunId(e.target.value)}
                      className={inputCls}
                    >
                      <option value="">Select a previous scan…</option>
                      {previousRuns.map((r) => (
                        <option key={r.runId} value={r.runId}>
                          {(r.targetUrl || "unknown target")} —{" "}
                          {new Date(r.startedAt).toLocaleString()}
                        </option>
                      ))}
                    </select>
                    <p className="text-[11px] text-muted-foreground">
                      Runs the eval against that scan's saved target (URL + auth) —
                      the target fields below are ignored.
                    </p>
                  </div>
                ) : (
                  <p className="text-[11px] text-muted-foreground">
                    No previous scans found — configure a new target instead, or run
                    a scan first.
                  </p>
                )
              ) : (
                <p className="text-[11px] text-muted-foreground">
                  Fill in the target section below (URL / auth / schema).
                </p>
              )}
            </div>
          )}
        </section>

        {/* ═══ Step 1: Template ═══ */}
        <section>
          <SectionHeader step={1} title="Choose a scan template" icon={Layers} />
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            {TEMPLATES.map((tpl) => {
              const Icon = tpl.icon;
              const isActive = activeTemplate === tpl.key;
              return (
                <button
                  key={tpl.key}
                  type="button"
                  onClick={() => applyTemplate(tpl.key)}
                  className={`relative flex flex-col items-start gap-3 p-5 rounded-xl border-2 transition-all text-left ${
                    isActive
                      ? `${tpl.border} ${tpl.bg} shadow-sm`
                      : "border-border bg-card hover:border-muted-foreground/20 hover:shadow-sm"
                  }`}
                >
                  <div
                    className={`w-10 h-10 rounded-lg flex items-center justify-center ${
                      isActive ? tpl.bg : "bg-muted"
                    }`}
                  >
                    <Icon className={`w-5 h-5 ${isActive ? tpl.color : "text-muted-foreground"}`} />
                  </div>
                  <div>
                    <span className="text-sm font-semibold text-foreground block">{tpl.label}</span>
                    <span className="text-xs text-muted-foreground leading-relaxed mt-1 block">
                      {tpl.description}
                    </span>
                  </div>
                  {isActive && (
                    <div className="absolute top-3 right-3">
                      <CheckCircle className={`w-5 h-5 ${tpl.color}`} />
                    </div>
                  )}
                </button>
              );
            })}
          </div>
        </section>

        {/* ═══ Step 2: Target ═══ */}
        <section>
          <SectionHeader step={2} title="Configure target" icon={Target} />
          <Card>
            <CardContent className="pt-5 space-y-4">
              {/* Scan name (optional) */}
              <FieldRow label="Scan name" hint="Optional — a friendly label for this scan (shown in Scan Activity)">
                <input
                  type="text"
                  value={scanName}
                  onChange={(e) => setScanName(e.target.value)}
                  placeholder="e.g. HR agent — nightly regression"
                  maxLength={120}
                  className={inputCls}
                />
              </FieldRow>

              {/* Target Type */}
              <FieldRow label="Target Type">
                <Segmented
                  options={[
                    { value: "http_agent", label: "HTTP Agent" },
                    { value: "mcp", label: "MCP" },
                    { value: "websocket_agent", label: "WebSocket" },
                  ]}
                  value={targetType}
                  onChange={(v) => {
                    setTargetType(v);
                    // Default to MCP-relevant categories when switching to MCP.
                    if (v === "mcp" && ref?.mcpCategories?.length) {
                      setSelectedCategories(
                        ref.categories.filter((c) => ref.mcpCategories!.includes(c)),
                      );
                    }
                  }}
                />
              </FieldRow>

              {/* ── HTTP Agent fields ── */}
              {targetType === "http_agent" && (
                <>
                  <FieldRow label="Base URL *" hint="The root URL of your target application">
                    <input
                      type="url"
                      value={baseUrl}
                      onChange={(e) => setBaseUrl(e.target.value)}
                      placeholder="https://api.example.com"
                      className={inputCls}
                    />
                  </FieldRow>
                  <div className="grid grid-cols-2 gap-4">
                    <FieldRow label="Agent Endpoint" hint="Path to the agent/chat endpoint">
                      <input
                        type="text"
                        value={agentEndpoint}
                        onChange={(e) => setAgentEndpoint(e.target.value)}
                        placeholder="/api/agent"
                        className={inputCls}
                      />
                    </FieldRow>
                    <FieldRow label="Auth Endpoint" hint="Login/token endpoint (if any)">
                      <input
                        type="text"
                        value={authEndpoint}
                        onChange={(e) => setAuthEndpoint(e.target.value)}
                        placeholder="/api/auth/login"
                        className={inputCls}
                      />
                    </FieldRow>
                  </div>
                </>
              )}

              {/* ── MCP fields ── */}
              {targetType === "mcp" && (
                <div className="space-y-4">
                  <FieldRow label="Transport" hint="How the scanner connects to your MCP server">
                    <div className="flex gap-2">
                      {(
                        [
                          { value: "streamable_http", label: "Streamable HTTP", desc: "Remote server (URL)" },
                          { value: "stdio", label: "Stdio", desc: "Local process (command)" },
                        ] as const
                      )
                        // Stdio spawns a local process on the server, so it's only
                        // offered on instances that explicitly enable it.
                        .filter((t) => t.value !== "stdio" || ref?.allowMcpStdio)
                        .map((t) => (
                          <button
                            key={t.value}
                            type="button"
                            onClick={() => setMcpTransport(t.value)}
                            className={`flex-1 px-3 py-2 rounded-lg text-left border transition-all ${
                              mcpTransport === t.value
                                ? "border-primary bg-primary/5"
                                : "border-border hover:border-muted-foreground/30"
                            }`}
                          >
                            <div className="text-xs font-semibold text-foreground">{t.label}</div>
                            <div className="text-[11px] text-muted-foreground">{t.desc}</div>
                          </button>
                        ))}
                    </div>
                    {!ref?.allowMcpStdio && (
                      <p className="text-[11px] text-muted-foreground mt-1.5">
                        Stdio (local process) targets are disabled on this instance. Connect a remote MCP server over Streamable HTTP.
                      </p>
                    )}
                  </FieldRow>

                  {mcpTransport === "streamable_http" ? (
                    <>
                      <FieldRow label="MCP Server URL *" hint="The MCP endpoint (streamable HTTP)">
                        <input
                          type="url"
                          value={mcpUrl}
                          onChange={(e) => setMcpUrl(e.target.value)}
                          placeholder="https://your-mcp-server.example.com/api/mcp"
                          className={inputCls}
                        />
                      </FieldRow>
                      <FieldRow label="Headers" hint="Auth headers sent to the MCP server (e.g. x-api-key)">
                        <div className="space-y-2">
                          {mcpHeaders.map((h, i) => (
                            <div key={i} className="flex gap-2">
                              <input
                                type="text"
                                value={h.key}
                                onChange={(e) => {
                                  const copy = [...mcpHeaders];
                                  copy[i] = { ...h, key: e.target.value };
                                  setMcpHeaders(copy);
                                }}
                                placeholder="Header name (e.g. x-api-key)"
                                className={`${inputCls} w-1/3`}
                              />
                              <input
                                type="text"
                                value={h.value}
                                onChange={(e) => {
                                  const copy = [...mcpHeaders];
                                  copy[i] = { ...h, value: e.target.value };
                                  setMcpHeaders(copy);
                                }}
                                placeholder="Value"
                                className={`${inputCls} flex-1`}
                              />
                              {mcpHeaders.length > 1 && (
                                <button
                                  type="button"
                                  onClick={() => setMcpHeaders(mcpHeaders.filter((_, j) => j !== i))}
                                  className="text-muted-foreground hover:text-red-500 px-1"
                                >
                                  <X className="w-4 h-4" />
                                </button>
                              )}
                            </div>
                          ))}
                          <button
                            type="button"
                            onClick={() => setMcpHeaders([...mcpHeaders, { key: "", value: "" }])}
                            className="text-xs font-medium text-primary hover:text-primary/80"
                          >
                            + Add header
                          </button>
                        </div>
                      </FieldRow>
                    </>
                  ) : (
                    <div className="grid grid-cols-2 gap-4">
                      <FieldRow label="Command *" hint="Executable that starts the MCP server">
                        <input
                          type="text"
                          value={mcpCommand}
                          onChange={(e) => setMcpCommand(e.target.value)}
                          placeholder="npx"
                          className={inputCls}
                        />
                      </FieldRow>
                      <FieldRow label="Arguments" hint="Space-separated args passed to the command">
                        <input
                          type="text"
                          value={mcpArgs}
                          onChange={(e) => setMcpArgs(e.target.value)}
                          placeholder="-y @modelcontextprotocol/server-filesystem /data"
                          className={inputCls}
                        />
                      </FieldRow>
                    </div>
                  )}

                  {/* Test connection & discover tools */}
                  <div>
                    <button
                      type="button"
                      onClick={handleDiscover}
                      disabled={mcpDiscovering}
                      className="inline-flex items-center gap-2 px-3 py-2 text-xs font-medium border border-border rounded-lg hover:border-primary hover:text-primary transition-colors disabled:opacity-50"
                    >
                      {mcpDiscovering ? (
                        <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      ) : (
                        <Globe className="w-3.5 h-3.5" />
                      )}
                      {mcpDiscovering ? "Connecting..." : "Test connection & discover tools"}
                    </button>

                    {mcpDiscoverError && (
                      <div className="mt-2 flex items-start gap-2 p-3 bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900 rounded-lg text-xs text-red-700 dark:text-red-400">
                        <AlertCircle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                        <span>{mcpDiscoverError}</span>
                      </div>
                    )}

                    {mcpDiscovery?.ok && (
                      <div className="mt-2 p-3 bg-emerald-50/50 dark:bg-emerald-950/20 border border-emerald-200 dark:border-emerald-900 rounded-lg">
                        <div className="flex items-center gap-2 text-xs font-medium text-emerald-700 dark:text-emerald-400 mb-2">
                          <CheckCircle className="w-3.5 h-3.5" />
                          Connected{mcpDiscovery.serverInfo?.name ? ` to ${mcpDiscovery.serverInfo.name}` : ""}
                          {mcpDiscovery.serverInfo?.version ? ` v${mcpDiscovery.serverInfo.version}` : ""}
                          <span className="text-muted-foreground font-normal">
                            · {mcpDiscovery.tools?.length ?? 0} tools · {mcpDiscovery.prompts?.length ?? 0} prompts · {mcpDiscovery.resources?.length ?? 0} resources
                          </span>
                        </div>
                        {(mcpDiscovery.tools?.length ?? 0) > 0 ? (
                          <>
                            <p className="text-[11px] text-muted-foreground mb-1.5">
                              Discovered tools (click to add to the allowlist):
                            </p>
                            <div className="flex flex-wrap gap-1.5">
                              {mcpDiscovery.tools!.map((t) => (
                                <button
                                  key={t.name}
                                  type="button"
                                  onClick={() => addToAllowlist(t.name)}
                                  title={t.description || t.name}
                                  className="inline-flex items-center gap-1 px-2 py-1 rounded-md text-[11px] font-medium border border-border bg-card hover:border-primary hover:text-primary transition-colors"
                                >
                                  {t.name}
                                </button>
                              ))}
                            </div>
                          </>
                        ) : (
                          <p className="text-[11px] text-muted-foreground">
                            The server exposed no tools.
                          </p>
                        )}
                      </div>
                    )}
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <FieldRow label="Tool Allowlist" hint="Only test these tools (comma/newline separated). Empty = all.">
                      <textarea
                        value={mcpAllowlist}
                        onChange={(e) => setMcpAllowlist(e.target.value)}
                        placeholder="read_file, search_docs"
                        rows={2}
                        className={`${inputCls} resize-y`}
                      />
                    </FieldRow>
                    <FieldRow label="Tool Denylist" hint="Never test these tools (keep destructive ops out of scope).">
                      <textarea
                        value={mcpDenylist}
                        onChange={(e) => setMcpDenylist(e.target.value)}
                        placeholder="delete_all, wire_transfer"
                        rows={2}
                        className={`${inputCls} resize-y`}
                      />
                    </FieldRow>
                  </div>
                  <p className="text-[11px] text-muted-foreground">
                    The scanner connects, auto-discovers the server&rsquo;s tools, prompts, and resources, then runs MCP-specific attacks (tool misuse, cross-tenant access, path traversal, SSRF, indirect prompt injection) against them.
                  </p>
                </div>
              )}

              {/* ── WebSocket fields ── */}
              {targetType === "websocket_agent" && (
                <>
                  <FieldRow label="Base URL *" hint="Host of the target (the WebSocket connects on this host)">
                    <input
                      type="url"
                      value={baseUrl}
                      onChange={(e) => setBaseUrl(e.target.value)}
                      placeholder="https://api.example.com"
                      className={inputCls}
                    />
                  </FieldRow>
                  <div className="grid grid-cols-2 gap-4">
                    <FieldRow label="WebSocket Path *" hint="Path for the chat socket on the same host">
                      <input
                        type="text"
                        value={wsPath}
                        onChange={(e) => setWsPath(e.target.value)}
                        placeholder="/ws/chat"
                        className={inputCls}
                      />
                    </FieldRow>
                    <FieldRow label="Subprotocols" hint="Optional, comma-separated">
                      <input
                        type="text"
                        value={wsSubprotocols}
                        onChange={(e) => setWsSubprotocols(e.target.value)}
                        placeholder="graphql-ws"
                        className={inputCls}
                      />
                    </FieldRow>
                  </div>
                  <FieldRow label="Token" hint="Optional auth token appended as a query param">
                    <input
                      type="text"
                      value={wsToken}
                      onChange={(e) => setWsToken(e.target.value)}
                      placeholder="Bearer/session token (if required)"
                      className={inputCls}
                    />
                  </FieldRow>
                </>
              )}

              {/* Application Details */}
              <FieldRow
                label="Application Details"
                hint="Describe your app's features, workflows, tools, and sensitive operations. Better descriptions produce more targeted attacks."
              >
                <textarea
                  value={applicationDetails}
                  onChange={(e) => setApplicationDetails(e.target.value)}
                  placeholder="E.g.: Next.js agentic app with JWT auth, RBAC, guardrails, RAG, and tools for files, DB, email, Slack..."
                  rows={3}
                  className={`${inputCls} resize-y`}
                />
              </FieldRow>
            </CardContent>
          </Card>
        </section>

        {/* ═══ Step 3: Attack Categories ═══ */}
        {ref && ref.categories.length > 0 && (
          <section>
            <SectionHeader step={3} title="Select attack categories" icon={Crosshair} />
            <Card>
              <CardContent className="pt-5">
                <div className="flex items-center justify-between mb-4">
                  <span className="text-xs text-muted-foreground">
                    {selectedCategories.length}/{selectableCategories.length} selected
                  </span>
                  <div className="flex gap-3">
                    <button
                      type="button"
                      onClick={() => setSelectedCategories([...selectableCategories])}
                      className="text-xs font-medium text-primary hover:text-primary/80"
                    >
                      Select all
                    </button>
                    <span className="text-border">|</span>
                    <button
                      type="button"
                      onClick={() => setSelectedCategories([])}
                      className="text-xs font-medium text-muted-foreground hover:text-foreground"
                    >
                      Clear
                    </button>
                  </div>
                </div>

                {selectedCategories.length > 0 && (
                  <div className="mb-4">
                    <div className="h-1.5 bg-muted rounded-full overflow-hidden">
                      <div
                        className="h-full bg-primary rounded-full transition-all duration-300"
                        style={{
                          width: `${(selectedCategories.length / Math.max(1, selectableCategories.length)) * 100}%`,
                        }}
                      />
                    </div>
                  </div>
                )}

                <div className="relative mb-3 max-w-xs">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
                  <input
                    type="text"
                    value={categorySearch}
                    onChange={(e) => setCategorySearch(e.target.value)}
                    placeholder="Search categories..."
                    className="w-full pl-9 pr-3 py-1.5 bg-background border border-border rounded-lg text-xs text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:ring-2 focus:ring-primary/20 focus:border-primary"
                  />
                </div>

                {isMcpTarget && (
                  <p className="text-[11px] text-muted-foreground mb-3 -mt-1">
                    Showing the {selectableCategories.length} categories with native MCP attacks — the rest don&rsquo;t apply to tool-call targets.
                  </p>
                )}

                <div className="flex flex-wrap gap-2">
                  {selectableCategories
                    .filter((cat) =>
                      !categorySearch ||
                      prettyCat(cat).toLowerCase().includes(categorySearch.toLowerCase()) ||
                      cat.toLowerCase().includes(categorySearch.toLowerCase()),
                    )
                    .map((cat) => {
                    const selected = selectedCategories.includes(cat);
                    return (
                      <button
                        key={cat}
                        type="button"
                        onClick={() => toggleCategory(cat)}
                        className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-all ${
                          selected
                            ? "bg-primary text-white border-primary shadow-sm"
                            : "bg-card text-muted-foreground border-border hover:border-muted-foreground/30 hover:text-foreground"
                        }`}
                      >
                        {selected && <CheckCircle className="w-3 h-3" />}
                        {prettyCat(cat)}
                      </button>
                    );
                  })}
                </div>

                {allCatsSelected && (
                  <p className="text-xs text-emerald-600 mt-3 flex items-center gap-1">
                    <CheckCircle className="w-3 h-3" />
                    All categories selected — comprehensive coverage
                  </p>
                )}
              </CardContent>
            </Card>
          </section>
        )}

        {/* ═══ Step 4: Strategies (pills, not dropdown) ═══ */}
        {ref && ref.strategies.length > 0 && (
          <section>
            <SectionHeader step={4} title="Choose strategies" icon={Play} />
            <Card>
              <CardContent className="pt-5">
                {isMcpTarget && (
                  <p className="text-[11px] text-muted-foreground mb-3">
                    Strategies shape LLM-generated attacks. MCP scans mainly run tool-call seed attacks, so strategies have limited effect here — leave LLM generation off for the most relevant MCP results.
                  </p>
                )}
                <div className="flex items-center justify-between mb-4">
                  <span className="text-xs text-muted-foreground">
                    {selectedStrategies.length}/{ref.strategies.length} selected
                  </span>
                  <div className="flex gap-3">
                    <button
                      type="button"
                      onClick={() => setSelectedStrategies(ref.strategies.map((s) => s.slug))}
                      className="text-xs font-medium text-primary hover:text-primary/80"
                    >
                      Select all
                    </button>
                    <span className="text-border">|</span>
                    <button
                      type="button"
                      onClick={() => setSelectedStrategies([])}
                      className="text-xs font-medium text-muted-foreground hover:text-foreground"
                    >
                      Clear
                    </button>
                  </div>
                </div>

                <div className="relative mb-3 max-w-xs">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
                  <input
                    type="text"
                    value={strategySearch}
                    onChange={(e) => setStrategySearch(e.target.value)}
                    placeholder="Search strategies..."
                    className="w-full pl-9 pr-3 py-1.5 bg-background border border-border rounded-lg text-xs text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:ring-2 focus:ring-primary/20 focus:border-primary"
                  />
                </div>

                {Object.entries(strategyGroups)
                  .map(([level, strategies]) => [
                    level,
                    strategies.filter(
                      (s) =>
                        !strategySearch ||
                        s.name.toLowerCase().includes(strategySearch.toLowerCase()) ||
                        s.slug.toLowerCase().includes(strategySearch.toLowerCase()),
                    ),
                  ] as [string, StrategyInfo[]])
                  .filter(([, strategies]) => strategies.length > 0)
                  .map(([level, strategies]) => (
                  <div key={level} className="mb-4 last:mb-0">
                    <div className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground mb-2">
                      {level}
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {strategies.map((s) => {
                        const selected = selectedStrategies.includes(s.slug);
                        return (
                          <button
                            key={s.slug}
                            type="button"
                            onClick={() => toggleStrategy(s.slug)}
                            className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-all ${
                              selected
                                ? "bg-primary text-white border-primary shadow-sm"
                                : "bg-card text-muted-foreground border-border hover:border-muted-foreground/30 hover:text-foreground"
                            }`}
                          >
                            {selected && <CheckCircle className="w-3 h-3" />}
                            {s.name}
                          </button>
                        );
                      })}
                    </div>
                  </div>
                ))}

                {allStratsSelected && (
                  <p className="text-xs text-emerald-600 mt-3 flex items-center gap-1">
                    <CheckCircle className="w-3 h-3" />
                    All strategies selected
                  </p>
                )}
              </CardContent>
            </Card>
          </section>
        )}

        {/* ═══ Step 5: Attack Configuration ═══ */}
        <section>
          <SectionHeader step={5} title="Attack configuration" icon={Gauge} />
          <Card>
            <CardContent className="pt-5 space-y-5">
              {/* Attack Mode */}
              <FieldRow label="Attack Mode">
                <div className="grid grid-cols-3 gap-3">
                  {ATTACK_MODES.map((mode) => (
                    <button
                      key={mode.value}
                      type="button"
                      onClick={() => setAttackMode(mode.value)}
                      className={`p-3 rounded-lg border-2 text-left transition-all ${
                        attackMode === mode.value
                          ? "border-primary bg-primary/5"
                          : "border-border hover:border-muted-foreground/20"
                      }`}
                    >
                      <div className="text-xs font-semibold text-foreground">{mode.label}</div>
                      <div className="text-[11px] text-muted-foreground mt-0.5">{mode.desc}</div>
                    </button>
                  ))}
                </div>
              </FieldRow>

              {/* Numeric params grid */}
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                <FieldRow label="Adaptive Rounds" hint="Number of attack rounds">
                  <input
                    type="number"
                    min={1}
                    max={10}
                    value={adaptiveRounds}
                    onChange={(e) => setAdaptiveRounds(Number(e.target.value))}
                    className={inputCls}
                  />
                </FieldRow>
                <FieldRow label="Max Attacks/Category" hint="Per category limit">
                  <input
                    type="number"
                    min={1}
                    max={100}
                    value={maxAttacksPerCategory}
                    onChange={(e) => setMaxAttacksPerCategory(Number(e.target.value))}
                    className={inputCls}
                  />
                </FieldRow>
                <FieldRow label="Concurrency" hint="Parallel attack threads">
                  <input
                    type="number"
                    min={1}
                    max={20}
                    value={concurrency}
                    onChange={(e) => setConcurrency(Number(e.target.value))}
                    className={inputCls}
                  />
                </FieldRow>
                <FieldRow label="Delay (ms)" hint="Between requests">
                  <input
                    type="number"
                    min={0}
                    max={5000}
                    step={50}
                    value={delayMs}
                    onChange={(e) => setDelayMs(Number(e.target.value))}
                    className={inputCls}
                  />
                </FieldRow>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <FieldRow label="Strategies per Round" hint="Sampled per category">
                  <input
                    type="number"
                    min={1}
                    max={50}
                    value={strategiesPerRound}
                    onChange={(e) => setStrategiesPerRound(Number(e.target.value))}
                    className={inputCls}
                  />
                </FieldRow>
                <FieldRow label="Attacks per Strategy" hint="Per strategy per category">
                  <input
                    type="number"
                    min={1}
                    max={10}
                    value={attacksPerStrategy}
                    onChange={(e) => setAttacksPerStrategy(Number(e.target.value))}
                    className={inputCls}
                  />
                </FieldRow>
              </div>

              {/* Toggles */}
              <div className="grid grid-cols-2 lg:grid-cols-3 gap-3">
                {[
                  { label: "LLM Generation", value: enableLlmGeneration, set: setEnableLlmGeneration },
                  { label: "Seed Attacks", value: includeSeedAttacks, set: setIncludeSeedAttacks },
                  { label: "Multi-turn", value: enableMultiTurn, set: setEnableMultiTurn },
                  { label: "Adaptive Multi-turn", value: enableAdaptiveMultiTurn, set: setEnableAdaptiveMultiTurn },
                  { label: "Discovery Round", value: enableDiscovery, set: setEnableDiscovery },
                  { label: "Skip Irrelevant", value: skipIrrelevant, set: setSkipIrrelevant },
                ].map((toggle) => (
                  <button
                    key={toggle.label}
                    type="button"
                    onClick={() => toggle.set(!toggle.value)}
                    className={`flex items-center gap-2.5 px-3 py-2.5 rounded-lg border text-xs font-medium transition-all ${
                      toggle.value
                        ? "border-primary/30 bg-primary/5 text-foreground"
                        : "border-border text-muted-foreground hover:border-muted-foreground/30"
                    }`}
                  >
                    <div
                      className={`w-8 h-4.5 rounded-full relative transition-colors ${
                        toggle.value ? "bg-primary" : "bg-muted"
                      }`}
                    >
                      <div
                        className={`absolute top-0.5 w-3.5 h-3.5 rounded-full bg-white shadow-sm transition-transform ${
                          toggle.value ? "translate-x-[14px]" : "translate-x-0.5"
                        }`}
                      />
                    </div>
                    {toggle.label}
                  </button>
                ))}
              </div>

              {enableMultiTurn && (
                <FieldRow label="Max Multi-turn Steps">
                  <input
                    type="number"
                    min={1}
                    max={30}
                    value={maxMultiTurnSteps}
                    onChange={(e) => setMaxMultiTurnSteps(Number(e.target.value))}
                    className={`${inputCls} max-w-[200px]`}
                  />
                </FieldRow>
              )}
            </CardContent>
          </Card>
        </section>

        {/* ═══ Collapsible sections ═══ */}
        <div className="space-y-3">
          <div className="flex items-center gap-3">
            <div className="h-px flex-1 bg-border" />
            <span className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
              Advanced configuration
            </span>
            <div className="h-px flex-1 bg-border" />
          </div>
          {/* Auth */}
          <CollapsibleSection title="Authentication" icon={Key}>
            <div className="space-y-4">
              <FieldRow label="Auth Methods">
                <div className="flex flex-wrap gap-2">
                  {AUTH_METHODS.map((m) => {
                    const selected = authMethods.includes(m.value);
                    return (
                      <button
                        key={m.value}
                        type="button"
                        onClick={() =>
                          setAuthMethods((prev) => {
                            if (selected) return prev.filter((x) => x !== m.value);
                            // "No Auth" is exclusive — selecting it clears the
                            // others, and selecting any real method clears it.
                            if (m.value === "none") return ["none"];
                            return [...prev.filter((x) => x !== "none"), m.value];
                          })
                        }
                        className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-all ${
                          selected
                            ? "bg-primary text-white border-primary"
                            : "bg-card text-muted-foreground border-border hover:border-muted-foreground/30"
                        }`}
                      >
                        {selected && <CheckCircle className="w-3 h-3" />}
                        {m.label}
                      </button>
                    );
                  })}
                </div>
              </FieldRow>

              {authMethods.includes("api_key") && (
                <FieldRow label="API Keys" hint="Role → Key mappings">
                  <div className="space-y-2">
                    {apiKeys.map((ak, i) => (
                      <div key={i} className="flex gap-2">
                        <input
                          type="text"
                          value={ak.role}
                          onChange={(e) => {
                            const copy = [...apiKeys];
                            copy[i] = { ...ak, role: e.target.value };
                            setApiKeys(copy);
                          }}
                          placeholder="Role (e.g. viewer)"
                          className={`${inputCls} w-1/3`}
                        />
                        <input
                          type="text"
                          value={ak.key}
                          onChange={(e) => {
                            const copy = [...apiKeys];
                            copy[i] = { ...ak, key: e.target.value };
                            setApiKeys(copy);
                          }}
                          placeholder="API key"
                          className={`${inputCls} flex-1`}
                        />
                        {apiKeys.length > 1 && (
                          <button
                            type="button"
                            onClick={() => setApiKeys(apiKeys.filter((_, j) => j !== i))}
                            className="text-muted-foreground hover:text-red-500 px-1"
                          >
                            <X className="w-4 h-4" />
                          </button>
                        )}
                      </div>
                    ))}
                    <button
                      type="button"
                      onClick={() => setApiKeys([...apiKeys, { role: "", key: "" }])}
                      className="text-xs font-medium text-primary hover:text-primary/80"
                    >
                      + Add API key
                    </button>
                  </div>
                </FieldRow>
              )}

              {authMethods.includes("bearer") && (
                <FieldRow label="Bearer Token">
                  <input
                    type="text"
                    value={bearerToken}
                    onChange={(e) => setBearerToken(e.target.value)}
                    placeholder="Enter bearer token"
                    className={inputCls}
                  />
                </FieldRow>
              )}

              {authMethods.includes("jwt") && (
                <FieldRow label="JWT Secret">
                  <input
                    type="text"
                    value={jwtSecret}
                    onChange={(e) => setJwtSecret(e.target.value)}
                    placeholder="Enter JWT secret"
                    className={inputCls}
                  />
                </FieldRow>
              )}
            </div>
          </CollapsibleSection>

          {/* LLM Configuration */}
          <CollapsibleSection title="LLM Configuration" icon={Cpu}>
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <FieldRow label="Attack LLM Provider">
                  <select value={llmProvider} onChange={(e) => setLlmProvider(e.target.value)} className={selectCls}>
                    {LLM_PROVIDERS.map((p) => (
                      <option key={p.value} value={p.value}>{p.label}</option>
                    ))}
                  </select>
                </FieldRow>
                <FieldRow label="Attack LLM Model">
                  <input
                    type="text"
                    value={llmModel}
                    onChange={(e) => setLlmModel(e.target.value)}
                    placeholder="gpt-4o"
                    className={inputCls}
                  />
                </FieldRow>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <FieldRow label="Judge Provider" hint="Defaults to attack provider if empty">
                  <select value={judgeProvider} onChange={(e) => setJudgeProvider(e.target.value)} className={selectCls}>
                    <option value="">Same as attack provider</option>
                    {LLM_PROVIDERS.map((p) => (
                      <option key={p.value} value={p.value}>{p.label}</option>
                    ))}
                  </select>
                </FieldRow>
                <FieldRow label="Judge Model" hint="Defaults to attack model if empty">
                  <input
                    type="text"
                    value={judgeModel}
                    onChange={(e) => setJudgeModel(e.target.value)}
                    placeholder="Same as attack model"
                    className={inputCls}
                  />
                </FieldRow>
              </div>
            </div>
          </CollapsibleSection>

          {/* Request / Response Schema */}
          <CollapsibleSection title="Request & Response Schema" icon={Braces}>
            <div className="space-y-4">
              <div className="grid grid-cols-2 lg:grid-cols-3 gap-4">
                <FieldRow label="Message Field" hint="Request body field for message">
                  <input value={messageField} onChange={(e) => setMessageField(e.target.value)} className={inputCls} />
                </FieldRow>
                <FieldRow label="Role Field" hint="Request body field for role">
                  <input value={roleField} onChange={(e) => setRoleField(e.target.value)} className={inputCls} />
                </FieldRow>
                <FieldRow label="API Key Field" hint="Request body field for API key">
                  <input value={apiKeyField} onChange={(e) => setApiKeyField(e.target.value)} className={inputCls} />
                </FieldRow>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <FieldRow label="Response Path" hint="JSONPath to response text">
                  <input value={responsePath} onChange={(e) => setResponsePath(e.target.value)} className={inputCls} />
                </FieldRow>
                <FieldRow label="Tool Calls Path" hint="JSONPath to tool calls array">
                  <input value={toolCallsPath} onChange={(e) => setToolCallsPath(e.target.value)} className={inputCls} />
                </FieldRow>
              </div>
            </div>
          </CollapsibleSection>

          {/* Sensitive Patterns */}
          <CollapsibleSection title="Sensitive Patterns" icon={Eye}>
            <FieldRow
              label="Patterns (one per line)"
              hint="Regex or string patterns to detect sensitive data leakage in responses"
            >
              <textarea
                value={sensitivePatterns}
                onChange={(e) => setSensitivePatterns(e.target.value)}
                placeholder={"sk-proj-\nsk_live_\nAKIA\npostgres://"}
                rows={4}
                className={`${inputCls} font-mono resize-y`}
              />
            </FieldRow>
          </CollapsibleSection>

          {/* Policy */}
          <CollapsibleSection title="Policy File" icon={FileText} defaultOpen>
            <div className="space-y-4">
              {/* Available policies */}
              <FieldRow label="Select a policy" hint="Choose from available policies or upload your own">
                <div className="flex flex-wrap gap-2">
                  {availablePolicies.map((p) => (
                    <button
                      key={p.path}
                      type="button"
                      onClick={() => setPolicyFile(p.path)}
                      title={p.description || p.name}
                      className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-all ${
                        policyFile === p.path
                          ? "bg-primary text-white border-primary shadow-sm"
                          : "bg-card text-muted-foreground border-border hover:border-muted-foreground/30 hover:text-foreground"
                      }`}
                    >
                      {policyFile === p.path && <CheckCircle className="w-3 h-3" />}
                      {p.name}
                    </button>
                  ))}
                </div>
              </FieldRow>

              {/* Upload custom policy */}
              <FieldRow label="Upload custom policy" hint="Upload a JSON policy file with global and category-specific rules">
                <div className="flex gap-2">
                  <input
                    type="file"
                    accept=".json"
                    id="policy-upload"
                    className="hidden"
                    onChange={async (e) => {
                      const file = e.target.files?.[0];
                      if (!file) return;
                      setPolicyUploadError(null);
                      setUploadingPolicy(true);
                      try {
                        const text = await file.text();
                        JSON.parse(text); // validate JSON
                        const name = file.name.replace(/\.json$/, "");
                        const res = await apiFetch<{ path: string; filename: string }>("/api/policy-upload", {
                          method: "POST",
                          body: JSON.stringify({ name, policy: text }),
                        });
                        setPolicyFile(res.path);
                        // Refresh policy list
                        const policies = await apiFetch<{ path: string; name: string; description: string }[]>("/api/policies").catch(() => []);
                        if (policies.length > 0) setAvailablePolicies(policies);
                      } catch (err) {
                        setPolicyUploadError(err instanceof Error ? err.message : "Upload failed");
                      } finally {
                        setUploadingPolicy(false);
                        e.target.value = "";
                      }
                    }}
                  />
                  <label
                    htmlFor="policy-upload"
                    className={`inline-flex items-center gap-2 px-4 py-2 text-xs font-medium border border-dashed border-border rounded-lg cursor-pointer transition-colors ${
                      uploadingPolicy ? "opacity-50 pointer-events-none" : "hover:border-primary hover:text-primary text-muted-foreground"
                    }`}
                  >
                    {uploadingPolicy ? (
                      <Loader2 className="w-4 h-4 animate-spin" />
                    ) : (
                      <Upload className="w-4 h-4" />
                    )}
                    {uploadingPolicy ? "Uploading..." : "Upload JSON policy file"}
                  </label>
                </div>
                {policyUploadError && (
                  <p className="text-xs text-red-600 dark:text-red-400 mt-1">{policyUploadError}</p>
                )}
              </FieldRow>

              {/* Current selection */}
              <FieldRow label="Selected policy path">
                <input
                  value={policyFile}
                  onChange={(e) => setPolicyFile(e.target.value)}
                  placeholder="policies/custom.json"
                  className={inputCls}
                />
              </FieldRow>
            </div>
          </CollapsibleSection>

          {/* Only shown when a dataset is actually in play: quality mode (a
              dataset is required) or arriving from the Datasets tab's "Use for
              evaluation" (?dataset=…). A plain "New Scan" hides it — the dataset
              list would be noise (and unwieldy with many datasets). */}
          {(mode === "quality" || !!deepLinkDataset) && (
          <CollapsibleSection
            title="Evaluation Dataset"
            icon={FileText}
            defaultOpen
          >
            <div className="space-y-4">
              <FieldRow
                label={mode === "quality" ? "Quality dataset (required)" : "Attack dataset"}
                hint={
                  mode === "quality"
                    ? "The quality dataset to score against the target. Manage datasets in the Datasets tab."
                    : "Run a generated NeMo dataset as the attack set (customAttacksFile). Manage datasets in the Datasets tab."
                }
              >
                <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    onClick={() => {
                      setDatasetFile("");
                      setDatasetOnly(false);
                    }}
                    className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-all ${
                      !datasetFile
                        ? "bg-primary text-white border-primary shadow-sm"
                        : "bg-card text-muted-foreground border-border hover:border-muted-foreground/30 hover:text-foreground"
                    }`}
                  >
                    {!datasetFile && <CheckCircle className="w-3 h-3" />}
                    None
                  </button>
                  {availableDatasets
                    .filter((d) =>
                      mode === "quality" ? d.kind === "quality" : d.kind !== "quality",
                    )
                    .map((d) => (
                    <button
                      key={d.path}
                      type="button"
                      onClick={() => setDatasetFile(d.path)}
                      title={`${d.rowCount} rows — ${d.path}`}
                      className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-all ${
                        datasetFile === d.path
                          ? "bg-primary text-white border-primary shadow-sm"
                          : "bg-card text-muted-foreground border-border hover:border-muted-foreground/30 hover:text-foreground"
                      }`}
                    >
                      {datasetFile === d.path && <CheckCircle className="w-3 h-3" />}
                      {d.name} ({d.rowCount})
                    </button>
                  ))}
                  {availableDatasets.length === 0 && (
                    <span className="text-xs text-muted-foreground py-1.5">
                      No datasets found — generate one in the Datasets tab.
                    </span>
                  )}
                </div>
              </FieldRow>

              {datasetFile && (
                <FieldRow
                  label="Dataset-only (regression eval)"
                  hint="Run ONLY the dataset cases — skip the planner and runtime generation. Reproducible for tracking score over time."
                >
                  <label className="inline-flex items-center gap-2 text-sm cursor-pointer">
                    <input
                      type="checkbox"
                      checked={datasetOnly}
                      onChange={(e) => setDatasetOnly(e.target.checked)}
                    />
                    <span className="text-muted-foreground">
                      customAttacksOnly
                    </span>
                  </label>
                </FieldRow>
              )}
            </div>
          </CollapsibleSection>
          )}
        </div>

        {/* ═══ Advanced JSON override ═══ */}
        <div>
          <button
            type="button"
            onClick={() => setShowJsonOverride(!showJsonOverride)}
            className="flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors"
          >
            <Code className="w-4 h-4" />
            {showJsonOverride ? "Hide" : "Show"} advanced JSON config
          </button>
        </div>

        {showJsonOverride && (
          <Card>
            <CardContent className="pt-5">
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-medium text-foreground">JSON Configuration Override</span>
                <button
                  type="button"
                  onClick={() => {
                    try {
                      setJsonConfig(JSON.stringify(buildConfig(), null, 2));
                    } catch {
                      // ignore
                    }
                  }}
                  className="text-xs font-medium text-primary hover:text-primary/80"
                >
                  Populate from form
                </button>
              </div>
              <textarea
                value={jsonConfig}
                onChange={(e) => setJsonConfig(e.target.value)}
                placeholder='{"target": {"baseUrl": "...", ...}, "auth": {...}, ...}'
                rows={12}
                className={`${inputCls} font-mono resize-y`}
              />
              <p className="text-[11px] text-muted-foreground mt-2">
                When provided, this JSON is sent directly to the API, overriding all form fields above.
              </p>
            </CardContent>
          </Card>
        )}

        {/* Quality-eval live progress + results (inline, no navigation). */}
        {mode === "quality" && (evalRunning || evalProgress || evalReport) && (
          <section className="rounded-xl border border-border p-4 space-y-3">
            <div className="flex items-center justify-between gap-2 flex-wrap">
              <span className="text-sm font-semibold">Quality eval</span>
              {evalProgress && (
                <span className="text-xs text-muted-foreground">
                  {evalProgress.done}/{evalProgress.total} scored
                </span>
              )}
            </div>
            {evalReport ? (
              <div className="space-y-3">
                <div className="flex flex-wrap gap-4 text-sm">
                  <span>
                    <span className="font-semibold text-lg">
                      {evalReport.summary.score}%
                    </span>{" "}
                    <span className="text-muted-foreground">avg score</span>
                  </span>
                  <span>
                    <span className="font-semibold text-emerald-600 dark:text-emerald-400">
                      {evalReport.summary.passed}
                    </span>{" "}
                    /{evalReport.summary.total}{" "}
                    <span className="text-muted-foreground">passed</span>
                  </span>
                  {evalReport.summary.errors > 0 && (
                    <span className="text-destructive">
                      {evalReport.summary.errors} errored
                    </span>
                  )}
                  <span className="text-muted-foreground">
                    threshold {evalReport.passThreshold}
                  </span>
                </div>
                <div className="space-y-1">
                  <span className="text-xs text-muted-foreground">By metric</span>
                  <div className="flex flex-wrap gap-1.5">
                    {Object.entries(evalReport.summary.byMetric).map(([m, v]) => (
                      <span
                        key={m}
                        className="text-[11px] rounded border border-border px-1.5 py-0.5"
                      >
                        {m}: {(v.mean * 100).toFixed(0)}% ({v.passed}/{v.count})
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            ) : (
              <div className="space-y-1 max-h-48 overflow-y-auto">
                {evalTail.map((r, i) => (
                  <div key={i} className="flex items-center gap-2 text-xs">
                    <span
                      className={
                        r.error
                          ? "text-amber-600 dark:text-amber-400"
                          : r.pass
                            ? "text-emerald-600 dark:text-emerald-400"
                            : "text-destructive"
                      }
                    >
                      {r.error ? "ERR" : r.pass ? "PASS" : "FAIL"}
                    </span>
                    <span className="text-muted-foreground">{r.metric}</span>
                    <span>{r.score.toFixed(2)}</span>
                  </div>
                ))}
              </div>
            )}
          </section>
        )}

        {/* ═══ Submit — sticky action bar ═══ */}
        <div className="sticky bottom-4 z-10">
          <div className="flex items-center gap-3 rounded-2xl border border-border bg-background/90 backdrop-blur supports-[backdrop-filter]:bg-background/75 px-4 py-3 shadow-lg">
            <p className="min-w-0 flex-1 text-xs text-muted-foreground truncate">
              {mode === "quality"
                ? !datasetFile.trim()
                  ? "Select a quality dataset to run"
                  : targetSource === "previous"
                    ? previousRunId
                      ? "Ready to score"
                      : "Select a previous scan"
                    : targetReady
                      ? "Ready to score"
                      : "Configure the target below"
                : targetReady
                  ? `Ready to scan${selectableCategories.length ? ` · ${allCatsSelected || selectedCategories.length === 0 ? "all" : selectedCategories.length} categories` : ""}`
                  : "Configure a target to start"}
            </p>
            <button
              type="submit"
              disabled={
                mode === "quality"
                  ? evalRunning ||
                    !datasetFile.trim() ||
                    (targetSource === "new" ? !targetReady : !previousRunId)
                  : submitting || !targetReady
              }
              className="flex items-center justify-center gap-2.5 px-6 py-3 bg-primary text-white font-semibold rounded-xl hover:bg-primary/90 disabled:opacity-40 disabled:cursor-not-allowed transition-all shadow-sm hover:shadow-md active:scale-[0.99] shrink-0"
            >
              {mode === "quality" ? (
                evalRunning ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                    Scoring…
                  </>
                ) : (
                  <>
                    <Play className="w-5 h-5" />
                    Run quality eval
                  </>
                )
              ) : submitting ? (
                <>
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  Starting Scan...
                </>
              ) : (
                <>
                  <Play className="w-5 h-5" />
                  Start Scan
                </>
              )}
            </button>
          </div>
        </div>
      </form>
    </div>
  );
}
