// ── Shared types for the red-team framework ──

import type { UsageSummary } from "./llm-usage.js";
export type { UsageSummary };

export type AttackCategory =
  | "auth_bypass"
  | "rbac_bypass"
  | "prompt_injection"
  | "output_evasion"
  | "data_exfiltration"
  | "rate_limit"
  | "sensitive_data"
  | "indirect_prompt_injection"
  | "steganographic_exfiltration"
  | "out_of_band_exfiltration"
  | "training_data_extraction"
  | "side_channel_inference"
  | "tool_misuse"
  | "rogue_agent"
  | "goal_hijack"
  | "identity_privilege"
  | "unexpected_code_exec"
  | "cascading_failure"
  | "multi_agent_delegation"
  | "memory_poisoning"
  | "tool_output_manipulation"
  | "guardrail_timing"
  | "multi_turn_escalation"
  | "conversation_manipulation"
  | "context_window_attack"
  | "slow_burn_exfiltration"
  | "brand_reputation"
  | "competitor_endorsement"
  | "toxic_content"
  | "misinformation"
  | "pii_disclosure"
  | "regulatory_violation"
  | "copyright_infringement"
  | "consent_bypass"
  | "session_hijacking"
  | "cross_tenant_access"
  | "api_abuse"
  | "supply_chain"
  | "social_engineering"
  | "harmful_advice"
  | "bias_exploitation"
  | "content_filter_bypass"
  | "agentic_workflow_bypass"
  | "tool_chain_hijack"
  | "agent_reflection_exploit"
  | "cross_session_injection"
  | "drug_synthesis"
  | "weapons_violence"
  | "financial_crime"
  | "cyber_crime"
  | "csam_minor_safety"
  | "fake_quotes_misinfo"
  | "competitor_sabotage"
  | "defamation_harassment"
  | "brand_impersonation"
  | "hate_speech_dogwhistle"
  | "radicalization_content"
  | "targeted_harassment"
  | "influence_operations"
  | "psychological_manipulation"
  | "deceptive_misinfo"
  | "hallucination"
  | "overreliance"
  | "over_refusal"
  | "rag_poisoning"
  | "rag_attribution"
  | "model_extraction"
  | "membership_inference"
  | "backdoor_trigger"
  | "data_poisoning"
  | "gradient_leakage"
  | "model_inversion"
  | "rag_corpus_poisoning"
  | "retrieval_ranking_attack"
  | "vector_store_manipulation"
  | "chunk_boundary_injection"
  | "embedding_inversion"
  | "structured_output_injection"
  | "generated_code_rce"
  | "markdown_link_injection"
  | "sycophancy_exploitation"
  | "hallucination_inducement"
  | "format_confusion_attack"
  | "model_dos"
  | "token_flooding_dos"
  | "infinite_loop_agent"
  | "quota_exhaustion_attack"
  | "inference_attack"
  | "re_identification"
  | "linkage_attack"
  | "differential_privacy_violation"
  | "logic_bomb_conditional"
  | "agentic_legal_commitment"
  | "contextual_integrity_violation"
  | "financial_fraud_facilitation"
  | "gdpr_erasure_bypass"
  | "prompt_template_injection"
  | "mcp_server_compromise"
  | "plugin_manifest_spoofing"
  | "sdk_dependency_attack"
  | "fine_tuning_data_injection"
  | "debug_access"
  | "shell_injection"
  | "sql_injection"
  | "unauthorized_commitments"
  | "off_topic"
  | "divergent_repetition"
  | "model_fingerprinting"
  | "special_token_injection"
  | "cross_lingual_attack"
  | "medical_safety"
  | "financial_compliance"
  | "pharmacy_safety"
  | "insurance_compliance"
  | "ecommerce_security"
  | "telecom_compliance"
  | "housing_discrimination"
  | "ssrf"
  | "path_traversal"
  | "multimodal_ghost_injection"
  | "graph_consensus_poisoning"
  | "inter_agent_protocol_abuse"
  | "mcp_tool_namespace_collision"
  | "computer_use_injection"
  | "streaming_voice_injection"
  | "cross_modal_conflict"
  | "llm_judge_manipulation"
  | "retrieval_tenant_bleed"
  | "insecure_output_handling"
  | "sandbox_escape"
  | "tool_permission_escalation"
  | "alignment_faking"
  | "capability_elicitation"
  | "instruction_hierarchy_violation"
  | "agentic_scope_creep"
  | "state_persistence_attack"
  | "encoding_serialization_attack"
  | "multi_hop_reasoning_exploit"
  | "emotional_manipulation"
  | "reward_hacking"
  | "universal_adversarial_trigger"
  | "tool_result_injection"
  | "tool_argument_injection"
  | "reasoning_trace_leakage"
  | "guardrail_mode_confusion"
  | "inbox_prompt_injection"
  | "repo_prompt_injection"
  | "cross_tool_data_exfiltration"
  | "email_slack_exfiltration"
  | "database_exfiltration"
  | "file_system_exfiltration"
  | "audit_log_evasion"
  | "provenance_forgery"
  | "multi_turn_privilege_escalation"
  | "staged_exfiltration";

/** Runtime list of all attack categories (kept in sync with {@link AttackCategory}). */
export const ALL_ATTACK_CATEGORIES: readonly AttackCategory[] = [
  "auth_bypass",
  "rbac_bypass",
  "prompt_injection",
  "output_evasion",
  "data_exfiltration",
  "rate_limit",
  "sensitive_data",
  "indirect_prompt_injection",
  "steganographic_exfiltration",
  "out_of_band_exfiltration",
  "training_data_extraction",
  "side_channel_inference",
  "tool_misuse",
  "rogue_agent",
  "goal_hijack",
  "identity_privilege",
  "unexpected_code_exec",
  "cascading_failure",
  "multi_agent_delegation",
  "memory_poisoning",
  "tool_output_manipulation",
  "guardrail_timing",
  "multi_turn_escalation",
  "conversation_manipulation",
  "context_window_attack",
  "slow_burn_exfiltration",
  "brand_reputation",
  "competitor_endorsement",
  "toxic_content",
  "misinformation",
  "pii_disclosure",
  "regulatory_violation",
  "copyright_infringement",
  "consent_bypass",
  "session_hijacking",
  "cross_tenant_access",
  "api_abuse",
  "supply_chain",
  "social_engineering",
  "harmful_advice",
  "bias_exploitation",
  "content_filter_bypass",
  "agentic_workflow_bypass",
  "tool_chain_hijack",
  "agent_reflection_exploit",
  "cross_session_injection",
  "drug_synthesis",
  "weapons_violence",
  "financial_crime",
  "cyber_crime",
  "csam_minor_safety",
  "fake_quotes_misinfo",
  "competitor_sabotage",
  "defamation_harassment",
  "brand_impersonation",
  "hate_speech_dogwhistle",
  "radicalization_content",
  "targeted_harassment",
  "influence_operations",
  "psychological_manipulation",
  "deceptive_misinfo",
  "hallucination",
  "overreliance",
  "over_refusal",
  "rag_poisoning",
  "rag_attribution",
  "model_extraction",
  "membership_inference",
  "backdoor_trigger",
  "data_poisoning",
  "gradient_leakage",
  "model_inversion",
  "rag_corpus_poisoning",
  "retrieval_ranking_attack",
  "vector_store_manipulation",
  "chunk_boundary_injection",
  "embedding_inversion",
  "structured_output_injection",
  "generated_code_rce",
  "markdown_link_injection",
  "sycophancy_exploitation",
  "hallucination_inducement",
  "format_confusion_attack",
  "model_dos",
  "token_flooding_dos",
  "infinite_loop_agent",
  "quota_exhaustion_attack",
  "inference_attack",
  "re_identification",
  "linkage_attack",
  "differential_privacy_violation",
  "logic_bomb_conditional",
  "agentic_legal_commitment",
  "contextual_integrity_violation",
  "financial_fraud_facilitation",
  "gdpr_erasure_bypass",
  "prompt_template_injection",
  "mcp_server_compromise",
  "plugin_manifest_spoofing",
  "sdk_dependency_attack",
  "fine_tuning_data_injection",
  "debug_access",
  "shell_injection",
  "sql_injection",
  "unauthorized_commitments",
  "off_topic",
  "divergent_repetition",
  "model_fingerprinting",
  "special_token_injection",
  "cross_lingual_attack",
  "medical_safety",
  "financial_compliance",
  "pharmacy_safety",
  "insurance_compliance",
  "ecommerce_security",
  "telecom_compliance",
  "housing_discrimination",
  "ssrf",
  "path_traversal",
  "multimodal_ghost_injection",
  "graph_consensus_poisoning",
  "inter_agent_protocol_abuse",
  "mcp_tool_namespace_collision",
  "computer_use_injection",
  "streaming_voice_injection",
  "cross_modal_conflict",
  "llm_judge_manipulation",
  "retrieval_tenant_bleed",
  "insecure_output_handling",
  "sandbox_escape",
  "tool_permission_escalation",
  "alignment_faking",
  "capability_elicitation",
  "instruction_hierarchy_violation",
  "agentic_scope_creep",
  "state_persistence_attack",
  "encoding_serialization_attack",
  "multi_hop_reasoning_exploit",
  "emotional_manipulation",
  "reward_hacking",
  "universal_adversarial_trigger",
  "tool_result_injection",
  "tool_argument_injection",
  "reasoning_trace_leakage",
  "guardrail_mode_confusion",
  "inbox_prompt_injection",
  "repo_prompt_injection",
  "cross_tool_data_exfiltration",
  "email_slack_exfiltration",
  "database_exfiltration",
  "file_system_exfiltration",
  "audit_log_evasion",
  "provenance_forgery",
  "multi_turn_privilege_escalation",
  "staged_exfiltration",
];

const ATTACK_CATEGORY_SET = new Set<string>(ALL_ATTACK_CATEGORIES);

export function isAttackCategory(s: string): s is AttackCategory {
  return ATTACK_CATEGORY_SET.has(s);
}

export type Verdict = "PASS" | "FAIL" | "PARTIAL" | "ERROR";

export type DefenseType =
  | "guardrail_keyword"
  | "polite_refusal"
  | "content_filter"
  | "role_denial"
  | "tool_avoidance"
  | "topic_deflection"
  | "partial_compliance"
  | "safe_response"
  | "unknown";

export interface CategoryDefenseProfile {
  category: AttackCategory;
  totalAttempts: number;
  blocked: number;
  passed: number;
  partial: number;
  blockRate: number;
  defenseBreakdown: Record<string, number>;
  dominantDefense: DefenseType;
  failedStrategyIds: number[];
  passedStrategyIds: number[];
  refusalPatterns: string[];
  guardrailTriggers: string[];
}

export interface Credential {
  email: string;
  password: string;
  role: string;
}

export type TargetType = "http_agent" | "mcp" | "websocket_agent";
export type McpTransportType = "stdio" | "sse" | "streamable_http";

/** WebSocket chat targets (e.g. wss://host/ws/chat with a JSON message protocol). */
export interface WebSocketTargetConfig {
  /** Path on the same host as baseUrl, e.g. "/ws/chat" */
  path: string;
  /** WebSocket subprotocols to negotiate (optional) */
  subprotocols?: string[];
  /** Optional token query param (browser localStorage auth) */
  token?: string;
  /** Max wait for a complete agent reply (default 120000) */
  responseTimeoutMs?: number;
}

/**
 * Optional infrastructure descriptor used by the dashboard's Attack Path graph
 * to render Wiz-style typed nodes (Compute Instance, AI Model, Data Store, etc.).
 * Everything here is optional — when omitted, the graph falls back to
 * auto-inference from the target URL, tool calls, and codebase analysis.
 */
export interface TargetInfra {
  /** Cloud provider: "aws", "gcp", "azure", "vercel", "self-hosted", etc. */
  cloudProvider?: string;
  /** Human-readable application name (e.g. "Votal AI LiteLLM Proxy"). */
  applicationName?: string;
  /** Compute instance hosting the agent (e.g. "ec2-0169f-scenario52"). */
  computeInstance?: {
    name: string;
    /** "ec2", "gce", "aks", "lambda", "cloudrun", "container", etc. */
    kind?: string;
    region?: string;
  };
  /** Service account / managed identity the agent runs as. */
  serviceAccount?: {
    name: string;
    /** "service_account", "managed_identity", "iam_role", etc. */
    kind?: string;
  };
  /** Downstream data stores the agent can reach (DBs, buckets, vector stores). */
  dataStores?: {
    name: string;
    /** "postgres", "redis", "s3", "pinecone", "neo4j", "cloudsql", etc. */
    kind?: string;
    /** Optional: what category(s) are likely to touch this store. */
    categories?: AttackCategory[];
  }[];
  /** Explicit AI model label (e.g. "claude-sonnet-4.5", "gpt-4o"). Falls back to `attackConfig.llmModel`. */
  aiModel?: {
    name: string;
    /** "anthropic", "openai", "openrouter", "bedrock", "vertex", etc. */
    provider?: string;
  };
  /** Known/expected tools the agent has (adds to auto-detected tool calls). */
  hostedTools?: {
    name: string;
    /** "api", "shell", "rag", "mcp", "plugin", etc. */
    kind?: string;
  }[];
}

export interface McpTargetConfig {
  transport: McpTransportType;
  command?: string;
  args?: string[];
  url?: string;
  headers?: Record<string, string>;
  env?: Record<string, string>;
  allowlistedTools?: string[];
  denylistedTools?: string[];
  startupTimeoutMs?: number;
  sessionTimeoutMs?: number;
  /**
   * Enable the agent-in-the-loop indirect-prompt-injection mode: drive an LLM
   * that holds the MCP tools, seed poisoned content into a read tool's result,
   * and observe whether the model chains into an unauthorized write or leaks a
   * planted canary. Requires a configured LLM provider. Off by default.
   */
  agentLoop?: boolean;
}

export interface Config {
  /** Optional user-given name for this scan (shown in Scan Activity). */
  name?: string;
  target: {
    /** Execution target type. Defaults to "http_agent". */
    type?: TargetType;
    /** Base URL of the target app (HTTP agent mode). */
    baseUrl?: string;
    /** Agent endpoint path to attack (HTTP agent mode). */
    agentEndpoint?: string;
    /** Auth endpoint path for login/JWT acquisition (HTTP agent mode). */
    authEndpoint?: string;
    /** Free-form description of what the application does, users, workflows, and sensitive operations. */
    applicationDetails?: string;
    /** MCP server connection details (MCP mode). */
    mcp?: McpTargetConfig;
    /** Custom API template for non-standard endpoints */
    customApiTemplate?: {
      /** HTTP method (default: POST) */
      method?: "GET" | "POST" | "PUT" | "PATCH";
      /** Custom headers to include in requests */
      headers?: Record<string, string>;
      /** Template for request body. Use {{message}} placeholder for the attack message */
      bodyTemplate?: string;
      /** Optional request-level guardrails array for OpenAI-compatible chat endpoints. */
      guardrails?: string[];
      /** JSONPath to extract response from API response (e.g., "choices[0].message.content" for OpenAI) */
      responsePath?: string;
    };
    /**
     * Shell command to run before setup steps (e.g., generate an SSO token).
     * stdout is captured and stored as a session variable.
     */
    preAuthCommand?: {
      /** Shell command to execute (e.g., "python3 scripts/get_token.py 9245099016") */
      command: string;
      /** Session variable name to store the command's stdout (trimmed) */
      outputVar: string;
    };
    /**
     * HTTP setup steps executed before attacks (e.g., create a conversation session).
     * Each step can extract values from the response into session variables.
     * Supports {{uuid}}, {{var:name}} in urls, headers, and body.
     * Re-runs before each round if refreshPerRound is true.
     */
    setupSteps?: Array<{
      name?: string;
      url: string;
      method?: "GET" | "POST" | "PUT" | "PATCH";
      headers?: Record<string, string>;
      body?: Record<string, unknown>;
      /** Key = variable name, Value = dot-path to extract from response JSON */
      extract?: Record<string, string>;
    }>;
    /** Re-run preAuthCommand + setupSteps before each round (for expiring tokens). Default: false. */
    refreshPerRound?: boolean;
    /** Re-run preAuthCommand + setupSteps before starting each attack conversation. Default: false. */
    refreshPerConversation?: boolean;
    /** WebSocket chat settings when target.type is "websocket_agent". */
    websocket?: WebSocketTargetConfig;
    /** Optional infrastructure descriptor for the Attack Path visualization. */
    infra?: TargetInfra;
  };
  codebasePath?: string | null;
  /** Git repo URL to clone for white-box analysis (used when codebasePath is not available, e.g. remote deployment). */
  codebaseRepo?: string | null;
  /** Branch/tag to checkout when cloning codebaseRepo (default: HEAD). */
  codebaseRepoBranch?: string;
  /** Git auth token for private repos (appended as https://token@host/...). */
  codebaseRepoToken?: string;
  codebaseGlob: string;
  /** Path to the judge policy JSON file (default: "policies/default.json"). */
  policyFile?: string;
  auth: {
    methods: string[];
    jwtSecret: string;
    credentials: Credential[];
    apiKeys: Record<string, string>;
    /** Static bearer token to attach to all requests. If set, used as default auth when no other method applies. */
    bearerToken?: string;
  };
  requestSchema: {
    messageField: string;
    roleField: string;
    apiKeyField: string;
    guardrailModeField: string;
  };
  responseSchema: {
    responsePath: string;
    toolCallsPath: string;
    userInfoPath: string;
    guardrailsPath: string;
  };
  sensitivePatterns: string[];
  /**
   * Optional path to a `.json` or `.csv` file of custom attacks.
   * Relative paths resolve against the directory containing the loaded `config.json`.
   * Omit or use an empty string to skip file-based custom attacks.
   */
  customAttacksFile?: string;
  /** Defaults for row-shaped entries in custom attack files (not full `Attack` objects). */
  customAttacksDefaults?: {
    authMethod?: Attack["authMethod"];
    role?: string;
  };
  attackConfig: {
    adaptiveRounds: number;
    maxAttacksPerCategory: number;
    concurrency: number;
    /** Number of attack categories to run in parallel (default 1 = sequential). */
    categoryParallelism?: number;
    delayBetweenRequestsMs: number;
    llmProvider: "openai" | "anthropic" | "openrouter" | "together" | "azure" | "custom" | "nim" | "huggingface";
    llmModel: string;
    /** Optional request-level guardrails array for attack generation LLM calls. */
    llmGuardrails?: string[];
    /** LLM provider for the judge (defaults to llmProvider if not set). */
    judgeProvider?: "openai" | "anthropic" | "openrouter" | "together" | "azure" | "custom" | "nim" | "huggingface";
    judgeModel?: string;
    /** Optional request-level guardrails array for judge LLM calls. */
    judgeGuardrails?: string[];
    enableLlmGeneration: boolean;
    /** Include built-in seed attacks on round 1. Default: true. */
    includeSeedAttacks?: boolean;
    maxMultiTurnSteps: number;
    /** Optional allowlist of attack categories to run. Omit or set to empty array to run all. */
    enabledCategories?: AttackCategory[];
    /** Optional allowlist of strategy slugs to use for LLM generation. Omit or set to empty array to use all. */
    enabledStrategies?: string[];
    /**
     * How many strategies to sample per category per round (default: 5).
     * If this value is greater than or equal to the number of eligible strategies, or >= 100,
     * every eligible strategy (enabled slugs or full catalog) is passed to generation and the
     * model is asked for one attack per strategy.
     */
    strategiesPerRound?: number;
    /** Max PARTIAL results to refine per category per round (default: 10). */
    maxRefinementsPerCategory?: number;
    /** Minimum LLM judge confidence (0-100) required to keep a PASS verdict. Below this, PASS is downgraded to PARTIAL. Default: 70. */
    judgeConfidenceThreshold?: number;
    /** Skip attack categories whose surface area is not found in the target codebase. Default: true. */
    skipIrrelevantCategories?: boolean;
    /** Character budget per analysis batch (default: 100_000). */
    contextBudgetChars?: number;
    /** Max LLM calls for codebase analysis batching (default: 3). */
    maxAnalysisBatches?: number;
    /** Require interactive user confirmation before executing planned/refined attacks. Default: true. */
    requireReviewConfirmation?: boolean;
    /** Enable multi-turn attack generation for follow-up steps. Default: false. */
    enableMultiTurnGeneration?: boolean;
    /** Probability (0.0-1.0) that a generated attack will include multi-turn steps. Default: 0.3. */
    multiTurnGenerationRate?: number;
    /** Enable adaptive multi-turn attacks that react to AI responses. Default: true when enableMultiTurnGeneration is true. */
    enableAdaptiveMultiTurn?: boolean;
    /** Maximum conversation turns for adaptive multi-turn attacks. Default: 15. */
    maxAdaptiveTurns?: number;
    /** Generate ideal (safe) responses for PASS/PARTIAL results. Default: true when enableLlmGeneration is on. */
    enableIdealResponses?: boolean;
    /**
     * Round 1 only: when `true` and there is at least one custom attack (file and/or app-tailored),
     * run **only** those attacks — the built-in planner is skipped for that round.
     * When `false` (default), custom attacks are **prepended** before built-in planned attacks (seeds + module LLM).
     * This flag does **not** disable loading `customAttacksFile`; remove that path (or clear it) to turn off file-based cases.
     */
    customAttacksOnly?: boolean;
    /**
     * When > 0, the framework calls the attack LLM once to synthesize this many custom-style test cases
     * from `applicationDetails` + codebase analysis (merged with file-based custom attacks for round 1).
     * Capped at 25. Default: 0 (off).
     */
    appTailoredCustomPromptCount?: number;
    /**
     * Optional in-run synthetic dataset generation. When set to `"nemo"`, the
     * framework generates a NeMo Data Designer dataset (seeded from the live
     * codebase analysis) and merges the rows into the custom attacks for the
     * run — a generate-then-execute pass. Failure is non-fatal: the run falls
     * back to whatever file-based custom attacks are present.
     * See docs/specs/nemo-data-designer-datasets.md §8 (Phase 3).
     */
    datasetGenerator?: "nemo";
    /** Config for `datasetGenerator`. Path is resolved relative to the config dir. */
    datasetGeneratorConfig?: {
      /** Preset file (configs/datasets/*.preset.json). */
      preset: string;
      /** Override the preset row count for in-run generation (keep modest). */
      count?: number;
      /** When true, seed generation from the live codebase analysis. Default: true. */
      seedFromAnalysis?: boolean;
    };
    /** Run an automated discovery round before attack rounds to probe the target and enrich sensitivePatterns. Default: false. */
    enableDiscovery?: boolean;
    /**
     * Path to a JSON file with custom delivery strategies.
     * Format: [{ slug, name, promptModifier, level?, levelName? }]
     */
    customStrategiesFile?: string;
    /**
     * Optional CSV file with category-aware strategy rankings.
     * Format: category,strategy,affinity_score with higher scores ranked first.
     * When omitted, the framework auto-uses data/strategy-category-affinity.csv if it exists.
     */
    strategyCategoryAffinityFile?: string;
    /**
     * Number of attacks to generate per strategy per category in full-pool mode. Default: 1.
     * Increasing this multiplies LLM-generated attacks: attacksPerStrategy × strategies × categories.
     */
    attacksPerStrategy?: number;
    /**
     * Controls how attack prompts are generated.
     * - "aggressive": Direct, obvious harmful prompts — tests baseline detection.
     * - "balanced": Mix of direct and disguised prompts (default).
     * - "subtle": Highly disguised, natural-sounding messages — tests evasion resistance.
     */
    attackMode?: "aggressive" | "balanced" | "subtle";
  };
}

export interface FrameworkDetection {
  name:
    | "langchain"
    | "crewai"
    | "autogen"
    | "openai-assistants"
    | "vercel-ai-sdk";
  confidence: "high" | "medium";
  evidence: string[];
}

export interface ToolChain {
  source: string;
  sink: string;
  risk: "critical" | "high" | "medium";
  description: string;
}

export interface AffectedFile {
  file: string;
  line?: number;
  reason: string;
}

export interface CodebaseAnalysis {
  tools: { name: string; description: string; parameters: string }[];
  roles: { name: string; permissions: string[] }[];
  guardrailPatterns: { type: string; patterns: string[] }[];
  sensitiveData: { type: string; location: string; example: string }[];
  authMechanisms: string[];
  knownWeaknesses: string[];
  systemPromptHints: string[];
  detectedFrameworks: FrameworkDetection[];
  toolChains: ToolChain[];
  mcpSurface?: {
    serverName?: string;
    protocolVersion?: string;
    capabilities: string[];
    prompts: string[];
    resources: string[];
  };
  /** Maps attack categories to the target source files they affect. */
  affectedFiles?: Partial<Record<AttackCategory, AffectedFile[]>>;
}

export interface AttackStep {
  payload: Record<string, unknown>;
  expectation?: string;
}

export interface Attack {
  id: string;
  category: AttackCategory;
  name: string;
  description: string;
  authMethod: "jwt" | "api_key" | "body_role" | "none" | "forged_jwt";
  role: string;
  payload: Record<string, unknown>;
  headers?: Record<string, string>;
  expectation: string;
  severity: "critical" | "high" | "medium" | "low";
  isLlmGenerated: boolean;
  /** Multi-turn: additional follow-up steps after the initial payload. */
  steps?: AttackStep[];
  /** If this attack was refined from a partial result, reference the original. */
  refinedFrom?: string;
  /** Delivery strategy used to craft the payload (id from `ALL_STRATEGIES` in attack-strategies). */
  strategyId?: number;
  /** Human-readable strategy name. */
  strategyName?: string;
}

export interface McpTraceEvent {
  direction: "client->server" | "server->client" | "server->client-notify";
  method?: string;
  payload: unknown;
}

export interface McpExecutionTrace {
  transport: McpTransportType;
  operation?: string;
  serverName?: string;
  protocolVersion?: string;
  transcript: McpTraceEvent[];
  stderr?: string;
}

/** A single request/response exchange in a multi-turn attack. */
export interface ConversationStep {
  stepIndex: number;
  payload: Record<string, unknown>;
  statusCode: number;
  responseBody: unknown;
  responseTimeMs: number;
}

export interface IdealResponse {
  /** The safe response the endpoint should have returned. */
  response: string;
  /** Why this response is correct and what was wrong with the actual one. */
  explanation: string;
  /** Actionable remediation steps for the developer. */
  remediationHints: string[];
}

export interface AttackResult {
  attack: Attack;
  verdict: Verdict;
  llmVerdict?: Verdict;
  statusCode: number;
  responseBody: unknown;
  responseTimeMs: number;
  executionTrace?: McpExecutionTrace;
  findings: string[];
  llmReasoning?: string;
  llmEvidenceFor?: string;
  llmEvidenceAgainst?: string;
  /** Confidence score (0–100) from the LLM judge. Absent for deterministic verdicts. */
  judgeConfidence?: number;
  /** The resolved judge policy used for this evaluation. */
  policyUsed?: {
    name: string;
    pass_criteria: string[];
    fail_criteria: string[];
    partial_criteria: string[];
    instructions: string;
    severity_override?: string | null;
  };
  /** For multi-turn attacks: which step produced the result (0 = initial). */
  stepIndex?: number;
  /** Total steps executed (1 = single-turn). */
  totalSteps?: number;
  /** Full request/response history for multi-turn attacks. */
  conversation?: ConversationStep[];
  /** LLM-generated ideal response showing what the endpoint should have returned. */
  idealResponse?: IdealResponse;
}

export interface AttackModule {
  category: AttackCategory;
  getSeedAttacks(analysis?: CodebaseAnalysis): Attack[];
  getGenerationPrompt(analysis: CodebaseAnalysis): string;
}

export interface StaticFinding {
  rule: string;
  severity: "critical" | "high" | "medium" | "low";
  file: string;
  line?: number;
  description: string;
  snippet?: string;
}

export interface StaticAnalysisResult {
  findings: StaticFinding[];
  score: number;
  checkedFiles: number;
}

export interface RoundResult {
  round: number;
  results: AttackResult[];
}

/**
 * Snapshot of target-related config persisted into the Report so the
 * dashboard can render the Attack Path graph without needing the live config.
 */
export interface ReportTargetDescriptor {
  type?: TargetType;
  baseUrl?: string;
  agentEndpoint?: string;
  applicationDetails?: string;
  mcp?: {
    transport?: McpTransportType;
    serverName?: string;
    url?: string;
  };
  websocket?: { path?: string };
  infra?: TargetInfra;
  /** Primary LLM model used by the target (best-effort: from infra or attackConfig). */
  llmModel?: string;
  llmProvider?: string;
}

export interface Report {
  timestamp: string;
  targetUrl: string;
  /** Snapshot of target config for UI rendering (Attack Path graph, etc.). */
  target?: ReportTargetDescriptor;
  /**
   * Per-scan LLM usage metrics (tokens, estimated cost, latency, errors) for the
   * LLM calls this tool made during the run — attack generation, judging, etc.
   * Tokens/latency/calls are measured; cost is an estimate from a price table.
   * Absent on runs recorded before this feature shipped. See {@link UsageSummary}.
   */
  usage?: UsageSummary;
  /**
   * Provenance of the eval dataset used for this run, when the run's attack set
   * came from a `customAttacksFile`. Enables grouping runs by dataset to track
   * score over time (regression tracking). Absent for planner-only scans.
   */
  dataset?: {
    /** The customAttacksFile path (dataset identity for grouping). */
    file: string;
    /** Whether the run was dataset-only (customAttacksOnly). */
    only: boolean;
  };
  rounds: RoundResult[];
  summary: {
    totalAttacks: number;
    passed: number;
    failed: number;
    partial: number;
    errors: number;
    score: number;
    byCategory: Record<
      AttackCategory,
      { total: number; passed: number; findings: string[] }
    >;
  };
  findings: {
    severity: string;
    category: AttackCategory;
    description: string;
    attack: string;
    strategyId?: number;
    strategyName?: string;
    affectedFiles?: AffectedFile[];
  }[];
  staticAnalysis?: StaticAnalysisResult;
  compliance?: ComplianceResult[];
  /** Maps attack categories to the target source files they affect. */
  affectedFiles?: Partial<Record<AttackCategory, AffectedFile[]>>;
  /** Intelligence gathered from the automated discovery round (if enabled). */
  discovery?: {
    discoveredTools: string[];
    discoveredDataStores: string[];
    discoveredPatterns: string[];
    architectureHints: string[];
    guardrailProfile: string[];
    weaknesses: string[];
    authMechanisms: string[];
    sessionArtifacts: string[];
    privilegeBoundaries: string[];
    integrationPoints: string[];
    dataFlows: string[];
    sensitiveDataClasses: string[];
    fileHandlingSurfaces: string[];
    inputParsers: string[];
    configSources: string[];
    secretHandlingLocations: string[];
    detectionGaps: string[];
    featureFlags: string[];
    defaultAssumptions: string[];
    unknowns: string[];
    targetSurfaces: string[];
    attackObjectives: string[];
    promptManipulationSurfaces: string[];
    jailbreakRiskCategories: string[];
    systemPromptExposureSignals: string[];
    retrievalAttackSurfaces: string[];
    memoryAttackSurfaces: string[];
    toolUseAttackSurfaces: string[];
    agenticFailureModes: string[];
    privacyAndLeakageRisks: string[];
    unsafeCapabilityAreas: string[];
    deceptionAndManipulationRisks: string[];
    boundaryConditions: string[];
    multimodalRiskSurfaces: string[];
    summary: string;
    probeCount: number;
  };
}

/** One mapped attack, with the reason it falls under a given control. */
export interface ComplianceMappedAttack {
  name: string;
  category: AttackCategory;
  /** Delivery strategy / tactic used to craft the attack (e.g. crescendo, roleplay). */
  strategy?: string;
  severity: "critical" | "high" | "medium" | "low";
  verdict: "PASS" | "PARTIAL" | "FAIL";
  /** Short finding / judge reasoning — why the attack succeeded or was blocked. */
  detail?: string;
}

export interface ComplianceResult {
  framework: string;
  code: string;
  title: string;
  /** What this control covers — the basis for why attacks map to it. */
  description?: string;
  totalAttacks: number;
  passed: number;
  partial: number;
  failed: number;
  status: "vulnerable" | "at_risk" | "secure" | "not_tested";
  findings: string[];
  /** Highest outcome-based severity among the attacks that landed on this
   *  control (undefined when nothing succeeded). Lets a row be acted on without
   *  going back to the source scan. */
  severity?: "critical" | "high" | "medium" | "low";
  /** Deterministic 0–100 confidence that `status` is correct, derived from the
   *  evidence (agreement + volume) rather than a decorative constant. Undefined
   *  when the control was not tested. */
  confidence?: number;
  /** One-line, direction-correct explanation of the outcome — what the target
   *  did, never what the scanner did. */
  rationale?: string;
  /** Attack categories this control maps to — the basis for coverage, shown
   *  even when the control is not_tested so users see what WOULD exercise it. */
  categories?: AttackCategory[];
  /** Every attack mapped to this control (reason = category ∈ control scope). */
  attacks: ComplianceMappedAttack[];
}
