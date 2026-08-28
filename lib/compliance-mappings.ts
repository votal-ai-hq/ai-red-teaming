// ── OWASP Compliance Mappings ──
// Maps attack categories to OWASP LLM Top 10 (2025) and OWASP Agentic Security Top 10

import type { AttackCategory } from "./types.js";

export interface ComplianceFramework {
  id: string;
  name: string;
  items: ComplianceItem[];
}

export interface ComplianceItem {
  code: string;
  title: string;
  description: string;
  categories: AttackCategory[];
}

export interface ComplianceResult {
  framework: string;
  code: string;
  title: string;
  totalAttacks: number;
  passed: number;
  partial: number;
  failed: number;
  status: "vulnerable" | "at_risk" | "secure" | "not_tested";
  findings: string[];
}

// ── OWASP LLM Top 10 (2025) ──

export const OWASP_LLM_TOP_10: ComplianceItem[] = [
  {
    code: "LLM01:2025",
    title: "Prompt Injection",
    description: "Manipulating model outputs via malicious inputs",
    categories: [
      "prompt_injection",
      "indirect_prompt_injection",
      "content_filter_bypass",
      "special_token_injection",
      "cross_lingual_attack",
      "agent_reflection_exploit",
      "context_window_attack",
      "multimodal_ghost_injection",
      "computer_use_injection",
      "streaming_voice_injection",
      "cross_modal_conflict",
      "tool_result_injection",
      "inbox_prompt_injection",
      "repo_prompt_injection",
      "guardrail_mode_confusion",
      "mcp_tool_poisoning",
      "mcp_prompt_poisoning",
    ],
  },
  {
    code: "LLM02:2025",
    title: "Sensitive Information Disclosure",
    description: "Leaking confidential data in outputs",
    categories: [
      "sensitive_data",
      "data_exfiltration",
      "pii_disclosure",
      "training_data_extraction",
      "side_channel_inference",
      "membership_inference",
      "model_inversion",
      "embedding_inversion",
      "inference_attack",
      "re_identification",
      "linkage_attack",
      "differential_privacy_violation",
      "steganographic_exfiltration",
      "slow_burn_exfiltration",
      "out_of_band_exfiltration",
      "retrieval_tenant_bleed",
      "cross_tool_data_exfiltration",
      "email_slack_exfiltration",
      "database_exfiltration",
      "file_system_exfiltration",
      "staged_exfiltration",
      "reasoning_trace_leakage",
    ],
  },
  {
    code: "LLM03:2025",
    title: "Supply Chain Vulnerabilities",
    description: "Compromised third-party models or plugins",
    categories: [
      "supply_chain",
      "rag_poisoning",
      "prompt_template_injection",
      "mcp_server_compromise",
      "plugin_manifest_spoofing",
      "sdk_dependency_attack",
      "mcp_tool_namespace_collision",
      "mcp_tool_poisoning",
    ],
  },
  {
    code: "LLM04:2025",
    title: "Data and Model Poisoning",
    description: "Manipulating training data or embeddings",
    categories: [
      "memory_poisoning",
      "cross_session_injection",
      "rag_poisoning",
      "rag_corpus_poisoning",
      "backdoor_trigger",
      "data_poisoning",
      "gradient_leakage",
      "vector_store_manipulation",
      "chunk_boundary_injection",
      "fine_tuning_data_injection",
      "tool_output_manipulation",
      "graph_consensus_poisoning",
    ],
  },
  {
    code: "LLM05:2025",
    title: "Improper Output Handling",
    description:
      "Failing to sanitize LLM responses, leading to downstream attacks",
    categories: [
      "insecure_output_handling",
      "output_evasion",
      "unexpected_code_exec",
      "generated_code_rce",
      "structured_output_injection",
      "markdown_link_injection",
      "format_confusion_attack",
      "shell_injection",
      "sql_injection",
    ],
  },
  {
    code: "LLM06:2025",
    title: "Excessive Agency",
    description: "Over-provisioning permissions, allowing unintended actions",
    categories: [
      "tool_misuse",
      "rbac_bypass",
      "identity_privilege",
      "auth_bypass",
      "tool_chain_hijack",
      "agentic_legal_commitment",
      "contextual_integrity_violation",
      "financial_fraud_facilitation",
      "unauthorized_commitments",
      "inter_agent_protocol_abuse",
      "retrieval_tenant_bleed",
      "audit_log_evasion",
    ],
  },
  {
    code: "LLM07:2025",
    title: "System Prompt Leakage",
    description: "Exposing hidden, foundational instructions",
    categories: [
      "prompt_injection",
      "training_data_extraction",
      "prompt_template_injection",
      "model_extraction",
      "model_fingerprinting",
      "debug_access",
      "reasoning_trace_leakage",
    ],
  },
  {
    code: "LLM08:2025",
    title: "Vector and Embedding Weaknesses",
    description: "Targeting RAG system vulnerabilities",
    categories: [
      "rag_poisoning",
      "rag_corpus_poisoning",
      "retrieval_ranking_attack",
      "vector_store_manipulation",
      "chunk_boundary_injection",
      "embedding_inversion",
      "rag_attribution",
      "cross_session_injection",
      "graph_consensus_poisoning",
      "retrieval_tenant_bleed",
    ],
  },
  {
    code: "LLM09:2025",
    title: "Misinformation",
    description: "Generating false or misleading content",
    categories: [
      "misinformation",
      "hallucination",
      "sycophancy_exploitation",
      "hallucination_inducement",
      "fake_quotes_misinfo",
      "deceptive_misinfo",
      "overreliance",
      "provenance_forgery",
    ],
  },
  {
    code: "LLM10:2025",
    title: "Unbounded Consumption",
    description: "Overloading resources, causing DoS",
    categories: [
      "rate_limit",
      "cascading_failure",
      "model_dos",
      "token_flooding_dos",
      "infinite_loop_agent",
      "quota_exhaustion_attack",
      "divergent_repetition",
      "context_window_attack",
      "streaming_voice_injection",
    ],
  },
];

// ── OWASP Agentic Security Top 10 ──

export const OWASP_AGENTIC_TOP_10: ComplianceItem[] = [
  {
    code: "ASI01",
    title: "Agent Goal Hijack",
    description:
      "Attackers manipulate instructions, prompts, or external content to redirect agent objectives",
    categories: [
      "goal_hijack",
      "prompt_injection",
      "indirect_prompt_injection",
      "agentic_workflow_bypass",
      "conversation_manipulation",
      "multi_turn_escalation",
      "multimodal_ghost_injection",
      "graph_consensus_poisoning",
      "cross_modal_conflict",
    ],
  },
  {
    code: "ASI02",
    title: "Tool Misuse & Exploitation",
    description:
      "Agents use legitimate tools to perform unauthorized, malicious actions due to poor validation",
    categories: [
      "tool_misuse",
      "tool_chain_hijack",
      "tool_output_manipulation",
      "structured_output_injection",
      "generated_code_rce",
      "shell_injection",
      "sql_injection",
      "path_traversal",
      "ssrf",
      "api_abuse",
      "computer_use_injection",
      "mcp_tool_namespace_collision",
      "tool_result_injection",
      "tool_argument_injection",
    ],
  },
  {
    code: "ASI03",
    title: "Identity & Privilege Abuse",
    description:
      "Exploiting agent permissions, session tokens, or credentials that often exceed user scope",
    categories: [
      "identity_privilege",
      "auth_bypass",
      "rbac_bypass",
      "session_hijacking",
      "cross_tenant_access",
      "debug_access",
      "inter_agent_protocol_abuse",
      "retrieval_tenant_bleed",
      "multi_turn_privilege_escalation",
    ],
  },
  {
    code: "ASI04",
    title: "Agentic Supply Chain Vulnerabilities",
    description:
      "Compromise of tools, plugins, models, or MCP servers used by the agent",
    categories: [
      "supply_chain",
      "rag_poisoning",
      "rag_corpus_poisoning",
      "prompt_template_injection",
      "backdoor_trigger",
      "mcp_server_compromise",
      "plugin_manifest_spoofing",
      "sdk_dependency_attack",
      "fine_tuning_data_injection",
      "mcp_tool_namespace_collision",
      "mcp_tool_poisoning",
      "graph_consensus_poisoning",
    ],
  },
  {
    code: "ASI05",
    title: "Unexpected Code Execution",
    description:
      "Agents are tricked into generating and executing malicious code",
    categories: [
      "unexpected_code_exec",
      "generated_code_rce",
      "shell_injection",
      "sql_injection",
      "insecure_output_handling",
    ],
  },
  {
    code: "ASI06",
    title: "Memory & Context Poisoning",
    description:
      "Corrupting the agent's memory or RAG databases to alter behavior",
    categories: [
      "memory_poisoning",
      "cross_session_injection",
      "rag_poisoning",
      "rag_corpus_poisoning",
      "data_poisoning",
      "vector_store_manipulation",
      "chunk_boundary_injection",
      "context_window_attack",
      "multimodal_ghost_injection",
      "graph_consensus_poisoning",
      "streaming_voice_injection",
      "cross_modal_conflict",
      "retrieval_tenant_bleed",
    ],
  },
  {
    code: "ASI07",
    title: "Insecure Inter-Agent Communication",
    description:
      "Interception or spoofing of messages within multi-agent systems",
    categories: [
      "multi_agent_delegation",
      "agent_reflection_exploit",
      "agentic_workflow_bypass",
      "inter_agent_protocol_abuse",
    ],
  },
  {
    code: "ASI08",
    title: "Cascading Failures",
    description:
      "One agent's error or compromise triggers a chain reaction leading to system-wide failure",
    categories: ["cascading_failure", "divergent_repetition", "rate_limit"],
  },
  {
    code: "ASI09",
    title: "Human-Agent Trust Exploitation",
    description:
      "Exploiting over-reliance on AI, where agents convince humans to approve unsafe actions",
    categories: [
      "social_engineering",
      "overreliance",
      "sycophancy_exploitation",
      "hallucination_inducement",
      "psychological_manipulation",
      "conversation_manipulation",
      "agentic_legal_commitment",
      "financial_fraud_facilitation",
      "unauthorized_commitments",
      "llm_judge_manipulation",
    ],
  },
  {
    code: "ASI10",
    title: "Rogue Agents",
    description:
      "Agents that behave unexpectedly or go rogue due to conflicting goals or adversarial tampering",
    categories: [
      "rogue_agent",
      "goal_hijack",
      "logic_bomb_conditional",
      "infinite_loop_agent",
      "influence_operations",
      "off_topic",
      "cross_modal_conflict",
      "streaming_voice_injection",
    ],
  },
];

export const ALL_FRAMEWORKS: ComplianceFramework[] = [
  {
    id: "owasp-llm-2025",
    name: "OWASP LLM Top 10 (2025)",
    items: OWASP_LLM_TOP_10,
  },
  {
    id: "owasp-agentic-2025",
    name: "OWASP Agentic Security Top 10",
    items: OWASP_AGENTIC_TOP_10,
  },
];
