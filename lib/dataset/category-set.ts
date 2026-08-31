/**
 * Single source of truth for dataset generation category pools + strategy slugs.
 *
 * Everything here is derived from the authoritative runtime exports in
 * `lib/types.ts` (`ALL_ATTACK_CATEGORIES`, `isAttackCategory`) and
 * `lib/attack-strategies.ts` (`ALL_STRATEGIES`) so the generator can never
 * drift from the executor's understanding of what a valid attack is.
 *
 * See docs/specs/nemo-data-designer-datasets.md §3.2 and §5.
 */
import {
  ALL_ATTACK_CATEGORIES,
  isAttackCategory,
  type AttackCategory,
} from "../types.js";
import { ALL_STRATEGIES } from "../attack-strategies.js";

export type DatasetFamily = "mcp" | "agent";

/**
 * MCP-server family: categories whose attacks are meaningful against a
 * tool/prompt/resource surface (multi-step chains, cross-tenant, injection).
 */
const MCP_CATEGORY_POOL: AttackCategory[] = [
  "tool_misuse",
  "tool_chain_hijack",
  "tool_output_manipulation",
  "cross_tenant_access",
  "cross_session_injection",
  "indirect_prompt_injection",
  "mcp_server_compromise",
  "mcp_tool_poisoning",
  "mcp_prompt_poisoning",
  "mcp_resource_poisoning",
  "mcp_tool_annotation_spoofing",
  "mcp_protocol_downgrade",
  "mcp_session_hijacking",
  "mcp_capability_manipulation",
  "plugin_manifest_spoofing",
  "sdk_dependency_attack",
  "debug_access",
  "data_exfiltration",
  "agentic_workflow_bypass",
  "rbac_bypass",
  "session_hijacking",
  "shell_injection",
  "sql_injection",
  "unexpected_code_exec",
  "prompt_template_injection",
];

/**
 * Agent family: broader conversational / agentic attack surface.
 */
const AGENT_CATEGORY_POOL: AttackCategory[] = [
  "prompt_injection",
  "indirect_prompt_injection",
  "system_prompt_disclosure",
  "tool_inventory_disclosure",
  "goal_hijack",
  "memory_poisoning",
  "pii_disclosure",
  "sensitive_data",
  "rbac_bypass",
  "auth_bypass",
  "output_evasion",
  "content_filter_bypass",
  "multi_turn_escalation",
  "conversation_manipulation",
  "social_engineering",
  "agent_reflection_exploit",
  "rogue_agent",
  "multi_agent_delegation",
  "data_exfiltration",
];

const FAMILY_POOLS: Record<DatasetFamily, AttackCategory[]> = {
  mcp: MCP_CATEGORY_POOL,
  agent: AGENT_CATEGORY_POOL,
};

/**
 * Default category pool for a family. Guaranteed to contain only members of
 * `AttackCategory`; a stray value here would be a programming error, so we
 * fail loudly at call time rather than silently shipping a bad seed set.
 */
export function defaultCategoryPool(family: DatasetFamily): AttackCategory[] {
  const pool = FAMILY_POOLS[family];
  const invalid = pool.filter((c) => !isAttackCategory(c));
  if (invalid.length > 0) {
    throw new Error(
      `internal error: family "${family}" pool contains non-categories: ${invalid.join(", ")}`,
    );
  }
  return [...pool];
}

/**
 * Resolve a preset's category list into a validated pool. Unknown labels are
 * rejected (fail-closed) — unlike the loader, which warns and defaults. This is
 * the guard that keeps a "deep eval" from silently misrouting cases.
 */
export function resolveCategoryPool(
  family: DatasetFamily,
  requested: string[] | undefined,
): AttackCategory[] {
  if (!requested || requested.length === 0) return defaultCategoryPool(family);
  const unknown = requested.filter((c) => !isAttackCategory(c));
  if (unknown.length > 0) {
    throw new Error(
      `preset category pool has values outside AttackCategory: ${unknown.join(", ")}`,
    );
  }
  return requested as AttackCategory[];
}

/** All strategy slugs available as a delivery-strategy sampler seed. */
export function allStrategySlugs(): string[] {
  return ALL_STRATEGIES.map((s) => s.slug);
}

/** The full authoritative category list, as data (for the union sampler). */
export function allCategories(): AttackCategory[] {
  return [...ALL_ATTACK_CATEGORIES];
}

export { isAttackCategory };
export type { AttackCategory };
