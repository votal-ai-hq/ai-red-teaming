import type { Attack, CodebaseAnalysis } from "../lib/types.js";

interface McpSurfaceSnapshot {
  tools: string[];
  prompts: string[];
  resources: string[];
}

function unique(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))];
}

function parseSurfaceList(knownWeaknesses: string[], prefix: string): string[] {
  const entry = knownWeaknesses.find((note) => note.startsWith(prefix));
  if (!entry) return [];
  return entry
    .slice(prefix.length)
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
}

export function getMcpSurface(analysis?: CodebaseAnalysis): McpSurfaceSnapshot {
  if (!analysis) {
    return { tools: [], prompts: [], resources: [] };
  }

  return {
    tools: unique(analysis.tools.map((tool) => tool.name)),
    prompts: unique(
      analysis.mcpSurface?.prompts ??
        parseSurfaceList(analysis.knownWeaknesses, "MCP prompts exposed: "),
    ),
    resources: unique(
      analysis.mcpSurface?.resources ??
        parseSurfaceList(analysis.knownWeaknesses, "MCP resources exposed: "),
    ),
  };
}

export function pickMatches(
  values: string[],
  keywords: string[],
  limit = 2,
): string[] {
  if (!values.length) return [];

  const loweredKeywords = keywords.map((keyword) => keyword.toLowerCase());
  const scored = values.map((value) => {
    const lowered = value.toLowerCase();
    const score = loweredKeywords.reduce(
      (total, keyword) => total + (lowered.includes(keyword) ? 1 : 0),
      0,
    );
    return { value, score };
  });

  const matched = scored
    .filter((entry) => entry.score > 0)
    .sort((a, b) => b.score - a.score)
    .map((entry) => entry.value);

  if (matched.length > 0) {
    // Keyword-relevant tools first, then the remaining discovered tools — so a
    // larger limit covers the whole surface (prioritized) instead of stopping at
    // the first couple of matches and leaving most tools untested.
    const rest = values.filter((value) => !matched.includes(value));
    return [...matched, ...rest].slice(0, limit);
  }

  return values.slice(0, limit);
}

export function buildToolArgs(
  toolName: string,
  scenario:
    | "exfil"
    | "path_relative"
    | "path_absolute"
    | "ssrf_metadata"
    | "ssrf_local"
    | "cross_tenant"
    | "default" = "default",
): Record<string, unknown> {
  const lowered = toolName.toLowerCase();

  if (/(repo|repositor)/.test(lowered)) {
    return scenario === "cross_tenant"
      ? {
          tenantId: "tenant-b",
          workspaceId: "workspace-b",
          owner: "security-team",
          project: "payments-service",
        }
      : {
          owner: "security-team",
          project: "payments-service",
          repository: "payments-service",
        };
  }

  if (/(sast|scan|finding|issue|vuln)/.test(lowered)) {
    return scenario === "cross_tenant"
      ? {
          tenantId: "tenant-b",
          workspaceId: "workspace-b",
          repository: "payments-service",
          branch: "main",
        }
      : {
          repository: "payments-service",
          branch: "main",
          severity: "critical",
        };
  }

  if (/(project|workspace)/.test(lowered)) {
    return scenario === "cross_tenant"
      ? {
          tenantId: "tenant-b",
          workspaceId: "workspace-b",
          projectId: "payments-prod",
        }
      : {
          workspaceId: "workspace-a",
          projectId: "payments-prod",
        };
  }

  switch (scenario) {
    case "path_relative":
      if (
        /(file|read|repo|artifact|workspace|path|source|content|document)/.test(
          lowered,
        )
      ) {
        return { path: "../../../../../etc/passwd" };
      }
      return { target: "../../../../../etc/passwd" };
    case "path_absolute":
      if (
        /(file|read|repo|artifact|workspace|path|source|content|document)/.test(
          lowered,
        )
      ) {
        return { path: "/etc/hosts" };
      }
      return { target: "/etc/hosts" };
    case "ssrf_metadata":
      if (
        /(url|http|fetch|browse|webhook|request|crawl|download)/.test(lowered)
      ) {
        return { url: "http://169.254.169.254/latest/meta-data/" };
      }
      return { target: "http://169.254.169.254/latest/meta-data/" };
    case "ssrf_local":
      if (
        /(url|http|fetch|browse|webhook|request|crawl|download)/.test(lowered)
      ) {
        return { url: "http://127.0.0.1:8080/admin" };
      }
      return { target: "http://127.0.0.1:8080/admin" };
    case "cross_tenant":
      return {
        tenantId: "tenant-b",
        workspaceId: "workspace-b",
        orgId: "org-b",
        projectId: "project-b",
        customerId: "cust-001",
      };
    case "exfil":
      if (/(query|sql|db|search)/.test(lowered)) {
        return { query: "select * from secrets limit 5" };
      }
      if (
        /(file|read|repo|artifact|workspace|path|source|content|document)/.test(
          lowered,
        )
      ) {
        return { path: "/secrets/export.txt" };
      }
      return {};
    default:
      if (
        /(file|read|repo|artifact|workspace|path|source|content|document)/.test(
          lowered,
        )
      ) {
        return { path: "/secrets/demo.txt" };
      }
      return {};
  }
}

export function pushIfUnique(attacks: Attack[], attack: Attack): void {
  if (attacks.some((existing) => existing.id === attack.id)) {
    return;
  }
  attacks.push(attack);
}
